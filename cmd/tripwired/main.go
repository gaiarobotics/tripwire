//go:build linux

// Command tripwired is the Tripwire daemon: it marks decoy credential files,
// attributes whoever opens one, holds the read while the response ladder runs,
// and answers the kernel afterwards.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mbarnathan/tripwire/internal/action"
	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/bait"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/daemon"
	"github.com/mbarnathan/tripwire/internal/policy"
	"github.com/mbarnathan/tripwire/internal/state"
	"github.com/mbarnathan/tripwire/internal/watch"
)

const (
	defaultConfigPath = "/etc/tripwire/config.yaml"
	fingerprintPath   = "/etc/tripwire/fingerprint"

	// refreshInterval keeps decoy expiry timestamps plausible. A token that
	// expired two years ago announces itself as bait.
	refreshInterval = 12 * time.Hour
)

func main() {
	configPath := flag.String("config", defaultConfigPath, "path to config.yaml")
	flag.Parse()

	log.SetFlags(0) // journald already timestamps every line

	// Escape hatch for a physically-present admin: boot with tripwire.disable=1.
	if kernelDisabled() {
		log.Println("tripwired: disabled via kernel cmdline (tripwire.disable=1); exiting")
		return
	}

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("tripwired: read config: %v", err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		log.Fatalf("tripwired: config: %v", err)
	}
	st := &state.Store{Dir: cfg.State}
	actions := daemon.EffectiveActions(cfg, st)

	watcher, marker, attributed := openWatcher(cfg)
	defer watcher.Close()

	// Without attribution there is no reader to kill and no identity to justify
	// powering a host off, so the fallback backend is alert-only by construction.
	if !attributed && hasDestructive(actions) {
		log.Printf("tripwired: destructive actions %v disabled: they require fanotify attribution", actions)
		actions = []string{"alert"}
	}

	marked := markAll(marker, cfg.BaitPaths())
	if marked == 0 {
		log.Fatalf("tripwired: no decoys could be marked; refusing to run disarmed")
	}

	// fanotify marks are per-inode, so watch the parent directories too and
	// re-mark anything that gets replaced underneath us.
	var replaced <-chan string
	if dw, err := watch.NewDirWatcher(cfg.BaitPaths()); err != nil {
		log.Printf("tripwired: parent-directory watch unavailable: %v (replaced decoys will not be re-marked)", err)
	} else {
		defer dw.Close()
		replaced = dw.Replaced()
	}

	tree := attrib.NewProcFS()
	killer := &action.Killer{Tree: tree}
	action.SetSignal(killer, attrib.Signal)

	host, _ := os.Hostname()
	fingerprint := readFingerprint()

	d := &daemon.Daemon{
		Cfg:     cfg,
		Actions: actions,
		Watcher: watcher,
		Marker:  marker,
		Replace: replaced,
		Snap:    &attrib.Snapshotter{},
		Rules:   policy.Compile(cfg.Allow),
		Ladder: &action.Ladder{
			Actions:      actions,
			Sinks:        alert.FromConfig(cfg),
			AlertTimeout: cfg.AlertTimeout,
			Killer:       killer,
			Scope:        cfg.Kill.Scope,
			MaxKill:      cfg.Kill.MaxKill,
			Power:        action.SystemPowerOffer{},
			PoweroffMode: cfg.Poweroff.Mode,
		},
		Hold:        action.NewHold(cfg.EffectiveHold()),
		State:       st,
		Host:        host,
		Fingerprint: fingerprint,
		Attributed:  attributed,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go refreshLoop(ctx, cfg, marker, fingerprint)

	log.Printf("tripwired: watching %d decoys, actions=%v, hold=%s, attribution=%t",
		marked, actions, cfg.EffectiveHold(), attributed)
	if err := d.Run(ctx); err != nil {
		log.Fatalf("tripwired: %v", err)
	}
	log.Println("tripwired: shutting down; pending reads fail open")
}

// openWatcher prefers fanotify (attribution + hold) and degrades to inotify.
func openWatcher(cfg *config.Config) (watch.Watcher, watch.Marker, bool) {
	fan, err := watch.NewFanotify()
	if err == nil {
		return fan, fan, true
	}
	log.Printf("tripwired: WARNING fanotify unavailable (%v)", err)
	log.Printf("tripwired: WARNING falling back to inotify: reads are DETECTED but NOT attributed and NOT held;")
	log.Printf("tripwired: WARNING destructive actions are disabled in this mode")
	ino, ierr := watch.NewInotify()
	if ierr != nil {
		log.Fatalf("tripwired: no usable watch backend: fanotify: %v; inotify: %v", err, ierr)
	}
	return ino, ino, false
}

func markAll(m watch.Marker, paths []string) int {
	marked := 0
	for _, p := range paths {
		if err := m.Mark(p); err != nil {
			log.Printf("tripwired: mark %s: %v", p, err)
			continue
		}
		marked++
	}
	return marked
}

// refreshLoop rewrites the decoys periodically so their expiry timestamps stay
// in the future. The write is unmark -> place (temp file + rename) -> re-mark:
// the daemon never opens a marked inode, because doing so would deadlock it
// against its own permission event.
func refreshLoop(ctx context.Context, cfg *config.Config, m watch.Marker, fingerprint string) {
	decoys, err := cfg.Decoys()
	if err != nil {
		// Validation already rejected this at startup; belt and braces.
		log.Printf("tripwired: refresh disabled: %v", err)
		return
	}
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, d := range decoys {
				if d.Kind == bait.KindLLM {
					// Generated decoys are the CLI's to rewrite. The daemon runs
					// as root with CAP_SYS_ADMIN and makes no outbound calls, and
					// overwriting generated content with a template would undo
					// exactly what the operator asked for.
					continue
				}
				_ = m.Unmark(d.Path)
				if err := bait.PlaceSafe(d, fingerprint, time.Now()); err != nil {
					log.Printf("tripwired: refresh %s: %v", d.Path, err)
				}
				if err := m.Mark(d.Path); err != nil {
					log.Printf("tripwired: re-mark %s after refresh: %v", d.Path, err)
				}
			}
		}
	}
}

func hasDestructive(actions []string) bool {
	for _, a := range actions {
		if a == "kill" || a == "poweroff" {
			return true
		}
	}
	return false
}

func kernelDisabled() bool {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "tripwire.disable=1")
}

func readFingerprint() string {
	if b, err := os.ReadFile(fingerprintPath); err == nil {
		if fp := strings.TrimSpace(string(b)); fp != "" {
			return fp
		}
	}
	return bait.Fingerprint()
}
