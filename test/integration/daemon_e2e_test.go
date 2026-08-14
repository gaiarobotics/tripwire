//go:build integration && linux

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/action"
	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/bait"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/daemon"
	"github.com/mbarnathan/tripwire/internal/policy"
	"github.com/mbarnathan/tripwire/internal/state"
)

// slowWebhook stands in for ntfy: it confirms only after a delay, so the test
// can tell whether the reader was really held until delivery.
type slowWebhook struct {
	*httptest.Server
	mu       sync.Mutex
	payloads [][]byte
}

func newSlowWebhook(delay time.Duration) *slowWebhook {
	w := &slowWebhook{}
	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		time.Sleep(delay)
		w.mu.Lock()
		w.payloads = append(w.payloads, b)
		w.mu.Unlock()
		rw.WriteHeader(200)
	}))
	return w
}

func (w *slowWebhook) received() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.payloads...)
}

// TestEndToEndHoldAlertRelease is the whole product in one test: a decoy is
// marked, a non-allowlisted reader opens it, the read is held while the incident
// is delivered off-host, and only then does the reader get the worthless token.
//
// The bug this guards against is subtle and was real: journald confirms
// instantly, so a fan-out that accepted any confirmation released the reader in
// milliseconds and the notification never left the machine.
func TestEndToEndHoldAlertRelease(t *testing.T) {
	const webhookDelay = 800 * time.Millisecond

	dir := t.TempDir()
	decoy := filepath.Join(dir, "auth.json")
	if err := bait.Place(bait.Decoy{Path: decoy, Kind: bait.KindCodex}, "tw-e2e", time.Now()); err != nil {
		t.Fatal(err)
	}

	hook := newSlowWebhook(webhookDelay)
	defer hook.Close()

	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(decoy); err != nil {
		t.Fatalf("mark: %v", err)
	}

	// Allowlist one specific reader so the benign path is covered too.
	benignExe, err := exec.LookPath("head")
	if err != nil {
		t.Skip("no head(1) available for the allowlist case")
	}

	cfg, err := config.Parse([]byte("profile: server\nactions: [alert]\nalert_timeout: 10s"))
	if err != nil {
		t.Fatal(err)
	}
	tree := attrib.NewProcFS()
	killer := &action.Killer{Tree: tree}
	action.SetSignal(killer, attrib.Signal)

	d := &daemon.Daemon{
		Cfg:     cfg,
		Actions: []string{"alert"},
		Watcher: fan,
		Marker:  fan,
		Snap:    &attrib.Snapshotter{},
		Rules:   policy.Compile([]config.AllowRule{{Exe: benignExe}}),
		Ladder: &action.Ladder{
			Actions:      []string{"alert"},
			Sinks:        []alert.Sink{alert.NewWebhookSink(hook.URL, nil), alert.NewJournalSink(false)},
			AlertTimeout: 10 * time.Second,
			Killer:       killer,
			Scope:        cfg.Kill.Scope,
			MaxKill:      cfg.Kill.MaxKill,
		},
		Hold:        action.NewHold(15 * time.Second),
		State:       &state.Store{Dir: filepath.Join(dir, "state")},
		Host:        "e2e",
		Fingerprint: "tw-e2e",
		Attributed:  true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()
	time.Sleep(100 * time.Millisecond) // let the loop start

	// --- the hostile read ---
	start := time.Now()
	out, err := exec.Command("cat", decoy).Output()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("the reader must still succeed — a denial would tell them they were caught: %v", err)
	}
	if elapsed < webhookDelay {
		t.Fatalf("read completed in %v, before the alert could be delivered (%v)", elapsed, webhookDelay)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("read was held %v, far past the delivery it was waiting on", elapsed)
	}
	if len(out) == 0 {
		t.Fatal("the reader should have received the (worthless) token")
	}

	payloads := hook.received()
	if len(payloads) != 1 {
		t.Fatalf("webhook got %d payloads, want exactly 1", len(payloads))
	}
	var inc alert.Incident
	if err := json.Unmarshal(payloads[0], &inc); err != nil {
		t.Fatalf("payload is not a valid incident: %v", err)
	}
	if inc.BaitPath != decoy {
		t.Fatalf("incident bait = %q, want %q", inc.BaitPath, decoy)
	}
	if inc.Exe == "" || inc.Cmdline == "" {
		t.Fatalf("incident is missing attribution: %+v", inc)
	}
	if inc.UID != os.Getuid() {
		t.Fatalf("incident uid = %d, want %d", inc.UID, os.Getuid())
	}
	if inc.Verdict != "hostile" {
		t.Fatalf("verdict = %q", inc.Verdict)
	}

	// --- the allowlisted read: no hold, no incident ---
	start = time.Now()
	if err := exec.Command(benignExe, "-c", "10", decoy).Run(); err != nil {
		t.Fatalf("allowlisted reader failed: %v", err)
	}
	if benignElapsed := time.Since(start); benignElapsed > webhookDelay {
		t.Fatalf("allowlisted reader was held for %v; benign readers are never held", benignElapsed)
	}
	if got := len(hook.received()); got != 1 {
		t.Fatalf("webhook got %d payloads; the allowlisted read must not alert", got)
	}
}

// A tripped host must come back alert-only, and only `tripwire reset` may
// restore the configured ladder. This is the anti-boot-loop guarantee, checked
// against a real on-disk state directory.
func TestTrippedHostBootsAlertOnly(t *testing.T) {
	st := &state.Store{Dir: t.TempDir()}
	cfg, err := config.Parse([]byte("actions: [alert, poweroff]"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Arm(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := daemon.EffectiveActions(cfg, st); len(got) != 2 {
		t.Fatalf("armed host should run %v, got %v", cfg.Actions, got)
	}
	if err := st.MarkTripped(state.Trip{Bait: "/etc/codex/auth.json", When: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := daemon.EffectiveActions(cfg, st); len(got) != 1 || got[0] != "alert" {
		t.Fatalf("tripped host must boot alert-only, got %v", got)
	}
	if err := st.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := daemon.EffectiveActions(cfg, st); len(got) != 2 {
		t.Fatalf("after reset the ladder returns, got %v", got)
	}
}

// The daemon must never deadlock against its own permission event, which is what
// would happen if it opened a marked decoy. Refreshing writes a temp file and
// renames it, so the marked inode is never opened by us.
func TestRefreshDoesNotDeadlockAgainstOwnMark(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "auth.json")
	if err := bait.Place(bait.Decoy{Path: decoy, Kind: bait.KindCodex}, "tw-e2e", time.Now()); err != nil {
		t.Fatal(err)
	}
	fan := newFanotifyOrSkip(t)
	defer fan.Close()
	if err := fan.Mark(decoy); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		// This is exactly what the daemon's refresh loop does.
		_ = fan.Unmark(decoy)
		err := bait.Place(bait.Decoy{Path: decoy, Kind: bait.KindCodex}, "tw-e2e-refreshed", time.Now())
		if err == nil {
			err = fan.Mark(decoy)
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh deadlocked against the daemon's own fanotify mark")
	}

	// Drop the mark before verifying: with the decoy re-marked and no event loop
	// consuming permission events, this very read would block forever. That is
	// the same hazard the daemon avoids by never opening a marked inode.
	if err := fan.Unmark(decoy); err != nil {
		t.Fatalf("unmark: %v", err)
	}
	raw, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(raw, "tw-e2e-refreshed") {
		t.Fatal("refresh did not rewrite the decoy")
	}
}

func contains(haystack []byte, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if string(haystack[i:i+len(needle)]) == needle {
					return true
				}
			}
			return false
		}()
}
