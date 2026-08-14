// Command tripwire controls and inspects the Tripwire daemon.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/bait"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/state"
)

const (
	defaultConfigPath = "/etc/tripwire/config.yaml"
	fingerprintPath   = "/etc/tripwire/fingerprint"
)

// cli holds everything the subcommands touch, so tests can redirect output and
// point at a temporary config and state directory.
type cli struct {
	configPath      string
	fingerprintPath string
	out             io.Writer
	now             func() time.Time
}

func main() {
	c := &cli{
		configPath:      envOr("TRIPWIRE_CONFIG", defaultConfigPath),
		fingerprintPath: envOr("TRIPWIRE_FINGERPRINT", fingerprintPath),
		out:             os.Stdout,
		now:             time.Now,
	}
	if err := c.run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c *cli) run(args []string) error {
	if len(args) < 1 {
		c.usage()
		return fmt.Errorf("no subcommand given")
	}
	switch args[0] {
	case "status":
		return c.status()
	case "verify":
		return c.verify()
	case "test":
		return c.test(context.Background())
	case "arm":
		return c.arm(args[1:])
	case "disarm":
		return c.disarm()
	case "reset":
		return c.reset()
	case "_place-bait": // used by the package postinstall; not documented
		return c.placeBait()
	case "-h", "--help", "help":
		c.usage()
		return nil
	default:
		c.usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func (c *cli) usage() {
	fmt.Fprintln(os.Stderr, "usage: tripwire {status|verify|test|arm [--force]|disarm|reset}")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  status   posture, arm state, and whether the wire has tripped")
	fmt.Fprintln(os.Stderr, "  verify   check that every decoy is present and 0600")
	fmt.Fprintln(os.Stderr, "  test     send a synthetic incident to the configured sinks")
	fmt.Fprintln(os.Stderr, "  arm      enable the configured destructive actions (needs a passing test)")
	fmt.Fprintln(os.Stderr, "  disarm   drop back to alert-only")
	fmt.Fprintln(os.Stderr, "  reset    clear a tripped record so the host can be armed again")
}

func (c *cli) loadConfig() (*config.Config, error) {
	raw, err := os.ReadFile(c.configPath)
	if err != nil {
		return nil, err
	}
	return config.Parse(raw)
}

func (c *cli) store(cfg *config.Config) *state.Store { return &state.Store{Dir: cfg.State} }

func (c *cli) status() error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	st := c.store(cfg)

	if st.IsTripped() {
		t, err := st.Read()
		if err != nil {
			fmt.Fprintf(c.out, "TRIPPED (record unreadable: %v)\n", err)
		} else {
			fmt.Fprintf(c.out, "TRIPPED: %s read %s at %s (auid=%d)\n",
				orUnknown(t.Exe), t.Bait, t.When.Format(time.RFC3339), t.AUID)
		}
		fmt.Fprintln(c.out, "Destructive actions are disabled until `tripwire reset`.")
	}

	posture := "alert-only"
	switch {
	case !cfg.HasDestructiveAction():
		posture = "alert-only (no destructive actions configured)"
	case st.IsTripped():
		posture = "alert-only (tripped; run `tripwire reset`)"
	case !st.IsArmed():
		posture = "alert-only (configured " + strings.Join(cfg.Actions, " -> ") + ", but NOT armed)"
	default:
		posture = "ARMED: " + strings.Join(cfg.Actions, " -> ")
	}

	fmt.Fprintf(c.out, "Profile:     %s\n", cfg.Profile)
	fmt.Fprintf(c.out, "Posture:     %s\n", posture)
	fmt.Fprintf(c.out, "Hold:        %s\n", cfg.EffectiveHold())
	fmt.Fprintf(c.out, "Kill scope:  %s (max %d)\n", cfg.Kill.Scope, cfg.Kill.MaxKill)
	fmt.Fprintf(c.out, "Decoys:      %d\n", len(c.baitPaths(cfg)))
	fmt.Fprintf(c.out, "Sinks:       %s\n", strings.Join(sinkNames(alert.FromConfig(cfg)), ", "))
	fmt.Fprintf(c.out, "Fingerprint: %s\n", c.fingerprint())

	if last, err := st.LastTest(); err == nil {
		fmt.Fprintf(c.out, "Last test:   %s (delivered=%t)\n", last.When.Format(time.RFC3339), last.Delivered)
	} else {
		fmt.Fprintln(c.out, "Last test:   never run")
	}
	return nil
}

func (c *cli) verify() error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	var bad int
	for _, p := range c.baitPaths(cfg) {
		if err := bait.Verify(bait.Decoy{Path: p}); err != nil {
			fmt.Fprintf(c.out, "  BAD  %s: %v\n", p, err)
			bad++
			continue
		}
		fmt.Fprintf(c.out, "  OK   %s\n", p)
	}
	if bad > 0 {
		return fmt.Errorf("%d decoy(s) failed verification", bad)
	}
	return nil
}

// test drives the real alert path — the same sinks, payload, and fan-out an
// incident uses — with every destructive action left out. Passing it is the
// precondition for `tripwire arm`.
func (c *cli) test(ctx context.Context) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	sinks := alert.FromConfig(cfg)
	host, _ := os.Hostname()
	exe, _ := os.Executable()

	inc := alert.Incident{
		Time:        c.now(),
		Host:        host,
		Fingerprint: c.fingerprint(),
		BaitPath:    firstOr(c.baitPaths(cfg), "/etc/codex/auth.json"),
		Verdict:     "test (no action taken)",
		Exe:         exe,
		Cmdline:     "tripwire test",
		UID:         os.Getuid(),
		AUID:        -1,
		Planned:     cfg.Actions,
		Test:        true,
	}

	fmt.Fprintf(c.out, "test: sending a synthetic incident to %d sink(s), no kill/poweroff\n", len(sinks))
	res := alert.FanOut(ctx, sinks, inc, cfg.AlertTimeout)

	result := state.TestResult{When: c.now(), Delivered: res.Delivered, Sinks: map[string]string{}}
	for _, name := range sortedKeys(res.Confirmations) {
		if err := res.Confirmations[name]; err != nil {
			fmt.Fprintf(c.out, "  FAIL %s: %v\n", name, err)
			result.Sinks[name] = err.Error()
			continue
		}
		fmt.Fprintf(c.out, "  OK   %s: confirmed\n", name)
		result.Sinks[name] = "confirmed"
	}
	if err := c.store(cfg).RecordTest(result); err != nil {
		fmt.Fprintf(c.out, "note: could not record the test result: %v\n", err)
	}
	if !res.Delivered {
		return fmt.Errorf("no sink confirmed delivery")
	}
	fmt.Fprintln(c.out, "test: at least one sink confirmed delivery")
	return nil
}

func (c *cli) arm(args []string) error {
	force := len(args) > 0 && (args[0] == "--force" || args[0] == "-f")

	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	st := c.store(cfg)

	if !cfg.HasDestructiveAction() {
		return fmt.Errorf("nothing to arm: %s lists actions %v — add kill and/or poweroff first",
			c.configPath, cfg.Actions)
	}
	if st.IsTripped() {
		return fmt.Errorf("host is tripped; run `tripwire reset` before arming")
	}
	if !force {
		last, err := st.LastTest()
		if err != nil {
			return fmt.Errorf("run `tripwire test` first so you know the alert reaches you (or arm --force)")
		}
		if !last.Delivered {
			return fmt.Errorf("the last `tripwire test` (%s) had no confirmed delivery; fix your sinks or arm --force",
				last.When.Format(time.RFC3339))
		}
	}
	if err := st.Arm(c.now()); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "armed: %s\n", strings.Join(cfg.Actions, " -> "))
	fmt.Fprintln(c.out, "run `systemctl restart tripwired` to apply")
	return nil
}

func (c *cli) disarm() error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	if err := c.store(cfg).Disarm(); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "disarmed: destructive actions are off; the daemon runs alert-only")
	fmt.Fprintln(c.out, "run `systemctl restart tripwired` to apply")
	return nil
}

func (c *cli) reset() error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	if err := c.store(cfg).Reset(); err != nil {
		return err
	}
	fmt.Fprintln(c.out, "reset: tripped state cleared")
	return nil
}

// placeBait generates the decoys. It runs from the package postinstall rather
// than shipping them as packaged files, so the decoys are owned by no package
// and look exactly like hand-configured credentials.
func (c *cli) placeBait() error {
	fp := bait.Fingerprint()
	if err := os.MkdirAll(dirOf(c.fingerprintPath), 0o755); err == nil {
		_ = os.WriteFile(c.fingerprintPath, []byte(fp+"\n"), 0o644)
	}
	now := c.now()
	for _, d := range bait.DefaultDecoys() {
		if err := bait.Place(d, fp, now); err != nil {
			return fmt.Errorf("place %s: %w", d.Path, err)
		}
		fmt.Fprintf(c.out, "placed %s\n", d.Path)
	}
	return nil
}

func (c *cli) baitPaths(cfg *config.Config) []string {
	if len(cfg.Bait) > 0 {
		return cfg.Bait
	}
	return bait.DefaultPaths()
}

func (c *cli) fingerprint() string {
	if b, err := os.ReadFile(c.fingerprintPath); err == nil {
		if fp := strings.TrimSpace(string(b)); fp != "" {
			return fp
		}
	}
	return bait.Fingerprint()
}

func sinkNames(sinks []alert.Sink) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Name())
	}
	return out
}

func sortedKeys(m map[string]error) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstOr(list []string, fallback string) string {
	if len(list) > 0 {
		return list[0]
	}
	return fallback
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "."
}
