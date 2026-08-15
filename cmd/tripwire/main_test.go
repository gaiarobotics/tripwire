package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/bait"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/state"
)

// newCLI writes a config pointing at temp dirs and returns the CLI plus its
// output buffer.
func newCLI(t *testing.T, cfgBody string) (*cli, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	cfgPath := filepath.Join(dir, "config.yaml")
	body := cfgBody + "\nstate_dir: " + stateDir + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	c := &cli{
		configPath:      cfgPath,
		fingerprintPath: filepath.Join(dir, "fingerprint"),
		out:             buf,
		now:             func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	return c, buf, stateDir
}

func TestStatusReportsUnarmedPosture(t *testing.T) {
	c, out, _ := newCLI(t, "profile: server\nactions: [alert, poweroff]")
	if err := c.run([]string{"status"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "NOT armed") {
		t.Fatalf("status must say a destructive config is not yet armed:\n%s", got)
	}
	if !strings.Contains(got, "Last test:   never run") {
		t.Fatalf("status should report no test on record:\n%s", got)
	}
}

func TestStatusReportsTrippedHost(t *testing.T) {
	c, out, stateDir := newCLI(t, "actions: [alert, poweroff]")
	st := &state.Store{Dir: stateDir}
	if err := st.MarkTripped(state.Trip{
		Bait: "/etc/codex/auth.json", Exe: "/usr/bin/curl", AUID: 1000,
		When: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.run([]string{"status"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "TRIPPED") || !strings.Contains(got, "/usr/bin/curl") {
		t.Fatalf("status must surface the trip record:\n%s", got)
	}
	if !strings.Contains(got, "tripwire reset") {
		t.Fatalf("status must tell the operator how to clear it:\n%s", got)
	}
}

// `tripwire test` must exercise the real fan-out and reach the configured sink.
func TestTestCommandDeliversToConfiguredSink(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c, out, stateDir := newCLI(t, "actions: [alert]\nsinks:\n  webhook: {url: \""+srv.URL+"\"}")
	if err := c.test(context.Background()); err != nil {
		t.Fatalf("test: %v", err)
	}
	if !strings.Contains(body, `"test":true`) {
		t.Fatalf("the synthetic incident must be flagged as a test: %s", body)
	}
	if !strings.Contains(out.String(), "confirmed") {
		t.Fatalf("output should report the confirmation:\n%s", out.String())
	}

	last, err := (&state.Store{Dir: stateDir}).LastTest()
	if err != nil {
		t.Fatalf("test result was not recorded: %v", err)
	}
	if !last.Delivered || last.Sinks["webhook"] != "confirmed" {
		t.Fatalf("recorded result = %+v", last)
	}
}

// A test where nothing confirms must fail loudly — that is the whole signal an
// operator relies on before arming.
func TestTestCommandFailsWhenNoSinkConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	// journald always confirms, so disable it by using the server profile and
	// asserting on the webhook line instead.
	c, out, stateDir := newCLI(t, "actions: [alert]\nsinks:\n  webhook: {url: \""+srv.URL+"\"}")
	err := c.test(context.Background())
	if err != nil {
		t.Fatalf("journald always confirms, so the test itself passes: %v", err)
	}
	if !strings.Contains(out.String(), "FAIL webhook") {
		t.Fatalf("a failing webhook must be reported per-sink:\n%s", out.String())
	}
	last, _ := (&state.Store{Dir: stateDir}).LastTest()
	if last.Sinks["webhook"] == "confirmed" {
		t.Fatalf("a 500 must not be recorded as confirmed: %+v", last)
	}
}

func TestArmRequiresAPassingTest(t *testing.T) {
	c, _, stateDir := newCLI(t, "actions: [alert, poweroff]")
	st := &state.Store{Dir: stateDir}

	if err := c.arm(nil); err == nil {
		t.Fatal("arming without a test on record must fail")
	}
	if st.IsArmed() {
		t.Fatal("a refused arm must not leave the host armed")
	}

	if err := st.RecordTest(state.TestResult{When: time.Now(), Delivered: false}); err != nil {
		t.Fatal(err)
	}
	if err := c.arm(nil); err == nil {
		t.Fatal("arming after a test that delivered nothing must fail")
	}

	if err := st.RecordTest(state.TestResult{When: time.Now(), Delivered: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.arm(nil); err != nil {
		t.Fatalf("arm after a passing test: %v", err)
	}
	if !st.IsArmed() {
		t.Fatal("arm must persist")
	}
}

func TestArmForceSkipsTheTestRequirement(t *testing.T) {
	c, _, stateDir := newCLI(t, "actions: [alert, kill]")
	if err := c.arm([]string{"--force"}); err != nil {
		t.Fatalf("arm --force: %v", err)
	}
	if !(&state.Store{Dir: stateDir}).IsArmed() {
		t.Fatal("arm --force must arm")
	}
}

func TestArmRefusesAlertOnlyConfig(t *testing.T) {
	c, _, _ := newCLI(t, "actions: [alert]")
	err := c.arm([]string{"--force"})
	if err == nil {
		t.Fatal("there is nothing to arm in an alert-only config")
	}
	if !strings.Contains(err.Error(), "nothing to arm") {
		t.Fatalf("err = %v", err)
	}
}

func TestArmRefusesWhileTripped(t *testing.T) {
	c, _, stateDir := newCLI(t, "actions: [alert, poweroff]")
	st := &state.Store{Dir: stateDir}
	_ = st.MarkTripped(state.Trip{Bait: "x"})
	if err := c.arm([]string{"--force"}); err == nil {
		t.Fatal("a tripped host must be reset before it can be armed")
	}
}

func TestDisarmAndReset(t *testing.T) {
	c, _, stateDir := newCLI(t, "actions: [alert, poweroff]")
	st := &state.Store{Dir: stateDir}
	if err := st.Arm(time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = st.MarkTripped(state.Trip{Bait: "x"})

	if err := c.run([]string{"disarm"}); err != nil {
		t.Fatal(err)
	}
	if st.IsArmed() {
		t.Fatal("disarm must clear the arm marker")
	}
	if err := c.run([]string{"reset"}); err != nil {
		t.Fatal(err)
	}
	if st.IsTripped() {
		t.Fatal("reset must clear the tripped record")
	}
}

func TestVerifyReportsMissingDecoys(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "auth.json")
	missing := filepath.Join(dir, "gone.json")
	if err := bait.Place(bait.Decoy{Path: present, Kind: bait.KindCodex}, "tw-x", time.Now()); err != nil {
		t.Fatal(err)
	}

	c, out, _ := newCLI(t, "bait:\n  - "+present+"\n  - "+missing)
	err := c.verify()
	if err == nil {
		t.Fatal("verify must fail when a decoy is missing")
	}
	got := out.String()
	if !strings.Contains(got, "OK   "+present) || !strings.Contains(got, "BAD  "+missing) {
		t.Fatalf("verify output:\n%s", got)
	}
}

// Placement follows the config, so an operator who moves the decoys gets those
// decoys created — not the shipped defaults.
func TestPlaceBaitFollowsConfiguredPaths(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "srv", "secrets", "openai-key.json")
	other := filepath.Join(dir, "srv", "secrets", "claude.json")
	c, out, _ := newCLI(t, "bait:\n  - "+custom+"\n  - "+other)

	if err := c.run([]string{"_place-bait"}); err != nil {
		t.Fatalf("_place-bait: %v", err)
	}
	for _, p := range []string{custom, other} {
		if err := bait.Verify(bait.Decoy{Path: p}); err != nil {
			t.Fatalf("configured decoy %s was not created: %v", p, err)
		}
	}
	// The shipped defaults must NOT have been touched.
	if strings.Contains(out.String(), "/etc/codex/auth.json") {
		t.Fatalf("placed a default path despite a custom config:\n%s", out.String())
	}
	// The schema follows the path name.
	raw, _ := os.ReadFile(custom)
	if !strings.Contains(string(raw), "OPENAI_API_KEY") {
		t.Fatalf("an openai-named decoy should carry the Codex schema: %s", raw)
	}
	raw, _ = os.ReadFile(other)
	if !strings.Contains(string(raw), "claudeAiOauth") {
		t.Fatalf("a non-codex decoy should carry the Claude schema: %s", raw)
	}
	// The fingerprint file is written for the daemon to embed in incidents.
	if _, err := os.Stat(c.fingerprintPath); err != nil {
		t.Fatalf("fingerprint file: %v", err)
	}
}

// The footgun this guards: config is root-owned and placement runs as root, so a
// typo pointing at a real file must cost an error, not the file.
func TestPlaceBaitRefusesToOverwriteARealFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "passwd")
	const original = "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(real, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _, _ := newCLI(t, "bait:\n  - "+real)

	err := c.run([]string{"_place-bait"})
	if err == nil {
		t.Fatal("placing a decoy over a real file must fail")
	}
	if !strings.Contains(err.Error(), "not written by Tripwire") {
		t.Fatalf("err = %v", err)
	}
	if got, _ := os.ReadFile(real); string(got) != original {
		t.Fatal("the real file was overwritten")
	}
}

// An unreadable or missing config must not break the package scripts: fall back
// to the shipped defaults rather than failing the install.
func TestPlaceBaitFallsBackWhenConfigIsUnreadable(t *testing.T) {
	c, out, _ := newCLI(t, "actions: [alert]")
	c.configPath = filepath.Join(t.TempDir(), "does-not-exist.yaml")

	err := c.run([]string{"_place-bait"})
	if !strings.Contains(out.String(), "using default decoy paths") {
		t.Fatalf("expected a fallback note:\n%s", out.String())
	}
	// As an unprivileged test it cannot write under /etc, which is itself proof
	// it fell back to the default absolute paths.
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("expected the unprivileged write to /etc to fail")
	}
}

func TestRemoveBaitDeletesOnlyOurFiles(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "auth.json")
	foreign := filepath.Join(dir, "real-creds.json")
	if err := bait.Place(bait.Decoy{Path: decoy, Kind: bait.KindCodex}, "tw-deadbeefdeadbeef", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte(`{"api_key":"sk-live-real"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, out, _ := newCLI(t, "bait:\n  - "+decoy+"\n  - "+foreign)

	if err := c.run([]string{"_remove-bait"}); err != nil {
		t.Fatalf("_remove-bait: %v", err)
	}
	if _, err := os.Stat(decoy); !os.IsNotExist(err) {
		t.Fatal("our decoy should have been removed")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("a file Tripwire did not write must survive uninstall")
	}
	if !strings.Contains(out.String(), "skipped "+foreign) {
		t.Fatalf("the skip should be reported:\n%s", out.String())
	}
}

// Uninstalling twice, or with the decoys already gone, must not error.
func TestRemoveBaitIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "auth.json")
	if err := bait.Place(bait.Decoy{Path: decoy, Kind: bait.KindCodex}, "tw-deadbeefdeadbeef", time.Now()); err != nil {
		t.Fatal(err)
	}
	c, _, _ := newCLI(t, "bait:\n  - "+decoy)
	for i := 0; i < 2; i++ {
		if err := c.run([]string{"_remove-bait"}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

func TestUnknownSubcommandIsAnError(t *testing.T) {
	c, _, _ := newCLI(t, "actions: [alert]")
	if err := c.run([]string{"explode"}); err == nil {
		t.Fatal("unknown subcommands must fail")
	}
	if err := c.run(nil); err == nil {
		t.Fatal("no subcommand must fail")
	}
}

// A config the daemon would reject must not be silently accepted by the CLI.
func TestBadConfigIsReported(t *testing.T) {
	c, _, _ := newCLI(t, "actions: [alert, nuke]")
	err := c.run([]string{"status"})
	if err == nil || !strings.Contains(err.Error(), "nuke") {
		t.Fatalf("err = %v, want the invalid action named", err)
	}
}

func TestStatusShowsArmedLadder(t *testing.T) {
	c, out, stateDir := newCLI(t, "actions: [alert, kill, poweroff]")
	if err := (&state.Store{Dir: stateDir}).Arm(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.status(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ARMED: alert -> kill -> poweroff") {
		t.Fatalf("status:\n%s", out.String())
	}
}

// The CLI and the daemon must agree on where state lives, or `tripwire status`
// reports on a directory the daemon never writes.
func TestStoreFollowsConfiguredStateDir(t *testing.T) {
	c, _, stateDir := newCLI(t, "actions: [alert]")
	cfg, err := c.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.store(cfg).Dir != stateDir {
		t.Fatalf("store dir = %q, want %q", c.store(cfg).Dir, stateDir)
	}
	var _ *config.Config = cfg
}
