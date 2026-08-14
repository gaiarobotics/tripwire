package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/action"
	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/policy"
	"github.com/mbarnathan/tripwire/internal/state"
	"github.com/mbarnathan/tripwire/internal/watch"
)

// fakeWatcher records responses with their arrival time so tests can assert the
// response really was deferred.
type fakeWatcher struct {
	events chan watch.Event

	mu        sync.Mutex
	responses []watch.Response
	at        []time.Time
}

func newFakeWatcher() *fakeWatcher {
	return &fakeWatcher{events: make(chan watch.Event, 4)}
}

func (f *fakeWatcher) Events() <-chan watch.Event { return f.events }
func (f *fakeWatcher) Respond(r watch.Response) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses = append(f.responses, r)
	f.at = append(f.at, time.Now())
	return nil
}
func (f *fakeWatcher) Close() error { return nil }
func (f *fakeWatcher) all() []watch.Response {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]watch.Response(nil), f.responses...)
}
func (f *fakeWatcher) respondedAt(i int) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at[i]
}

type countingSink struct {
	mu   sync.Mutex
	took time.Duration
	sent []alert.Incident
}

func (c *countingSink) Name() string { return "counting" }
func (c *countingSink) Send(ctx context.Context, inc alert.Incident) error {
	if c.took > 0 {
		select {
		case <-time.After(c.took):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, inc)
	return nil
}
func (c *countingSink) incidents() []alert.Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]alert.Incident(nil), c.sent...)
}

type recordPower struct {
	mu    sync.Mutex
	modes []string
}

func (r *recordPower) PowerOff(mode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modes = append(r.modes, mode)
	return nil
}
func (r *recordPower) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.modes...)
}

// fakeProcRoot writes a minimal /proc tree and returns a Snapshotter over it.
func fakeProcRoot(t *testing.T, pid int, exe string, uid int, auid string) *attrib.Snapshotter {
	t.Helper()
	root := filepath.Join(t.TempDir(), "proc")
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", itoa(pid)+" (reader) R 1 "+itoa(pid)+" "+itoa(pid)+" 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 4242 0 0 ...")
	write("status", "Name:\treader\nUid:\t"+itoa(uid)+"\t"+itoa(uid)+"\t"+itoa(uid)+"\t"+itoa(uid)+"\nCapEff:\t0\n")
	write("loginuid", auid)
	write("sessionid", "3")
	write("cmdline", "cat\x00/etc/codex/auth.json\x00")
	write("cgroup", "0::/user.slice/user-1000.slice/session-3.scope\n")
	_ = exe
	return &attrib.Snapshotter{ProcRoot: root}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func testDaemon(t *testing.T, actions []string, rules []config.AllowRule, sink alert.Sink, pw action.PowerOffer) (*Daemon, *fakeWatcher) {
	t.Helper()
	fw := newFakeWatcher()
	cfg, err := config.Parse([]byte("profile: server"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		Cfg:        cfg,
		Actions:    actions,
		Watcher:    fw,
		Snap:       fakeProcRoot(t, 4242, "/usr/bin/cat", 1000, "1000"),
		Rules:      policy.Compile(rules),
		Hold:       action.NewHold(0),
		State:      &state.Store{Dir: t.TempDir()},
		Host:       "testhost",
		Attributed: true,
		SelfPID:    999999,
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	d.Ladder = &action.Ladder{
		Actions: actions, Sinks: []alert.Sink{sink}, AlertTimeout: time.Second,
		Power: pw, PoweroffMode: "graceful",
	}
	return d, fw
}

func TestBenignReaderIsAllowedWithoutAlerting(t *testing.T) {
	sink := &countingSink{}
	uid := 1000
	d, fw := testDaemon(t, []string{"alert"}, []config.AllowRule{{UID: &uid}}, sink, nil)

	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})

	resp := fw.all()
	if len(resp) != 1 || !resp[0].Allow || resp[0].Token != 7 {
		t.Fatalf("responses = %+v, want a single allow for token 7", resp)
	}
	if len(sink.incidents()) != 0 {
		t.Fatal("an allowlisted reader must not raise an incident")
	}
}

func TestHostileReaderIsAlertedThenAllowed(t *testing.T) {
	sink := &countingSink{}
	d, fw := testDaemon(t, []string{"alert"}, nil, sink, nil)

	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})

	incs := sink.incidents()
	if len(incs) != 1 {
		t.Fatalf("incidents = %d, want 1", len(incs))
	}
	if incs[0].BaitPath != "/etc/codex/auth.json" || incs[0].AUID != 1000 || incs[0].UID != 1000 {
		t.Fatalf("incident missing attribution: %+v", incs[0])
	}
	if incs[0].Cmdline != "cat /etc/codex/auth.json" {
		t.Fatalf("cmdline = %q", incs[0].Cmdline)
	}
	if incs[0].Host != "testhost" || incs[0].Verdict != "hostile" {
		t.Fatalf("incident = %+v", incs[0])
	}
	if resp := fw.all(); len(resp) != 1 || !resp[0].Allow {
		t.Fatalf("responses = %+v, want one allow", resp)
	}
}

// The whole point of the hold: the token is not returned until the alert has
// gone out.
func TestResponseIsDeferredUntilTheLadderCompletes(t *testing.T) {
	sink := &countingSink{took: 150 * time.Millisecond}
	d, fw := testDaemon(t, []string{"alert"}, nil, sink, nil)
	d.Hold = action.NewHold(5 * time.Second)

	start := time.Now()
	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})

	if len(fw.all()) != 1 {
		t.Fatalf("want exactly one response, got %d", len(fw.all()))
	}
	if delay := fw.respondedAt(0).Sub(start); delay < 100*time.Millisecond {
		t.Fatalf("responded after %v; the read must be held until the alert lands", delay)
	}
}

// Fail-open: a wedged sink must not hold the reader past the cap.
func TestResponseIsReleasedAtTheHoldCap(t *testing.T) {
	sink := &countingSink{took: time.Hour}
	d, fw := testDaemon(t, []string{"alert"}, nil, sink, nil)
	d.Ladder.AlertTimeout = time.Hour
	d.Hold = action.NewHold(80 * time.Millisecond)

	start := time.Now()
	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("held for %v despite an 80ms cap", elapsed)
	}
	if resp := fw.all(); len(resp) != 1 || !resp[0].Allow {
		t.Fatalf("responses = %+v, want the reader released", resp)
	}
}

// A read the daemon itself performs must be answered immediately: waiting on
// ourselves is an unrecoverable deadlock.
func TestSelfReadIsAllowedImmediately(t *testing.T) {
	sink := &countingSink{took: time.Hour}
	d, fw := testDaemon(t, []string{"alert"}, nil, sink, nil)
	d.SelfPID = 4242
	d.Hold = action.NewHold(time.Hour)

	done := make(chan struct{})
	go func() {
		d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon deadlocked on its own read")
	}
	if resp := fw.all(); len(resp) != 1 || !resp[0].Allow {
		t.Fatalf("responses = %+v", resp)
	}
	if len(sink.incidents()) != 0 {
		t.Fatal("the daemon's own read must not raise an incident")
	}
}

// An unattributable reader (already exited, or /proc unreadable) must not wedge
// the path.
func TestUnattributablePIDIsAllowed(t *testing.T) {
	sink := &countingSink{}
	d, fw := testDaemon(t, []string{"alert"}, nil, sink, nil)

	d.HandleEvent(context.Background(), watch.Event{PID: 5555, Path: "/etc/codex/auth.json", Token: 9, Perm: true})

	if resp := fw.all(); len(resp) != 1 || !resp[0].Allow || resp[0].Token != 9 {
		t.Fatalf("responses = %+v, want an allow for token 9", resp)
	}
}

// The tripped record has to be on disk before the machine dies, or the next boot
// re-arms and loops.
func TestTrippedStateIsPersistedBeforePoweroff(t *testing.T) {
	sink := &countingSink{}
	pw := &recordPower{}
	d, _ := testDaemon(t, []string{"alert", "poweroff"}, nil, sink, pw)

	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})

	if !d.State.IsTripped() {
		t.Fatal("tripped state was not persisted")
	}
	trip, err := d.State.Read()
	if err != nil {
		t.Fatal(err)
	}
	if trip.Bait != "/etc/codex/auth.json" || trip.AUID != 1000 {
		t.Fatalf("trip record = %+v", trip)
	}
	if modes := pw.seen(); len(modes) != 1 || modes[0] != "graceful" {
		t.Fatalf("poweroff modes = %v", modes)
	}
}

// Alert-only must leave no tripped record: nothing destructive happened, and a
// stale record would block arming later.
func TestAlertOnlyDoesNotMarkTripped(t *testing.T) {
	sink := &countingSink{}
	d, _ := testDaemon(t, []string{"alert"}, nil, sink, nil)

	d.HandleEvent(context.Background(), watch.Event{PID: 4242, Path: "/etc/codex/auth.json", Token: 7, Perm: true})

	if d.State.IsTripped() {
		t.Fatal("alert-only must not write a tripped record")
	}
}

func TestEffectiveActionsDowngradesAfterATrip(t *testing.T) {
	dir := t.TempDir()
	st := &state.Store{Dir: dir}
	if err := st.Arm(time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("actions: [alert, kill, poweroff]"))
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveActions(cfg, st); len(got) != 3 {
		t.Fatalf("armed clean host must keep its ladder, got %v", got)
	}
	if err := st.MarkTripped(state.Trip{Bait: "x"}); err != nil {
		t.Fatal(err)
	}
	got := EffectiveActions(cfg, st)
	if len(got) != 1 || got[0] != "alert" {
		t.Fatalf("tripped host must boot alert-only, got %v", got)
	}
	if err := st.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := EffectiveActions(cfg, st); len(got) != 3 {
		t.Fatalf("reset must restore the configured ladder, got %v", got)
	}
}

// Editing the config is not the same as arming: a destructive ladder on an
// unarmed host must still run alert-only.
func TestEffectiveActionsRequiresArming(t *testing.T) {
	st := &state.Store{Dir: t.TempDir()}
	cfg, err := config.Parse([]byte("actions: [alert, poweroff]"))
	if err != nil {
		t.Fatal(err)
	}
	if got := EffectiveActions(cfg, st); len(got) != 1 || got[0] != "alert" {
		t.Fatalf("unarmed host must run alert-only, got %v", got)
	}
	if err := st.Arm(time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if got := EffectiveActions(cfg, st); len(got) != 2 {
		t.Fatalf("armed host must run the configured ladder, got %v", got)
	}
	if err := st.Disarm(); err != nil {
		t.Fatal(err)
	}
	if got := EffectiveActions(cfg, st); len(got) != 1 {
		t.Fatalf("disarm must drop back to alert-only, got %v", got)
	}
}

// Alert-only configs are unaffected by a tripped record — there is nothing to
// downgrade.
func TestEffectiveActionsLeavesAlertOnlyAlone(t *testing.T) {
	st := &state.Store{Dir: t.TempDir()}
	_ = st.MarkTripped(state.Trip{Bait: "x"})
	cfg, _ := config.Parse([]byte("actions: [alert]"))
	if got := EffectiveActions(cfg, st); len(got) != 1 || got[0] != "alert" {
		t.Fatalf("actions = %v", got)
	}
}

// In fallback mode there is no reader identity, so a destructive ladder must not
// fire on a nameless event — but the alert still must.
func TestFallbackModeAlertsButNeverDestroys(t *testing.T) {
	sink := &countingSink{}
	pw := &recordPower{}
	d, fw := testDaemon(t, []string{"alert", "poweroff"}, nil, sink, pw)
	d.Attributed = false

	d.HandleEvent(context.Background(), watch.Event{Path: "/etc/codex/auth.json", Perm: false})

	if len(sink.incidents()) != 1 {
		t.Fatalf("fallback mode must still alert, got %d incidents", len(sink.incidents()))
	}
	if modes := pw.seen(); len(modes) != 0 {
		t.Fatalf("fallback mode must never power off: %v", modes)
	}
	if len(fw.all()) != 0 {
		t.Fatal("inotify events are not permission events; nothing to answer")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	d, _ := testDaemon(t, []string{"alert"}, nil, &countingSink{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func TestRunReturnsWhenTheWatchStreamEnds(t *testing.T) {
	d, fw := testDaemon(t, []string{"alert"}, nil, &countingSink{}, nil)
	close(fw.events)
	done := make(chan error, 1)
	go func() { done <- d.Run(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a closed watch stream must be reported as an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not notice the closed stream")
	}
}

type recordMarker struct {
	mu     sync.Mutex
	marked []string
}

func (m *recordMarker) Mark(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.marked = append(m.marked, path)
	return nil
}
func (m *recordMarker) Unmark(string) error { return nil }
func (m *recordMarker) seen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.marked...)
}

// A decoy replaced on disk must be re-marked, or the wire goes quietly dead.
func TestReplacedDecoyIsRemarked(t *testing.T) {
	d, _ := testDaemon(t, []string{"alert"}, nil, &countingSink{}, nil)
	mk := &recordMarker{}
	replace := make(chan string, 1)
	d.Marker = mk
	d.Replace = replace

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	replace <- "/etc/codex/auth.json"
	deadline := time.After(2 * time.Second)
	for {
		if len(mk.seen()) == 1 && mk.seen()[0] == "/etc/codex/auth.json" {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("decoy was not re-marked, marks = %v", mk.seen())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
