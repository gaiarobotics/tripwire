package action

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
)

type recordPower struct {
	mu    sync.Mutex
	modes []string
	err   error
}

func (r *recordPower) PowerOff(mode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modes = append(r.modes, mode)
	return r.err
}

func (r *recordPower) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.modes...)
}

type recordSink struct {
	mu   sync.Mutex
	sent int
	last alert.Incident
	took time.Duration
}

func (r *recordSink) Name() string { return "rec" }
func (r *recordSink) Send(ctx context.Context, inc alert.Incident) error {
	if r.took > 0 {
		select {
		case <-time.After(r.took):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent++
	r.last = inc
	return nil
}

func (r *recordSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent
}

func (r *recordSink) incident() alert.Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func TestLadderRunsAlertThenPoweroff(t *testing.T) {
	pw := &recordPower{}
	sink := &recordSink{}
	lad := &Ladder{
		Actions:      []string{"alert", "poweroff"},
		Sinks:        []alert.Sink{sink},
		AlertTimeout: time.Second,
		Power:        pw,
		PoweroffMode: "graceful",
	}
	res := lad.Run(context.Background(), attrib.Identity{PID: 10}, alert.Incident{})
	if sink.count() != 1 {
		t.Fatalf("alert sent = %d, want 1", sink.count())
	}
	if modes := pw.seen(); len(modes) != 1 || modes[0] != "graceful" {
		t.Fatalf("poweroff modes = %v", modes)
	}
	if len(res.Ran) != 2 || res.Ran[0] != "alert" || res.Ran[1] != "poweroff" {
		t.Fatalf("ran = %v", res.Ran)
	}
}

func TestLadderAlertOnlyDoesNotPowerOff(t *testing.T) {
	pw := &recordPower{}
	lad := &Ladder{Actions: []string{"alert"}, Sinks: []alert.Sink{&recordSink{}}, AlertTimeout: time.Second, Power: pw}
	lad.Run(context.Background(), attrib.Identity{PID: 10}, alert.Incident{})
	if modes := pw.seen(); len(modes) != 0 {
		t.Fatalf("alert-only must not power off, got %v", modes)
	}
}

// The alert must name what is about to happen, so a phone notification arriving
// seconds before the host dies says so.
func TestAlertCarriesPlannedLadder(t *testing.T) {
	sink := &recordSink{}
	lad := &Ladder{
		Actions:      []string{"alert", "poweroff"},
		Sinks:        []alert.Sink{sink},
		AlertTimeout: time.Second,
		Power:        &recordPower{},
		PoweroffMode: "graceful",
	}
	lad.Run(context.Background(), attrib.Identity{PID: 10}, alert.Incident{})
	planned := sink.incident().Planned
	if len(planned) != 2 || planned[1] != "poweroff" {
		t.Fatalf("planned = %v, want the full configured ladder", planned)
	}
}

// kill implies a freeze pre-step, and the freeze must land before the alert so
// the reader cannot exfiltrate during the (up to 10s) alert window.
func TestKillImpliesFreezeBeforeAlert(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{
		10: {ppid: 1, sessionid: 3, loginuid: 1000, starttime: 100},
		11: {ppid: 10, sessionid: 3, loginuid: 1000, starttime: 101},
	}}
	var order []string
	killer := &Killer{Tree: pt, signal: func(pid, sig int) error {
		switch sig {
		case sigSTOP:
			order = append(order, "stop")
		case sigKILL:
			order = append(order, "kill")
		}
		return nil
	}}
	sink := &sequenceSink{order: &order}

	lad := &Ladder{
		Actions: []string{"alert", "kill"}, Sinks: []alert.Sink{sink},
		AlertTimeout: time.Second, Killer: killer, Scope: "tree", MaxKill: 50,
	}
	res := lad.Run(context.Background(), attrib.Identity{PID: 10, SessionID: 3, LoginUID: 1000, StartTime: 100}, alert.Incident{})

	if len(order) < 3 || order[0] != "stop" || order[1] != "stop" {
		t.Fatalf("order = %v, want both SIGSTOPs first", order)
	}
	if order[2] != "alert" {
		t.Fatalf("order = %v, want alert after the freeze", order)
	}
	if len(res.FreezeSet) != 2 {
		t.Fatalf("freeze set = %v, want 2 pids", res.FreezeSet)
	}
	if len(res.Killed) != 2 {
		t.Fatalf("killed = %v, want 2 records", res.Killed)
	}
}

type sequenceSink struct{ order *[]string }

func (sequenceSink) Name() string { return "seq" }
func (s sequenceSink) Send(context.Context, alert.Incident) error {
	*s.order = append(*s.order, "alert")
	return nil
}

// A guard refusal (unset auid, max_kill ceiling) must not abort the ladder: the
// alert still goes out and poweroff still runs.
func TestKillRefusalDoesNotAbortLadder(t *testing.T) {
	pt := procTable{procs: map[int]fakeProc{5: {ppid: 1, loginuid: attrib.LoginUIDUnsetValue, starttime: 1}}}
	killer := &Killer{Tree: pt, signal: func(int, int) error { return nil }}
	pw := &recordPower{}
	sink := &recordSink{}
	lad := &Ladder{
		Actions: []string{"alert", "kill", "poweroff"}, Sinks: []alert.Sink{sink},
		AlertTimeout: time.Second, Killer: killer, Scope: "loginuid", MaxKill: 50,
		Power: pw, PoweroffMode: "graceful",
	}
	res := lad.Run(context.Background(), attrib.Identity{PID: 5, LoginUID: attrib.LoginUIDUnsetValue}, alert.Incident{})

	if sink.count() != 1 {
		t.Fatal("alert must still fire when kill is refused")
	}
	if modes := pw.seen(); len(modes) != 1 {
		t.Fatalf("poweroff must still run when kill is refused, got %v", modes)
	}
	for _, a := range res.Ran {
		if a == "kill" {
			t.Fatalf("a refused kill must not be reported as run: %v", res.Ran)
		}
	}
}

// A failing poweroff is reported, not silently recorded as done — the operator
// needs to know the host is still up.
func TestFailedPoweroffIsNotRecordedAsRun(t *testing.T) {
	pw := &recordPower{err: errors.New("systemctl missing")}
	lad := &Ladder{
		Actions: []string{"poweroff"}, AlertTimeout: time.Second,
		Power: pw, PoweroffMode: "graceful",
	}
	res := lad.Run(context.Background(), attrib.Identity{PID: 10}, alert.Incident{})
	if len(res.Ran) != 0 {
		t.Fatalf("ran = %v, want poweroff excluded after failure", res.Ran)
	}
}

func TestHoldBlocksForDuration(t *testing.T) {
	h := NewHold(40 * time.Millisecond)
	start := time.Now()
	h.Wait(context.Background())
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond {
		t.Fatalf("hold returned too early: %v", elapsed)
	}
}

func TestHoldReleasesEarlyOnCancel(t *testing.T) {
	h := NewHold(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	start := time.Now()
	h.Wait(ctx)
	if time.Since(start) > time.Second {
		t.Fatal("hold did not release on cancel")
	}
}

func TestZeroHoldDoesNotBlock(t *testing.T) {
	start := time.Now()
	NewHold(0).Wait(context.Background())
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("a zero hold must return immediately")
	}
}

// The reader is released as soon as the ladder finishes — no need to burn the
// whole cap when the alert already landed.
func TestRunHeldReturnsWhenLadderFinishesFirst(t *testing.T) {
	lad := &Ladder{Actions: []string{"alert"}, Sinks: []alert.Sink{&recordSink{}}, AlertTimeout: time.Second}
	start := time.Now()
	res := lad.RunHeld(context.Background(), NewHold(5*time.Second), attrib.Identity{PID: 10}, alert.Incident{})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("RunHeld waited %v; it should return when the ladder finishes", elapsed)
	}
	if !res.Completed {
		t.Fatal("result should be marked completed")
	}
}

// A wedged sink must never hold the reader past the cap: fail-open is the whole
// anti-brick guarantee.
func TestRunHeldReleasesAtCapWhenLadderHangs(t *testing.T) {
	lad := &Ladder{
		Actions:      []string{"alert"},
		Sinks:        []alert.Sink{&recordSink{took: time.Hour}},
		AlertTimeout: time.Hour,
	}
	start := time.Now()
	res := lad.RunHeld(context.Background(), NewHold(60*time.Millisecond), attrib.Identity{PID: 10}, alert.Incident{})
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("RunHeld blocked %v past its 60ms cap", elapsed)
	}
	if res.Completed {
		t.Fatal("a ladder cut short by the cap must not report completion")
	}
}
