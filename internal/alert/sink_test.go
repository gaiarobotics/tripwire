package alert

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSink struct {
	name string
	err  error
	took time.Duration
}

func (f fakeSink) Name() string { return f.name }
func (f fakeSink) Send(ctx context.Context, _ Incident) error {
	select {
	case <-time.After(f.took):
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestFanOutSucceedsIfAnySinkConfirms(t *testing.T) {
	sinks := []Sink{
		fakeSink{name: "a", err: errors.New("boom")},
		fakeSink{name: "b", err: nil},
	}
	res := FanOut(context.Background(), sinks, Incident{}, time.Second)
	if !res.Delivered {
		t.Fatalf("expected delivered, got %+v", res)
	}
	if res.Confirmations["b"] != nil {
		t.Fatalf("b should have confirmed: %v", res.Confirmations["b"])
	}
	if res.Confirmations["a"] == nil {
		t.Fatal("a should have recorded its failure")
	}
}

func TestFanOutTimesOutButStillReportsPerSink(t *testing.T) {
	sinks := []Sink{
		fakeSink{name: "slow", took: time.Hour},
	}
	res := FanOut(context.Background(), sinks, Incident{}, 50*time.Millisecond)
	if res.Delivered {
		t.Fatal("should not be delivered before timeout")
	}
	if res.Confirmations["slow"] == nil {
		t.Fatal("slow sink should record a timeout error")
	}
}

// The ladder blocks on FanOut while the reader is held, so FanOut must return
// within roughly the timeout even when a sink hangs forever.
func TestFanOutReturnsWithinTimeout(t *testing.T) {
	sinks := []Sink{
		fakeSink{name: "hang", took: time.Hour},
		fakeSink{name: "fast", took: time.Millisecond},
	}
	start := time.Now()
	res := FanOut(context.Background(), sinks, Incident{}, 100*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("FanOut blocked for %v; must be bounded by the timeout", elapsed)
	}
	if !res.Delivered {
		t.Fatal("the fast sink confirmed, so the fan-out is delivered")
	}
}

// A sink that panics must not take the daemon down mid-incident.
func TestFanOutSurvivesPanickingSink(t *testing.T) {
	res := FanOut(context.Background(), []Sink{panicSink{}, fakeSink{name: "ok"}}, Incident{}, time.Second)
	if !res.Delivered {
		t.Fatal("the healthy sink should still confirm")
	}
	if res.Confirmations["panic"] == nil {
		t.Fatal("panicking sink should record an error, not crash the process")
	}
}

type panicSink struct{}

func (panicSink) Name() string { return "panic" }
func (panicSink) Send(context.Context, Incident) error {
	panic("sink exploded")
}

type localSink struct {
	name string
	took time.Duration
}

func (l localSink) Name() string { return l.name }
func (l localSink) Local() bool  { return true }
func (l localSink) Send(ctx context.Context, _ Incident) error {
	select {
	case <-time.After(l.took):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// journald confirms instantly and never leaves the box. If that were enough to
// end the fan-out, the ladder would power the host off before the phone
// notification was even sent.
func TestLocalConfirmationDoesNotPreemptTheRemoteSink(t *testing.T) {
	remote := fakeSink{name: "ntfy", took: 120 * time.Millisecond}
	res := FanOut(context.Background(), []Sink{localSink{name: "journal"}, remote}, Incident{}, 5*time.Second)

	if res.Confirmations["ntfy"] != nil {
		t.Fatalf("the fan-out must wait for the off-host sink, got %v", res.Confirmations["ntfy"])
	}
	if !res.OffHost {
		t.Fatal("OffHost must be set once a remote sink confirms")
	}
}

// With only local sinks configured there is nothing to wait for, so the fan-out
// must not burn the whole alert timeout before a poweroff.
func TestLocalOnlyFanOutReturnsImmediately(t *testing.T) {
	start := time.Now()
	res := FanOut(context.Background(), []Sink{localSink{name: "journal"}}, Incident{}, 30*time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("local-only fan-out took %v; it should return as soon as it settles", elapsed)
	}
	if !res.Delivered {
		t.Fatal("the journal write is still a delivery")
	}
	if res.OffHost {
		t.Fatal("a local sink must never report an off-host delivery")
	}
}

// A remote sink that fails leaves the operator with only the local record, and
// the result must say so rather than claiming success.
func TestOffHostIsFalseWhenOnlyLocalSucceeds(t *testing.T) {
	res := FanOut(context.Background(),
		[]Sink{localSink{name: "journal"}, fakeSink{name: "ntfy", err: errors.New("no route to host")}},
		Incident{}, time.Second)
	if !res.Delivered {
		t.Fatal("the journal still delivered")
	}
	if res.OffHost {
		t.Fatal("nothing reached another device")
	}
}

func TestFanOutWithNoSinksIsNotDelivered(t *testing.T) {
	res := FanOut(context.Background(), nil, Incident{}, time.Second)
	if res.Delivered {
		t.Fatal("no sinks means nothing was delivered")
	}
	if len(res.Confirmations) != 0 {
		t.Fatalf("confirmations = %v, want empty", res.Confirmations)
	}
}
