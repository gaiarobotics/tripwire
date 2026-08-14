package watch

import (
	"testing"
	"time"
)

// fakeWatcher emits events on demand and records responses.
type fakeWatcher struct {
	events    chan Event
	responded chan Response
}

func newFake() *fakeWatcher {
	return &fakeWatcher{events: make(chan Event, 1), responded: make(chan Response, 1)}
}
func (f *fakeWatcher) Events() <-chan Event { return f.events }
func (f *fakeWatcher) Respond(r Response) error {
	f.responded <- r
	return nil
}
func (f *fakeWatcher) Close() error { return nil }

// The fake must satisfy the same contract the daemon codes against.
var _ Watcher = (*fakeWatcher)(nil)

func TestEventCarriesPathAndPID(t *testing.T) {
	f := newFake()
	f.events <- Event{PID: 4242, Path: "/etc/codex/auth.json"}
	ev := <-f.Events()
	if ev.PID != 4242 || ev.Path != "/etc/codex/auth.json" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRespondAllowIsRecorded(t *testing.T) {
	f := newFake()
	if err := f.Respond(Response{Allow: true, Token: 7}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-f.responded:
		if !r.Allow || r.Token != 7 {
			t.Fatalf("response = %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no response recorded")
	}
}
