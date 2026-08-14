// Package alert delivers incident notifications to multiple sinks and confirms
// delivery, so a human is notified before the host powers off.
package alert

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Killed is one process terminated by the kill action, recorded for the payload.
type Killed struct {
	PID     int    `json:"pid"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	UID     int    `json:"uid"`
	AUID    int64  `json:"auid"`
}

// Incident is the payload sent to every sink.
type Incident struct {
	Time         time.Time `json:"time"`
	Host         string    `json:"host"`
	Fingerprint  string    `json:"fingerprint"`
	BaitPath     string    `json:"bait_path"`
	Verdict      string    `json:"verdict"`
	Exe          string    `json:"exe"`
	Cmdline      string    `json:"cmdline"`
	UID          int       `json:"uid"`
	AUID         int64     `json:"auid"`
	SessionID    int       `json:"session_id"`
	Cgroup       string    `json:"cgroup"`
	Ancestors    []string  `json:"ancestors"`
	ActionsTaken []string  `json:"actions_taken"`
	Killed       []Killed  `json:"killed,omitempty"`
	AuditNote    string    `json:"audit_note,omitempty"`
	Test         bool      `json:"test,omitempty"` // set by `tripwire test`
}

// Sink delivers one Incident and returns nil only on confirmed delivery.
type Sink interface {
	Name() string
	Send(ctx context.Context, inc Incident) error
}

// ErrPending marks a sink that had not finished when the fan-out returned. Its
// delivery may still succeed in the background — but it did not confirm in time
// to gate a destructive action.
var ErrPending = errors.New("delivery still in flight when the fan-out returned")

// Result reports the fan-out outcome.
type Result struct {
	Delivered     bool             // true if >=1 sink confirmed
	Confirmations map[string]error // per-sink error (nil == confirmed)
}

// Summary renders the per-sink outcome for the journal record.
func (r Result) Summary() string {
	if len(r.Confirmations) == 0 {
		return "no sinks configured"
	}
	parts := make([]string, 0, len(r.Confirmations))
	for name, err := range r.Confirmations {
		if err == nil {
			parts = append(parts, name+"=confirmed")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", name, err))
	}
	return fmt.Sprint(parts)
}

// FanOut sends to all sinks concurrently and returns as soon as one confirms
// delivery or the timeout elapses — whichever comes first. Sinks that have not
// settled by then are recorded as ErrPending and keep trying in the background
// until the timeout; returning early matters because the ladder holds the
// reader (and may power the host off) while this call is outstanding.
func FanOut(parent context.Context, sinks []Sink, inc Incident, timeout time.Duration) Result {
	res := Result{Confirmations: make(map[string]error, len(sinks))}
	if len(sinks) == 0 {
		return res
	}

	ctx, cancel := context.WithTimeout(parent, timeout)

	type outcome struct {
		name string
		err  error
	}
	ch := make(chan outcome, len(sinks))
	var wg sync.WaitGroup
	for _, s := range sinks {
		wg.Add(1)
		go func(s Sink) {
			defer wg.Done()
			ch <- outcome{s.Name(), send(ctx, s, inc)}
		}(s)
	}
	// Release the context once every sink has settled, so a fast confirmation
	// does not leave the timer running longer than it must.
	go func() {
		wg.Wait()
		cancel()
	}()

	pending := make(map[string]bool, len(sinks))
	for _, s := range sinks {
		pending[s.Name()] = true
	}

	unsettled := ErrPending
collect:
	for len(pending) > 0 {
		select {
		case o := <-ch:
			delete(pending, o.name)
			res.Confirmations[o.name] = o.err
			if o.err == nil {
				res.Delivered = true
				break collect
			}
		case <-ctx.Done():
			unsettled = fmt.Errorf("no confirmation within alert timeout: %w", ctx.Err())
			break collect
		}
	}

	// Drain anything that landed while we were deciding, then mark the rest.
	for len(pending) > 0 {
		select {
		case o := <-ch:
			delete(pending, o.name)
			res.Confirmations[o.name] = o.err
			if o.err == nil {
				res.Delivered = true
			}
		default:
			for name := range pending {
				res.Confirmations[name] = unsettled
			}
			return res
		}
	}
	return res
}

// send isolates one sink: a panicking or misbehaving sink must never take down
// the daemon in the middle of an incident.
func send(ctx context.Context, s Sink, inc Incident) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink panicked: %v", r)
		}
	}()
	return s.Send(ctx, inc)
}
