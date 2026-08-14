// Package action runs Tripwire's response ladder and implements the hold that
// makes a hostile read look like slow I/O until the ladder completes.
package action

import (
	"context"
	"log"
	"time"

	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
)

// Hold defers the fanotify response for up to a duration, releasing early if the
// context is cancelled (e.g. daemon shutdown). The reader sits in open() the
// whole time, indistinguishable from slow I/O.
type Hold struct{ d time.Duration }

func NewHold(d time.Duration) *Hold { return &Hold{d: d} }

// Duration reports the configured cap.
func (h *Hold) Duration() time.Duration { return h.d }

// Wait blocks for the hold duration, or until ctx is done.
func (h *Hold) Wait(ctx context.Context) {
	if h.d <= 0 {
		return
	}
	t := time.NewTimer(h.d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Ladder is the configured response sequence.
type Ladder struct {
	Actions      []string
	Sinks        []alert.Sink
	AlertTimeout time.Duration

	// kill wiring (nil Killer => kill action is skipped with a logged note)
	Killer  *Killer
	Scope   string
	MaxKill int

	// poweroff wiring
	Power        PowerOffer
	PoweroffMode string
}

// Result records what actually ran, for the incident payload and the journal.
type Result struct {
	Ran       []string
	Killed    []alert.Killed
	AlertRes  alert.Result
	FreezeSet []int
	Completed bool // false if the hold cap fired before the ladder finished
}

// Run executes the ladder in order against the reader identity.
//
// Ordering guidance lives in the config, not here: keeping alert first means the
// notification — the thing that cannot be recovered once the host dies — goes
// out before kill or poweroff. The implicit freeze has already stopped the
// bleeding by then.
func (l *Ladder) Run(ctx context.Context, id attrib.Identity, inc alert.Incident) Result {
	var res Result

	// Implicit freeze pre-step when kill is configured: stop the tree so it can't
	// fork away or keep exfiltrating while we alert.
	if l.hasAction("kill") && l.Killer != nil {
		set, err := l.Killer.Freeze(l.Scope, id, l.MaxKill)
		if err != nil {
			log.Printf("tripwire: freeze skipped: %v", err)
		} else {
			res.FreezeSet = set
		}
	}

	inc.Planned = l.Actions
	for _, a := range l.Actions {
		switch a {
		case "alert":
			inc.ActionsTaken = append([]string(nil), res.Ran...)
			inc.Killed = res.Killed
			res.AlertRes = alert.FanOut(ctx, l.Sinks, inc, l.AlertTimeout)
			res.Ran = append(res.Ran, "alert")
			if !res.AlertRes.Delivered {
				log.Printf("tripwire: no sink confirmed delivery: %s", res.AlertRes.Summary())
			}
		case "kill":
			if l.Killer == nil {
				log.Printf("tripwire: kill configured but no killer wired; skipping")
				continue
			}
			killed, err := l.Killer.Kill(l.Scope, id, l.MaxKill)
			if err != nil {
				// Guard refusals (unset auid, max_kill ceiling) are not fatal —
				// the rest of the ladder still runs.
				log.Printf("tripwire: kill refused: %v", err)
				continue
			}
			res.Killed = append(res.Killed, killed...)
			res.Ran = append(res.Ran, "kill")
		case "poweroff":
			if l.Power == nil {
				log.Printf("tripwire: poweroff configured but no power offer wired; skipping")
				continue
			}
			if err := l.Power.PowerOff(l.PoweroffMode); err != nil {
				log.Printf("tripwire: poweroff failed: %v", err)
				continue
			}
			res.Ran = append(res.Ran, "poweroff")
		}
	}
	res.Completed = true
	return res
}

// RunHeld runs the ladder while the caller keeps the reader blocked in open(),
// returning as soon as the ladder finishes or the hold cap elapses — whichever
// comes first. A ladder that outlives the cap keeps running in the background;
// the caller releases the reader anyway so a stuck sink can never wedge file
// access past the cap.
func (l *Ladder) RunHeld(ctx context.Context, hold *Hold, id attrib.Identity, inc alert.Incident) Result {
	done := make(chan Result, 1)
	go func() { done <- l.Run(ctx, id, inc) }()

	if hold == nil || hold.Duration() <= 0 {
		// No hold: still wait for the ladder itself, since releasing the reader
		// before alerting would hand over the token first.
		return <-done
	}

	t := time.NewTimer(hold.Duration())
	defer t.Stop()
	select {
	case res := <-done:
		return res
	case <-t.C:
		log.Printf("tripwire: hold cap %s reached; releasing the reader while the ladder finishes", hold.Duration())
		return Result{}
	case <-ctx.Done():
		return Result{}
	}
}

func (l *Ladder) hasAction(name string) bool {
	for _, a := range l.Actions {
		if a == name {
			return true
		}
	}
	return false
}
