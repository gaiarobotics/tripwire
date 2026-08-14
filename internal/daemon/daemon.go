// Package daemon holds Tripwire's event loop: snapshot the reader, judge it,
// hold the read while the ladder runs, then answer the kernel.
package daemon

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mbarnathan/tripwire/internal/action"
	"github.com/mbarnathan/tripwire/internal/alert"
	"github.com/mbarnathan/tripwire/internal/attrib"
	"github.com/mbarnathan/tripwire/internal/config"
	"github.com/mbarnathan/tripwire/internal/policy"
	"github.com/mbarnathan/tripwire/internal/state"
	"github.com/mbarnathan/tripwire/internal/watch"
)

// Daemon wires the watcher to the policy engine and the action ladder. Every
// collaborator is an interface or an injected value so the whole event path is
// unit-testable without fanotify.
type Daemon struct {
	Cfg     *config.Config
	Actions []string // effective ladder (may be downgraded; see EffectiveActions)

	Watcher watch.Watcher
	Marker  watch.Marker  // optional: re-marks replaced decoys
	Replace <-chan string // optional: paths that reappeared and need re-marking
	Snap    *attrib.Snapshotter
	Rules   *policy.Ruleset
	Ladder  *action.Ladder
	Hold    *action.Hold
	State   *state.Store

	Host        string
	Fingerprint string
	SelfPID     int
	Now         func() time.Time

	// Attributed is false for the inotify fallback, where events carry no PID
	// and no read can be held.
	Attributed bool
}

func (d *Daemon) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Daemon) selfPID() int {
	if d.SelfPID != 0 {
		return d.SelfPID
	}
	return os.Getpid()
}

// EffectiveActions resolves the ladder the daemon will actually run.
//
// Two gates stand between a destructive config and a destructive daemon:
//   - the host must not already have tripped (otherwise one intrusion becomes a
//     boot loop — a tripped host comes up alert-only until `tripwire reset`);
//   - an operator must have armed it deliberately with `tripwire arm`, which is
//     a separate act from editing the config.
func EffectiveActions(cfg *config.Config, st *state.Store) []string {
	if !cfg.HasDestructiveAction() || st == nil {
		return cfg.Actions
	}
	if st.IsTripped() {
		log.Println("tripwired: prior trip on record; running ALERT-ONLY until `tripwire reset`")
		return []string{"alert"}
	}
	if !st.IsArmed() {
		log.Println("tripwired: destructive actions configured but not armed; running ALERT-ONLY " +
			"(run `tripwire test`, then `tripwire arm`)")
		return []string{"alert"}
	}
	return cfg.Actions
}

// Run processes events until the context is cancelled or the watch stream ends.
func (d *Daemon) Run(ctx context.Context) error {
	events := d.Watcher.Events()
	for {
		select {
		case <-ctx.Done():
			return nil
		case path, ok := <-d.Replace:
			if !ok {
				d.Replace = nil
				continue
			}
			d.remark(path)
		case ev, ok := <-events:
			if !ok {
				return errors.New("watch stream closed")
			}
			// Handle concurrently: a hostile read is held for up to 15s, and
			// that must not stall detection of a second reader.
			go d.HandleEvent(ctx, ev)
		}
	}
}

// remark re-adds the fanotify mark to a decoy that was replaced. Marks are
// per-inode, so without this a `mv` over the bait silently disarms the wire.
func (d *Daemon) remark(path string) {
	if d.Marker == nil {
		return
	}
	if err := d.Marker.Mark(path); err != nil {
		log.Printf("tripwired: re-mark %s failed: %v", path, err)
		return
	}
	log.Printf("tripwired: decoy %s was replaced; re-marked", path)
}

// HandleEvent runs the full pipeline for one access and always answers the
// kernel exactly once — except when the host powers off first, where the
// unanswered event dies with the machine.
func (d *Daemon) HandleEvent(ctx context.Context, ev watch.Event) {
	allow := func() {
		if !ev.Perm {
			return // nothing to answer (inotify fallback)
		}
		if err := d.Watcher.Respond(watch.Response{Token: ev.Token, Allow: true}); err != nil {
			log.Printf("tripwired: respond to event on %s: %v", ev.Path, err)
		}
	}

	// Never hold our own read: the daemon blocking on its own permission event
	// would deadlock with no way out but the restart.
	if ev.PID != 0 && ev.PID == d.selfPID() {
		allow()
		return
	}

	if !d.Attributed || ev.PID == 0 {
		// Fallback mode: we know a decoy was opened and nothing else. Alert on
		// it; never run a destructive action against an unidentified reader.
		d.alertUnattributed(ctx, ev)
		allow()
		return
	}

	id, err := d.Snap.Snapshot(ev.PID)
	if err != nil {
		// Can't attribute (the reader already exited, or /proc is restricted).
		// Allow rather than wedge the path, and leave a forensic record.
		log.Printf("tripwired: snapshot pid %d for %s: %v; allowing", ev.PID, ev.Path, err)
		allow()
		return
	}

	if verdict := d.Rules.Evaluate(id); verdict == policy.Benign {
		// Allowlisted readers are never held and never alerted on.
		allow()
		return
	}

	inc := d.incident(ev, id)

	// Persist the trip before anything destructive: the record is what stops the
	// next boot from re-arming into a loop, and it has to survive the poweroff.
	if hasDestructive(d.Actions) && d.State != nil {
		if err := d.State.MarkTripped(state.Trip{
			Bait: ev.Path, Exe: id.Exe, AUID: id.LoginUID, When: d.now(),
		}); err != nil {
			log.Printf("tripwired: could not persist tripped state: %v", err)
		}
	}

	res := d.Ladder.RunHeld(ctx, d.Hold, id, inc)
	if !res.Completed {
		log.Printf("tripwired: ladder still running when the hold cap expired for %s", ev.Path)
	}

	// Release the reader: it gets the worthless token, and the deception holds.
	allow()
}

// alertUnattributed handles the degraded path, where all we can say is that a
// decoy was opened.
func (d *Daemon) alertUnattributed(ctx context.Context, ev watch.Event) {
	inc := alert.Incident{
		Time: d.now(), Host: d.Host, Fingerprint: d.Fingerprint, BaitPath: ev.Path,
		Verdict: "hostile (unattributed: fanotify unavailable)",
	}
	lad := *d.Ladder
	lad.Actions = []string{"alert"} // no target to kill, no identity to justify a poweroff
	lad.Run(ctx, attrib.Identity{}, inc)
}

func (d *Daemon) incident(ev watch.Event, id attrib.Identity) alert.Incident {
	return alert.Incident{
		Time:        d.now(),
		Host:        d.Host,
		Fingerprint: d.Fingerprint,
		BaitPath:    ev.Path,
		Verdict:     policy.Hostile.String(),
		Exe:         id.Exe,
		Cmdline:     strings.Join(id.Cmdline, " "),
		UID:         id.UID,
		AUID:        id.LoginUID,
		SessionID:   id.SessionID,
		Cgroup:      id.Cgroup,
		Ancestors:   ancestorNames(id),
		AuditNote:   attrib.AuditNote(id),
	}
}

func ancestorNames(id attrib.Identity) []string {
	out := make([]string, 0, len(id.Ancestors))
	for _, a := range id.Ancestors {
		out = append(out, a.Comm)
	}
	return out
}

func hasDestructive(actions []string) bool {
	for _, a := range actions {
		if a == "kill" || a == "poweroff" {
			return true
		}
	}
	return false
}
