package alert

import (
	"context"
	"fmt"
	"log"
	"os/exec"
)

// JournalSink always writes a structured record to stderr (captured by journald
// under systemd) and, when notify is set, best-effort notify-send to the GUI
// session. The journal write always confirms — it is the post-reboot record.
type JournalSink struct {
	notify bool
}

func NewJournalSink(notify bool) *JournalSink { return &JournalSink{notify: notify} }

func (s *JournalSink) Name() string { return "journal" }

func (s *JournalSink) Send(ctx context.Context, inc Incident) error {
	log.Printf("TRIPWIRE incident host=%s bait=%s verdict=%s exe=%q cmdline=%q uid=%d auid=%d session=%d cgroup=%s actions=%v killed=%d fp=%s test=%t",
		inc.Host, inc.BaitPath, inc.Verdict, inc.Exe, inc.Cmdline, inc.UID, inc.AUID,
		inc.SessionID, inc.Cgroup, inc.ActionsTaken, len(inc.Killed), inc.Fingerprint, inc.Test)
	if s.notify {
		// Best effort: there may be no graphical session at all.
		_ = exec.CommandContext(ctx, "notify-send", "-u", "critical",
			"Tripwire tripped", fmt.Sprintf("%s read %s", inc.Exe, inc.BaitPath)).Run()
	}
	return nil // journald write is local and always "delivered"
}
