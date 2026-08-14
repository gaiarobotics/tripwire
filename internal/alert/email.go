package alert

import (
	"context"
	"fmt"
	"net/smtp"
	"os/exec"
	"strings"
)

// EmailSink sends via direct SMTP if smtpAddr is set, else pipes to a local MTA
// (sendmail). Local-MTA handoff is weak confirmation — the mail is queued, not
// necessarily sent — which is why email should never be the only sink.
type EmailSink struct {
	to, from, smtpAddr string
}

func NewEmailSink(to, from, smtpAddr string) *EmailSink {
	return &EmailSink{to: to, from: from, smtpAddr: smtpAddr}
}

func (s *EmailSink) Name() string { return "email" }

func (s *EmailSink) Send(ctx context.Context, inc Incident) error {
	subject := fmt.Sprintf("Tripwire tripped on %s", inc.Host)
	if inc.Test {
		subject = fmt.Sprintf("Tripwire test notification from %s", inc.Host)
	}
	body := fmt.Sprintf("Bait: %s\nVerdict: %s\nExe: %s\nUID: %d AUID: %d\nCmdline: %s\nActions: %s\nFingerprint: %s\n",
		inc.BaitPath, inc.Verdict, inc.Exe, inc.UID, inc.AUID, inc.Cmdline,
		strings.Join(inc.ActionsTaken, ","), inc.Fingerprint)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.from, s.to, subject, body)

	if s.smtpAddr != "" {
		return smtp.SendMail(s.smtpAddr, nil, s.from, []string{s.to}, []byte(msg))
	}
	cmd := exec.CommandContext(ctx, "sendmail", "-t")
	cmd.Stdin = strings.NewReader(msg)
	return cmd.Run()
}
