package alert

import "github.com/mbarnathan/tripwire/internal/config"

// FromConfig builds the configured sink fan-out. journald is always included —
// it is the record that survives the poweroff — and notify-send is enabled only
// on the workstation profile, where a graphical session may exist.
//
// Both binaries build their sinks here so `tripwire test` exercises exactly the
// path a real incident takes.
func FromConfig(cfg *config.Config) []Sink {
	var sinks []Sink
	if w := cfg.Sinks.Webhook; w != nil && w.URL != "" {
		sinks = append(sinks, NewWebhookSink(w.URL, w.Headers))
	}
	if n := cfg.Sinks.Ntfy; n != nil && n.URL != "" {
		sinks = append(sinks, NewNtfySink(n.URL, n.Priority, n.Tags))
	}
	if e := cfg.Sinks.Email; e != nil && e.To != "" {
		sinks = append(sinks, NewEmailSink(e.To, e.From, e.SMTPAddr))
	}
	sinks = append(sinks, NewJournalSink(cfg.DesktopNotify()))
	return sinks
}
