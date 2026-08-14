package attrib

import (
	"os"
	"strings"
)

// AuditdAvailable reports whether an auditd daemon appears to be running.
// Enrichment is a bonus; loginuid from /proc already gives the login user.
func AuditdAvailable() bool {
	// auditd holds /run/auditd.pid on all common distros.
	if _, err := os.Stat("/run/auditd.pid"); err == nil {
		return true
	}
	return false
}

// AuditNote returns a short human-readable enrichment string for the incident,
// or "" when auditd is not available. It intentionally does not parse the audit
// log stream in v1 — it records that a correlating record should exist.
func AuditNote(id Identity) string {
	if !AuditdAvailable() {
		return ""
	}
	var b strings.Builder
	b.WriteString("auditd present; correlate auid=")
	if id.LoginUIDUnset() {
		b.WriteString("unset")
	} else {
		b.WriteString(itoa(int(id.LoginUID)))
	}
	b.WriteString(" ses=")
	b.WriteString(itoa(id.SessionID))
	return b.String()
}
