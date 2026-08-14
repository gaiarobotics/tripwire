package alert

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// NtfySink pushes to an ntfy topic. 2xx is confirmed delivery. This is the sink
// most likely to reach a different device before the host powers off.
type NtfySink struct {
	url      string
	priority string
	tags     string
	client   *http.Client
}

func NewNtfySink(url, priority, tags string) *NtfySink {
	if priority == "" {
		priority = "urgent"
	}
	return &NtfySink{url: url, priority: priority, tags: tags, client: &http.Client{}}
}

func (s *NtfySink) Name() string { return "ntfy" }

func (s *NtfySink) Send(ctx context.Context, inc Incident) error {
	auid := "unset"
	if inc.AUID >= 0 && inc.AUID != loginUIDUnset {
		auid = fmt.Sprint(inc.AUID)
	}
	msg := fmt.Sprintf("Tripwire on %s: %s read of %s by %s (auid=%s, uid=%d)",
		inc.Host, inc.Verdict, inc.BaitPath, inc.Exe, auid, inc.UID)
	if len(inc.ActionsTaken) > 0 {
		msg += "\nactions: " + strings.Join(inc.ActionsTaken, " -> ")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(msg))
	if err != nil {
		return err
	}
	title := "Tripwire credential canary tripped"
	if inc.Test {
		title = "Tripwire test notification"
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", s.priority)
	if s.tags != "" {
		req.Header.Set("Tags", s.tags)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy status %d", resp.StatusCode)
	}
	return nil
}

// loginUIDUnset mirrors attrib.LoginUIDUnsetValue without importing it, keeping
// the alert package free of attribution dependencies.
const loginUIDUnset int64 = 4294967295
