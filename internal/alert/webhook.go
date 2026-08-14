package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// WebhookSink POSTs the incident as JSON. Any 2xx is confirmed delivery. One
// URL plus headers covers Slack, Discord, Teams, PagerDuty and homegrown
// receivers.
type WebhookSink struct {
	url     string
	headers map[string]string
	client  *http.Client
}

func NewWebhookSink(url string, headers map[string]string) *WebhookSink {
	return &WebhookSink{url: url, headers: headers, client: &http.Client{}}
}

func (s *WebhookSink) Name() string { return "webhook" }

func (s *WebhookSink) Send(ctx context.Context, inc Incident) error {
	body, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}
