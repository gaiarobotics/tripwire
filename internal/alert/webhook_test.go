package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookPostsJSONIncident(t *testing.T) {
	var got string
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		gotHeader = r.Header.Get("X-Test")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewWebhookSink(srv.URL, map[string]string{"X-Test": "1"})
	err := s.Send(context.Background(), Incident{Host: "h1", BaitPath: "/etc/codex/auth.json", Fingerprint: "tw-x"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(got, "tw-x") || !strings.Contains(got, "/etc/codex/auth.json") {
		t.Fatalf("payload missing fields: %s", got)
	}
	if gotHeader != "1" {
		t.Fatalf("custom header not sent: %q", gotHeader)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("payload is not valid json: %v", err)
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := NewWebhookSink(srv.URL, nil)
	if err := s.Send(context.Background(), Incident{}); err == nil {
		t.Fatal("500 must be an error")
	}
}

// Delivery confirmation must respect the caller's deadline: a sink that hangs
// cannot hold the ladder past alert_timeout.
func TestWebhookRespectsContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Release the handler before Close, which waits for outstanding requests.
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s := NewWebhookSink(srv.URL, nil)
	if err := s.Send(ctx, Incident{}); err == nil {
		t.Fatal("a hanging webhook must return the context error")
	}
}

func TestNtfyPostsMessageWithPriority(t *testing.T) {
	var body, prio, title string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, prio, title = string(b), r.Header.Get("Priority"), r.Header.Get("Title")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewNtfySink(srv.URL, "", "rotating_light")
	inc := Incident{Host: "h1", Verdict: "hostile", BaitPath: "/etc/codex/auth.json", AUID: 1000, Exe: "/usr/bin/curl"}
	if err := s.Send(context.Background(), inc); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(body, "h1") || !strings.Contains(body, "/etc/codex/auth.json") {
		t.Fatalf("ntfy body missing detail: %q", body)
	}
	if prio != "urgent" {
		t.Fatalf("priority = %q, want the urgent default", prio)
	}
	if title == "" {
		t.Fatal("ntfy notification needs a title")
	}
}

func TestNtfyNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()
	if err := NewNtfySink(srv.URL, "urgent", "").Send(context.Background(), Incident{}); err == nil {
		t.Fatal("403 must be an error")
	}
}

// The journal sink is the post-reboot forensic record: it must always confirm,
// even with no GUI session and no network.
func TestJournalSinkAlwaysConfirms(t *testing.T) {
	if err := NewJournalSink(false).Send(context.Background(), Incident{Host: "h"}); err != nil {
		t.Fatalf("journal sink must always confirm: %v", err)
	}
}
