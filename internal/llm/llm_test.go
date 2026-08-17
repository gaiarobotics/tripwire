package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mbarnathan/tripwire/internal/bait"
)

func testRequest() bait.GenRequest {
	return bait.GenRequest{
		Path:        "/srv/app/config/openai-key.json",
		Fingerprint: "tw-deadbeefdeadbeef",
		Now:         time.Unix(1_700_000_000, 0).UTC(),
		Fallback:    bait.KindCodex,
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	cases := map[string]Options{
		"unknown provider": {Provider: "gemini", Model: "x", APIKey: "k"},
		"missing model":    {Provider: ProviderAnthropic, APIKey: "k"},
		"no key or url":    {Provider: ProviderAnthropic, Model: "claude-opus-5"},
	}
	for name, opts := range cases {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A keyless self-hosted endpoint is legitimate.
	if _, err := New(Options{Provider: ProviderOpenAICompatible, Model: "llama3", BaseURL: "http://localhost:11434/v1"}); err != nil {
		t.Fatalf("keyless local endpoint should be allowed: %v", err)
	}
}

func TestAnthropicRequestShapeAndAuth(t *testing.T) {
	var body map[string]any
	var apiKey, version string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		apiKey, version = r.Header.Get("x-api-key"), r.Header.Get("anthropic-version")
		w.Write([]byte(`{"stop_reason":"end_turn","content":[{"type":"text","text":"{\"k\":\"tw-deadbeefdeadbeef\"}"}]}`))
	}))
	defer srv.Close()

	c, err := New(Options{Provider: ProviderAnthropic, Model: "claude-opus-5", APIKey: "secret", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Generate(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(out), "tw-deadbeefdeadbeef") {
		t.Fatalf("output = %s", out)
	}
	if apiKey != "secret" || version == "" {
		t.Fatalf("auth headers: x-api-key=%q anthropic-version=%q", apiKey, version)
	}
	if body["model"] != "claude-opus-5" {
		t.Fatalf("model = %v", body["model"])
	}
	// Current Claude models reject sampling params and a fixed thinking budget;
	// sending either would 400 every request.
	for _, banned := range []string{"temperature", "top_p", "top_k", "thinking"} {
		if _, ok := body[banned]; ok {
			t.Errorf("request must not carry %q", banned)
		}
	}
	// Effort is model-dependent, so it is only sent when configured.
	if _, ok := body["output_config"]; ok {
		t.Error("output_config should be omitted when effort is unset")
	}
	// The prompt has to carry the fingerprint or the model cannot embed it.
	msgs, _ := json.Marshal(body["messages"])
	if !strings.Contains(string(msgs), "tw-deadbeefdeadbeef") {
		t.Fatalf("prompt is missing the fingerprint: %s", msgs)
	}
	if sys, _ := body["system"].(string); !strings.Contains(sys, "JSON") {
		t.Fatalf("system prompt should demand JSON: %q", sys)
	}
}

func TestAnthropicSendsEffortWhenConfigured(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Write([]byte(`{"stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}`))
	}))
	defer srv.Close()

	c, _ := New(Options{Provider: ProviderAnthropic, Model: "claude-opus-5", APIKey: "k", BaseURL: srv.URL, Effort: "low"})
	_, _ = c.Generate(context.Background(), testRequest())

	oc, ok := body["output_config"].(map[string]any)
	if !ok || oc["effort"] != "low" {
		t.Fatalf("output_config = %v", body["output_config"])
	}
}

// A refusal is an HTTP 200 with an empty content array — reading content[0]
// without checking stop_reason first would panic or silently write nothing.
func TestAnthropicRefusalIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stop_reason":"refusal","stop_details":{"category":"cyber"},"content":[]}`))
	}))
	defer srv.Close()

	c, _ := New(Options{Provider: ProviderAnthropic, Model: "claude-opus-5", APIKey: "k", BaseURL: srv.URL})
	_, err := c.Generate(context.Background(), testRequest())
	if err == nil {
		t.Fatal("a refusal must surface as an error")
	}
	if !strings.Contains(err.Error(), "cyber") {
		t.Fatalf("err = %v, want the refusal category named", err)
	}
}

func TestAnthropicTruncationIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stop_reason":"max_tokens","content":[{"type":"text","text":"{\"partial\":"}]}`))
	}))
	defer srv.Close()

	c, _ := New(Options{Provider: ProviderAnthropic, Model: "claude-opus-5", APIKey: "k", BaseURL: srv.URL})
	if _, err := c.Generate(context.Background(), testRequest()); err == nil {
		t.Fatal("truncated output must not be written as a decoy")
	}
}

func TestAPIErrorsAreReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	}))
	defer srv.Close()

	c, _ := New(Options{Provider: ProviderAnthropic, Model: "claude-opus-5", APIKey: "bad", BaseURL: srv.URL})
	_, err := c.Generate(context.Background(), testRequest())
	if err == nil {
		t.Fatal("a 401 must be an error")
	}
	if !strings.Contains(err.Error(), "invalid x-api-key") {
		t.Fatalf("err = %v, want the provider message quoted", err)
	}
}

func TestOpenAICompatibleRequestShapeAndAuth(t *testing.T) {
	var body map[string]any
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":"{\"k\":\"tw-deadbeefdeadbeef\"}"}}]}`))
	}))
	defer srv.Close()

	c, err := New(Options{Provider: ProviderOpenAICompatible, Model: "gpt-4o", APIKey: "sk-test", BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Generate(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(out), "tw-deadbeefdeadbeef") {
		t.Fatalf("output = %s", out)
	}
	if auth != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", auth)
	}
	if path != "/v1/chat/completions" {
		t.Fatalf("path = %q, want the chat-completions endpoint appended to base_url", path)
	}
	msgs, _ := json.Marshal(body["messages"])
	if !strings.Contains(string(msgs), "system") || !strings.Contains(string(msgs), "tw-deadbeefdeadbeef") {
		t.Fatalf("messages = %s", msgs)
	}
}

func TestOpenAIRefusalAndTruncation(t *testing.T) {
	refusal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"refusal":"I can't help with that"}}]}`))
	}))
	defer refusal.Close()
	c, _ := New(Options{Provider: ProviderOpenAICompatible, Model: "gpt-4o", APIKey: "k", BaseURL: refusal.URL})
	if _, err := c.Generate(context.Background(), testRequest()); err == nil {
		t.Fatal("a refusal must be an error")
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"content":"{\"partial\":"}}]}`))
	}))
	defer truncated.Close()
	c2, _ := New(Options{Provider: ProviderOpenAICompatible, Model: "gpt-4o", APIKey: "k", BaseURL: truncated.URL})
	if _, err := c2.Generate(context.Background(), testRequest()); err == nil {
		t.Fatal("truncated output must be an error")
	}
}

// A full endpoint in base_url must be used as-is, so a proxy on a custom path
// still works.
func TestBaseURLFormsAreAccepted(t *testing.T) {
	cases := map[string]struct{ provider, base, wantPath string }{
		"anthropic host":     {ProviderAnthropic, "https://proxy.internal", "/v1/messages"},
		"anthropic full":     {ProviderAnthropic, "https://proxy.internal/api/v1/messages", "/api/v1/messages"},
		"openai host":        {ProviderOpenAICompatible, "https://proxy.internal/v1", "/v1/chat/completions"},
		"openai full":        {ProviderOpenAICompatible, "https://proxy.internal/x/chat/completions", "/x/chat/completions"},
		"trailing slash ok":  {ProviderOpenAICompatible, "https://proxy.internal/v1/", "/v1/chat/completions"},
		"anthropic trailing": {ProviderAnthropic, "https://proxy.internal/", "/v1/messages"},
	}
	for name, tc := range cases {
		c, err := New(Options{Provider: tc.provider, Model: "m", APIKey: "k", BaseURL: tc.base})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		def := anthropicDefaultURL
		if tc.provider == ProviderOpenAICompatible {
			def = openAIDefaultURL
		}
		got := c.endpoint(def)
		if !strings.HasSuffix(got, tc.wantPath) {
			t.Errorf("%s: endpoint = %q, want it to end in %q", name, got, tc.wantPath)
		}
	}
}

func TestDefaultEndpointsWhenNoBaseURL(t *testing.T) {
	a, _ := New(Options{Provider: ProviderAnthropic, Model: "m", APIKey: "k"})
	if got := a.endpoint(anthropicDefaultURL); got != anthropicDefaultURL {
		t.Fatalf("anthropic endpoint = %q", got)
	}
	o, _ := New(Options{Provider: ProviderOpenAICompatible, Model: "m", APIKey: "k"})
	if got := o.endpoint(openAIDefaultURL); got != openAIDefaultURL {
		t.Fatalf("openai endpoint = %q", got)
	}
}

func TestGuidanceReachesThePrompt(t *testing.T) {
	c, _ := New(Options{Provider: ProviderAnthropic, Model: "m", APIKey: "k", Guidance: "a Jenkins build host"})
	_, user := c.prompt(testRequest())
	if !strings.Contains(user, "Jenkins build host") {
		t.Fatalf("guidance missing from prompt: %s", user)
	}
	if !strings.Contains(user, "/srv/app/config/openai-key.json") {
		t.Fatal("prompt should name the target path")
	}
	if !strings.Contains(user, "OpenAI") {
		t.Fatal("prompt should name the service the path implies")
	}
}

// A hanging provider must not wedge the operator's command.
func TestTimeoutIsEnforced(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c, _ := New(Options{Provider: ProviderAnthropic, Model: "m", APIKey: "k", BaseURL: srv.URL, Timeout: 50 * time.Millisecond})
	start := time.Now()
	if _, err := c.Generate(context.Background(), testRequest()); err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Generate blocked for %v despite a 50ms timeout", elapsed)
	}
}
