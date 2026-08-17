// Package llm generates decoy credential content with a language model.
//
// This is an opt-in path: a decoy only reaches it when its bait entry says
// `kind: llm`. Nothing here runs in the daemon — generation happens in the
// `tripwire` CLI, so the root process that holds CAP_SYS_ADMIN never makes an
// outbound API call and never needs an API key.
package llm

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/mbarnathan/tripwire/internal/bait"
)

// Providers understood by New.
const (
	ProviderAnthropic = "anthropic"
	// ProviderOpenAICompatible covers OpenAI itself and everything that speaks
	// its /chat/completions shape: vLLM, Ollama, LiteLLM, OpenRouter, and most
	// self-hosted gateways.
	ProviderOpenAICompatible = "openai-compatible"
)

// ProviderNames lists the accepted providers, for error messages.
func ProviderNames() string { return ProviderAnthropic + ", " + ProviderOpenAICompatible }

// ValidProvider reports whether name is a provider we can talk to.
func ValidProvider(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ProviderAnthropic, ProviderOpenAICompatible:
		return true
	}
	return false
}

// Options configures a Client. The caller resolves the API key — this package
// never reads the environment or the filesystem itself.
type Options struct {
	Provider  string
	Model     string
	APIKey    string
	BaseURL   string // override the provider default, for self-hosted endpoints
	Timeout   time.Duration
	MaxTokens int
	Effort    string // Anthropic only; sent only when set, since not every model accepts it
	Guidance  string // operator hint folded into the prompt
}

// Client generates decoy content from a chat-completion API.
type Client struct {
	opts Options
	http *http.Client
}

const (
	defaultTimeout   = 30 * time.Second
	defaultMaxTokens = 8192

	anthropicDefaultURL = "https://api.anthropic.com/v1/messages"
	openAIDefaultURL    = "https://api.openai.com/v1/chat/completions"

	// anthropicVersion is the dated API version header the Messages API requires.
	anthropicVersion = "2023-06-01"
)

// New validates the options and returns a ready client.
func New(opts Options) (*Client, error) {
	opts.Provider = strings.ToLower(strings.TrimSpace(opts.Provider))
	if !ValidProvider(opts.Provider) {
		return nil, fmt.Errorf("unknown llm provider %q (valid: %s)", opts.Provider, ProviderNames())
	}
	if strings.TrimSpace(opts.Model) == "" {
		return nil, fmt.Errorf("llm.model is required for provider %s", opts.Provider)
	}
	// A self-hosted endpoint may legitimately need no key; a hosted one always does.
	if strings.TrimSpace(opts.APIKey) == "" && strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("no API key resolved for provider %s: set llm.api_key_env, llm.api_key_file, or llm.base_url for a keyless endpoint", opts.Provider)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = defaultMaxTokens
	}
	return &Client{opts: opts, http: &http.Client{Timeout: opts.Timeout}}, nil
}

// Describe names the provider and model, for operator-facing output.
func (c *Client) Describe() string { return c.opts.Provider + "/" + c.opts.Model }

// Generate asks the model for one decoy file's contents. The caller validates
// and, on any error, falls back to the built-in template.
func (c *Client) Generate(ctx context.Context, req bait.GenRequest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	system, user := c.prompt(req)
	switch c.opts.Provider {
	case ProviderAnthropic:
		return c.generateAnthropic(ctx, system, user)
	case ProviderOpenAICompatible:
		return c.generateOpenAI(ctx, system, user)
	}
	return nil, fmt.Errorf("unknown llm provider %q", c.opts.Provider)
}

func (c *Client) endpoint(def string) string {
	base := strings.TrimSpace(c.opts.BaseURL)
	if base == "" {
		return def
	}
	base = strings.TrimRight(base, "/")
	// Accept either a bare host ("http://localhost:11434/v1") or a full endpoint.
	if strings.HasSuffix(base, "/messages") || strings.HasSuffix(base, "/chat/completions") {
		return base
	}
	if c.opts.Provider == ProviderAnthropic {
		return base + "/v1/messages"
	}
	return base + "/chat/completions"
}

// prompt builds the instruction pair. It is deliberately explicit about the two
// properties the caller enforces anyway — JSON only, fingerprint present — so
// the common case does not need a retry.
func (c *Client) prompt(req bait.GenRequest) (system, user string) {
	system = strings.Join([]string{
		"You write decoy credential files for a defensive security canary.",
		"The file is planted on a server so that any process reading it can be detected; it is never used to authenticate anything.",
		"",
		"Rules, all mandatory:",
		"- Respond with a single JSON object and nothing else: no prose, no explanation, no Markdown code fence.",
		"- Every credential-like value (tokens, keys, secrets, ids) MUST contain the tracking string given below, verbatim. That string is how a leaked decoy is traced back to the host it came from.",
		"- Values must be structurally plausible for the service but non-functional. Never reproduce a real credential, and never emit a key you have seen before.",
		"- Any expiry or timestamp field must be in the future relative to the reference time given below, so the file does not look abandoned.",
		"- Match the shape a real credential file for this service would have: the same field names, nesting, and value formats an operator would expect.",
		"- Do not include internal or system XML tags in your response.",
	}, "\n")

	var b strings.Builder
	fmt.Fprintf(&b, "File path: %s\n", req.Path)
	fmt.Fprintf(&b, "File name: %s\n", filepath.Base(req.Path))
	fmt.Fprintf(&b, "Service suggested by the path: %s\n", serviceHint(req.Path, req.Fallback))
	fmt.Fprintf(&b, "Tracking string that must appear in every credential value: %s\n", req.Fingerprint)
	fmt.Fprintf(&b, "Reference time: %s\n", req.Now.UTC().Format(time.RFC3339))
	if g := strings.TrimSpace(c.opts.Guidance); g != "" {
		fmt.Fprintf(&b, "Additional context about this host: %s\n", g)
	}
	b.WriteString("\nWrite the JSON object now.")
	return system, b.String()
}

// serviceHint tells the model what the file is supposed to be, from the path
// plus the schema the template would have used.
func serviceHint(path string, fallback bait.Kind) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "codex"), strings.Contains(lower, "openai"):
		return "OpenAI / Codex CLI credentials"
	case strings.Contains(lower, "claude"), strings.Contains(lower, "anthropic"):
		return "Anthropic / Claude Code credentials"
	case fallback == bait.KindCodex:
		return "an OpenAI-style API credential file"
	default:
		return "an AI coding assistant credential file"
	}
}

var _ bait.Generator = (*Client)(nil)
