package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mbarnathan/tripwire/internal/bait"
	"github.com/mbarnathan/tripwire/internal/llm"
)

// LLMConfig configures decoy generation for `kind: llm` bait entries. It is
// inert unless some entry asks for it.
//
// The API key is deliberately not a required config field: APIKeyEnv (the
// default) and APIKeyFile keep the secret out of a file that is world-readable
// on most installs.
type LLMConfig struct {
	Provider string `yaml:"provider"` // anthropic | openai-compatible
	Model    string `yaml:"model"`

	APIKeyEnv  string `yaml:"api_key_env"`  // env var holding the key (default per provider)
	APIKeyFile string `yaml:"api_key_file"` // file holding the key, trimmed
	APIKey     string `yaml:"api_key"`      // inline; discouraged, see docs

	BaseURL   string        `yaml:"base_url"` // self-hosted or proxied endpoint
	Timeout   time.Duration `yaml:"timeout"`
	MaxTokens int           `yaml:"max_tokens"`
	Effort    string        `yaml:"effort"`   // anthropic only; sent only when set
	Guidance  string        `yaml:"guidance"` // "a CI build host", "a finance team laptop"
}

// defaultKeyEnv is the conventional environment variable per provider.
func defaultKeyEnv(provider string) string {
	if provider == llm.ProviderOpenAICompatible {
		return "OPENAI_API_KEY"
	}
	return "ANTHROPIC_API_KEY"
}

// UsesLLM reports whether any decoy defers its contents to a language model.
func (c *Config) UsesLLM() bool {
	for _, b := range c.Bait {
		if strings.EqualFold(strings.TrimSpace(b.Kind), bait.KindNameLLM) {
			return true
		}
	}
	return false
}

// ResolveAPIKey finds the key without ever logging it: environment variable
// first, then a file, then the inline value. An empty result is not an error —
// a self-hosted endpoint may not need one.
func (l *LLMConfig) ResolveAPIKey() (string, error) {
	env := strings.TrimSpace(l.APIKeyEnv)
	if env == "" {
		env = defaultKeyEnv(strings.ToLower(strings.TrimSpace(l.Provider)))
	}
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v, nil
	}
	if path := strings.TrimSpace(l.APIKeyFile); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read llm.api_key_file %s: %w", path, err)
		}
		if v := strings.TrimSpace(string(raw)); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("llm.api_key_file %s is empty", path)
	}
	return strings.TrimSpace(l.APIKey), nil
}

// LLMOptions resolves the config into client options, including the API key.
func (c *Config) LLMOptions() (llm.Options, error) {
	if c.LLM == nil {
		return llm.Options{}, fmt.Errorf("no llm section in the config")
	}
	key, err := c.LLM.ResolveAPIKey()
	if err != nil {
		return llm.Options{}, err
	}
	return llm.Options{
		Provider:  c.LLM.Provider,
		Model:     c.LLM.Model,
		APIKey:    key,
		BaseURL:   c.LLM.BaseURL,
		Timeout:   c.LLM.Timeout,
		MaxTokens: c.LLM.MaxTokens,
		Effort:    c.LLM.Effort,
		Guidance:  c.LLM.Guidance,
	}, nil
}

// validateLLM enforces that an llm-kind decoy has a usable llm section. The API
// key is not required here: it is resolved at generation time so a missing key
// fails the operator's command rather than every config read.
func (c *Config) validateLLM() error {
	if c.LLM != nil {
		if !llm.ValidProvider(c.LLM.Provider) {
			return fmt.Errorf("llm.provider %q is unknown (valid: %s)", c.LLM.Provider, llm.ProviderNames())
		}
		if strings.TrimSpace(c.LLM.Model) == "" {
			return fmt.Errorf("llm.model is required when an llm section is present")
		}
		if c.LLM.MaxTokens < 0 {
			return fmt.Errorf("llm.max_tokens must not be negative, got %d", c.LLM.MaxTokens)
		}
		if c.LLM.Timeout < 0 {
			return fmt.Errorf("llm.timeout must not be negative, got %s", c.LLM.Timeout)
		}
	}
	if c.UsesLLM() && c.LLM == nil {
		return fmt.Errorf("a bait entry uses kind: llm but no llm section is configured")
	}
	return nil
}
