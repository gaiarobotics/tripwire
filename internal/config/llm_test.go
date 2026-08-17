package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLLMIsAbsentByDefault(t *testing.T) {
	cfg, err := Parse([]byte("profile: server"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LLM != nil {
		t.Fatal("no llm section should be configured by default")
	}
	if cfg.UsesLLM() {
		t.Fatal("default decoys must not use llm generation")
	}
}

// kind: llm without an llm section is a config error rather than a silent
// fallback — the operator asked for generation and should learn it isn't wired.
func TestLLMKindRequiresAnLLMSection(t *testing.T) {
	_, err := Parse([]byte("bait:\n  - {path: /srv/x.json, kind: llm}"))
	if err == nil || !strings.Contains(err.Error(), "llm") {
		t.Fatalf("err = %v, want a complaint about the missing llm section", err)
	}
}

func TestLLMSectionParsesAndValidates(t *testing.T) {
	cfg, err := Parse([]byte(`
bait:
  - {path: /srv/app/creds.json, kind: llm}
llm:
  provider: anthropic
  model: claude-opus-5
  api_key_env: TRIPWIRE_TEST_KEY
  timeout: 45s
  max_tokens: 4096
  guidance: a Jenkins build host
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UsesLLM() {
		t.Fatal("UsesLLM should be true")
	}
	if cfg.LLM.Model != "claude-opus-5" || cfg.LLM.Timeout != 45*time.Second || cfg.LLM.MaxTokens != 4096 {
		t.Fatalf("llm = %+v", cfg.LLM)
	}
	if cfg.LLM.Guidance != "a Jenkins build host" {
		t.Fatalf("guidance = %q", cfg.LLM.Guidance)
	}
}

func TestLLMValidationRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"unknown provider": "llm:\n  provider: gemini\n  model: x",
		"missing model":    "llm:\n  provider: anthropic",
		"negative tokens":  "llm:\n  provider: anthropic\n  model: x\n  max_tokens: -1",
		"negative timeout": "llm:\n  provider: anthropic\n  model: x\n  timeout: -5s",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// The key comes from the environment or a file by default so it never has to be
// written into a config file that is world-readable on most installs.
func TestResolveAPIKeyPrecedence(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "llm.key")
	if err := os.WriteFile(keyFile, []byte("  file-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	l := &LLMConfig{Provider: "anthropic", Model: "m", APIKeyEnv: "TRIPWIRE_TEST_KEY", APIKeyFile: keyFile, APIKey: "inline-key"}

	t.Setenv("TRIPWIRE_TEST_KEY", "env-key")
	if got, err := l.ResolveAPIKey(); err != nil || got != "env-key" {
		t.Fatalf("env should win: %q, %v", got, err)
	}

	t.Setenv("TRIPWIRE_TEST_KEY", "")
	if got, err := l.ResolveAPIKey(); err != nil || got != "file-key" {
		t.Fatalf("file should be next, and trimmed: %q, %v", got, err)
	}

	l.APIKeyFile = ""
	if got, err := l.ResolveAPIKey(); err != nil || got != "inline-key" {
		t.Fatalf("inline is the last resort: %q, %v", got, err)
	}
}

func TestResolveAPIKeyDefaultsToTheConventionalEnvVar(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "from-anthropic-env")
	t.Setenv("OPENAI_API_KEY", "from-openai-env")

	anthropic := &LLMConfig{Provider: "anthropic", Model: "m"}
	if got, _ := anthropic.ResolveAPIKey(); got != "from-anthropic-env" {
		t.Fatalf("anthropic key = %q", got)
	}
	openai := &LLMConfig{Provider: "openai-compatible", Model: "m"}
	if got, _ := openai.ResolveAPIKey(); got != "from-openai-env" {
		t.Fatalf("openai key = %q", got)
	}
}

func TestResolveAPIKeyReportsAnUnreadableFile(t *testing.T) {
	l := &LLMConfig{Provider: "anthropic", Model: "m", APIKeyEnv: "TRIPWIRE_UNSET_KEY", APIKeyFile: "/nonexistent/llm.key"}
	if _, err := l.ResolveAPIKey(); err == nil {
		t.Fatal("a configured but unreadable key file must be an error")
	}
}

// A missing key is not a config error: it surfaces when the operator actually
// runs a command that needs it.
func TestMissingKeyIsNotAConfigError(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	cfg, err := Parse([]byte("bait:\n  - {path: /srv/x.json, kind: llm}\nllm: {provider: anthropic, model: claude-opus-5}"))
	if err != nil {
		t.Fatalf("config should parse without a key present: %v", err)
	}
	opts, err := cfg.LLMOptions()
	if err != nil {
		t.Fatal(err)
	}
	if opts.APIKey != "" {
		t.Fatalf("expected no key, got %q", opts.APIKey)
	}
	if opts.Model != "claude-opus-5" || opts.Provider != "anthropic" {
		t.Fatalf("options = %+v", opts)
	}
}
