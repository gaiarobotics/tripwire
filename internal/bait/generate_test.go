package bait

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeGen struct {
	out  string
	err  error
	seen GenRequest
}

func (f *fakeGen) Generate(_ context.Context, req GenRequest) ([]byte, error) {
	f.seen = req
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.out), nil
}

func TestKindLLMIsNeverInferred(t *testing.T) {
	// auto must never select the LLM kind — it costs an API call and money, so
	// an operator has to ask for it by name.
	for _, path := range []string{
		"/etc/codex/auth.json", "/srv/llm/creds.json", "/srv/ai-generated.json",
	} {
		if got := KindFor(path); got == KindLLM {
			t.Fatalf("KindFor(%q) inferred KindLLM", path)
		}
	}
	got, err := KindByName("llm", "/srv/x.json")
	if err != nil || got != KindLLM {
		t.Fatalf("KindByName(llm) = %v, %v", got, err)
	}
}

func TestPlaceGeneratedWritesModelContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "creds.json")
	gen := &fakeGen{out: `{"service_account":"ci-runner","api_key":"sk-live-tw-deadbeefdeadbeef-xyz"}`}

	res, err := PlaceGenerated(context.Background(), Decoy{Path: target, Kind: KindLLM},
		"tw-deadbeefdeadbeef", time.Unix(1_700_000_000, 0).UTC(), gen)
	if err != nil {
		t.Fatalf("PlaceGenerated: %v", err)
	}
	if !res.Generated || res.GenErr != nil {
		t.Fatalf("result = %+v, want generated with no error", res)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ci-runner") {
		t.Fatalf("model content was not written: %s", raw)
	}
	if err := Verify(Decoy{Path: target}); err != nil {
		t.Fatalf("a generated decoy must still be a 0600 regular file: %v", err)
	}
	// The generator gets what it needs to write a plausible file.
	if gen.seen.Fingerprint != "tw-deadbeefdeadbeef" || gen.seen.Path != target {
		t.Fatalf("request = %+v", gen.seen)
	}
	if gen.seen.Fallback != KindFor(target) {
		t.Fatalf("fallback kind = %v, want the inferred schema", gen.seen.Fallback)
	}
}

// A decoy that does not exist cannot trip the wire, so any generation failure
// must still leave a working template decoy behind.
func TestPlaceGeneratedFallsBackToTemplate(t *testing.T) {
	cases := map[string]*fakeGen{
		"api error":       {err: errors.New("503 from provider")},
		"not json":        {out: "Sure! Here is a credential file."},
		"no fingerprint":  {out: `{"api_key":"sk-live-something-else"}`},
		"empty object":    {out: `{}`},
		"empty response":  {out: "   "},
		"json but a list": {out: `[{"api_key":"tw-deadbeefdeadbeef"}]`},
	}
	for name, gen := range cases {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "codex-auth.json")
			res, err := PlaceGenerated(context.Background(), Decoy{Path: target, Kind: KindLLM},
				"tw-deadbeefdeadbeef", time.Unix(1_700_000_000, 0).UTC(), gen)
			if err != nil {
				t.Fatalf("fallback must not fail: %v", err)
			}
			if res.Generated {
				t.Fatal("content should not be reported as generated")
			}
			if res.GenErr == nil {
				t.Fatal("the failure must be reported to the caller")
			}
			raw, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("the template decoy must exist: %v", err)
			}
			if !strings.Contains(string(raw), "OPENAI_API_KEY") {
				t.Fatalf("expected the codex template (inferred from the name): %s", raw)
			}
			if !strings.Contains(string(raw), "tw-deadbeefdeadbeef") {
				t.Fatal("the fallback must still carry the fingerprint")
			}
		})
	}
}

func TestPlaceGeneratedWithoutAGeneratorUsesTemplate(t *testing.T) {
	target := filepath.Join(t.TempDir(), "auth.json")
	res, err := PlaceGenerated(context.Background(), Decoy{Path: target, Kind: KindLLM}, "tw-x", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated || res.GenErr == nil {
		t.Fatalf("result = %+v, want a template with a reported reason", res)
	}
	if err := Verify(Decoy{Path: target}); err != nil {
		t.Fatalf("decoy missing: %v", err)
	}
}

// The no-clobber guard has to cover generated content too.
func TestPlaceGeneratedRefusesToOverwriteForeignFiles(t *testing.T) {
	target := filepath.Join(t.TempDir(), "passwd")
	const original = "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	gen := &fakeGen{out: `{"api_key":"tw-deadbeefdeadbeef-abc"}`}

	_, err := PlaceGenerated(context.Background(), Decoy{Path: target, Kind: KindLLM},
		"tw-deadbeefdeadbeef", time.Now(), gen)
	if err == nil {
		t.Fatal("must refuse to overwrite a file Tripwire did not write")
	}
	if got, _ := os.ReadFile(target); string(got) != original {
		t.Fatal("the existing file was modified")
	}
}

// Non-LLM kinds must not consult the generator at all.
func TestPlaceGeneratedIgnoresGeneratorForTemplateKinds(t *testing.T) {
	target := filepath.Join(t.TempDir(), "auth.json")
	gen := &fakeGen{out: `{"should":"not be used"}`}
	res, err := PlaceGenerated(context.Background(), Decoy{Path: target, Kind: KindCodex}, "tw-x", time.Now(), gen)
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated {
		t.Fatal("a template kind must not be reported as generated")
	}
	if gen.seen.Path != "" {
		t.Fatal("the generator should not have been called")
	}
}

func TestSanitizeGeneratedStripsCodeFences(t *testing.T) {
	fenced := "```json\n{\"api_key\": \"tw-deadbeefdeadbeef-abc\"}\n```"
	out, err := SanitizeGenerated([]byte(fenced), "tw-deadbeefdeadbeef")
	if err != nil {
		t.Fatalf("a fenced response should be recovered, not rejected: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid json: %v", err)
	}
	if strings.Contains(string(out), "```") {
		t.Fatalf("fence survived: %s", out)
	}
}

func TestSanitizeGeneratedRejectsOversizeContent(t *testing.T) {
	huge := `{"fp":"tw-deadbeefdeadbeef","pad":"` + strings.Repeat("x", 70<<10) + `"}`
	if _, err := SanitizeGenerated([]byte(huge), "tw-deadbeefdeadbeef"); err == nil {
		t.Fatal("oversize content must be rejected")
	}
}

// Whatever the model returns, the file on disk should look like every other
// decoy — same indentation, no trailing prose.
func TestSanitizeGeneratedNormalisesFormatting(t *testing.T) {
	out, err := SanitizeGenerated([]byte(`   {"a":{"b":"tw-deadbeefdeadbeef"}}   `), "tw-deadbeefdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\n  \"a\"") {
		t.Fatalf("expected indented json, got: %s", out)
	}
}
