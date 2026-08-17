package bait

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxGeneratedSize bounds what we will accept from a generator. A decoy is a
// small credential file; anything larger is a malfunction, and writing it would
// make the bait conspicuous.
const maxGeneratedSize = 64 << 10

// GenRequest describes the decoy a Generator should write content for.
type GenRequest struct {
	Path        string    // absolute path the decoy will live at
	Fingerprint string    // per-install id that must appear in every token
	Now         time.Time // reference time, for expiry values
	Guidance    string    // optional operator hint, e.g. "a CI service account"
	Fallback    Kind      // the built-in schema used if generation fails
}

// Generator produces decoy content. It is implemented by internal/llm; the bait
// package deliberately knows nothing about providers, HTTP, or credentials.
type Generator interface {
	Generate(ctx context.Context, req GenRequest) ([]byte, error)
}

// PlaceResult reports how a decoy's content was produced.
type PlaceResult struct {
	Generated bool  // true if the content came from the generator
	GenErr    error // generation was attempted and failed; the template was used instead
}

// PlaceGenerated writes a decoy, using the generator for KindLLM decoys and the
// built-in template for everything else.
//
// Generation failure is never fatal: a decoy that does not exist is a decoy that
// cannot trip, so any error falls back to the template schema inferred from the
// path and is reported in PlaceResult.GenErr for the caller to surface.
func PlaceGenerated(ctx context.Context, d Decoy, fingerprint string, now time.Time, gen Generator) (PlaceResult, error) {
	if d.Kind != KindLLM {
		return PlaceResult{}, PlaceSafe(d, fingerprint, now)
	}

	fallback := Decoy{Path: d.Path, Kind: KindFor(d.Path)}
	if gen == nil {
		return PlaceResult{GenErr: fmt.Errorf("no LLM generator configured")},
			PlaceSafe(fallback, fingerprint, now)
	}

	raw, err := gen.Generate(ctx, GenRequest{
		Path:        d.Path,
		Fingerprint: fingerprint,
		Now:         now,
		Fallback:    fallback.Kind,
	})
	if err == nil {
		raw, err = SanitizeGenerated(raw, fingerprint)
	}
	if err != nil {
		return PlaceResult{GenErr: err}, PlaceSafe(fallback, fingerprint, now)
	}
	// Generated content goes through the same no-clobber guard as templates: a
	// mistyped bait path must not cost a real file whichever kind produced it.
	ours, err := IsOurs(d.Path)
	if err != nil {
		return PlaceResult{}, fmt.Errorf("inspect %s: %w", d.Path, err)
	}
	if !ours {
		return PlaceResult{}, fmt.Errorf("refusing to overwrite %s: it exists and was not written by Tripwire", d.Path)
	}
	if err := writeDecoy(d.Path, raw); err != nil {
		return PlaceResult{}, err
	}
	return PlaceResult{Generated: true}, nil
}

// SanitizeGenerated normalises and checks generated content before it is written.
//
// The fingerprint check is the load-bearing one: a decoy token that cannot be
// traced back to the host it leaked from is not worth planting, so content that
// omits it is rejected rather than written.
func SanitizeGenerated(raw []byte, fingerprint string) ([]byte, error) {
	body := bytes.TrimSpace(unfence(raw))
	if len(body) == 0 {
		return nil, fmt.Errorf("generated content is empty")
	}
	if len(body) > maxGeneratedSize {
		return nil, fmt.Errorf("generated content is %d bytes, over the %d byte limit", len(body), maxGeneratedSize)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("generated content is not a JSON object: %w", err)
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("generated content is an empty JSON object")
	}
	if !bytes.Contains(body, []byte(fingerprint)) {
		return nil, fmt.Errorf("generated content does not embed the install fingerprint %s", fingerprint)
	}

	// Re-marshal so the file looks like every other decoy on disk regardless of
	// how the model formatted it.
	pretty, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return pretty, nil
}

// unfence strips a Markdown code fence, which models add even when told not to.
func unfence(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, "```") {
		return raw
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return []byte(strings.TrimSpace(s))
}
