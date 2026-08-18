// Package bait generates, places, and verifies the decoy credential files that
// Tripwire watches. The tokens are structurally valid but non-functional; each
// carries the per-install fingerprint so a leaked token names the host it came
// from.
package bait

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Kind selects which credential schema a decoy mimics.
type Kind int

const (
	KindClaude Kind = iota
	KindCodex
	KindAWS
	KindGCP
	KindNPM
	KindPyPI
	KindGitHub
	// KindLLM defers the file's contents to a configured language model instead
	// of a built-in template. It is never inferred — an operator has to ask for
	// it by name — and it falls back to a template if generation fails.
	KindLLM
)

// Format is the on-disk syntax a schema renders. Not every credential file is
// JSON: an npmrc that parsed as JSON would announce itself as fake.
type Format int

const (
	FormatJSON Format = iota
	FormatText
)

// Format reports the syntax the kind writes. KindLLM has no syntax of its own —
// it borrows the fallback schema's, so the model is asked for the right one.
func (k Kind) Format() Format {
	switch k {
	case KindAWS, KindNPM, KindPyPI, KindGitHub:
		return FormatText
	}
	return FormatJSON
}

// Decoy is one planted credential file.
type Decoy struct {
	Path string
	Kind Kind
}

// DefaultPaths are the shipped decoy locations. They mimic a system-wide managed
// install and are deliberately nowhere near ~/.claude or ~/.codex.
func DefaultPaths() []string {
	decoys := DefaultDecoys()
	out := make([]string, 0, len(decoys))
	for _, d := range decoys {
		out = append(out, d.Path)
	}
	return out
}

// DefaultDecoys pairs each default path with the schema it should mimic.
//
// Every path here is one a real tool would *not* read. /etc/npm/npmrc and
// /etc/pip/pip.conf are deliberately not npm's and pip's own system config
// locations (those are $PREFIX/etc/npmrc and /etc/pip.conf): a decoy that the
// real client loads would hand a non-functional token to every build on the
// host. The same rule picks /etc/aws over the SDK's ~/.aws and /etc/gh over
// gh's ~/.config/gh — plausible to a human reading /etc, inert to the tooling.
func DefaultDecoys() []Decoy {
	return []Decoy{
		{"/etc/claude-code/credentials.json", KindClaude},
		{"/etc/anthropic/claude.credentials.json", KindClaude},
		{"/etc/codex/auth.json", KindCodex},
		{"/etc/openai/codex-auth.json", KindCodex},
		{"/etc/aws/credentials", KindAWS},
		{"/etc/gcloud/service-account.json", KindGCP},
		{"/etc/npm/npmrc", KindNPM},
		{"/etc/pip/pip.conf", KindPyPI},
		{"/etc/gh/hosts.yml", KindGitHub},
	}
}

// Schema names accepted in configuration. "auto" defers to KindFor, which reads
// the filename — the default, and all most installs ever need.
const (
	KindNameAuto   = "auto"
	KindNameClaude = "claude"
	KindNameCodex  = "codex"
	KindNameAWS    = "aws"
	KindNameGCP    = "gcp"
	KindNameNPM    = "npm"
	KindNamePyPI   = "pip"
	KindNameGitHub = "github"
	KindNameLLM    = "llm"
)

// kindsByName resolves an explicit selector. "auto" is absent on purpose: it
// means "infer", which needs the path.
var kindsByName = map[string]Kind{
	KindNameClaude: KindClaude,
	KindNameCodex:  KindCodex,
	KindNameAWS:    KindAWS,
	KindNameGCP:    KindGCP,
	KindNameNPM:    KindNPM,
	KindNamePyPI:   KindPyPI,
	KindNameGitHub: KindGitHub,
	KindNameLLM:    KindLLM,
}

// kindNameOrder fixes the order selectors are listed in for operators; a map
// alone would shuffle the error message on every run.
var kindNameOrder = []string{
	KindNameAuto, KindNameClaude, KindNameCodex, KindNameAWS, KindNameGCP,
	KindNameNPM, KindNamePyPI, KindNameGitHub, KindNameLLM,
}

// ValidKindName reports whether name is a schema selector we understand. The
// empty string means unset, which is treated as "auto".
func ValidKindName(name string) bool {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" || norm == KindNameAuto {
		return true
	}
	_, ok := kindsByName[norm]
	return ok
}

// KindNames lists the accepted selectors, for error messages.
func KindNames() string {
	return strings.Join(kindNameOrder, ", ")
}

// KindByName resolves a configured schema selector for a path. An unset or
// "auto" selector infers from the filename; anything else names a schema
// explicitly and overrides inference.
func KindByName(name, path string) (Kind, error) {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" || norm == KindNameAuto {
		return KindFor(path), nil
	}
	if k, ok := kindsByName[norm]; ok {
		return k, nil
	}
	return 0, fmt.Errorf("unknown decoy kind %q (valid: %s)", name, KindNames())
}

// kindHints infers a schema from what a path is named, most specific match
// first. It is a list rather than a map so the order is fixed: a path that
// mentions two services resolves the same way on every host.
var kindHints = []struct {
	substr string
	kind   Kind
}{
	{"codex", KindCodex},
	{"openai", KindCodex},
	{"claude", KindClaude},
	{"anthropic", KindClaude},
	{"github", KindGitHub},
	{"/gh/", KindGitHub},
	{"aws", KindAWS},
	{"gcloud", KindGCP},
	{"gcp", KindGCP},
	{"google", KindGCP},
	{"service-account", KindGCP},
	{"npmrc", KindNPM},
	{"npm", KindNPM},
	{"pypi", KindPyPI},
	{"pip.conf", KindPyPI},
	{"/pip/", KindPyPI},
}

// KindFor guesses which credential schema a path should mimic. Operator-added
// paths are not in DefaultDecoys, so fall back to naming (see kindHints).
// Anything that names no service at all gets the Claude schema, which is what
// this tool was built to bait.
func KindFor(path string) Kind {
	for _, d := range DefaultDecoys() {
		if d.Path == path {
			return d.Kind
		}
	}
	lower := strings.ToLower(path)
	for _, h := range kindHints {
		if strings.Contains(lower, h.substr) {
			return h.kind
		}
	}
	return KindClaude
}

// DecoysFor pairs configured paths with the schema each should mimic, so the
// installer, the daemon's refresh loop, and the CLI all agree on what belongs at
// a given path.
func DecoysFor(paths []string) []Decoy {
	out := make([]Decoy, 0, len(paths))
	for _, p := range paths {
		out = append(out, Decoy{Path: p, Kind: KindFor(p)})
	}
	return out
}

// fingerprintPattern matches the per-install id embedded in every decoy token.
// It is how we recognise a file as one of ours.
var fingerprintPattern = regexp.MustCompile(`tw-[0-9a-f]{16}`)

// IsOurs reports whether the path is absent (safe to create) or holds a file
// Tripwire itself wrote. It is what stands between a mistyped bait path and
// overwriting a real credential file as root.
func IsOurs(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return fingerprintPattern.Match(raw), nil
}

// PlaceSafe writes a decoy, refusing to clobber any file Tripwire did not
// create. Every path that comes from configuration goes through here; Place
// itself stays a raw write for tests and for callers that have already checked.
func PlaceSafe(d Decoy, fingerprint string, now time.Time) error {
	if !filepath.IsAbs(d.Path) {
		return fmt.Errorf("decoy path %q must be absolute", d.Path)
	}
	ours, err := IsOurs(d.Path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", d.Path, err)
	}
	if !ours {
		return fmt.Errorf("refusing to overwrite %s: it exists and was not written by Tripwire", d.Path)
	}
	return Place(d, fingerprint, now)
}

// Place writes a structurally-valid, non-functional credential file with the
// install fingerprint embedded and a future expiry (no stale-token tell).
// Mode is 0600 root:root (ownership applied by the caller/postinst as root).
func Place(d Decoy, fingerprint string, now time.Time) error {
	body, err := render(d.Kind, fingerprint, now)
	if err != nil {
		return err
	}
	return writeDecoy(d.Path, body)
}

// writeDecoy writes decoy content atomically: temp file + rename, so a reader
// never sees a partial file and never trips the wire on a half-written decoy.
func writeDecoy(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Verify confirms the decoy still exists and is a regular 0600 file. It does not
// re-check contents — the daemon re-marks on replacement via the parent-dir watch.
func Verify(d Decoy) error {
	fi, err := os.Stat(d.Path)
	if err != nil {
		return fmt.Errorf("decoy %s: %w", d.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("decoy %s is not a regular file", d.Path)
	}
	if fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("decoy %s perm = %v, want 0600", d.Path, fi.Mode().Perm())
	}
	return nil
}

// Refresh rewrites every decoy with a fresh expiry timestamp. The daemon calls
// this periodically so the tokens never look abandoned.
func Refresh(decoys []Decoy, fingerprint string, now time.Time) error {
	for _, d := range decoys {
		if err := PlaceSafe(d, fingerprint, now); err != nil {
			return err
		}
	}
	return nil
}
