package bait

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDecoysCoverEveryBaitedService(t *testing.T) {
	paths := DefaultPaths()
	joined := strings.Join(paths, " ")
	for _, want := range []string{"claude", "anthropic", "codex", "openai", "aws", "gcloud", "npm", "pip", "gh"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("default paths missing %q: %v", want, paths)
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) || !strings.HasPrefix(p, "/etc/") {
			t.Fatalf("decoy %q must be an absolute /etc path", p)
		}
	}
	// A decoy the real client loads is worse than no decoy: every build on the
	// host would authenticate with a dead token. These are the paths npm, pip,
	// and the AWS SDK actually read.
	for _, forbidden := range []string{"/etc/npmrc", "/etc/pip.conf", "/etc/xdg/pip/pip.conf", "/etc/aws/config"} {
		for _, p := range paths {
			if p == forbidden {
				t.Errorf("%s is read by the real tool; a decoy there breaks the host", p)
			}
		}
	}
	// Inference has to agree with the shipped pairings even without the
	// exact-path shortcut, so an operator who moves a decoy elsewhere still gets
	// the schema its name implies.
	for _, d := range DefaultDecoys() {
		moved := strings.Replace(d.Path, "/etc/", "/srv/secrets/", 1)
		if got := KindFor(moved); got != d.Kind {
			t.Errorf("KindFor(%q) = %v, but the default pairs that name with %v", moved, got, d.Kind)
		}
	}
}

func TestPlaceWritesValidJSONWithFingerprint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex", "auth.json")
	now := time.Unix(1_700_000_000, 0).UTC()

	d := Decoy{Path: target, Kind: KindCodex}
	if err := Place(d, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatalf("Place: %v", err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if !strings.Contains(string(raw), "tw-deadbeefdeadbeef") {
		t.Fatal("fingerprint not embedded")
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
	}
}

// A decoy carrying a long-expired token is a tell that it is bait, so every
// rendered schema must express its expiry in the future relative to `now`.
func TestPlacedTokenExpiryIsInTheFuture(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()

	claudePath := filepath.Join(dir, "claude", "credentials.json")
	if err := Place(Decoy{Path: claudePath, Kind: KindClaude}, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(claudePath)
	var claudeDoc struct {
		OAuth struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &claudeDoc); err != nil {
		t.Fatal(err)
	}
	if claudeDoc.OAuth.ExpiresAt <= now.UnixMilli() {
		t.Fatalf("claude expiresAt = %d, want > %d", claudeDoc.OAuth.ExpiresAt, now.UnixMilli())
	}

	codexPath := filepath.Join(dir, "codex", "auth.json")
	if err := Place(Decoy{Path: codexPath, Kind: KindCodex}, "tw-deadbeefdeadbeef", now); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(codexPath)
	var codexDoc struct {
		LastRefresh time.Time `json:"last_refresh"`
	}
	if err := json.Unmarshal(raw, &codexDoc); err != nil {
		t.Fatal(err)
	}
	if !codexDoc.LastRefresh.Equal(now) {
		t.Fatalf("codex last_refresh = %v, want %v", codexDoc.LastRefresh, now)
	}
}

// Every schema has to satisfy the two properties the rest of Tripwire relies
// on: the file carries a greppable fingerprint (so a leak names this host, and
// so IsOurs will let a refresh rewrite it), and it is written in the syntax the
// real tool uses (so it does not read as fake).
func TestEverySchemaIsRecognisableAndWellFormed(t *testing.T) {
	const fp = "tw-deadbeefdeadbeef"
	now := time.Unix(1_700_000_000, 0).UTC()

	cases := []struct {
		kind  Kind
		name  string
		json  bool
		marks []string // strings a reader of the real format would expect
	}{
		{KindClaude, "claude", true, []string{"claudeAiOauth", "sk-ant-oat01-"}},
		{KindCodex, "codex", true, []string{"OPENAI_API_KEY", "sk-proj-"}},
		{KindAWS, "aws", false, []string{"[default]", "aws_access_key_id = AKIA", "aws_secret_access_key = "}},
		{KindGCP, "gcp", true, []string{"service_account", "BEGIN PRIVATE KEY", "iam.gserviceaccount.com"}},
		{KindNPM, "npm", false, []string{"registry=https://registry.npmjs.org/", ":_authToken=npm_"}},
		{KindPyPI, "pip", false, []string{"[global]", "index-url = ", "pypi-"}},
		{KindGitHub, "github", false, []string{"github.com:", "oauth_token: gho_"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "decoy")
			if err := Place(Decoy{Path: target, Kind: tc.kind}, fp, now); err != nil {
				t.Fatalf("Place: %v", err)
			}
			raw, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			if !strings.Contains(body, fp) {
				t.Fatalf("fingerprint not embedded:\n%s", body)
			}
			if ours, err := IsOurs(target); err != nil || !ours {
				t.Fatalf("IsOurs = %t, %v — a refresh could not rewrite this decoy", ours, err)
			}
			for _, want := range tc.marks {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q:\n%s", want, body)
				}
			}

			gotJSON := json.Unmarshal(raw, new(map[string]any)) == nil
			if gotJSON != tc.json {
				t.Errorf("json = %t, want %t:\n%s", gotJSON, tc.json, body)
			}
			wantFormat := FormatJSON
			if !tc.json {
				wantFormat = FormatText
				if !strings.HasSuffix(body, "\n") {
					t.Errorf("a line-oriented credential file should end in a newline:\n%q", body)
				}
			}
			if tc.kind.Format() != wantFormat {
				t.Errorf("Format() = %v, want %v", tc.kind.Format(), wantFormat)
			}
		})
	}
}

// Token filler is derived from the fingerprint, not drawn at random: rendering
// twice has to produce identical bytes, or every 12-hour refresh would read as
// a credential that quietly rotates itself.
func TestRenderingIsDeterministicPerHost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, d := range DefaultDecoys() {
		first, err := render(d.Kind, "tw-deadbeefdeadbeef", now)
		if err != nil {
			t.Fatal(err)
		}
		again, err := render(d.Kind, "tw-deadbeefdeadbeef", now)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Errorf("%s: re-rendering changed the file", d.Path)
		}
		// ...and two hosts must not share tokens, or one leaked decoy would
		// implicate every install.
		other, err := render(d.Kind, "tw-0123456789abcdef", now)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, other) {
			t.Errorf("%s: two fingerprints produced the same decoy", d.Path)
		}
	}
}

// Sizes are the cheapest tell there is: a 30-character AWS secret is not one.
func TestTokenWidthsMatchTheRealFormats(t *testing.T) {
	const fp = "tw-deadbeefdeadbeef"
	widths := map[string]struct {
		body   []byte
		prefix string
		want   int // total token length, prefix included
	}{
		"aws access key id":  {renderAWS(fp, time.Now()), "AKIA", 20},
		"npm auth token":     {renderNPM(fp), "npm_", 40},
		"github oauth token": {renderGitHub(fp), "gho_", 40},
	}
	for name, tc := range widths {
		body := string(tc.body)
		i := strings.Index(body, tc.prefix)
		if i < 0 {
			t.Fatalf("%s: prefix %q not found in\n%s", name, tc.prefix, body)
		}
		token := body[i:]
		if j := strings.IndexAny(token, "\n \t"); j >= 0 {
			token = token[:j]
		}
		if len(token) != tc.want {
			t.Errorf("%s: %q is %d chars, want %d", name, token, len(token), tc.want)
		}
	}
	// An AWS secret is 40 characters on its own line.
	for _, line := range strings.Split(string(renderAWS(fp, time.Now())), "\n") {
		if secret, ok := strings.CutPrefix(line, "aws_secret_access_key = "); ok && len(secret) != 40 {
			t.Errorf("aws secret is %d chars, want 40", len(secret))
		}
	}
}

func TestVerifyDetectsMissingAndModified(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex", "auth.json")
	d := Decoy{Path: target, Kind: KindCodex}
	now := time.Unix(1_700_000_000, 0).UTC()
	_ = Place(d, "tw-deadbeefdeadbeef", now)

	if err := Verify(d); err != nil {
		t.Fatalf("freshly placed decoy should verify: %v", err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(d); err == nil {
		t.Fatal("world-readable decoy should fail verify")
	}
	_ = os.Remove(target)
	if err := Verify(d); err == nil {
		t.Fatal("missing decoy should fail verify")
	}
}

func TestKindForKnownAndInferredPaths(t *testing.T) {
	cases := map[string]Kind{
		"/etc/codex/auth.json":                    KindCodex, // known default
		"/etc/claude-code/credentials.json":       KindClaude,
		"/etc/openai/codex-auth.json":             KindCodex,
		"/srv/secrets/openai.json":                KindCodex,  // inferred by name
		"/srv/secrets/CODEX-creds.json":           KindCodex,  // case-insensitive
		"/srv/secrets/anthropic-credentials.json": KindClaude, // default schema
		"/srv/secrets/api.json":                   KindClaude,
		"/etc/aws/credentials":                    KindAWS, // known default
		"/etc/gcloud/service-account.json":        KindGCP,
		"/etc/npm/npmrc":                          KindNPM,
		"/etc/pip/pip.conf":                       KindPyPI,
		"/etc/gh/hosts.yml":                       KindGitHub,
		"/srv/deploy/aws-prod.credentials":        KindAWS, // inferred by name
		"/srv/deploy/GCP-key.json":                KindGCP,
		"/srv/deploy/google-service-account.json": KindGCP,
		"/srv/deploy/.npmrc":                      KindNPM,
		"/srv/deploy/.pypirc":                     KindPyPI,
		"/srv/deploy/github-token.yml":            KindGitHub,
	}
	for path, want := range cases {
		if got := KindFor(path); got != want {
			t.Errorf("KindFor(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDecoysForPairsEveryPath(t *testing.T) {
	paths := []string{"/etc/codex/auth.json", "/srv/custom/creds.json"}
	got := DecoysFor(paths)
	if len(got) != 2 {
		t.Fatalf("DecoysFor returned %d decoys", len(got))
	}
	if got[0].Kind != KindCodex || got[1].Kind != KindClaude {
		t.Fatalf("kinds = %v, %v", got[0].Kind, got[1].Kind)
	}
	for i, d := range got {
		if d.Path != paths[i] {
			t.Fatalf("path %d = %q, want %q", i, d.Path, paths[i])
		}
	}
}

// A mistyped bait path must never cost the operator a real credential file:
// placement follows configuration, so it has to refuse anything it did not write.
func TestPlaceSafeRefusesToClobberForeignFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "passwd")
	const original = "root:x:0:0:root:/root:/bin/bash\n"
	if err := os.WriteFile(real, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	err := PlaceSafe(Decoy{Path: real, Kind: KindCodex}, "tw-deadbeefdeadbeef", time.Now())
	if err == nil {
		t.Fatal("PlaceSafe must refuse to overwrite a file it did not write")
	}
	if !strings.Contains(err.Error(), "not written by Tripwire") {
		t.Fatalf("err = %v, want it to explain the refusal", err)
	}
	got, _ := os.ReadFile(real)
	if string(got) != original {
		t.Fatal("the existing file was modified despite the refusal")
	}
}

func TestPlaceSafeCreatesAndThenRefreshesItsOwnFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "auth.json")
	d := Decoy{Path: target, Kind: KindCodex}

	if err := PlaceSafe(d, "tw-deadbeefdeadbeef", time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Fatalf("creating a new decoy must succeed: %v", err)
	}
	// A refresh rewrites the same path: it is ours, so it is allowed.
	later := time.Unix(1_800_000_000, 0).UTC()
	if err := PlaceSafe(d, "tw-deadbeefdeadbeef", later); err != nil {
		t.Fatalf("refreshing our own decoy must succeed: %v", err)
	}
	raw, _ := os.ReadFile(target)
	if !strings.Contains(string(raw), later.Format(time.RFC3339)) {
		t.Fatal("refresh did not update the timestamp")
	}
}

func TestPlaceSafeRequiresAbsolutePaths(t *testing.T) {
	if err := PlaceSafe(Decoy{Path: "relative/auth.json"}, "tw-x", time.Now()); err == nil {
		t.Fatal("a relative decoy path must be rejected")
	}
}

func TestIsOursRecognisesOurFilesOnly(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.json")
	if ours, err := IsOurs(missing); err != nil || !ours {
		t.Fatalf("a missing path is free to create: ours=%t err=%v", ours, err)
	}

	decoy := filepath.Join(dir, "auth.json")
	if err := Place(Decoy{Path: decoy, Kind: KindCodex}, "tw-deadbeefdeadbeef", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ours, err := IsOurs(decoy); err != nil || !ours {
		t.Fatalf("a placed decoy must be recognised: ours=%t err=%v", ours, err)
	}

	foreign := filepath.Join(dir, "real-creds.json")
	if err := os.WriteFile(foreign, []byte(`{"api_key":"sk-live-not-a-decoy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ours, err := IsOurs(foreign); err != nil || ours {
		t.Fatalf("a real credential file must not look like ours: ours=%t err=%v", ours, err)
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ours, _ := IsOurs(empty); ours {
		t.Fatal("an empty file is not recognisably ours; refuse rather than guess")
	}
}

func TestKindByNameResolvesSelectors(t *testing.T) {
	cases := []struct {
		name, path string
		want       Kind
	}{
		{"", "/etc/codex/auth.json", KindCodex},           // unset == auto
		{"auto", "/etc/codex/auth.json", KindCodex},       // auto infers
		{"auto", "/srv/anything.json", KindClaude},        // auto default
		{"claude", "/etc/codex/auth.json", KindClaude},    // explicit beats name
		{"codex", "/etc/anthropic/creds.json", KindCodex}, // explicit beats name
		{"CODEX", "/srv/x.json", KindCodex},               // case-insensitive
		{"  codex  ", "/srv/x.json", KindCodex},           // tolerant of spacing
		{"aws", "/srv/x.json", KindAWS},
		{"gcp", "/srv/x.json", KindGCP},
		{"npm", "/srv/x.json", KindNPM},
		{"pip", "/srv/x.json", KindPyPI},
		{"github", "/srv/x.json", KindGitHub},
	}
	for _, tc := range cases {
		got, err := KindByName(tc.name, tc.path)
		if err != nil {
			t.Fatalf("KindByName(%q, %q): %v", tc.name, tc.path, err)
		}
		if got != tc.want {
			t.Errorf("KindByName(%q, %q) = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
}

func TestKindByNameRejectsUnknownSelector(t *testing.T) {
	if _, err := KindByName("gemini", "/srv/x.json"); err == nil {
		t.Fatal("an unknown kind must be an error, not a silent default")
	}
}

func TestValidKindName(t *testing.T) {
	for _, ok := range []string{"", "auto", "claude", "codex", "CODEX", "aws", "gcp", "npm", "pip", "github", "llm"} {
		if !ValidKindName(ok) {
			t.Errorf("ValidKindName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"gemini", "openai", "kind", "pypi", "gh"} {
		if ValidKindName(bad) {
			t.Errorf("ValidKindName(%q) = true", bad)
		}
	}
	// The error message an operator gets has to name every selector they could
	// have meant, and name them in the same order every time.
	for _, want := range []string{"auto", "claude", "codex", "aws", "gcp", "npm", "pip", "github", "llm"} {
		if !strings.Contains(KindNames(), want) {
			t.Errorf("KindNames() = %q, missing %q", KindNames(), want)
		}
	}
}
