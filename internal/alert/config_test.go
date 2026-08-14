package alert

import (
	"testing"

	"github.com/mbarnathan/tripwire/internal/config"
)

func names(sinks []Sink) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Name())
	}
	return out
}

// journald is not optional: it is the forensic record that outlives a poweroff.
func TestJournalSinkIsAlwaysPresent(t *testing.T) {
	cfg, err := config.Parse([]byte("profile: server"))
	if err != nil {
		t.Fatal(err)
	}
	got := names(FromConfig(cfg))
	if len(got) != 1 || got[0] != "journal" {
		t.Fatalf("sinks = %v, want just journal", got)
	}
}

func TestConfiguredSinksAreBuilt(t *testing.T) {
	cfg, err := config.Parse([]byte(`
profile: workstation
sinks:
  webhook: {url: "https://example.com/hook"}
  ntfy: {url: "https://ntfy.sh/topic"}
  email: {to: you@example.com, from: tripwire@example.com}
`))
	if err != nil {
		t.Fatal(err)
	}
	got := names(FromConfig(cfg))
	want := map[string]bool{"webhook": true, "ntfy": true, "email": true, "journal": true}
	if len(got) != len(want) {
		t.Fatalf("sinks = %v, want %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected sink %q in %v", n, got)
		}
	}
}

// A sink block present but empty (commented-out URL) must not create a sink that
// can only ever fail.
func TestEmptySinkConfigIsSkipped(t *testing.T) {
	cfg, err := config.Parse([]byte("sinks:\n  webhook: {url: \"\"}\n  ntfy: {url: \"\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := names(FromConfig(cfg))
	if len(got) != 1 || got[0] != "journal" {
		t.Fatalf("sinks = %v, want just journal", got)
	}
}
