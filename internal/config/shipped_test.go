package config

import (
	"os"
	"testing"

	"github.com/mbarnathan/tripwire/internal/bait"
)

func TestShippedConfigsParse(t *testing.T) {
	for _, p := range []string{"../../packaging/config/server.yaml", "../../packaging/config/workstation.yaml"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if cfg.LLM != nil {
			t.Fatalf("%s: shipped config must not enable llm generation", p)
		}
		// The shipped list has to be the built-in default, path for path: the
		// packaging scripts prune and clean up exactly these directories, so a
		// config that drifted would leave a decoy indexed or orphaned.
		want := bait.DefaultPaths()
		if len(cfg.Bait) != len(want) {
			t.Fatalf("%s: bait count = %d, want %d", p, len(cfg.Bait), len(want))
		}
		for i, b := range cfg.Bait {
			if b.Path != want[i] {
				t.Errorf("%s: bait[%d] = %s, want %s", p, i, b.Path, want[i])
			}
		}
	}
}
