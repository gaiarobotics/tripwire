package config

import (
	"os"
	"testing"
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
		if len(cfg.Bait) != 4 {
			t.Fatalf("%s: bait count = %d", p, len(cfg.Bait))
		}
	}
}
