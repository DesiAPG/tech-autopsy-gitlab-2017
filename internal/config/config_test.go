package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"production_hosts":["db1"],"protected_paths":["/srv/app/uploads"],"disabled_rules":["helm-uninstall"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ProductionHosts) != 1 || c.ProductionHosts[0] != "db1" {
		t.Errorf("hosts = %v", c.ProductionHosts)
	}
	paths := c.AllProtectedPaths()
	if paths[len(paths)-1] != "/srv/app/uploads" {
		t.Errorf("extra path not appended: %v", paths)
	}
	for _, r := range c.Rules() {
		if r.ID == "helm-uninstall" {
			t.Error("disabled rule still present")
		}
	}
}

func TestMissingFileIsEmptyConfig(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(c.ProductionHosts) != 0 {
		t.Fatalf("missing file: %+v, %v", c, err)
	}
}

func TestInvalidJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(p, []byte(`{`), 0o600)
	if _, err := Load(p); err == nil {
		t.Error("invalid JSON must fail")
	}
}
