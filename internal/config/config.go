// Package config loads go-guard's optional JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/rules"
)

// Config tunes what counts as production and what counts as protected.
// Every list extends the built-in defaults; nothing here can disable the
// production check itself.
type Config struct {
	// ProductionHosts are hostnames (or prefixes ending in "*") that are
	// production even if their names do not say so, e.g. "db1", "db2".
	ProductionHosts []string `json:"production_hosts"`
	// ProductionPatterns are extra regular expressions matched against the
	// hostname, kube context and AWS profile.
	ProductionPatterns []string `json:"production_patterns"`
	// ProtectedPaths are extra data directories (protected with contents).
	ProtectedPaths []string `json:"protected_paths"`
	// DisabledRules lists rule IDs to skip (see `go-guard rules`).
	DisabledRules []string `json:"disabled_rules"`
	// AllowSelfApproval lets the requester approve their own command.
	// Off by default: the point is a second pair of eyes.
	AllowSelfApproval bool `json:"allow_self_approval"`
}

// Path returns the config file location: $GO_GUARD_CONFIG, else
// $XDG_CONFIG_HOME/go-guard/config.json, else ~/.config/go-guard/config.json.
func Path() string {
	if p := os.Getenv("GO_GUARD_CONFIG"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "go-guard", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "go-guard", "config.json")
}

// Load reads the config at path. A missing file is not an error.
func Load(path string) (Config, error) {
	var c Config
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// AllProtectedPaths returns the defaults plus the configured extras.
func (c Config) AllProtectedPaths() []string {
	return append(append([]string{}, rules.DefaultProtectedPaths...), c.ProtectedPaths...)
}

// Rules returns the built-in rules minus the disabled ones.
func (c Config) Rules() []rules.Rule {
	off := map[string]bool{}
	for _, id := range c.DisabledRules {
		off[id] = true
	}
	var out []rules.Rule
	for _, r := range rules.All() {
		if !off[r.ID] {
			out = append(out, r)
		}
	}
	return out
}
