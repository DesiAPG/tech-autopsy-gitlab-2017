// Package audit appends one JSON line per guarded decision, so a post-mortem
// can answer "who tried to run what, where, and was it allowed?".
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry is one decision.
type Entry struct {
	Time       time.Time `json:"time"`
	User       string    `json:"user"`
	Host       string    `json:"host"`
	Cwd        string    `json:"cwd,omitempty"`
	Command    string    `json:"command"`
	Decision   string    `json:"decision"` // allowed | blocked | approved | warned
	Production bool      `json:"production"`
	Rules      []string  `json:"rules,omitempty"`
	Reasons    []string  `json:"reasons,omitempty"`
	Approver   string    `json:"approver,omitempty"`
}

// Path returns $GO_GUARD_AUDIT_LOG, else $XDG_STATE_HOME/go-guard/audit.log,
// else ~/.local/state/go-guard/audit.log. "off" disables auditing.
func Path() string {
	if p := os.Getenv("GO_GUARD_AUDIT_LOG"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "go-guard", "audit.log")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "go-guard", "audit.log")
}

// Write appends e to the log at path.
func Write(path string, e Entry) error {
	if path == "" || path == "off" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(e)
}
