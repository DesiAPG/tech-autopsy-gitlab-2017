// Package env decides whether the current shell is talking to production.
//
// The GitLab incident of 2017-01-31 happened because two production database
// hosts (db1 and db2) looked alike from a terminal. go-guard therefore treats
// "production" as a property of where the command lands, from several signals:
// an explicit variable, the hostname, the Kubernetes context and the AWS
// profile — and, for `ssh host '…'`, the remote host.
package env

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultPattern matches names like prod, prd, production, db-prod-1, eks-prd.
const DefaultPattern = `(?i)(^|[-_.:/@])(prod|prd|production|live)([-_.:/0-9]|$)`

// Signals are the raw facts the decision is made from.
type Signals struct {
	Explicit    string // $GO_GUARD_ENV
	Hostname    string
	KubeContext string
	AWSProfile  string
}

// Detector holds the configured notion of production.
type Detector struct {
	Hosts    []string // exact hostnames or "prefix*"
	Patterns []*regexp.Regexp
}

// NewDetector compiles the default pattern plus the configured extras.
func NewDetector(hosts, patterns []string) (*Detector, error) {
	d := &Detector{Hosts: hosts}
	for _, p := range append([]string{DefaultPattern}, patterns...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("production pattern %q: %w", p, err)
		}
		d.Patterns = append(d.Patterns, re)
	}
	return d, nil
}

// Result says whether we are in production and why.
type Result struct {
	Production bool     `json:"production"`
	Reasons    []string `json:"reasons"`
}

// Detect evaluates the signals. GO_GUARD_ENV wins when set: "prod",
// "production" force production; "dev", "staging", "test", "local" force
// non-production.
func (d *Detector) Detect(s Signals) Result {
	switch strings.ToLower(s.Explicit) {
	case "prod", "production", "prd", "live":
		return Result{true, []string{"GO_GUARD_ENV=" + s.Explicit}}
	case "dev", "development", "staging", "stage", "test", "local", "sandbox":
		return Result{false, []string{"GO_GUARD_ENV=" + s.Explicit}}
	}
	var r Result
	if why, ok := d.IsProductionHost(s.Hostname); ok {
		r.Production = true
		r.Reasons = append(r.Reasons, why)
	}
	if s.KubeContext != "" && d.matches(s.KubeContext) {
		r.Production = true
		r.Reasons = append(r.Reasons, fmt.Sprintf("kube context %q", s.KubeContext))
	}
	if s.AWSProfile != "" && d.matches(s.AWSProfile) {
		r.Production = true
		r.Reasons = append(r.Reasons, fmt.Sprintf("AWS profile %q", s.AWSProfile))
	}
	return r
}

// IsProductionHost reports whether a hostname is production, by explicit
// list (short name or FQDN) or by pattern.
func (d *Detector) IsProductionHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	short := host
	if i := strings.IndexByte(host, '.'); i > 0 {
		short = host[:i]
	}
	for _, h := range d.Hosts {
		if prefix, ok := strings.CutSuffix(h, "*"); ok {
			if strings.HasPrefix(host, prefix) || strings.HasPrefix(short, prefix) {
				return fmt.Sprintf("host %q es producción (%s)", host, h), true
			}
		} else if strings.EqualFold(host, h) || strings.EqualFold(short, h) {
			return fmt.Sprintf("host %q es producción (%s)", host, h), true
		}
	}
	if d.matches(host) {
		return fmt.Sprintf("hostname %q parece producción", host), true
	}
	return "", false
}

func (d *Detector) matches(s string) bool {
	for _, re := range d.Patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Gather reads the live signals from the process environment.
func Gather() Signals {
	host, _ := os.Hostname()
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}
	return Signals{
		Explicit:    os.Getenv("GO_GUARD_ENV"),
		Hostname:    host,
		KubeContext: kubeContext(),
		AWSProfile:  profile,
	}
}

// kubeContext reads current-context from the first kubeconfig file without
// shelling out to kubectl (which may be slow or absent).
func kubeContext() string {
	path := os.Getenv("KUBECONFIG")
	if i := strings.IndexByte(path, os.PathListSeparator); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		path = filepath.Join(home, ".kube", "config")
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "current-context:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
