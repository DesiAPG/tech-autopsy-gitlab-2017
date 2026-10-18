// Package guard combines the parser, the rules, the production detector and
// the approval check into one decision for a command line.
package guard

import (
	"time"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/approval"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/env"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/rules"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/shell"
)

// maxDepth bounds `bash -c "ssh h 'bash -c …'"` recursion.
const maxDepth = 4

// Input is everything a decision depends on, so it can be tested without
// touching the real machine.
type Input struct {
	Line           string
	Cwd            string
	Signals        env.Signals
	Detector       *env.Detector
	Rules          []rules.Rule
	ProtectedPaths []string
	CriticalDirs   []string

	ApprovalToken string
	Secret        string
	User          string
	AllowSelf     bool
	Now           time.Time
}

// Finding is a destructive command together with where it would run.
type Finding struct {
	rules.Hit
	Production bool     `json:"production"`
	Reasons    []string `json:"reasons,omitempty"`
	RemoteHost string   `json:"remote_host,omitempty"`
}

// Verdict values.
const (
	Allowed  = "allowed"  // nothing destructive
	Warned   = "warned"   // destructive, but not in production
	Approved = "approved" // destructive in production, with a valid approval
	Blocked  = "blocked"  // destructive in production, no valid approval
)

// Decision is the outcome for one command line.
type Decision struct {
	Verdict     string           `json:"verdict"`
	Production  bool             `json:"production"`
	EnvReasons  []string         `json:"env_reasons,omitempty"`
	Findings    []Finding        `json:"findings,omitempty"`
	Approval    *approval.Claims `json:"approval,omitempty"`
	ApprovalErr string           `json:"approval_error,omitempty"`
}

// Run reports whether the command may proceed.
func (d Decision) Run() bool { return d.Verdict != Blocked }

// Evaluate decides on in.Line.
func Evaluate(in Input) Decision {
	local := in.Detector.Detect(in.Signals)
	d := Decision{Production: local.Production, EnvReasons: local.Reasons}

	d.Findings = scan(in, in.Line, in.Cwd, local, "", 0)

	blocking := false
	for _, f := range d.Findings {
		if f.Production {
			blocking = true
			break
		}
	}
	switch {
	case len(d.Findings) == 0:
		d.Verdict = Allowed
	case !blocking:
		d.Verdict = Warned
	case in.ApprovalToken == "":
		d.Verdict = Blocked
	default:
		claims, err := approval.Verify(in.Secret, in.ApprovalToken, in.Line, in.User, in.AllowSelf, in.Now)
		if err != nil {
			d.Verdict = Blocked
			d.ApprovalErr = err.Error()
		} else {
			d.Verdict = Approved
			d.Approval = &claims
		}
	}
	return d
}

func scan(in Input, line, cwd string, where env.Result, remote string, depth int) []Finding {
	var out []Finding
	for _, c := range shell.Parse(line) {
		// Track `cd` so relative paths resolve the way the shell would.
		if c.Name() == "cd" && len(c.Argv) > 1 {
			cwd = resolve(cwd, c.Argv[1])
			continue
		}
		ctx := rules.Context{Cwd: cwd, ProtectedPaths: in.ProtectedPaths, CriticalDirs: in.CriticalDirs, FullLine: line}
		for _, r := range in.Rules {
			if detail, ok := r.Match(c, ctx); ok {
				out = append(out, Finding{
					Hit:        rules.Hit{RuleID: r.ID, Detail: detail, Command: c.Raw},
					Production: where.Production,
					Reasons:    where.Reasons,
					RemoteHost: remote,
				})
			}
		}
		if depth >= maxDepth {
			continue
		}
		if n, ok := shell.Unwrap(c); ok {
			inner, innerCwd, innerRemote := where, cwd, remote
			if n.Host != "" {
				// Over ssh the remote host decides; the local cwd is meaningless.
				innerCwd, innerRemote = "", n.Host
				inner = env.Result{Production: where.Production, Reasons: append([]string{}, where.Reasons...)}
				if why, prod := in.Detector.IsProductionHost(n.Host); prod {
					inner.Production = true
					inner.Reasons = append(inner.Reasons, why)
				}
			}
			out = append(out, scan(in, n.Line, innerCwd, inner, innerRemote, depth+1)...)
		}
	}
	return out
}

func resolve(cwd, dir string) string {
	if len(dir) > 0 && dir[0] == '/' {
		return dir
	}
	if cwd == "" || dir == "-" || (len(dir) > 0 && dir[0] == '~') {
		return ""
	}
	return cwd + "/" + dir
}
