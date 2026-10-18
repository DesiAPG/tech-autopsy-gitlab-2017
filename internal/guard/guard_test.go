package guard

import (
	"testing"
	"time"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/approval"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/env"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/rules"
)

var now = time.Date(2017, 1, 31, 23, 0, 0, 0, time.UTC)

func input(t *testing.T, line, host string) Input {
	t.Helper()
	det, err := env.NewDetector([]string{"db1", "db2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Line:           line,
		Cwd:            "/home/yp",
		Signals:        env.Signals{Hostname: host},
		Detector:       det,
		Rules:          rules.All(),
		ProtectedPaths: rules.DefaultProtectedPaths,
		CriticalDirs:   rules.DefaultCriticalDirs,
		Secret:         "secret",
		User:           "yp",
		Now:            now,
	}
}

// The 2017-01-31 scenario: the engineer believed he was on db2, was on db1.
// Both are production, so the command is blocked either way.
func TestGitLabIncidentIsBlocked(t *testing.T) {
	for _, host := range []string{"db1.cluster.gitlab.com", "db2.cluster.gitlab.com"} {
		d := Evaluate(input(t, "sudo rm -rf /var/opt/gitlab/postgresql/data", host))
		if d.Verdict != Blocked {
			t.Errorf("on %s: verdict = %s, want blocked", host, d.Verdict)
		}
	}
}

func TestRelativePathAfterCd(t *testing.T) {
	d := Evaluate(input(t, "cd /var/opt/gitlab/postgresql && rm -rf data", "db1"))
	if d.Verdict != Blocked {
		t.Fatalf("verdict = %s, want blocked", d.Verdict)
	}
}

func TestSSHToProductionHost(t *testing.T) {
	d := Evaluate(input(t, "ssh yp@db1.cluster.gitlab.com 'sudo rm -rf /var/opt/gitlab/postgresql/data'", "laptop"))
	if d.Verdict != Blocked {
		t.Fatalf("verdict = %s, want blocked", d.Verdict)
	}
	if d.Findings[0].RemoteHost != "db1.cluster.gitlab.com" {
		t.Errorf("remote host = %q", d.Findings[0].RemoteHost)
	}
	if d.Production {
		t.Error("the laptop itself is not production")
	}
}

func TestNonProductionOnlyWarns(t *testing.T) {
	d := Evaluate(input(t, "rm -rf /var/lib/postgresql/16/main", "laptop"))
	if d.Verdict != Warned || !d.Run() {
		t.Fatalf("verdict = %s, want warned", d.Verdict)
	}
}

func TestHarmlessInProduction(t *testing.T) {
	d := Evaluate(input(t, "tail -f /var/log/gitlab/postgresql/current", "db1"))
	if d.Verdict != Allowed {
		t.Fatalf("verdict = %s, want allowed", d.Verdict)
	}
}

func TestApprovedBySecondEngineer(t *testing.T) {
	line := "sudo rm -rf /var/opt/gitlab/postgresql/data"
	tok, err := approval.Sign("secret", line, "alice", 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	in := input(t, line, "db2")
	in.ApprovalToken = tok
	d := Evaluate(in)
	if d.Verdict != Approved || d.Approval.Approver != "alice" {
		t.Fatalf("verdict = %s (%s), want approved by alice", d.Verdict, d.ApprovalErr)
	}

	// The same token does not cover a different command.
	in = input(t, "sudo rm -rf /var/opt/gitlab", "db2")
	in.ApprovalToken = tok
	if d := Evaluate(in); d.Verdict != Blocked || d.ApprovalErr == "" {
		t.Fatalf("reused token: verdict = %s", d.Verdict)
	}
}

func TestNestedShell(t *testing.T) {
	d := Evaluate(input(t, `bash -c "kubectl delete ns payments"`, "bastion-prod"))
	if d.Verdict != Blocked {
		t.Fatalf("verdict = %s, want blocked", d.Verdict)
	}
}
