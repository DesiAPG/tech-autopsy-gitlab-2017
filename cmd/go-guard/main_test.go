package main

import (
	"bytes"
	"strings"
	"testing"
)

func cli(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("GO_GUARD_AUDIT_LOG", "off")
	t.Setenv("GO_GUARD_CONFIG", "/nonexistent/config.json")
	t.Setenv("GO_GUARD_APPROVAL", "")
	t.Setenv("KUBECONFIG", "/nonexistent")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	for k, v := range env {
		t.Setenv(k, v)
	}
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheckBlocksInProduction(t *testing.T) {
	code, _, stderr := cli(t, map[string]string{"GO_GUARD_ENV": "prod"},
		"check", "--", "sudo", "rm", "-rf", "/var/opt/gitlab/postgresql/data")
	if code != exitBlocked {
		t.Fatalf("exit = %d, want %d", code, exitBlocked)
	}
	if !strings.Contains(stderr, "BLOQUEADO") || !strings.Contains(stderr, "go-guard approve --") {
		t.Errorf("stderr missing block report:\n%s", stderr)
	}
}

func TestCheckAllowsOutsideProduction(t *testing.T) {
	code, _, _ := cli(t, map[string]string{"GO_GUARD_ENV": "dev"}, "check", "--", "rm -rf /var/lib/postgresql")
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestApproveThenCheck(t *testing.T) {
	cmd := "sudo rm -rf /var/opt/gitlab/postgresql/data"
	code, token, _ := cli(t, map[string]string{"GO_GUARD_SECRET": "s"}, "approve", "--by", "alice", "--", cmd)
	if code != exitOK || !strings.HasPrefix(token, "gg1.") {
		t.Fatalf("approve: exit %d, token %q", code, token)
	}
	code, _, stderr := cli(t, map[string]string{
		"GO_GUARD_ENV": "prod", "GO_GUARD_SECRET": "s", "SUDO_USER": "bob",
		"GO_GUARD_APPROVAL": strings.TrimSpace(token),
	}, "check", "--", cmd)
	if code != exitOK || !strings.Contains(stderr, "APROBADO") {
		t.Fatalf("approved check: exit %d\n%s", code, stderr)
	}
}

func TestJSONOutput(t *testing.T) {
	_, stdout, _ := cli(t, map[string]string{"GO_GUARD_ENV": "prod"}, "check", "--json", "--", `psql -c "DROP DATABASE app"`)
	if !strings.Contains(stdout, `"verdict": "blocked"`) || !strings.Contains(stdout, "sql-destructive") {
		t.Errorf("unexpected JSON:\n%s", stdout)
	}
}

func TestRunExecutesAllowedCommand(t *testing.T) {
	code, _, _ := cli(t, map[string]string{"GO_GUARD_ENV": "prod"}, "run", "--", "true")
	if code != exitOK {
		t.Fatalf("run true: exit %d", code)
	}
	code, _, _ = cli(t, map[string]string{"GO_GUARD_ENV": "prod"}, "run", "--", "false")
	if code != 1 {
		t.Fatalf("run false: exit %d, want 1", code)
	}
}

func TestHookAndUsage(t *testing.T) {
	if code, out, _ := cli(t, nil, "hook", "bash"); code != exitOK || !strings.Contains(out, "extdebug") {
		t.Errorf("bash hook: %d %q", code, out)
	}
	if code, out, _ := cli(t, nil, "hook", "zsh"); code != exitOK || !strings.Contains(out, "accept-line") {
		t.Errorf("zsh hook: %d %q", code, out)
	}
	if code, _, _ := cli(t, nil, "hook", "fish"); code != exitError {
		t.Error("unsupported shell must fail")
	}
	if code, _, _ := cli(t, nil, "nope"); code != exitError {
		t.Error("unknown subcommand must fail")
	}
}

func TestQuote(t *testing.T) {
	if got := commandLine([]string{"--", "psql", "-c", "DROP DATABASE x"}); got != `psql -c 'DROP DATABASE x'` {
		t.Errorf("commandLine = %q", got)
	}
}
