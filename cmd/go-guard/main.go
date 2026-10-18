// Command go-guard blocks destructive commands on production hosts unless a
// second engineer has approved that exact command.
//
//	go-guard check -- sudo rm -rf /var/opt/gitlab/postgresql/data
//	go-guard run   -- terraform destroy
//	eval "$(go-guard hook bash)"
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/approval"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/audit"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/config"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/env"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/guard"
	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/rules"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

// Exit codes.
const (
	exitOK      = 0
	exitError   = 2
	exitBlocked = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	switch args[0] {
	case "check":
		return cmdCheck(args[1:], stdout, stderr, false)
	case "run":
		return cmdCheck(args[1:], stdout, stderr, true)
	case "approve":
		return cmdApprove(args[1:], stdout, stderr)
	case "hook":
		return cmdHook(args[1:], stdout, stderr)
	case "rules":
		for _, r := range rules.All() {
			fmt.Fprintf(stdout, "%-26s %s\n", r.ID, r.Description)
		}
		return exitOK
	case "env":
		return cmdEnv(stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "go-guard", version)
		return exitOK
	case "help", "--help", "-h":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "go-guard: subcomando desconocido %q\n\n", args[0])
		usage(stderr)
		return exitError
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `go-guard — bloquea comandos destructivos en producción sin aprobación.

Uso:
  go-guard check [--json] -- <comando…>   evalúa un comando (exit 0 = permitido, 3 = bloqueado)
  go-guard run -- <comando…>              evalúa y, si está permitido, lo ejecuta
  go-guard approve [--by NOMBRE] [--ttl 15m] -- <comando…>
                                          firma una aprobación para ese comando exacto
  go-guard hook bash|zsh                  imprime la integración con la shell
  go-guard rules                          lista las reglas
  go-guard env                            muestra si este entorno se considera producción
  go-guard version

Variables:
  GO_GUARD_ENV        prod|staging|dev… fuerza el entorno
  GO_GUARD_APPROVAL   token emitido por 'go-guard approve'
  GO_GUARD_SECRET     secreto compartido para firmar/verificar aprobaciones
  GO_GUARD_CONFIG     ruta del config JSON (por defecto ~/.config/go-guard/config.json)
  GO_GUARD_AUDIT_LOG  ruta del log de auditoría, u "off"
`)
}

// commandLine turns the arguments after "--" into one line. A single
// argument is taken verbatim (that is how the shell hooks pass $BASH_COMMAND
// and $BUFFER); several are re-quoted.
func commandLine(args []string) string {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 1 {
		return args[0]
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = quote(a)
	}
	return strings.Join(parts, " ")
}

func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`;&|<>(){}*?[]#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func loadInput(line string) (guard.Input, config.Config, error) {
	cfg, err := config.Load(config.Path())
	if err != nil {
		return guard.Input{}, cfg, err
	}
	det, err := env.NewDetector(cfg.ProductionHosts, cfg.ProductionPatterns)
	if err != nil {
		return guard.Input{}, cfg, err
	}
	cwd, _ := os.Getwd()
	return guard.Input{
		Line:           line,
		Cwd:            cwd,
		Signals:        env.Gather(),
		Detector:       det,
		Rules:          cfg.Rules(),
		ProtectedPaths: cfg.AllProtectedPaths(),
		CriticalDirs:   rules.DefaultCriticalDirs,
		ApprovalToken:  os.Getenv("GO_GUARD_APPROVAL"),
		Secret:         os.Getenv("GO_GUARD_SECRET"),
		User:           currentUser(),
		AllowSelf:      cfg.AllowSelfApproval,
		Now:            time.Now(),
	}, cfg, nil
}

func cmdCheck(args []string, stdout, stderr io.Writer, execute bool) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "imprime la decisión en JSON")
	quiet := fs.Bool("quiet", false, "no imprime avisos para comandos permitidos")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	line := commandLine(fs.Args())
	if strings.TrimSpace(line) == "" {
		fmt.Fprintln(stderr, "go-guard: falta el comando (usa: go-guard check -- <comando…>)")
		return exitError
	}
	in, _, err := loadInput(line)
	if err != nil {
		fmt.Fprintln(stderr, "go-guard:", err)
		// Fail closed: a broken config must not silently disable the guard.
		return exitBlocked
	}
	d := guard.Evaluate(in)
	writeAudit(in, d)

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(d)
	} else {
		report(stderr, d, line, *quiet)
	}
	if !d.Run() {
		return exitBlocked
	}
	if !execute {
		return exitOK
	}
	return execLine(fs.Args(), stderr)
}

func execLine(args []string, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	var cmd *exec.Cmd
	if len(args) == 1 {
		cmd = exec.Command("/bin/sh", "-c", args[0])
	} else {
		cmd = exec.Command(args[0], args[1:]...)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintln(stderr, "go-guard:", err)
		return exitError
	}
	return exitOK
}

const (
	red   = "\x1b[1;38;2;255;51;102m"
	green = "\x1b[1;38;2;0;255;102m"
	gray  = "\x1b[38;2;139;149;165m"
	reset = "\x1b[0m"
)

func report(w io.Writer, d guard.Decision, line string, quiet bool) {
	color := os.Getenv("NO_COLOR") == "" && isTerminal(os.Stderr)
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + reset
	}
	switch d.Verdict {
	case guard.Allowed:
		return
	case guard.Warned:
		if quiet {
			return
		}
		for _, f := range d.Findings {
			fmt.Fprintf(w, "%s %s %s\n", c(gray, "go-guard ⚠"), f.Detail, c(gray, "(entorno no productivo: permitido)"))
		}
	case guard.Approved:
		fmt.Fprintf(w, "%s %s\n", c(green, "✔ APROBADO · go-guard"), c(gray, d.Approval.String()))
	case guard.Blocked:
		fmt.Fprintln(w, c(red, "× BLOQUEADO · go-guard"))
		fmt.Fprintln(w, "comando destructivo en entorno de producción")
		for _, f := range d.Findings {
			if !f.Production {
				continue
			}
			fmt.Fprintf(w, "  %s %s  %s\n", c(gray, "regla:  "), f.RuleID, c(gray, "("+f.Detail+")"))
			if f.RemoteHost != "" {
				fmt.Fprintf(w, "  %s %s\n", c(gray, "remoto: "), f.RemoteHost)
			}
			for _, r := range f.Reasons {
				fmt.Fprintf(w, "  %s %s\n", c(gray, "entorno:"), r)
			}
		}
		if d.ApprovalErr != "" {
			fmt.Fprintf(w, "  %s %s\n", c(gray, "token:  "), d.ApprovalErr)
		}
		fmt.Fprintf(w, "%s requiere aprobación de un segundo ingeniero:\n", c(gray, "→"))
		fmt.Fprintf(w, "    go-guard approve -- %s\n", line)
		fmt.Fprintf(w, "  %s\n", c(gray, "y luego: export GO_GUARD_APPROVAL=<token>"))
	}
}

func writeAudit(in guard.Input, d guard.Decision) {
	if d.Verdict == guard.Allowed {
		return // only destructive commands are worth a line
	}
	e := audit.Entry{
		Time:       in.Now.UTC(),
		User:       in.User,
		Host:       in.Signals.Hostname,
		Cwd:        in.Cwd,
		Command:    in.Line,
		Decision:   d.Verdict,
		Production: d.Production,
		Reasons:    d.EnvReasons,
	}
	for _, f := range d.Findings {
		e.Rules = append(e.Rules, f.RuleID)
	}
	if d.Approval != nil {
		e.Approver = d.Approval.Approver
	}
	if err := audit.Write(audit.Path(), e); err != nil && os.Getenv("GO_GUARD_DEBUG") != "" {
		fmt.Fprintln(os.Stderr, "go-guard: audit:", err)
	}
}

func cmdApprove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	by := fs.String("by", currentUser(), "quién aprueba")
	ttl := fs.Duration("ttl", 15*time.Minute, "validez del token")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	line := commandLine(fs.Args())
	if strings.TrimSpace(line) == "" {
		fmt.Fprintln(stderr, "go-guard: falta el comando a aprobar")
		return exitError
	}
	tok, err := approval.Sign(os.Getenv("GO_GUARD_SECRET"), line, *by, *ttl, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "go-guard:", err)
		return exitError
	}
	fmt.Fprintf(stderr, "aprobación de %s para: %s (válida %s)\n", *by, approval.Normalize(line), ttl.String())
	fmt.Fprintln(stdout, tok)
	return exitOK
}

func cmdEnv(stdout, stderr io.Writer) int {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fmt.Fprintln(stderr, "go-guard:", err)
		return exitError
	}
	det, err := env.NewDetector(cfg.ProductionHosts, cfg.ProductionPatterns)
	if err != nil {
		fmt.Fprintln(stderr, "go-guard:", err)
		return exitError
	}
	s := env.Gather()
	r := det.Detect(s)
	fmt.Fprintf(stdout, "hostname:     %s\nkube context: %s\naws profile:  %s\nGO_GUARD_ENV: %s\n", s.Hostname, s.KubeContext, s.AWSProfile, s.Explicit)
	if r.Production {
		fmt.Fprintf(stdout, "producción:   sí (%s)\n", strings.Join(r.Reasons, "; "))
	} else {
		fmt.Fprintln(stdout, "producción:   no")
	}
	return exitOK
}

func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u // the human behind sudo, not root
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
