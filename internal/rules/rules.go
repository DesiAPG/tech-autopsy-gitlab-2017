// Package rules holds the catalogue of destructive-command detectors.
//
// A rule looks at one simple command (already unwrapped from sudo/env/…) and
// reports whether it destroys data or infrastructure. Rules never decide
// whether to block: that depends on the environment and is the guard's job.
package rules

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DesiAPG/tech-autopsy-gitlab-2017/internal/shell"
)

// Context is what a rule may consult besides the command itself.
type Context struct {
	Cwd            string   // working directory, to resolve relative paths
	ProtectedPaths []string // data directories: the directory and anything inside it
	CriticalDirs   []string // system directories: only the directory itself
	FullLine       string   // the whole command line (for pipelines like `echo … | psql`)
}

// Rule detects one family of destructive commands.
type Rule struct {
	ID          string
	Description string
	Match       func(c shell.Command, ctx Context) (detail string, ok bool)
}

// Hit is a rule that matched a command.
type Hit struct {
	RuleID  string `json:"rule"`
	Detail  string `json:"detail"`
	Command string `json:"command"`
}

// DefaultProtectedPaths are data directories: deleting them or anything
// inside them recursively is never routine on a server.
var DefaultProtectedPaths = []string{
	"/var/opt/gitlab",
	"/var/lib/postgresql",
	"/var/lib/pgsql",
	"/var/lib/mysql",
	"/var/lib/mongodb",
	"/var/lib/redis",
	"/var/lib/etcd",
	"/var/lib/docker",
	"/var/lib/kubelet",
	"/data",
}

// DefaultCriticalDirs are system directories that must never be removed as a
// whole (their contents can still be managed normally).
var DefaultCriticalDirs = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/mnt",
	"/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
	"/var/lib", "/var/opt", "/var/log",
}

// All returns the built-in rules in evaluation order.
func All() []Rule {
	return []Rule{
		{"rm-recursive-protected", "rm recursivo sobre una ruta protegida (datos o sistema)", matchRm},
		{"find-delete-protected", "find -delete / -exec rm sobre una ruta protegida", matchFindDelete},
		{"disk-wipe", "escritura directa o formateo de un disco (dd, mkfs, wipefs, shred)", matchDiskWipe},
		{"sql-destructive", "SQL destructivo: DROP, TRUNCATE o DELETE sin WHERE", matchSQL},
		{"db-drop-tool", "herramienta que elimina una base de datos (dropdb, FLUSHALL, dropDatabase)", matchDBTool},
		{"kubectl-delete-stateful", "kubectl delete de namespaces, volúmenes, statefulsets o --all", matchKubectl},
		{"helm-uninstall", "helm uninstall / delete de un release", matchHelm},
		{"terraform-destroy", "terraform / tofu / terragrunt destroy", matchTerraform},
		{"cloud-delete", "borrado de recursos cloud (RDS, S3, EC2, DynamoDB, Cloud SQL…)", matchCloud},
		{"docker-volume-delete", "borrado o prune de volúmenes Docker", matchDocker},
	}
}

// ─── filesystem ──────────────────────────────────────────────────────────────

func matchRm(c shell.Command, ctx Context) (string, bool) {
	if c.Name() != "rm" {
		return "", false
	}
	recursive := false
	var targets []string
	endOfFlags := false
	for _, a := range c.Argv[1:] {
		switch {
		case isRedirect(a):
			continue
		case !endOfFlags && a == "--":
			endOfFlags = true
		case !endOfFlags && (a == "--recursive" || a == "-r" || a == "-R"):
			recursive = true
		case !endOfFlags && strings.HasPrefix(a, "--"):
			// --force, --no-preserve-root, …
		case !endOfFlags && strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.ContainsAny(a[1:], "rR") {
				recursive = true
			}
		default:
			targets = append(targets, a)
		}
	}
	if !recursive {
		return "", false
	}
	for _, t := range targets {
		if p, ok := protected(t, ctx); ok {
			return "rm -r sobre " + p, true
		}
	}
	return "", false
}

func matchFindDelete(c shell.Command, ctx Context) (string, bool) {
	if c.Name() != "find" || len(c.Argv) < 2 {
		return "", false
	}
	destructive := false
	for i, a := range c.Argv {
		if a == "-delete" {
			destructive = true
		}
		if (a == "-exec" || a == "-execdir") && i+1 < len(c.Argv) && path.Base(c.Argv[i+1]) == "rm" {
			destructive = true
		}
	}
	if !destructive {
		return "", false
	}
	for _, a := range c.Argv[1:] {
		if strings.HasPrefix(a, "-") {
			break
		}
		if p, ok := protected(a, ctx); ok {
			return "find -delete sobre " + p, true
		}
	}
	return "", false
}

func matchDiskWipe(c shell.Command, _ Context) (string, bool) {
	name := c.Name()
	switch {
	case strings.HasPrefix(name, "mkfs"):
		return name + " formatea un dispositivo", true
	case name == "wipefs" || name == "blkdiscard":
		return name + " borra un dispositivo", true
	case name == "shred":
		for _, a := range c.Argv[1:] {
			if strings.HasPrefix(a, "/dev/") {
				return "shred sobre " + a, true
			}
		}
	case name == "dd":
		for _, a := range c.Argv[1:] {
			if strings.HasPrefix(a, "of=/dev/") && !strings.HasPrefix(a, "of=/dev/null") {
				return "dd escribe directamente en " + strings.TrimPrefix(a, "of="), true
			}
		}
	}
	return "", false
}

// ─── databases ───────────────────────────────────────────────────────────────

var sqlClients = map[string]bool{
	"psql": true, "gitlab-psql": true, "mysql": true, "mariadb": true,
	"sqlcmd": true, "sqlite3": true, "clickhouse-client": true, "cqlsh": true,
}

var (
	reDrop     = regexp.MustCompile(`(?i)\bdrop\s+(database|schema|table)\b`)
	reTruncate = regexp.MustCompile(`(?i)\btruncate\s+(table\s+)?\w`)
	// DELETE FROM x followed by end of statement, without a WHERE clause.
	reDeleteAll = regexp.MustCompile(`(?i)\bdelete\s+from\s+[\w."]+\s*(;|'|"|$)`)
)

func matchSQL(c shell.Command, ctx Context) (string, bool) {
	if !sqlClients[c.Name()] {
		return "", false
	}
	// The statement can be in -c/-e, in a heredoc or piped in, so look at the
	// whole line once a SQL client is involved.
	text := ctx.FullLine
	if text == "" {
		text = c.Raw
	}
	switch {
	case reDrop.MatchString(text):
		return "SQL " + strings.ToUpper(reDrop.FindString(text)), true
	case reTruncate.MatchString(text):
		return "SQL TRUNCATE", true
	case reDeleteAll.MatchString(text):
		return "SQL DELETE sin WHERE", true
	}
	return "", false
}

var reFlush = regexp.MustCompile(`(?i)\bflush(all|db)\b`)

func matchDBTool(c shell.Command, _ Context) (string, bool) {
	switch c.Name() {
	case "dropdb":
		return "dropdb elimina una base de datos", true
	case "redis-cli":
		if reFlush.MatchString(strings.Join(c.Argv[1:], " ")) {
			return "redis " + strings.ToUpper(reFlush.FindString(strings.Join(c.Argv[1:], " "))), true
		}
	case "mongo", "mongosh":
		if strings.Contains(strings.Join(c.Argv[1:], " "), "dropDatabase") {
			return "mongo dropDatabase()", true
		}
	}
	return "", false
}

// ─── orchestration / IaC ─────────────────────────────────────────────────────

var kubeStateful = map[string]bool{
	"ns": true, "namespace": true, "namespaces": true,
	"pv": true, "persistentvolume": true, "persistentvolumes": true,
	"pvc": true, "persistentvolumeclaim": true, "persistentvolumeclaims": true,
	"sts": true, "statefulset": true, "statefulsets": true,
	"crd": true, "crds": true, "customresourcedefinition": true, "customresourcedefinitions": true,
	"all": true,
}

func matchKubectl(c shell.Command, _ Context) (string, bool) {
	if c.Name() != "kubectl" && c.Name() != "oc" {
		return "", false
	}
	args := c.Argv[1:]
	idx := indexOf(args, "delete")
	if idx < 0 {
		return "", false
	}
	for _, a := range args[idx+1:] {
		if a == "--all" || a == "-A" || a == "--all-namespaces" {
			return "kubectl delete " + a, true
		}
		res := strings.ToLower(a)
		if i := strings.IndexByte(res, '/'); i > 0 {
			res = res[:i]
		}
		for _, r := range strings.Split(res, ",") {
			if kubeStateful[r] {
				return "kubectl delete " + r, true
			}
		}
	}
	return "", false
}

func matchHelm(c shell.Command, _ Context) (string, bool) {
	if c.Name() != "helm" || len(c.Argv) < 2 {
		return "", false
	}
	if sub := c.Argv[1]; sub == "uninstall" || sub == "delete" || sub == "del" || sub == "un" {
		return "helm " + sub, true
	}
	return "", false
}

func matchTerraform(c shell.Command, _ Context) (string, bool) {
	switch c.Name() {
	case "terraform", "tofu", "terragrunt":
	default:
		return "", false
	}
	args := c.Argv[1:]
	if indexOf(args, "destroy") >= 0 {
		return c.Name() + " destroy", true
	}
	if indexOf(args, "apply") >= 0 && (indexOf(args, "-destroy") >= 0 || indexOf(args, "--destroy") >= 0) {
		return c.Name() + " apply -destroy", true
	}
	return "", false
}

// cloudOps maps "<cli> <service> <operation>" prefixes to destructive operations.
var cloudOps = []struct {
	cli, service, op string
	needsFlag        string // optional flag that makes it destructive
}{
	{"aws", "rds", "delete-db-instance", ""},
	{"aws", "rds", "delete-db-cluster", ""},
	{"aws", "s3", "rb", ""},
	{"aws", "s3", "rm", "--recursive"},
	{"aws", "s3api", "delete-bucket", ""},
	{"aws", "ec2", "terminate-instances", ""},
	{"aws", "ec2", "delete-volume", ""},
	{"aws", "ec2", "delete-snapshot", ""},
	{"aws", "dynamodb", "delete-table", ""},
	{"aws", "cloudformation", "delete-stack", ""},
	{"aws", "eks", "delete-cluster", ""},
	{"aws", "elasticache", "delete-replication-group", ""},
	{"aws", "elasticache", "delete-cache-cluster", ""},
	{"aws", "backup", "delete-recovery-point", ""},
	{"gcloud", "sql", "instances", "delete"},
	{"gcloud", "compute", "instances", "delete"},
	{"gcloud", "compute", "disks", "delete"},
	{"gcloud", "container", "clusters", "delete"},
	{"az", "group", "delete", ""},
	{"az", "sql", "db", "delete"},
}

func matchCloud(c shell.Command, _ Context) (string, bool) {
	var pos []string // positional words, flags skipped
	for _, a := range c.Argv[1:] {
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
		}
	}
	for _, o := range cloudOps {
		if c.Name() != o.cli || len(pos) < 2 || pos[0] != o.service || pos[1] != o.op {
			continue
		}
		if o.needsFlag == "" {
			return o.cli + " " + o.service + " " + o.op, true
		}
		// gcloud/az style: the 4th word is the verb; aws style: a flag.
		if (len(pos) > 2 && pos[2] == o.needsFlag) || indexOf(c.Argv, o.needsFlag) >= 0 {
			return o.cli + " " + o.service + " " + o.op + " " + o.needsFlag, true
		}
	}
	return "", false
}

func matchDocker(c shell.Command, _ Context) (string, bool) {
	if c.Name() != "docker" && c.Name() != "podman" {
		return "", false
	}
	args := c.Argv[1:]
	if len(args) >= 2 && args[0] == "volume" && (args[1] == "rm" || args[1] == "prune" || args[1] == "remove") {
		return c.Name() + " volume " + args[1], true
	}
	if len(args) >= 2 && args[0] == "system" && args[1] == "prune" && indexOf(args, "--volumes") >= 0 {
		return c.Name() + " system prune --volumes", true
	}
	return "", false
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func isRedirect(w string) bool {
	w = strings.TrimLeft(w, "0123456789")
	return strings.HasPrefix(w, ">") || strings.HasPrefix(w, "<")
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// protected resolves target against the working directory and reports
// whether it is, or lies inside, a protected path.
func protected(target string, ctx Context) (string, bool) {
	if target == "" {
		return "", false
	}
	t := target
	if strings.HasPrefix(t, "~") {
		return "", false // home-relative paths are the user's own
	}
	if !filepath.IsAbs(t) {
		if ctx.Cwd == "" {
			return "", false
		}
		t = filepath.Join(ctx.Cwd, t)
	}
	t = filepath.Clean(t)
	// "/*" and "/." both mean the root.
	if t == "/" || strings.TrimRight(t, "/*.") == "" {
		return "/", true
	}
	for _, p := range ctx.ProtectedPaths {
		p = filepath.Clean(p)
		if p != "/" && (t == p || strings.HasPrefix(t, p+"/")) {
			return t, true
		}
	}
	for _, d := range ctx.CriticalDirs {
		// "/usr/*" empties the directory: as bad as removing it.
		if t == filepath.Clean(d) || t == filepath.Join(filepath.Clean(d), "*") {
			return t, true
		}
	}
	return "", false
}
