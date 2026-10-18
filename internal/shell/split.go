// Package shell splits a shell command line into simple commands and argv
// tokens. It is a deliberately small POSIX-ish lexer: enough to see through
// quoting, command lists, pipelines and the usual wrappers (sudo, env, nohup…)
// without executing anything.
package shell

import (
	"path"
	"strings"
)

// Command is one simple command of a command line.
type Command struct {
	Raw  string   // the segment's source text, trimmed
	Argv []string // tokens after quote removal, wrappers stripped
}

// Name returns the base name of the program, or "" for an empty command.
func (c Command) Name() string {
	if len(c.Argv) == 0 {
		return ""
	}
	return path.Base(c.Argv[0])
}

// Parse splits line on ; & && || | and newlines (outside quotes) and returns
// each non-empty simple command with its wrappers stripped.
func Parse(line string) []Command {
	var out []Command
	for _, seg := range segments(line) {
		argv := StripWrappers(Tokenize(seg))
		if len(argv) == 0 {
			continue
		}
		out = append(out, Command{Raw: strings.TrimSpace(seg), Argv: argv})
	}
	return out
}

// segments splits a command line on list and pipeline operators that appear
// outside of quotes. Subshell parentheses and braces are treated as separators
// too, so `(cd /x && rm -rf y)` still yields `rm -rf y`.
func segments(line string) []string {
	var (
		out      []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
	)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			cur.WriteRune(r)
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteRune(r)
		case r == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteRune(r)
		case !inSingle && !inDouble && strings.ContainsRune(";&|\n(){}`", r):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// Tokenize splits one simple command into words, removing quotes and
// backslash escapes. Redirections stay attached to their words.
func Tokenize(s string) []string {
	var (
		out      []string
		cur      strings.Builder
		inWord   bool
		inSingle bool
		inDouble bool
		escaped  bool
	)
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
			inWord = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			inWord = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			inWord = true
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// sudo options that consume the following word.
var sudoArgFlags = map[string]bool{
	"-u": true, "-g": true, "-h": true, "-p": true, "-C": true,
	"-c": true, "-r": true, "-t": true, "-D": true, "-U": true,
}

// StripWrappers removes leading variable assignments and transparent
// wrappers (sudo, env, nohup, time, nice, command, exec, stdbuf, timeout) so
// the real program is argv[0].
func StripWrappers(argv []string) []string {
	for len(argv) > 0 {
		head := argv[0]
		switch {
		case isAssignment(head):
			argv = argv[1:]
		case path.Base(head) == "sudo" || path.Base(head) == "doas":
			argv = argv[1:]
			for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				if argv[0] == "--" {
					argv = argv[1:]
					break
				}
				if sudoArgFlags[argv[0]] && len(argv) > 1 {
					argv = argv[2:]
				} else {
					argv = argv[1:]
				}
			}
		case path.Base(head) == "env":
			argv = argv[1:]
			for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || isAssignment(argv[0])) {
				argv = argv[1:]
			}
		case path.Base(head) == "nice":
			argv = argv[1:]
			if len(argv) > 1 && argv[0] == "-n" {
				argv = argv[2:]
			} else if len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				argv = argv[1:]
			}
		case path.Base(head) == "timeout":
			argv = argv[1:]
			for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				if (argv[0] == "-s" || argv[0] == "-k" || argv[0] == "--signal" || argv[0] == "--kill-after") && len(argv) > 1 {
					argv = argv[2:]
				} else {
					argv = argv[1:]
				}
			}
			if len(argv) > 0 { // the duration
				argv = argv[1:]
			}
		case path.Base(head) == "stdbuf":
			argv = argv[1:]
			for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				argv = argv[1:]
			}
		case head == "nohup" || head == "time" || head == "command" || head == "exec" || head == "builtin":
			argv = argv[1:]
		default:
			return argv
		}
	}
	return argv
}

func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j, r := range w[:i] {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || j > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// ssh options that consume the following word.
var sshArgFlags = map[string]bool{
	"-b": true, "-c": true, "-D": true, "-E": true, "-e": true, "-F": true,
	"-I": true, "-i": true, "-J": true, "-L": true, "-l": true, "-m": true,
	"-O": true, "-o": true, "-p": true, "-Q": true, "-R": true, "-S": true,
	"-W": true, "-w": true, "-B": true,
}

// Nested is a command that runs another command line, possibly elsewhere.
type Nested struct {
	Host string // remote host for ssh, "" for a local shell
	Line string // the inner command line
}

// Unwrap detects `bash -c '…'`, `sh -c '…'` and `ssh host '…'` and returns
// the inner command line so it can be evaluated too.
func Unwrap(c Command) (Nested, bool) {
	switch c.Name() {
	case "bash", "sh", "zsh", "dash", "ksh":
		for i := 1; i < len(c.Argv)-1; i++ {
			if c.Argv[i] == "-c" || (strings.HasPrefix(c.Argv[i], "-") && strings.HasSuffix(c.Argv[i], "c") && !strings.HasPrefix(c.Argv[i], "--")) {
				return Nested{Line: c.Argv[i+1]}, true
			}
		}
	case "ssh":
		args := c.Argv[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			if args[0] == "--" {
				args = args[1:]
				break
			}
			if sshArgFlags[args[0]] && len(args) > 1 {
				args = args[2:]
			} else {
				args = args[1:]
			}
		}
		if len(args) < 2 {
			return Nested{}, false
		}
		host := args[0]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		return Nested{Host: host, Line: strings.Join(args[1:], " ")}, true
	}
	return Nested{}, false
}
