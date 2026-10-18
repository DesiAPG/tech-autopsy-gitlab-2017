package main

import (
	"fmt"
	"io"
)

// bashHook uses extdebug: when a DEBUG trap returns non-zero, bash skips the
// command it was about to run. Every simple command — including each stage
// of a pipeline — passes through go-guard first.
const bashHook = `# go-guard: bloquea comandos destructivos en producción
__go_guard_debug() {
  [[ -n "${COMP_LINE-}" ]] && return 0                 # tab completion
  case "$BASH_COMMAND" in __go_guard*|go-guard*) return 0 ;; esac
  command go-guard check --quiet -- "$BASH_COMMAND"
}
shopt -s extdebug
trap '__go_guard_debug' DEBUG
`

// zshHook wraps accept-line: the whole buffer is checked before zsh runs it.
// A blocked line is kept in history (so it can be approved and re-run) and
// the prompt is returned empty.
const zshHook = `# go-guard: bloquea comandos destructivos en producción
__go_guard_accept_line() {
  if [[ -n "$BUFFER" ]]; then
    zle -I
    if ! command go-guard check --quiet -- "$BUFFER"; then
      print -s -- "$BUFFER"
      BUFFER=""
    fi
  fi
  zle .accept-line
}
zle -N accept-line __go_guard_accept_line
`

func cmdHook(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "uso: go-guard hook bash|zsh")
		return exitError
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(stdout, bashHook)
	case "zsh":
		fmt.Fprint(stdout, zshHook)
	default:
		fmt.Fprintf(stderr, "go-guard: shell no soportada %q (bash|zsh)\n", args[0])
		return exitError
	}
	return exitOK
}
