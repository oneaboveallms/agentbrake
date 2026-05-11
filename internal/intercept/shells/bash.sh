# AgentBrake — bash integration
# Source this file in your ~/.bashrc:
#   source <(agentbrake init bash)

# Skip if not interactive or agentbrake not installed
[[ $- != *i* ]] && return
command -v agentbrake >/dev/null 2>&1 || return

# Honor emergency disable env var — checked at hook fire time
__agentbrake_should_skip() {
  local cmd="$1"

  # Empty
  [[ -z "$cmd" ]] && return 0

  # Emergency bypass — env var disables hook entirely
  [[ "$AGENTBRAKE_DISABLE" == "1" ]] && return 0

  # Skip the tool itself — match agentbrake binary by basename,
  # regardless of full path (/usr/local/bin/agentbrake, ./agentbrake, etc.)
  local first_word="${cmd%% *}"
  local basename="${first_word##*/}"
  [[ "$basename" == "agentbrake" ]] && return 0

  # Skip our own internal helpers
  [[ "$cmd" == __agentbrake* ]] && return 0

  # Skip if it's the prompt command (cosmetic shell internals)
  [[ "$cmd" == "$PROMPT_COMMAND" ]] && return 0

  # Skip env var assignments that don't call commands
  # e.g. "export FOO=1" or "FOO=bar" alone
  [[ "$cmd" =~ ^(export[[:space:]]+)?[A-Z_][A-Z0-9_]*= ]] && {
    # If there's a command AFTER the var assignment, we still want to check it.
    # Pattern: "FOO=1 actual_command args"
    # If line has space after the assignment and a non-= word follows, check that.
    if [[ "$cmd" =~ ^([A-Z_][A-Z0-9_]*=[^[:space:]]+[[:space:]]+)+(.+)$ ]]; then
      local rest="${BASH_REMATCH[2]}"
      # Recursively check the actual command part
      __agentbrake_preexec_check "$rest"
      return $?
    fi
    # Pure assignment, no command — skip
    return 0
  }

  return 1
}

# Inner check function — takes a command string, returns 0 if safe, 1 if blocked
__agentbrake_preexec_check() {
  local cmd="$1"
  if ! agentbrake check "$cmd" </dev/tty; then
    echo "✗ Command blocked by AgentBrake" >&2
    return 1
  fi
  return 0
}

# Main preexec — bash DEBUG trap entry point
__agentbrake_preexec() {
  local cmd="$BASH_COMMAND"

  # Skip checks for various non-applicable commands
  if __agentbrake_should_skip "$cmd"; then
    return 0
  fi

  __agentbrake_preexec_check "$cmd"
  return $?
}

# Enable extdebug — lets DEBUG trap skip commands by returning non-zero
shopt -s extdebug
trap '__agentbrake_preexec' DEBUG

echo "✓ AgentBrake active for bash"