# AgentBrake — bash integration
# Source this file in your ~/.bashrc:
#   source <(agentbrake init bash)
# Or add the contents to your ~/.bashrc directly.

# Skip if not interactive or agentbrake not installed
[[ $- != *i* ]] && return
command -v agentbrake >/dev/null 2>&1 || return

# Bash uses DEBUG trap — runs before every command
__agentbrake_preexec() {
  # $BASH_COMMAND holds the command about to run
  local cmd="$BASH_COMMAND"

  # Skip empty / agentbrake itself / shell internals
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == agentbrake* ]] && return 0
  [[ "$cmd" == __agentbrake* ]] && return 0
  [[ "$cmd" == "$PROMPT_COMMAND" ]] && return 0

  # Run the check
  if ! agentbrake check "$cmd" </dev/tty; then
    # Block by killing the current command via SIGINT to subshell
    echo "✗ Command blocked by AgentBrake" >&2
    # Returning non-zero from DEBUG trap with extdebug skips the command
    return 1
  fi
  return 0
}

# Enable the extdebug feature (lets us skip commands by returning non-zero)
shopt -s extdebug
trap '__agentbrake_preexec' DEBUG

echo "✓ AgentBrake active for bash"