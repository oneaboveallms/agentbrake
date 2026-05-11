# AgentBrake — zsh integration
# Source this file in your ~/.zshrc:
#   source <(agentbrake init zsh)
# Or add the contents to your ~/.zshrc directly.

# Skip if not interactive or agentbrake not installed
[[ $- != *i* ]] && return
command -v agentbrake >/dev/null 2>&1 || return

# Track whether the last preexec blocked a command
__agentbrake_blocked=0

# preexec runs BEFORE every command — perfect for interception
__agentbrake_preexec() {
  local cmd="$1"

  # Skip empty commands and our own check command (avoid recursion)
  [[ -z "$cmd" ]] && return 0
  [[ "$cmd" == agentbrake* ]] && return 0

  # Run the check. Exit codes:
  #   0 — safe OR approved
  #   1,2 — destructive and denied
  #   3 — timeout (treated as denied)
  if ! agentbrake check "$cmd" </dev/tty; then
    __agentbrake_blocked=1
    # Reset the prompt — command is "consumed" but not executed
    # The actual command gets blocked by overriding BUFFER below
    return 1
  fi

  __agentbrake_blocked=0
  return 0
}

# Hook into zsh's preexec
autoload -Uz add-zsh-hook
add-zsh-hook preexec __agentbrake_preexec

# Override the command if blocked — zsh-specific trick
__agentbrake_zshaddhistory() {
  if [[ $__agentbrake_blocked -eq 1 ]]; then
    __agentbrake_blocked=0
    # Return 1 to skip history AND prevent execution
    return 1
  fi
  return 0
}
add-zsh-hook zshaddhistory __agentbrake_zshaddhistory

echo "✓ AgentBrake active for zsh"