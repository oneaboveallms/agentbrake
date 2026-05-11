# AgentBrake — zsh integration

[[ $- != *i* ]] && return
command -v agentbrake >/dev/null 2>&1 || return

__agentbrake_blocked=0

__agentbrake_preexec() {
  local cmd="$1"

  # Empty
  [[ -z "$cmd" ]] && return 0

  # Emergency bypass
  [[ "$AGENTBRAKE_DISABLE" == "1" ]] && return 0

  # Skip agentbrake binary by basename (any path)
  local first_word="${cmd%% *}"
  local basename="${first_word##*/}"
  [[ "$basename" == "agentbrake" ]] && return 0

  # Skip pure env var assignments
  [[ "$cmd" =~ ^(export[[:space:]]+)?[A-Z_][A-Z0-9_]*=[^[:space:]]*$ ]] && return 0

  if ! agentbrake check "$cmd" </dev/tty; then
    __agentbrake_blocked=1
    return 1
  fi

  __agentbrake_blocked=0
  return 0
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec __agentbrake_preexec

__agentbrake_zshaddhistory() {
  if [[ $__agentbrake_blocked -eq 1 ]]; then
    __agentbrake_blocked=0
    return 1
  fi
  return 0
}
add-zsh-hook zshaddhistory __agentbrake_zshaddhistory

echo "✓ AgentBrake active for zsh"