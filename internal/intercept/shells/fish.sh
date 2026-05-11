# AgentBrake — fish integration

if not status is-interactive
    exit
end

if not type -q agentbrake
    exit
end

function __agentbrake_preexec --on-event fish_preexec
    set cmd $argv[1]

    # Empty
    if test -z "$cmd"
        return 0
    end

    # Emergency bypass
    if test "$AGENTBRAKE_DISABLE" = "1"
        return 0
    end

    # Skip agentbrake binary by basename
    set first_word (string split " " -- $cmd)[1]
    set bname (string split "/" -- $first_word)[-1]
    if test "$bname" = "agentbrake"
        return 0
    end

    if not agentbrake check "$cmd" </dev/tty
        commandline -f kill-whole-line
        commandline -f repaint
        return 1
    end
    return 0
end

echo "✓ AgentBrake active for fish"