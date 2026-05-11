# AgentBrake — fish integration
# Source this file in your ~/.config/fish/config.fish:
#   agentbrake init fish | source
# Or save it as a function.

if not status is-interactive
    exit
end

if not type -q agentbrake
    exit
end

function __agentbrake_preexec --on-event fish_preexec
    set cmd $argv[1]

    # Skip empty / agentbrake itself
    if test -z "$cmd"
        return 0
    end
    if string match -q "agentbrake*" -- "$cmd"
        return 0
    end

    # Run the check
    if not agentbrake check "$cmd" </dev/tty
        # Cancel the command — fish doesn't have a clean way to skip,
        # so we abort with commandline -f
        commandline -f kill-whole-line
        commandline -f repaint
        return 1
    end
    return 0
end

echo "✓ AgentBrake active for fish"