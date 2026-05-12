package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oneaboveallms/agentbrake/internal/audit"
	"github.com/oneaboveallms/agentbrake/internal/config"
	"github.com/oneaboveallms/agentbrake/internal/intercept"
	"github.com/oneaboveallms/agentbrake/internal/patterns"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "agentbrake",
	Short: "Stops AI coding agents from running destructive commands",
	Long: `AgentBrake is a CLI guardrail that intercepts destructive 
commands (DROP TABLE, rm -rf /, terraform destroy, etc.) and 
requires explicit human approval before execution.

Built for the era of AI coding agents — Cursor, Claude Code, 
Copilot, Aider — that can accidentally delete your production.`,
	Version: version,
}

// flags
var (
	flagTimeout  time.Duration
	flagNoPrompt bool
	flagNoLog    bool
)

var checkCmd = &cobra.Command{
	Use:   "check [command]",
	Short: "Check a command and prompt for approval if destructive",
	Long: `Check analyzes a shell command for known destructive patterns.
If destructive patterns are matched, an interactive y/N prompt asks the
user for explicit approval. If no response within the timeout, the
command is blocked (fail-closed).

Every check is logged to ~/.agentbrake/audit.db (use --no-log to disable).

Exit codes:
  0 — command is safe OR user approved
  1 — destructive pattern detected and denied (warning severity)
  2 — destructive pattern detected and denied (critical severity)
  3 — timeout (no response within window)`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if os.Getenv("AGENTBRAKE_DISABLE") == "1" {
			fmt.Println("⚠ AgentBrake disabled via AGENTBRAKE_DISABLE=1")
			os.Exit(0)
		}
		command := args[0]

		// Load user config — failures are non-fatal (use defaults).
		// This is critical: a broken config must not lock the user
		// out of their own terminal. Better to ignore custom rules
		// than to block every command.
		cfg, err := config.Load("")
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"⚠ Config error (using defaults): %v\n", err)
			cfg = config.Default()
		}

		// Resolve timeout: CLI flag > config > default
		timeout := flagTimeout
		if timeout == 0 {
			timeout = cfg.Timeout
		}
		if timeout == 0 {
			timeout = intercept.DefaultTimeout
		}

// Compile custom patterns from config (non-fatal on errors)
		customSpecs := make([]patterns.CustomPatternSpec, 0, len(cfg.CustomPatterns))
		for _, c := range cfg.CustomPatterns {
			customSpecs = append(customSpecs, patterns.CustomPatternSpec{
				Name:        c.Name,
				Regex:       c.Regex,
				Severity:    c.Severity,
				Description: c.Description,
				Category:    c.Category,
			})
		}

		customPatterns, cerr := patterns.CompileCustom(customSpecs)
		if cerr != nil {
			fmt.Fprintf(os.Stderr,
				"⚠ Custom pattern compile error (ignoring): %v\n", cerr)
			customPatterns = nil
		}

		// Match against built-in + custom patterns
		matches := patterns.MatchWith(command, customPatterns)
		// (Day 6+: merge in cfg.CustomPatterns)

		// Set up audit logger (best-effort: log failures don't crash)
		var logger *audit.Logger
		if !flagNoLog {
			logger, err = audit.Open("")
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ Audit log unavailable: %v\n", err)
			}
			defer func() {
				if logger != nil {
					_ = logger.Close()
				}
			}()
		}

		entry := buildAuditEntry(command, matches)

		// Safe command — log and exit 0 silently.
		// Shell hooks call this on every command, so chatter is unacceptable.
		// Only print when explicitly checking via `agentbrake check` directly.
		if len(matches) == 0 {
			entry.Decision = audit.DecisionSafe
			entry.Severity = "safe"
			logAudit(logger, entry)
			// Stay silent unless --verbose is set in future
			os.Exit(0)
		}

		// No-prompt mode: report and exit with severity
		if flagNoPrompt {
			reportMatches(command, matches)
			entry.Decision = audit.DecisionDenied
			logAudit(logger, entry)
			os.Exit(severityExitCode(matches))
		}

		// Interactive approval prompt
		decision := intercept.AskApproval(command, matches, timeout)

		switch decision {
		case intercept.Approved:
			entry.Decision = audit.DecisionApproved
			logAudit(logger, entry)
			os.Exit(0)
		case intercept.Denied:
			entry.Decision = audit.DecisionDenied
			logAudit(logger, entry)
			os.Exit(severityExitCode(matches))
		case intercept.Timeout:
			entry.Decision = audit.DecisionTimeout
			logAudit(logger, entry)
			os.Exit(3)
		}
	},
}

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View recent audit log entries",
	Long:  `Show the most recent intercepts logged to ~/.agentbrake/audit.db.`,
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := audit.Open("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}
		defer logger.Close()

		entries, err := logger.Recent(20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}

		if len(entries) == 0 {
			fmt.Println("No audit log entries yet.")
			return
		}

		stats, _ := logger.Stats()

		bold := color.New(color.Bold)
		dim := color.New(color.FgHiBlack)

		bold.Println("\n  Recent intercepts (last 20)")
		dim.Println("  ─────────────────────────────────────────────────────────────")

		for _, e := range entries {
			ts := e.Timestamp.Local().Format("Jan 02 15:04:05")
			icon, c := decisionIcon(e.Decision, e.Severity)
			truncCmd := truncate(e.Command, 50)

			dim.Printf("  %s  ", ts)
			c.Printf("%s %-9s ", icon, e.Decision)
			fmt.Println(truncCmd)
		}

		fmt.Println()
		bold.Println("  Summary")
		dim.Println("  ─────────────────────────────────────────────────────────────")
		for d, count := range stats {
			icon, c := decisionIcon(d, "")
			c.Printf("  %s %-10s %d\n", icon, d, count)
		}
		fmt.Println()
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known destructive patterns",
	Run: func(cmd *cobra.Command, args []string) {
		all := patterns.All()
		fmt.Printf("AgentBrake knows %d destructive patterns:\n\n", len(all))

		categories := make(map[string][]patterns.Pattern)
		for _, p := range all {
			categories[p.Category] = append(categories[p.Category], p)
		}

		for cat, ps := range categories {
			fmt.Printf("── %s ─────────────\n", cat)
			for _, p := range ps {
				icon := "🟡"
				if p.Severity == patterns.SeverityCritical {
					icon = "🔴"
				}
				fmt.Printf("  %s %-30s %s\n", icon, p.Name, p.Description)
			}
			fmt.Println()
		}
	},
}

var initConfigCmd = &cobra.Command{
	Use:   "init-config",
	Short: "Write an example config file to ~/.agentbrake/config.yml",
	Run: func(cmd *cobra.Command, args []string) {
		path, err := config.DefaultPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}

		if _, err := os.Stat(path); err == nil {
			fmt.Fprintf(os.Stderr, "✗ Config already exists at %s\n", path)
			fmt.Fprintln(os.Stderr, "  Edit it directly or delete to regenerate.")
			os.Exit(1)
		}

		if err := config.WriteExample(path); err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Example config written to %s\n", path)
	},
}

var initCmd = &cobra.Command{
	Use:   "init [shell]",
	Short: "Print shell init script (bash/zsh/fish)",
	Long: `Init prints the shell integration script for your shell.

Add this to your shell config to automatically intercept destructive
commands before they run.

Usage:
  # zsh — add to ~/.zshrc
  source <(agentbrake init zsh)

  # bash — add to ~/.bashrc
  source <(agentbrake init bash)

  # fish — add to ~/.config/fish/config.fish
  agentbrake init fish | source

Supported shells: zsh, bash, fish`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		shell := args[0]
		script, err := intercept.ShellScript(shell)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s\n", err)
			os.Exit(1)
		}
		fmt.Print(script)
	},
}

// ─────── Helpers ───────

func buildAuditEntry(command string, matches []patterns.Pattern) audit.Entry {
	cwd, _ := os.Getwd()
	shell := os.Getenv("SHELL")

	names := make([]string, 0, len(matches))
	severity := "safe"
	for _, m := range matches {
		names = append(names, m.Name)
		if m.Severity == patterns.SeverityCritical {
			severity = "critical"
		} else if severity != "critical" {
			severity = "warning"
		}
	}

	return audit.Entry{
		Command:    command,
		Patterns:   strings.Join(names, ","),
		Severity:   severity,
		Shell:      shell,
		WorkingDir: cwd,
	}
}

func logAudit(logger *audit.Logger, entry audit.Entry) {
	if logger == nil {
		return
	}
	if err := logger.Log(entry); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Audit log write failed: %v\n", err)
	}
}

func reportMatches(command string, matches []patterns.Pattern) {
	fmt.Printf("\n⚠ DESTRUCTIVE COMMAND DETECTED\n")
	fmt.Printf("Command: %s\n\n", command)
	fmt.Printf("Matched patterns (%d):\n", len(matches))
	for _, p := range matches {
		icon := "🟡"
		if p.Severity == patterns.SeverityCritical {
			icon = "🔴"
		}
		fmt.Printf("  %s [%s] %s\n", icon, p.Severity, p.Name)
		fmt.Printf("     Category: %s\n", p.Category)
		fmt.Printf("     %s\n\n", p.Description)
	}
}

func severityExitCode(matches []patterns.Pattern) int {
	for _, m := range matches {
		if m.Severity == patterns.SeverityCritical {
			return 2
		}
	}
	return 1
}

func decisionIcon(d audit.Decision, severity string) (string, *color.Color) {
	switch d {
	case audit.DecisionSafe:
		return "✓", color.New(color.FgGreen)
	case audit.DecisionApproved:
		return "✓", color.New(color.FgYellow)
	case audit.DecisionDenied:
		if severity == "critical" {
			return "✗", color.New(color.FgRed, color.Bold)
		}
		return "✗", color.New(color.FgRed)
	case audit.DecisionTimeout:
		return "⏱", color.New(color.FgMagenta)
	default:
		return "?", color.New(color.FgWhite)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func main() {
	checkCmd.Flags().DurationVar(&flagTimeout, "timeout", 0,
		"how long to wait for approval before blocking (e.g. 30s, 2m)")
	checkCmd.Flags().BoolVar(&flagNoPrompt, "no-prompt", false,
		"only detect, don't ask for approval")
	checkCmd.Flags().BoolVar(&flagNoLog, "no-log", false,
		"skip writing to the audit log")

	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(logCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(initConfigCmd)
	rootCmd.AddCommand(initCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
