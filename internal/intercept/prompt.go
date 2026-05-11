// Package intercept handles the runtime interception of destructive commands.
// It displays a warning to the user and waits for explicit approval (y/N)
// before allowing execution. Defaults to BLOCK if the user doesn't respond
// within the timeout — fail-closed for safety.
package intercept

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/oneaboveallms/agentbrake/internal/patterns"
)

// DefaultTimeout is how long we wait for user input before blocking.
const DefaultTimeout = 60 * time.Second

// Decision represents the outcome of an approval prompt.
type Decision string

const (
	// Approved means the user typed 'y' or 'yes'.
	Approved Decision = "approved"

	// Denied means the user typed 'n' or 'no' (or anything else).
	Denied Decision = "denied"

	// Timeout means the user didn't respond within the timeout window.
	Timeout Decision = "timeout"
)

// IsAllowed returns true only if the decision was an explicit approval.
// Both Denied and Timeout result in BLOCK — fail-closed by design.
func (d Decision) IsAllowed() bool {
	return d == Approved
}

// AskApproval shows the user a warning about the detected destructive
// command and asks for explicit y/N approval. Returns a Decision.
//
// The prompt fails closed: if the user doesn't respond within the timeout,
// the action is blocked. This is critical for safety — AI agents shouldn't
// be able to "wait out" a missing operator.
func AskApproval(command string, matches []patterns.Pattern, timeout time.Duration) Decision {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	printWarning(command, matches)
	printPrompt(timeout)

	// Read user input in a goroutine so we can race it against a timer.
	// If timeout fires first, we block by default — fail-closed.
	answerCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			answerCh <- strings.TrimSpace(strings.ToLower(scanner.Text()))
		} else {
			answerCh <- ""
		}
	}()

	select {
	case answer := <-answerCh:
		if answer == "y" || answer == "yes" {
			printApproved()
			return Approved
		}
		printDenied()
		return Denied

	case <-time.After(timeout):
		printTimeout()
		return Timeout
	}
}

// ─────── Display helpers ───────

func printWarning(command string, matches []patterns.Pattern) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgHiBlack)

	hasCritical := false
	for _, m := range matches {
		if m.Severity == patterns.SeverityCritical {
			hasCritical = true
			break
		}
	}

	fmt.Println()
	if hasCritical {
		red.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		red.Println("⚠  CRITICAL: DESTRUCTIVE COMMAND DETECTED")
		red.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	} else {
		yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		yellow.Println("⚠  WARNING: RISKY COMMAND DETECTED")
		yellow.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	fmt.Println()
	dim.Print("  Command:  ")
	white.Println(command)
	fmt.Println()

	dim.Printf("  Matched %d pattern(s):\n", len(matches))
	for _, m := range matches {
		icon := "🟡"
		sev := yellow
		if m.Severity == patterns.SeverityCritical {
			icon = "🔴"
			sev = red
		}
		fmt.Printf("    %s ", icon)
		sev.Printf("[%s] ", m.Severity)
		white.Println(m.Name)
		dim.Printf("       %s\n", m.Description)
	}
	fmt.Println()
}

func printPrompt(timeout time.Duration) {
	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)

	dim.Printf("  Auto-deny in %s if no response.\n", timeout)
	bold.Print("  Allow this command? (y/N): ")
}

func printApproved() {
	green := color.New(color.FgGreen, color.Bold)
	fmt.Println()
	green.Println("  ✓ APPROVED — command will execute")
	fmt.Println()
}

func printDenied() {
	red := color.New(color.FgRed, color.Bold)
	fmt.Println()
	red.Println("  ✗ DENIED — command blocked")
	fmt.Println()
}

func printTimeout() {
	red := color.New(color.FgRed, color.Bold)
	dim := color.New(color.FgHiBlack)
	fmt.Println()
	red.Println("  ⏱ TIMEOUT — command blocked by default")
	dim.Println("    (fail-closed: no response = no execution)")
	fmt.Println()
}