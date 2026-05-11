// Package patterns provides destructive command pattern detection.
// It defines a set of regex-based patterns that identify potentially
// dangerous shell commands which should be blocked or require approval.
package patterns

import (
	"regexp"
)

// Severity indicates how dangerous a matched pattern is.
type Severity string

const (
	// SeverityWarning is for risky but recoverable actions.
	SeverityWarning Severity = "warning"

	// SeverityCritical is for irreversible destructive actions.
	SeverityCritical Severity = "critical"
)

// Pattern represents a single destructive command pattern.
type Pattern struct {
	// Name is a short identifier (e.g. "SQL_DROP_TABLE")
	Name string

	// Regex is the compiled pattern that matches the command
	Regex *regexp.Regexp

	// Severity is how dangerous the action is
	Severity Severity

	// Description is a human-readable explanation
	Description string

	// Category groups related patterns (sql, filesystem, cloud, etc.)
	Category string
}

// All returns the complete list of destructive patterns.
// New patterns can be added here without changing the matcher logic.
func All() []Pattern {
	return []Pattern{
		// ─────── SQL ───────
		{
			Name:        "SQL_DROP_TABLE",
			Regex:       regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
			Severity:    SeverityCritical,
			Description: "Permanently deletes a database table and all its data",
			Category:    "sql",
		},
		{
			Name:        "SQL_DROP_DATABASE",
			Regex:       regexp.MustCompile(`(?i)\bDROP\s+DATABASE\b`),
			Severity:    SeverityCritical,
			Description: "Permanently deletes an entire database",
			Category:    "sql",
		},
		{
			Name:        "SQL_TRUNCATE_TABLE",
			Regex:       regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`),
			Severity:    SeverityCritical,
			Description: "Removes all rows from a table (faster than DELETE, no rollback)",
			Category:    "sql",
		},
		{
			Name:        "SQL_DELETE_NO_WHERE",
			Regex:       regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w+\s*;?\s*$`),
			Severity:    SeverityCritical,
			Description: "DELETE without WHERE clause — wipes entire table",
			Category:    "sql",
		},

		// ─────── FILESYSTEM ───────
		{
			Name:        "RM_RF_ROOT",
			Regex:       regexp.MustCompile(`\brm\s+-[rf]+\s+/(\s|$)`),
			Severity:    SeverityCritical,
			Description: "Recursive force delete on root filesystem",
			Category:    "filesystem",
		},
		{
			Name:        "RM_RF_HOME",
			Regex:       regexp.MustCompile(`\brm\s+-[rf]+\s+~(/|$|\s)`),
			Severity:    SeverityCritical,
			Description: "Recursive force delete on home directory",
			Category:    "filesystem",
		},
		{
			Name:        "RM_RF_WILDCARD",
			Regex:       regexp.MustCompile(`\brm\s+-[rf]+\s+\*`),
			Severity:    SeverityCritical,
			Description: "Recursive force delete using wildcard",
			Category:    "filesystem",
		},

		// ─────── CLOUD: AWS ───────
		{
			Name:        "AWS_S3_REMOVE_BUCKET",
			Regex:       regexp.MustCompile(`\baws\s+s3\s+rb\b.*--force`),
			Severity:    SeverityCritical,
			Description: "Force deletes an S3 bucket and all its contents",
			Category:    "cloud",
		},
		{
			Name:        "AWS_RDS_DELETE",
			Regex:       regexp.MustCompile(`\baws\s+rds\s+delete-db-instance\b`),
			Severity:    SeverityCritical,
			Description: "Deletes an RDS database instance",
			Category:    "cloud",
		},

		// ─────── KUBERNETES ───────
		{
			Name:        "KUBECTL_DELETE_NAMESPACE",
			Regex:       regexp.MustCompile(`\bkubectl\s+delete\s+(ns|namespace)\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a Kubernetes namespace and all its resources",
			Category:    "kubernetes",
		},
		{
			Name:        "KUBECTL_DELETE_PVC",
			Regex:       regexp.MustCompile(`\bkubectl\s+delete\s+(pvc|persistentvolumeclaim)\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a persistent volume claim (may destroy data)",
			Category:    "kubernetes",
		},

		// ─────── GIT ───────
		{
			Name:        "GIT_PUSH_FORCE",
			Regex:       regexp.MustCompile(`\bgit\s+push\s+(-f|--force)\b`),
			Severity:    SeverityWarning,
			Description: "Force push rewrites remote history (can destroy others' work)",
			Category:    "git",
		},
		{
			Name:        "GIT_RESET_HARD",
			Regex:       regexp.MustCompile(`\bgit\s+reset\s+--hard\b`),
			Severity:    SeverityWarning,
			Description: "Discards all local changes — uncommitted work lost",
			Category:    "git",
		},

		// ─────── INFRASTRUCTURE ───────
		{
			Name:        "TERRAFORM_DESTROY",
			Regex:       regexp.MustCompile(`\bterraform\s+destroy\b`),
			Severity:    SeverityCritical,
			Description: "Destroys all infrastructure managed by Terraform",
			Category:    "infrastructure",
		},
		{
			Name:        "RAILWAY_VOLUME_DELETE",
			Regex:       regexp.MustCompile(`\brailway\s+volume\s+delete\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a Railway volume (caused PocketOS disaster)",
			Category:    "cloud",
		},
	}
}

// Match takes a shell command and returns all patterns that match it.
// An empty slice means the command appears safe.
func Match(command string) []Pattern {
	var matches []Pattern
	for _, p := range All() {
		if p.Regex.MatchString(command) {
			matches = append(matches, p)
		}
	}
	return matches
}