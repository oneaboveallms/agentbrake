// Package patterns provides destructive command pattern detection.
// It defines a set of regex-based patterns that identify potentially
// dangerous shell commands which should be blocked or require approval.
package patterns

import (
	"fmt"
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
		// ─────── DOCKER ───────
		{
			Name:        "DOCKER_SYSTEM_PRUNE_ALL",
			Regex:       regexp.MustCompile(`\bdocker\s+system\s+prune\s+.*-a`),
			Severity:    SeverityCritical,
			Description: "Removes ALL unused containers, images, networks, volumes",
			Category:    "docker",
		},
		{
			Name:        "DOCKER_VOLUME_RM_ALL",
			Regex:       regexp.MustCompile(`\bdocker\s+volume\s+rm\s+\$\(docker\s+volume\s+ls`),
			Severity:    SeverityCritical,
			Description: "Removes all Docker volumes (data loss)",
			Category:    "docker",
		},
		{
			Name:        "DOCKER_RMI_ALL",
			Regex:       regexp.MustCompile(`\bdocker\s+rmi\s+\$\(docker\s+images`),
			Severity:    SeverityWarning,
			Description: "Removes all Docker images",
			Category:    "docker",
		},
		{
			Name:        "DOCKER_KILL_ALL",
			Regex:       regexp.MustCompile(`\bdocker\s+kill\s+\$\(docker\s+ps`),
			Severity:    SeverityWarning,
			Description: "Kills all running Docker containers",
			Category:    "docker",
		},

		// ─────── PACKAGE MANAGERS ───────
		{
			Name:        "NPM_PUBLISH_FORCE",
			Regex:       regexp.MustCompile(`\bnpm\s+publish\s+.*--force`),
			Severity:    SeverityCritical,
			Description: "Force-publishes an npm package (irreversible version overwrite)",
			Category:    "package",
		},
		{
			Name:        "NPM_UNPUBLISH",
			Regex:       regexp.MustCompile(`\bnpm\s+unpublish\b`),
			Severity:    SeverityCritical,
			Description: "Unpublishes an npm package — breaks dependents",
			Category:    "package",
		},
		{
			Name:        "PIP_UNINSTALL_ALL",
			Regex:       regexp.MustCompile(`\bpip\s+uninstall\s+.*-y\s+.*\*`),
			Severity:    SeverityWarning,
			Description: "Uninstalls multiple Python packages without confirmation",
			Category:    "package",
		},
		{
			Name:        "CARGO_YANK",
			Regex:       regexp.MustCompile(`\bcargo\s+yank\b`),
			Severity:    SeverityWarning,
			Description: "Yanks a published Cargo crate version",
			Category:    "package",
		},

		// ─────── DATABASES ───────
		{
			Name:        "MONGO_DROP_DATABASE",
			Regex:       regexp.MustCompile(`(?i)db\.dropDatabase\(\)`),
			Severity:    SeverityCritical,
			Description: "Drops the current MongoDB database",
			Category:    "database",
		},
		{
			Name:        "MONGO_DROP_COLLECTION",
			Regex:       regexp.MustCompile(`(?i)db\.\w+\.drop\(\)`),
			Severity:    SeverityCritical,
			Description: "Drops a MongoDB collection and all its documents",
			Category:    "database",
		},
		{
			Name:        "MONGO_REMOVE_ALL",
			Regex:       regexp.MustCompile(`(?i)db\.\w+\.remove\(\s*\{\s*\}\s*\)`),
			Severity:    SeverityCritical,
			Description: "Removes all documents from a MongoDB collection",
			Category:    "database",
		},
		{
			Name:        "REDIS_FLUSHALL",
			Regex:       regexp.MustCompile(`(?i)\bFLUSHALL\b`),
			Severity:    SeverityCritical,
			Description: "Deletes all data in all Redis databases",
			Category:    "database",
		},
		{
			Name:        "REDIS_FLUSHDB",
			Regex:       regexp.MustCompile(`(?i)\bFLUSHDB\b`),
			Severity:    SeverityCritical,
			Description: "Deletes all keys in the current Redis database",
			Category:    "database",
		},
		{
			Name:        "ELASTICSEARCH_DELETE_INDEX",
			Regex:       regexp.MustCompile(`\bDELETE\s+/\w+/?$`),
			Severity:    SeverityCritical,
			Description: "Deletes an Elasticsearch index",
			Category:    "database",
		},

		// ─────── CLOUD: AWS (more) ───────
		{
			Name:        "AWS_DYNAMODB_DELETE_TABLE",
			Regex:       regexp.MustCompile(`\baws\s+dynamodb\s+delete-table\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a DynamoDB table and all its data",
			Category:    "cloud",
		},
		{
			Name:        "AWS_EC2_TERMINATE",
			Regex:       regexp.MustCompile(`\baws\s+ec2\s+terminate-instances\b`),
			Severity:    SeverityWarning,
			Description: "Terminates EC2 instances (cannot be undone)",
			Category:    "cloud",
		},
		{
			Name:        "AWS_IAM_DELETE_USER",
			Regex:       regexp.MustCompile(`\baws\s+iam\s+delete-user\b`),
			Severity:    SeverityCritical,
			Description: "Deletes an IAM user account",
			Category:    "cloud",
		},
		{
			Name:        "AWS_CLOUDFORMATION_DELETE",
			Regex:       regexp.MustCompile(`\baws\s+cloudformation\s+delete-stack\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a CloudFormation stack and all its resources",
			Category:    "cloud",
		},

		// ─────── CLOUD: GCP ───────
		{
			Name:        "GCP_PROJECT_DELETE",
			Regex:       regexp.MustCompile(`\bgcloud\s+projects\s+delete\b`),
			Severity:    SeverityCritical,
			Description: "Schedules a GCP project for deletion",
			Category:    "cloud",
		},
		{
			Name:        "GCP_COMPUTE_DELETE",
			Regex:       regexp.MustCompile(`\bgcloud\s+compute\s+instances\s+delete\b`),
			Severity:    SeverityWarning,
			Description: "Deletes a GCE virtual machine instance",
			Category:    "cloud",
		},
		{
			Name:        "GCP_SQL_DELETE",
			Regex:       regexp.MustCompile(`\bgcloud\s+sql\s+instances\s+delete\b`),
			Severity:    SeverityCritical,
			Description: "Deletes a Cloud SQL database instance",
			Category:    "cloud",
		},
		{
			Name:        "GCP_STORAGE_RB",
			Regex:       regexp.MustCompile(`\bgsutil\s+rb\b.*-r`),
			Severity:    SeverityCritical,
			Description: "Recursively removes a GCS bucket and contents",
			Category:    "cloud",
		},

		// ─────── CLOUD: AZURE ───────
		{
			Name:        "AZURE_GROUP_DELETE",
			Regex:       regexp.MustCompile(`\baz\s+group\s+delete\b`),
			Severity:    SeverityCritical,
			Description: "Deletes an Azure resource group and all resources",
			Category:    "cloud",
		},
		{
			Name:        "AZURE_VM_DELETE",
			Regex:       regexp.MustCompile(`\baz\s+vm\s+delete\b`),
			Severity:    SeverityWarning,
			Description: "Deletes an Azure VM",
			Category:    "cloud",
		},

		// ─────── KUBERNETES (more) ───────
		{
			Name:        "KUBECTL_DELETE_ALL",
			Regex:       regexp.MustCompile(`\bkubectl\s+delete\s+all\s+--all\b`),
			Severity:    SeverityCritical,
			Description: "Deletes all resources in the current namespace",
			Category:    "kubernetes",
		},
		{
			Name:        "KUBECTL_DELETE_DEPLOYMENT",
			Regex:       regexp.MustCompile(`\bkubectl\s+delete\s+(deploy|deployment)\b`),
			Severity:    SeverityWarning,
			Description: "Deletes a Kubernetes deployment",
			Category:    "kubernetes",
		},
		{
			Name:        "HELM_UNINSTALL",
			Regex:       regexp.MustCompile(`\bhelm\s+(uninstall|delete)\b`),
			Severity:    SeverityWarning,
			Description: "Uninstalls a Helm release",
			Category:    "kubernetes",
		},

		// ─────── GIT (more) ───────
		{
			Name:        "GIT_CLEAN_FORCE",
			Regex:       regexp.MustCompile(`\bgit\s+clean\s+-[fdx]+\b`),
			Severity:    SeverityWarning,
			Description: "Removes untracked files (including ignored if -x)",
			Category:    "git",
		},
		{
			Name:        "GIT_BRANCH_DELETE_FORCE",
			Regex:       regexp.MustCompile(`\bgit\s+branch\s+-D\b`),
			Severity:    SeverityWarning,
			Description: "Force deletes a Git branch (even unmerged)",
			Category:    "git",
		},
		{
			Name:        "GIT_TAG_DELETE",
			Regex:       regexp.MustCompile(`\bgit\s+push\s+(--delete|-d)\s+\w+\s+`),
			Severity:    SeverityWarning,
			Description: "Deletes a remote tag or branch",
			Category:    "git",
		},

		// ─────── DANGEROUS SYSTEM ───────
		{
			Name:        "DD_TO_DEVICE",
			Regex:       regexp.MustCompile(`\bdd\s+.*of=/dev/(sd|nvme|hd|disk)`),
			Severity:    SeverityCritical,
			Description: "Writes raw data to a disk device — wipes data",
			Category:    "system",
		},
		{
			Name:        "MKFS",
			Regex:       regexp.MustCompile(`\bmkfs(\.\w+)?\s+/dev/`),
			Severity:    SeverityCritical,
			Description: "Formats a disk partition — destroys all data",
			Category:    "system",
		},
		{
			Name:        "SHRED",
			Regex:       regexp.MustCompile(`\bshred\s+.*-u\b`),
			Severity:    SeverityCritical,
			Description: "Securely deletes files — unrecoverable",
			Category:    "system",
		},
		{
			Name:        "CHMOD_777_RECURSIVE",
			Regex:       regexp.MustCompile(`\bchmod\s+-R\s+777\b`),
			Severity:    SeverityWarning,
			Description: "Makes all files world-writable recursively (security risk)",
			Category:    "system",
		},
		{
			Name:        "CHOWN_RECURSIVE_ROOT",
			Regex:       regexp.MustCompile(`\bchown\s+-R\s+\w+\s+/(\s|$)`),
			Severity:    SeverityCritical,
			Description: "Recursively changes ownership starting at root",
			Category:    "system",
		},

		// ─────── NETWORK / DNS ───────
		{
			Name:        "IPTABLES_FLUSH",
			Regex:       regexp.MustCompile(`\biptables\s+-F\b`),
			Severity:    SeverityWarning,
			Description: "Flushes all iptables rules (firewall down)",
			Category:    "network",
		},

		// ─────── PROCESS ───────
		{
			Name:        "KILL_ALL_PROCESSES",
			Regex:       regexp.MustCompile(`\bkillall\s+-9\b`),
			Severity:    SeverityWarning,
			Description: "Forcefully kills all matching processes",
			Category:    "system",
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

// ─────── CUSTOM PATTERNS (user-defined via config) ───────

// CustomPatternSpec is a user-supplied pattern definition from config.
// Different from the internal Pattern struct so we can validate and
// compile separately before merging into the matcher.
type CustomPatternSpec struct {
	Name        string
	Regex       string
	Severity    string // "warning" | "critical"
	Description string
	Category    string
}

// CompileCustom turns user-supplied specs into Pattern values.
// Returns an error if any regex fails to compile (validation should
// catch this earlier, but we double-check here).
func CompileCustom(specs []CustomPatternSpec) ([]Pattern, error) {
	out := make([]Pattern, 0, len(specs))
	for _, s := range specs {
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return nil, fmt.Errorf("custom pattern %q: %w", s.Name, err)
		}

		sev := SeverityWarning
		if s.Severity == "critical" {
			sev = SeverityCritical
		}

		category := s.Category
		if category == "" {
			category = "custom"
		}

		out = append(out, Pattern{
			Name:        s.Name,
			Regex:       re,
			Severity:    sev,
			Description: s.Description,
			Category:    category,
		})
	}
	return out, nil
}

// MatchWith matches a command against both built-in patterns AND
// the supplied custom patterns. Built-in matches appear first.
func MatchWith(command string, custom []Pattern) []Pattern {
	matches := Match(command)
	for _, p := range custom {
		if p.Regex.MatchString(command) {
			matches = append(matches, p)
		}
	}
	return matches
}