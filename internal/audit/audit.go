// Package audit provides local SQLite-based logging of every
// intercepted command. Every check — safe, denied, approved, timeout —
// gets a permanent tamper-evident record.
//
// The audit DB lives at ~/.agentbrake/audit.db by default.
// This package handles schema creation, writes, and reads.
package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Decision mirrors the intercept package's outcomes but is also used
// for safe commands (Decision = "safe") which never hit a prompt.
type Decision string

const (
	DecisionSafe     Decision = "safe"
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
	DecisionTimeout  Decision = "timeout"
)

// Entry is one row in the audit log.
type Entry struct {
	ID         int64
	Timestamp  time.Time
	Command    string
	Patterns   string // comma-separated pattern names (or "" if safe)
	Severity   string // "safe" | "warning" | "critical"
	Decision   Decision
	Shell      string // detected shell at time of intercept
	WorkingDir string
}

// Logger writes audit entries to a SQLite database.
type Logger struct {
	db *sql.DB
}

// Open returns a Logger backed by the database at the given path.
// Creates the file and schema if they don't exist.
// Pass empty string to use the default location ~/.agentbrake/audit.db.
func Open(path string) (*Logger, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Tight settings for a single-user local DB
	db.SetMaxOpenConns(1)

	logger := &Logger{db: db}
	if err := logger.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return logger, nil
}

// DefaultPath returns ~/.agentbrake/audit.db
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agentbrake", "audit.db"), nil
}

// Close releases the DB handle.
func (l *Logger) Close() error {
	return l.db.Close()
}

func (l *Logger) initSchema() error {
	_, err := l.db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    DATETIME NOT NULL,
			command      TEXT NOT NULL,
			patterns     TEXT NOT NULL DEFAULT '',
			severity     TEXT NOT NULL,
			decision     TEXT NOT NULL,
			shell        TEXT NOT NULL DEFAULT '',
			working_dir  TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_decision  ON audit_log(decision);
	`)
	if err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	return nil
}

// Log writes a new entry to the audit log.
func (l *Logger) Log(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	_, err := l.db.Exec(
		`INSERT INTO audit_log
			(timestamp, command, patterns, severity, decision, shell, working_dir)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp.UTC(),
		e.Command,
		e.Patterns,
		e.Severity,
		string(e.Decision),
		e.Shell,
		e.WorkingDir,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// Recent returns the last `limit` entries, newest first.
func (l *Logger) Recent(limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := l.db.Query(
		`SELECT id, timestamp, command, patterns, severity, decision, shell, working_dir
			FROM audit_log
			ORDER BY id DESC
			LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var decision string
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.Command, &e.Patterns,
			&e.Severity, &decision, &e.Shell, &e.WorkingDir,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		e.Decision = Decision(decision)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Stats returns counts of decisions for a quick summary.
func (l *Logger) Stats() (map[Decision]int, error) {
	rows, err := l.db.Query(
		`SELECT decision, COUNT(*) FROM audit_log GROUP BY decision`,
	)
	if err != nil {
		return nil, fmt.Errorf("query stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[Decision]int)
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		stats[Decision(d)] = n
	}
	return stats, rows.Err()
}