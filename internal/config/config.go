// Package config handles loading the user's YAML configuration.
// Config lives at ~/.agentbrake/config.yml by default.
//
// Users can:
//   - add custom destructive patterns
//   - allowlist directories where prompts are skipped
//   - tune timeout and other behavior
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level user configuration.
type Config struct {
	// Timeout is how long to wait for approval before blocking.
	Timeout time.Duration `yaml:"timeout"`

	// CustomPatterns the user wants to add on top of built-ins.
	CustomPatterns []CustomPattern `yaml:"custom_patterns"`

	// Allowlist directories — skip prompts when CWD matches.
	AllowlistDirs []string `yaml:"allowlist_dirs"`

	// SilenceAuditFor patterns that should still execute but not
	// produce a prompt (e.g. "git reset --hard" in sandbox repos).
	SilenceAuditFor []string `yaml:"silence_audit_for"`
}

// CustomPattern is a user-defined destructive pattern.
type CustomPattern struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	Severity    string `yaml:"severity"` // "warning" or "critical"
	Description string `yaml:"description"`
	Category    string `yaml:"category"`
}

// Default returns the baseline configuration.
func Default() Config {
	return Config{
		Timeout:         60 * time.Second,
		CustomPatterns:  []CustomPattern{},
		AllowlistDirs:   []string{},
		SilenceAuditFor: []string{},
	}
}

// DefaultPath returns ~/.agentbrake/config.yml
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".agentbrake", "config.yml"), nil
}

// Load reads and parses the config file.
// If the file doesn't exist, returns Default() and no error.
// If it exists but is invalid, returns an error.
func Load(path string) (Config, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return Config{}, err
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// Validate checks the config for obvious problems.
func (c Config) Validate() error {
	seenNames := make(map[string]bool)
	for i, p := range c.CustomPatterns {
		if p.Name == "" {
			return fmt.Errorf("custom_patterns[%d]: name is required", i)
		}
		if p.Regex == "" {
			return fmt.Errorf("custom_patterns[%d] (%s): regex is required", i, p.Name)
		}
		if _, err := regexp.Compile(p.Regex); err != nil {
			return fmt.Errorf("custom_patterns[%d] (%s): invalid regex: %w", i, p.Name, err)
		}
		if p.Severity != "warning" && p.Severity != "critical" {
			return fmt.Errorf("custom_patterns[%d] (%s): severity must be 'warning' or 'critical', got %q",
				i, p.Name, p.Severity)
		}
		if seenNames[p.Name] {
			return fmt.Errorf("custom_patterns: duplicate name %q", p.Name)
		}
		seenNames[p.Name] = true
	}
	return nil
}

// WriteExample writes a sample config file to the given path.
// Useful for `agentbrake init-config` or similar.
func WriteExample(path string) error {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	example := `# AgentBrake configuration
# Located at ~/.agentbrake/config.yml

# How long to wait for approval before blocking (fail-closed).
timeout: 60s

# Add your own destructive patterns. They're checked alongside
# the 15+ built-in patterns.
custom_patterns:
  - name: COMPANY_PROD_DB_DELETE
    regex: '(?i)psql.*--host=prod\.mycompany\.com.*-c "DROP'
    severity: critical
    description: Direct destructive SQL against production DB
    category: company

# Directories where prompts are skipped (e.g. throwaway repos).
allowlist_dirs:
  # - /home/me/sandbox
  # - /tmp

# Patterns to never prompt for, even if they match a built-in.
# Useful for harmless force-pushes in personal repos.
silence_audit_for:
  # - GIT_PUSH_FORCE
`
	return os.WriteFile(path, []byte(example), 0o600)
}