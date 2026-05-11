package patterns

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantMatches int
		wantPattern string // first matched pattern name (or empty if 0)
	}{
		// ─────── SQL — should match ───────
		{
			name:        "drop table lowercase",
			command:     "drop table users;",
			wantMatches: 1,
			wantPattern: "SQL_DROP_TABLE",
		},
		{
			name:        "drop table uppercase",
			command:     "DROP TABLE customers",
			wantMatches: 1,
			wantPattern: "SQL_DROP_TABLE",
		},
		{
			name:        "drop database",
			command:     "DROP DATABASE production",
			wantMatches: 1,
			wantPattern: "SQL_DROP_DATABASE",
		},
		{
			name:        "delete without where",
			command:     "DELETE FROM users;",
			wantMatches: 1,
			wantPattern: "SQL_DELETE_NO_WHERE",
		},

		// ─────── SQL — should NOT match (safe) ───────
		{
			name:        "delete with where is safe",
			command:     "DELETE FROM users WHERE id = 5",
			wantMatches: 0,
		},
		{
			name:        "select is safe",
			command:     "SELECT * FROM users",
			wantMatches: 0,
		},

		// ─────── Filesystem ───────
		{
			name:        "rm -rf root",
			command:     "rm -rf /",
			wantMatches: 1,
			wantPattern: "RM_RF_ROOT",
		},
		{
			name:        "rm -rf home",
			command:     "rm -rf ~/",
			wantMatches: 1,
			wantPattern: "RM_RF_HOME",
		},
		{
			name:        "rm safe file",
			command:     "rm myfile.txt",
			wantMatches: 0,
		},

		// ─────── Cloud ───────
		{
			name:        "aws s3 force delete bucket",
			command:     "aws s3 rb s3://my-bucket --force",
			wantMatches: 1,
			wantPattern: "AWS_S3_REMOVE_BUCKET",
		},
		{
			name:        "aws s3 list is safe",
			command:     "aws s3 ls",
			wantMatches: 0,
		},
		{
			name:        "railway volume delete",
			command:     "railway volume delete prod-pg",
			wantMatches: 1,
			wantPattern: "RAILWAY_VOLUME_DELETE",
		},

		// ─────── Kubernetes ───────
		{
			name:        "kubectl delete namespace",
			command:     "kubectl delete namespace production",
			wantMatches: 1,
			wantPattern: "KUBECTL_DELETE_NAMESPACE",
		},
		{
			name:        "kubectl delete ns shortcut",
			command:     "kubectl delete ns staging",
			wantMatches: 1,
			wantPattern: "KUBECTL_DELETE_NAMESPACE",
		},
		{
			name:        "kubectl get pods is safe",
			command:     "kubectl get pods",
			wantMatches: 0,
		},

		// ─────── Git ───────
		{
			name:        "git push force",
			command:     "git push --force origin main",
			wantMatches: 1,
			wantPattern: "GIT_PUSH_FORCE",
		},
		{
			name:        "git push short flag",
			command:     "git push -f origin main",
			wantMatches: 1,
			wantPattern: "GIT_PUSH_FORCE",
		},
		{
			name:        "git push safe",
			command:     "git push origin main",
			wantMatches: 0,
		},
		{
			name:        "git reset hard",
			command:     "git reset --hard HEAD~1",
			wantMatches: 1,
			wantPattern: "GIT_RESET_HARD",
		},

		// ─────── Infrastructure ───────
		{
			name:        "terraform destroy",
			command:     "terraform destroy -auto-approve",
			wantMatches: 1,
			wantPattern: "TERRAFORM_DESTROY",
		},
		{
			name:        "terraform plan is safe",
			command:     "terraform plan",
			wantMatches: 0,
		},

		// ─────── Edge cases ───────
		{
			name:        "empty command",
			command:     "",
			wantMatches: 0,
		},
		{
			name:        "harmless echo",
			command:     "echo 'hello world'",
			wantMatches: 0,
		},
		{
			name:        "ls is safe",
			command:     "ls -la /home",
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := Match(tt.command)

			if len(matches) != tt.wantMatches {
				t.Errorf("Match(%q) returned %d matches, want %d",
					tt.command, len(matches), tt.wantMatches)
				for _, m := range matches {
					t.Logf("  matched: %s", m.Name)
				}
				return
			}

			if tt.wantMatches > 0 && tt.wantPattern != "" {
				if matches[0].Name != tt.wantPattern {
					t.Errorf("Match(%q) first match was %q, want %q",
						tt.command, matches[0].Name, tt.wantPattern)
				}
			}
		})
	}
}

func TestAllPatternsValid(t *testing.T) {
	patterns := All()

	if len(patterns) < 15 {
		t.Errorf("expected at least 15 patterns, got %d", len(patterns))
	}

	seen := make(map[string]bool)
	for _, p := range patterns {
		if p.Name == "" {
			t.Error("pattern has empty Name")
		}
		if p.Regex == nil {
			t.Errorf("pattern %s has nil Regex", p.Name)
		}
		if p.Description == "" {
			t.Errorf("pattern %s has empty Description", p.Name)
		}
		if p.Category == "" {
			t.Errorf("pattern %s has empty Category", p.Name)
		}
		if seen[p.Name] {
			t.Errorf("duplicate pattern name: %s", p.Name)
		}
		seen[p.Name] = true
	}
}