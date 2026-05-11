# AgentBrake

> The safety brake between AI coding agents and your production database.

![Demo](./assets/demo.gif)

AgentBrake intercepts destructive commands (`DROP TABLE`, `rm -rf /`, `terraform destroy`, etc.) and requires explicit human approval before execution.

Built for the era of AI coding agents — Cursor, Claude Code, Copilot, Aider — that can (and do) accidentally delete production.

## Why?

In April 2026, an AI agent deleted PocketOS's production database **and all backups in 9 seconds**. Replit's agent deleted 1,206 executive records and lied about recovery. Cursor's "Plan Mode" gets bypassed regularly.

AgentBrake is the missing safety layer.

## Features

- 🛡️ **50 built-in destructive patterns** — SQL, filesystem, cloud (AWS/GCP/Azure), Kubernetes, Git, Docker, databases, system
- ⏱️ **60-second fail-closed timeout** — AI agents can't "wait out" a missing operator  
- 🔧 **Custom patterns** — define your company's dangerous commands in YAML
- 📊 **Tamper-evident audit log** — every action recorded in local SQLite
- 🐚 **Shell-native** — works with bash, zsh, fish via preexec hooks
- 🚨 **Emergency bypass** — `AGENTBRAKE_DISABLE=1` when you need to override
- 💎 **Single binary** — no runtime dependencies, ~10MB

## Install

### Quick install (Linux/macOS)

\`\`\`bash
curl -L https://github.com/oneaboveallms/agentbrake/releases/latest/download/agentbrake_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv agentbrake /usr/local/bin/
\`\`\`

### Manual

Download the binary for your platform from [Releases](https://github.com/oneaboveallms/agentbrake/releases).

### Activate shell integration

Add to your shell config:

\`\`\`bash
# bash — ~/.bashrc
source <(agentbrake init bash)

# zsh — ~/.zshrc  
source <(agentbrake init zsh)

# fish — ~/.config/fish/config.fish
agentbrake init fish | source
\`\`\`

Reload shell. You'll see:

\`\`\`
✓ AgentBrake active for bash
\`\`\`

## Usage

Once installed and activated, AgentBrake works **silently in the background**. You don't run it manually — it intercepts destructive commands automatically.

Try it:

\`\`\`bash
git push --force origin main
# ⚠ WARNING: RISKY COMMAND DETECTED
# Allow this command? (y/N):
\`\`\`

### Manual check

\`\`\`bash
agentbrake check "DROP TABLE users"
\`\`\`

### View audit log

\`\`\`bash
agentbrake log
\`\`\`

### List all patterns

\`\`\`bash
agentbrake list
\`\`\`

### Add custom patterns

Edit \`~/.agentbrake/config.yml\`:

\`\`\`yaml
custom_patterns:
  - name: COMPANY_PROD_DELETE
    regex: 'psql.*--host=prod\.mycompany\.com.*DROP'
    severity: critical
    description: Direct destructive SQL against production
    category: company
\`\`\`

## Emergency Bypass

If you need to disable AgentBrake for a session:

\`\`\`bash
export AGENTBRAKE_DISABLE=1
# ... your commands run without checks ...
unset AGENTBRAKE_DISABLE
\`\`\`

## How it works

\`\`\`
You type: DROP TABLE users
       ↓
Shell preexec hook fires
       ↓
agentbrake check "DROP TABLE users"
       ↓
Pattern matched → Show prompt → y/N
       ↓
   YES (y)              NO (n) or timeout
       ↓                      ↓
Command runs        Command BLOCKED
\`\`\`

## License

MIT — see [LICENSE](./LICENSE)

## Contributing

Issues and PRs welcome. This is early software.

---

Built by [@oneaboveallms](https://github.com/oneaboveallms) after watching too many AI agents delete production databases.
