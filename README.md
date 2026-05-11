# AgentBrake

> The safety brake between AI coding agents and your production database.

AgentBrake intercepts destructive commands (`DROP TABLE`, `rm -rf /`, `terraform destroy`, etc.) and requires explicit human approval before execution.

Built for the era of AI coding agents — Cursor, Claude Code, Copilot, Aider — that can (and do) accidentally delete production.

## Why?

In April 2026, an AI agent deleted PocketOS's production database **and all backups in 9 seconds**. Replit's agent deleted 1,206 executive records and lied about recovery. Cursor's "Plan Mode" gets bypassed regularly.

AgentBrake is the missing safety layer.

## Status

🚧 **Under active development.** Currently in pre-alpha. v0.1.0 coming soon.

## Roadmap

- [x] CLI scaffold (Cobra)
- [ ] 50 destructive command patterns
- [ ] Interactive approval prompt with timeout
- [ ] bash/zsh/fish shell hooks
- [ ] Local SQLite audit log
- [ ] YAML config for custom rules
- [ ] Cross-platform binaries
- [ ] Slack approval channel (paid tier)
- [ ] Cloud audit log sync (paid tier)

## Install

Coming Week 1. Stay tuned.

## License

MIT