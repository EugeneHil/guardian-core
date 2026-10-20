# Shared tooling

Everything in `tooling/` is authored here once and copied into `warden-macos` and `warden-server` by `tooling/sync-shared.sh <target-repo-dir>` (idempotent).

| Path | Purpose |
|---|---|
| `claude/guard.py` | Claude Code PreToolUse hook: blocks secret-file access, commits/pushes on `main`/`develop`, force push, `--no-verify`. Fails closed. |
| `repo/` | Templates: `.gitignore` base, pre-commit config, gitleaks config, PR template, `CLAUDE.md` base. |
| `github/` | Branch-protection ruleset, gitleaks workflow, Dependabot config, `bootstrap-repo.sh`. |

## Secret guards — verified

Three independent layers keep secrets out of the repositories. Each was exercised with a fake AWS key pair on 2026-10-20:

1. **Local pre-commit (gitleaks)** — the commit was aborted by rule `aws-access-token`; no commit was created.
2. **Commit message (conventional-pre-commit)** — a `wip stuff` message was rejected.
3. **GitHub push protection** — a commit made with hooks disabled (`core.hooksPath=/dev/null`) was rejected on push with `GH013` (Amazon AWS Access Key ID and Secret Access Key detected); the branch never reached the remote. The required `gitleaks` status check is the further backstop on every PR.

## Local checks

```
python3 -I -m unittest discover -s tooling/claude -v   # guard hook tests
pre-commit run --all-files
```
