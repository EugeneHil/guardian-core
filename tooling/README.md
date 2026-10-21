# Shared tooling

Everything in `tooling/` is authored here once and copied into `warden-macos` and `warden-server` by `tooling/sync-shared.sh <target-repo-dir>` (idempotent).

| Path | Purpose |
|---|---|
| `claude/guard.py` | Claude Code PreToolUse hook: blocks secret-file access (incl. globs, variables, substitutions, interpreter code), commits/pushes on `main`/`develop` (also via `git -C`, `bash -c`, `+ref`, `HEAD:main`), force push, `--no-verify`/`-n`/`core.hooksPath`, and edits to itself and `.claude/settings*.json`. Fails closed; runs on the stock macOS Python 3.9. Best-effort: it is a seatbelt against agent mistakes, not a sandbox. |
| `repo/` | Templates: `.gitignore` base, pre-commit config, gitleaks config, PR template, `CLAUDE.md` base. |
| `github/` | Rulesets (`ruleset-develop.json`: squash + linear history; `ruleset-main.json`: merge commits allowed so release PRs do not drift), gitleaks workflow, Dependabot config, idempotent `bootstrap-repo.sh`. |

## Secret guards — verified

Three independent layers keep secrets out of the repositories. Each was exercised with a fake AWS key pair on 2026-10-20:

1. **Local pre-commit (gitleaks)** — the commit was aborted by rule `aws-access-token`; no commit was created.
2. **Commit message (conventional-pre-commit)** — a `wip stuff` message was rejected.
3. **GitHub push protection** — a commit made with hooks disabled (`core.hooksPath=/dev/null`) was rejected on push with `GH013` (Amazon AWS Access Key ID and Secret Access Key detected); the branch never reached the remote. The required `gitleaks` status check is the further backstop on every PR.

## Local checks

```
python3 -I -B -m unittest discover -s tooling/claude -v   # guard hook tests
pre-commit run --all-files
```
