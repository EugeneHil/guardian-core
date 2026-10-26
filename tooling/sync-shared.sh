#!/usr/bin/env bash
# Copy the shared repository tooling from guardian-core into another Guardian repo.
# Idempotent: running it twice produces no further changes.
# Usage: tooling/sync-shared.sh <target-repo-dir>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <target-repo-dir>" >&2
  exit 2
fi

src=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd -P)
dst=$(CDPATH='' cd -- "$1" && pwd -P)
[ "$src" != "$dst" ] || { echo "target must differ from guardian-core" >&2; exit 2; }

mkdir -p "$dst/tooling/claude" "$dst/.claude" "$dst/.github/workflows"

cp "$src/tooling/claude/guard.py" "$src/tooling/claude/test_guard.py" "$dst/tooling/claude/"
cp "$src/.claude/settings.json" "$dst/.claude/settings.json"
cp "$src/tooling/repo/.pre-commit-config.yaml" "$src/tooling/repo/.gitleaks.toml" "$dst/"
cp "$src/tooling/repo/pull_request_template.md" "$dst/.github/pull_request_template.md"
cp "$src/tooling/github/workflows/gitleaks.yml" "$dst/.github/workflows/gitleaks.yml"
[ -f "$dst/.github/dependabot.yml" ] || cp "$src/tooling/github/dependabot.yml" "$dst/.github/dependabot.yml"

marker="# --- guardian shared ignores"
# Former name of the block (before the Warden -> Guardian rename): replace it once, never duplicate it.
old_start="# --- warden shared ignores"
old_end="# --- end warden shared ignores"
if ! grep -qF "$marker" "$dst/.gitignore" 2>/dev/null; then
  if grep -qF "$old_start" "$dst/.gitignore" 2>/dev/null; then
    python3 -I -B - "$dst/.gitignore" "$src/tooling/repo/gitignore.base" "$old_start" "$old_end" <<'PY'
import sys

path, base, old_start, old_end = sys.argv[1:5]
with open(path, encoding="utf-8") as fh:
    lines = fh.read().splitlines(keepends=True)
with open(base, encoding="utf-8") as fh:
    block = fh.read()
start = next(i for i, line in enumerate(lines) if line.startswith(old_start))
end = next((i for i in range(start, len(lines)) if lines[i].startswith(old_end)), None)
if end is None:
    sys.exit("old shared-ignores block has no end marker; fix " + path + " by hand")
if not block.endswith("\n"):
    block += "\n"
with open(path, "w", encoding="utf-8") as fh:
    fh.write("".join(lines[:start]) + block + "".join(lines[end + 1:]))
PY
  else
    cat "$src/tooling/repo/gitignore.base" >> "$dst/.gitignore"
  fi
fi

[ -f "$dst/CLAUDE.md" ] || cp "$src/tooling/repo/CLAUDE.base.md" "$dst/CLAUDE.md"

echo "synced shared tooling into $dst"
