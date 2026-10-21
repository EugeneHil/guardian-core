#!/usr/bin/env bash
# Publish a local Warden repo to GitHub as a public repository and apply the
# shared protection settings. Idempotent: safe to re-run to update settings and
# rulesets. Run from the repo root after the bootstrap commit exists on
# `develop` and a local `main` branch points at it.
#
# Rulesets: `develop` forces squash + linear history; `main` allows merge
# commits so release PRs (develop -> main) never make the branches drift.
# Usage: <warden-core>/tooling/github/bootstrap-repo.sh <name> "<description>"
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <name> \"<description>\"" >&2
  exit 2
fi

name=$1
description=$2
here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd -P)
login=$(gh api user -q .login)
repo="$login/$name"

if gh repo view "$repo" >/dev/null 2>&1; then
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$repo.git"
else
  gh repo create "$repo" --public --description "$description" --source . --remote origin
fi
# Push only branches the remote lacks: protected branches reject direct pushes.
for branch in develop main; do
  git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1 || git push -u origin "$branch"
done

gh repo edit "$repo" \
  --default-branch develop \
  --delete-branch-on-merge \
  --enable-squash-merge \
  --enable-merge-commit \
  --enable-rebase-merge=false >/dev/null

gh api -X PATCH "repos/$repo" --input - >/dev/null <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON

ruleset_id() {
  gh api "repos/$repo/rulesets" -q ".[] | select(.name == \"$1\") | .id" | head -1
}

# Replace the legacy single ruleset.
legacy=$(ruleset_id protected-branches)
[ -z "$legacy" ] || gh api -X DELETE "repos/$repo/rulesets/$legacy" >/dev/null

# Upsert: create when missing, otherwise update in place.
for file in "$here"/ruleset-*.json; do
  rs_name=$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$file")
  id=$(ruleset_id "$rs_name")
  if [ -n "$id" ]; then
    gh api -X PUT "repos/$repo/rulesets/$id" --input "$file" >/dev/null
  else
    gh api -X POST "repos/$repo/rulesets" --input "$file" >/dev/null
  fi
done

echo "bootstrapped https://github.com/$repo"
