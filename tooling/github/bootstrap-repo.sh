#!/usr/bin/env bash
# Publish a local Warden repo to GitHub as a public repository and apply the
# shared protection settings. Run from the repo root after the bootstrap commit
# exists on `develop` and a local `main` branch points at it.
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
  git push -u origin develop
else
  gh repo create "$repo" --public --description "$description" --source . --remote origin --push
fi
git push origin main

gh repo edit "$repo" \
  --default-branch develop \
  --delete-branch-on-merge \
  --enable-squash-merge \
  --enable-merge-commit=false \
  --enable-rebase-merge=false

gh api -X PATCH "repos/$repo" --input - <<'JSON'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON

if ! gh api "repos/$repo/rulesets" -q '.[].name' | grep -qx protected-branches; then
  gh api -X POST "repos/$repo/rulesets" --input "$here/ruleset-protected.json" >/dev/null
fi

echo "bootstrapped https://github.com/$repo"
