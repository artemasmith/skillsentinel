#!/usr/bin/env bash
# Apply repo description + topics from repo-metadata.json to GitHub.
# Requires: gh CLI authenticated with repo admin scope for artemasmith/skillsentinel.
set -euo pipefail
REPO="artemasmith/skillsentinel"
META="$(cd "$(dirname "$0")" && pwd)/repo-metadata.json"

# 1) description + homepage
gh api -X PATCH "repos/$REPO" \
  -f description="$(python3 -c 'import json;print(json.load(open("'$META'"))["description"])')" \
  -f homepage="$(python3 -c 'import json;print(json.load(open("'$META'"))["homepage"])')"

# 2) topics (single call, replaces the whole list)
gh api -X PUT "repos/$REPO/topics" \
  -H "Accept: application/vnd.github.mercy-preview+json" \
  --input - <<<"$(python3 -c 'import json;print(json.dumps({"names": json.load(open("'$META'"))["topics"]}))')"

echo "metadata applied to $REPO"
