#!/usr/bin/env bash
# Usage: check-public-safe.sh <base> <head>
# Reads PR_TITLE, PR_BODY and HEAD_REF from the environment when they are set.
set -euo pipefail

base=$1
head=$2
patterns=.github/public-safe-patterns.txt
regex=$(grep -v -E '^(#|$)' "$patterns" | paste -sd '|' -)
found=0

check() {
  local hits
  hits=$(printf '%s\n' "$2" | grep -n -E "$regex" || true)
  if [ -n "$hits" ]; then
    echo "::error::Internal text in $1:"
    printf '%s\n' "$hits"
    found=1
  fi
}

check "the branch name" "${HEAD_REF:-}"
check "the pull request title" "${PR_TITLE:-}"
check "the pull request body" "${PR_BODY:-}"

# A sign-off names the contributor on purpose, so trailers are left out.
for commit in $(git rev-list "$base..$head"); do
  check "commit $(git log -1 --format='%h %s' "$commit")" "$(git log -1 --format=%B "$commit" | grep -v -E '^(Signed-off-by|Co-authored-by):' || true)"
done

check "the added lines" "$(git diff "$base...$head" -- . ":(exclude)$patterns" | grep '^+' | grep -v '^+++' || true)"

if [ "$found" -ne 0 ]; then
  echo "Remove the text above, as CONTRIBUTING.md explains under \"Keep internal details out\"."
  exit 1
fi
echo "Nothing internal found."
