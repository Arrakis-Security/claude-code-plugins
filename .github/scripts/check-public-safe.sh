#!/usr/bin/env bash
# Usage: check-public-safe.sh [<base> <head>]
# Reads PR_TITLE, PR_BODY, HEAD_REF and COMMENT_BODY from the environment when they are set.
# Without <base> and <head>, it checks only the text from the environment.
#
# Private patterns, one per line, come from PUBLIC_SAFE_EXTRA_PATTERNS in CI and from the
# git-ignored public-safe-patterns.local.txt in the main checkout on your machine.
set -euo pipefail

base=${1:-}
head=${2:-}
patterns=.github/public-safe-patterns.txt
local_name=.github/public-safe-patterns.local.txt
# A worktree has no copy of an ignored file, so read the one in the main checkout.
local_file="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/$local_name"
in_ci=${GITHUB_ACTIONS:-false}

if [ -n "$(git ls-files -- "$local_name")" ]; then
  echo "::error::$local_name is tracked. Remove it with git rm --cached, because its patterns must stay private."
  exit 1
fi

extra=${PUBLIC_SAFE_EXTRA_PATTERNS:-}
if [ -f "$local_file" ]; then
  extra=$(printf '%s\n%s\n' "$extra" "$(cat "$local_file")")
fi
if [ "$in_ci" = true ] && [ -z "$extra" ]; then
  echo "::warning::No private patterns, so only $patterns is checked. A pull request from a fork gets no secrets."
fi

regex=$(printf '%s\n%s\n' "$(cat "$patterns")" "$extra" | grep -v -E '^[[:space:]]*(#|$)' | paste -sd '|' -)
found=0

# grep exits 2 on a bad pattern, and `|| true` below would read that as "nothing found".
status=0
grep -E "$regex" </dev/null || status=$?
if [ "$status" -gt 1 ]; then
  echo "::error::A pattern is not a valid extended regular expression."
  exit 1
fi

check() {
  local hits
  hits=$(printf '%s\n' "$2" | grep -n -E "$regex" || true)
  if [ -n "$hits" ]; then
    found=1
    # The log of a public repo is public too, so CI names only the line, never its text.
    if [ "$in_ci" = true ] && [ "${3:-}" = no-lines ]; then
      echo "::error::Internal text in $1."
    elif [ "$in_ci" = true ]; then
      echo "::error::Internal text in $1, line $(printf '%s\n' "$hits" | cut -d: -f1 | paste -sd ',' - | sed 's/,/, /g')."
    else
      echo "Internal text in $1:"
      printf '%s\n' "$hits"
    fi
  fi
}

check "the branch name" "${HEAD_REF:-}"
check "the pull request title" "${PR_TITLE:-}"
check "the pull request body" "${PR_BODY:-}"
check "the comment" "${COMMENT_BODY:-}"

if [ -n "$base" ]; then
  # A sign-off names the contributor on purpose, so trailers are left out.
  for commit in $(git rev-list "$base..$head"); do
    check "the message of commit $(git log -1 --format=%h "$commit")" "$(git log -1 --format=%B "$commit" | grep -v -E '^(Signed-off-by|Co-authored-by):' || true)"
  done

  while IFS= read -r -d '' file; do
    check "the added lines of $file" "$(git diff -U0 "$base...$head" -- "$file" | grep '^+' | grep -v '^+++' || true)" no-lines
  done < <(git diff -z --name-only --diff-filter=d "$base...$head" -- . ":(exclude)$patterns")
fi

if [ "$found" -ne 0 ]; then
  echo "Remove the text above, as CONTRIBUTING.md explains under \"Keep internal details out\"."
  [ "$in_ci" = true ] && echo "Run .github/scripts/check-public-safe.sh on your machine to see the text."
  exit 1
fi
echo "Nothing internal found."
