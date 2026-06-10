#!/usr/bin/env bash
# Spin up a sibling git worktree for parallel amd64 debug sprints.
#
# Per R-amd64e's op-finding (cloud-boot/docs/m6-2-edk2-upstream-investigation.md §15):
# parallel agents kept switching the main tamago-uefi working tree's branch
# back and forth mid-build, breaking each other's incremental builds. The
# clean pattern is one sibling worktree per concurrent amd64 sprint, each
# on its own branch.
#
# Usage:
#
#     ./internal/scripts/worktree-amd64.sh r-amd64f
#     ./internal/scripts/worktree-amd64.sh r-amd64g
#
# Creates ../tamago-uefi-<name>/ as a sibling worktree on a new branch
# m6-2-pr2-amd64-wip-<name> based on origin/main.
#
# Cleanup:
#
#     git worktree remove ../tamago-uefi-<name>
#     git branch -D m6-2-pr2-amd64-wip-<name>     # if the branch is no longer needed
#
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
    echo "usage: $0 <sprint-suffix>" >&2
    echo "  e.g.  $0 r-amd64f" >&2
    exit 2
fi

SUFFIX="$1"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PARENT_DIR="$(dirname "$REPO_DIR")"
WORKTREE_DIR="$PARENT_DIR/tamago-uefi-$SUFFIX"
BRANCH="m6-2-pr2-amd64-wip-$SUFFIX"

if [[ -e "$WORKTREE_DIR" ]]; then
    echo "$WORKTREE_DIR already exists. Remove it first with:" >&2
    echo "  git worktree remove $WORKTREE_DIR" >&2
    exit 1
fi

cd "$REPO_DIR"
git fetch origin main
git worktree add "$WORKTREE_DIR" -b "$BRANCH" origin/main

cat <<EOF

Worktree ready:

  cd $WORKTREE_DIR
  # branch: $BRANCH (tracks origin/main as base)

When done:

  cd $REPO_DIR
  git worktree remove $WORKTREE_DIR
  # optional: git branch -D $BRANCH (if not pushed / not needed)

EOF
