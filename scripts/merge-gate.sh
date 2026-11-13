#!/usr/bin/env bash
# Merge a pull request only when the branch checked out here is its head, is
# not behind main, and every check on that head has passed.
#
#   scripts/merge-gate.sh <pr>
#
# Run it from the PR's worktree, after scripts/push-gate.sh.
set -euo pipefail
pr=${1:?usage: scripts/merge-gate.sh <pr>}
cd "$(git rev-parse --show-toplevel)"
fail() { echo "merge-gate: $*" >&2; exit 1; }

git fetch -q origin
behind=$(git rev-list --count HEAD..origin/main)
[ "$behind" = 0 ] || fail "$behind commit(s) behind origin/main: rebase, run scripts/push-gate.sh, wait for CI, retry"

head=$(git rev-parse HEAD)
pr_head=$(gh pr view "$pr" --json headRefOid -q .headRefOid)
[ -n "$pr_head" ] || fail "gh returned no head for #$pr (a slow clock makes gh print nothing; check chronyc tracking)"
[ "$head" = "$pr_head" ] || fail "local HEAD $head is not the PR head $pr_head: push first"

repo=$(gh repo view --json nameWithOwner -q .nameWithOwner)
# Every check run on the head: none pending, none failed, and the ones every PR
# gets among them, so a head nothing has reported on yet does not pass on an
# empty list.
gh api --paginate "repos/$repo/commits/$head/check-runs?per_page=100" \
	-q '.check_runs[] | [.name, .status, (.conclusion // "")] | @tsv' > "${TMPDIR:-/tmp}/merge-gate-$pr.tsv"
python3 - "${TMPDIR:-/tmp}/merge-gate-$pr.tsv" <<'EOF' || fail "checks are not all green on $head"
import sys
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1]) if line.strip()]
bad = [r for r in rows if r[1] != "completed" or r[2] not in ("success", "skipped", "neutral")]
for name, status, conclusion in bad:
    print(f"  {name}: {status} {conclusion}", file=sys.stderr)
# CI's jobs register together, so its Style check stands for all of them; the
# apps report on their own and may not have started yet.
missing = {"Style check", "Codacy Static Code Analysis", "GitGuardian Security Checks"} - {r[0] for r in rows}
for name in sorted(missing):
    print(f"  {name}: no run on this head yet", file=sys.stderr)
if missing:
    sys.exit(1)
sys.exit(1 if bad else 0)
EOF
state=$(gh api "repos/$repo/commits/$head/status" -q '[.total_count, .state] | @tsv')
case "$state" in 0*|*success) ;; *) fail "commit statuses on $head: $state" ;; esac

# From a worktree, gh merges and then exits 1 trying to check out main locally,
# so the PR's state, not the exit code, says whether it merged.
gh pr merge "$pr" --merge --delete-branch --match-head-commit "$head" || true
[ "$(gh pr view "$pr" --json state -q .state)" = MERGED ] || fail "#$pr did not merge"
echo "merge-gate: #$pr merged at $head"
