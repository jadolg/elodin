#!/usr/bin/env bash
# Run the local gates on this branch, and push only if every one passed.
#
#   scripts/push-gate.sh [--leak] [--fuzz] [-- <git push args>]
#
# --leak adds `mise run leakcheck` (the change allocates or frees), --fuzz adds
# `mise run fuzz-regression` (a parser changed). Anything after `--` goes to
# `git push`; without it the branch is pushed to origin under its own name,
# whatever its upstream (a worktree made from origin/main tracks main).
#
# The gates run on the working tree and the push sends HEAD, so a tree with
# anything uncommitted or untracked is refused before either.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

leak=0 fuzz=0
while [ $# -gt 0 ]; do
	case "$1" in
	--leak) leak=1 ;;
	--fuzz) fuzz=1 ;;
	--) shift; break ;;
	*) echo "push-gate: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

# A slow clock fails gh's TLS, live DNSSEC and every deadline test.
if command -v chronyc >/dev/null; then
	off=$(chronyc tracking | awk '/^System time/ {print $4}')
	if awk -v o="${off:-0}" 'BEGIN {exit !(o > 1)}'; then
		echo "push-gate: the clock is ${off}s off NTP; run: sudo chronyc makestep" >&2
		exit 1
	fi
fi

if [ -n "$(git status --porcelain)" ]; then
	git status --short >&2
	echo "push-gate: commit or remove these first: the gates would test them and the push would not send them" >&2
	exit 1
fi

git fetch -q origin
# Every file the branch changes. One you did not touch means the base moved
# under the commit (a `reset --soft` onto a newer main reverts its merges).
echo "== files this branch changes against origin/main"
git diff --stat origin/main...HEAD
behind=$(git rev-list --count HEAD..origin/main)
[ "$behind" = 0 ] || echo "note: $behind commit(s) behind origin/main; the merge gate will ask for a rebase"

mise run verify
mise run parity-regression
if [ "$leak" = 1 ]; then
	# An ASan server can grow to gigabytes; cap it so the OOM killer takes it
	# rather than the terminal it runs under.
	# Refused rather than run uncapped where there is no user systemd.
	if ! systemd-run --user --scope --quiet true 2>/dev/null; then
		echo "push-gate: --leak needs systemd-run --user to cap the ASan build's memory" >&2
		exit 1
	fi
	systemd-run --user --scope --quiet -p MemoryMax=3G -- mise run leakcheck
fi
if [ "$fuzz" = 1 ]; then mise run fuzz-regression; fi

if [ $# -eq 0 ]; then
	set -- -u origin HEAD
fi
git push "$@"
