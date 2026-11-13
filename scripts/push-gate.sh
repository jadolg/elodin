#!/usr/bin/env bash
# Run the local gates on this branch, and push only if every one passed.
#
#   scripts/push-gate.sh [--leak] [--fuzz] [-- <git push args>]
#
# --leak adds `mise run leakcheck` (the change allocates or frees), --fuzz adds
# `mise run fuzz-regression` (a parser changed). Anything after `--` goes to
# `git push`.
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

git fetch -q origin
echo "== branch against origin/main"
git diff --stat "$(git merge-base origin/main HEAD)" HEAD | tail -n 1
behind=$(git rev-list --count HEAD..origin/main)
[ "$behind" = 0 ] || echo "note: $behind commit(s) behind origin/main; the merge gate will ask for a rebase"

mise run verify
mise run parity-regression
if [ "$leak" = 1 ]; then
	# An ASan server can grow to gigabytes; cap it so the OOM killer takes it
	# rather than the terminal it runs under.
	if command -v systemd-run >/dev/null && systemd-run --user --scope --quiet true 2>/dev/null; then
		systemd-run --user --scope --quiet -p MemoryMax=3G -- mise run leakcheck
	else
		mise run leakcheck
	fi
fi
if [ "$fuzz" = 1 ]; then mise run fuzz-regression; fi

git push "$@"
