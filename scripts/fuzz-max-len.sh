#!/usr/bin/env bash
# Print the -max_len flag for fuzz target $1, or nothing if it keeps libFuzzer's
# default cap: 4 KB, or the largest seed input if that is longer.
#
# With it goes -len_control=0. Left to itself libFuzzer starts near the seeds'
# length and raises its limit slowly - in a 20-minute nightly the http and doh
# targets reached 5.6 KB and 17 KB of their 64 KB - so a target that declares
# long inputs are what it needs is given them from the first run.
#
# A target that needs longer inputs says so in
# testdata/fuzz-corpus/<target>.max_len, next to its dict: `#` lines say why it
# needs it, empty lines are skipped, and the one other line is the cap, a bare
# number. Any other line, a second number, or
# 0 (libFuzzer's "use the default") is an error rather than a quiet fall back to
# the default. Nine digits at most, as libFuzzer reads the flag into an int and
# an overflow wraps.
#
# The nightly fuzz job reads the cap through this, and `fuzz-regression` checks
# every file, so a malformed file fails on the PR that adds it.
set -euo pipefail
cd "$(dirname "$0")/.."

f=testdata/fuzz-corpus/$1.max_len
[ -f "$f" ] || exit 0
len=$(grep -v -e '^#' -e '^$' "$f" || true)
if ! [[ $len =~ ^[1-9][0-9]{0,8}$ ]]; then
  echo "::error file=$f::needs exactly one line that is not a # comment, a bare number above 0" >&2
  exit 1
fi
echo "-max_len=$len -len_control=0"
