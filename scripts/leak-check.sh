#!/usr/bin/env bash
#
# Run the integration suite against an AddressSanitizer build of elodin and fail
# if anything was leaked, freed twice, or used after being freed.
#
# This is the layer the unit tests cannot reach. `odin test` tracks the memory
# each test allocates, which catches a library procedure that keeps what it was
# lent — but a good deal of this codebase's memory is owned by the running
# server rather than by any procedure a test calls: the configuration, the
# listeners' TLS contexts, a race worker's heap allocations. None of that is
# exercised by a unit test, and all of it has leaked at some point.
#
# So the artefact under test here is the binary, driven by the same integration
# suite that already runs it, with LeakSanitizer watching. `--graceful-stop`
# makes the suite ask each server to exit rather than killing it, because a
# sanitizer reports on its way out and a killed process never gets there.
#
# ASAN_OPTIONS writes one report per process into a directory rather than to
# stderr, where it would be interleaved with the suite's own output and with
# every server's log. An empty directory at the end is the pass condition.

set -euo pipefail

BIN=bin/elodin-asan
REPORTS=bin/leak-reports

: "${ELODIN_LDFLAGS:=}"
: "${ELODIN_DEFINES:=}"

rm -rf "$REPORTS"
mkdir -p "$REPORTS" bin

echo "==> building $BIN with -sanitize:address"
# shellcheck disable=SC2086
odin build src/main \
	-out:"$BIN" \
	-collection:elodin=src \
	-debug \
	-sanitize:address \
	-extra-linker-flags:"$ELODIN_LDFLAGS" \
	$ELODIN_DEFINES

echo "==> building bin/itest"
# shellcheck disable=SC2086
odin build src/itest \
	-out:bin/itest \
	-collection:elodin=src \
	-extra-linker-flags:"$ELODIN_LDFLAGS" \
	$ELODIN_DEFINES

# A report with nothing but hex offsets in it is a report nobody reads. ASan
# symbolizes for itself when it can find llvm-symbolizer, so point it at one if
# the machine has it under a versioned name; `addr2line -e bin/elodin-asan` is
# the fallback for whoever reads the log.
if [ -z "${ASAN_SYMBOLIZER_PATH:-}" ]; then
	for candidate in llvm-symbolizer llvm-symbolizer-20 llvm-symbolizer-19 llvm-symbolizer-18; do
		if command -v "$candidate" >/dev/null 2>&1; then
			ASAN_SYMBOLIZER_PATH=$(command -v "$candidate")
			export ASAN_SYMBOLIZER_PATH
			break
		fi
	done
fi

echo "==> running the integration suite against $BIN"
# `exitcode=0` so a leak does not fail the elodin process itself: several cases
# assert on the exit code they get, and a sanitizer turning a clean shutdown
# into a failure would report itself as those cases breaking rather than as the
# leak it found. The reports below are what this job judges.
ASAN_OPTIONS="detect_leaks=1:exitcode=0:log_path=$PWD/$REPORTS/asan" \
	./bin/itest --graceful-stop --binary "$BIN" "$@"

# The suite's own result still counts: a sanitizer build that cannot answer a
# query is a finding too, and `set -e` has already failed the job if so.

shopt -s nullglob
reports=("$REPORTS"/asan.*)
if [ ${#reports[@]} -eq 0 ]; then
	echo "==> no leaks, bad frees or use-after-free reported"
	exit 0
fi

echo
echo "==> AddressSanitizer reported findings in ${#reports[@]} process(es):"
echo
for report in "${reports[@]}"; do
	echo "--- $report"
	cat "$report"
	echo
done
echo "To symbolize a frame by hand: addr2line -f -C -e $BIN 0x<offset>"
exit 1
