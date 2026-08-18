/*
Self-contained SanitizerCoverage runtime for elodin's `mise run coverage` build.

Odin has no coverage instrumentation of its own, but `odin build
-build-mode:llvm-ir` emits LLVM IR that clang can instrument, exactly as the
fuzz targets already do. Building the server that way with
`-fsanitize-coverage=trace-pc-guard,pc-table` gives two parallel tables:

  * the PC table (pc-table) — every instrumented point, known at startup, so it
    is the denominator: total lines that could be covered.
  * the guards (trace-pc-guard) — one per point, flipped the first time that
    point runs, so the set of flipped guards is the numerator.

Two things make this fit the integration suite without touching any test code:

  * The hit bitmap is mmap'd to a file, so a point's "covered" bit is on disk
    the instant it is set. The suite stops most servers with SIGKILL (see
    src/itest/harness.odin), which no atexit or signal handler survives — but a
    memory-mapped byte does.
  * Each server process writes its own files ($ELODIN_COV_DIR/cov.<pid>.*), so
    the many processes the suite spawns never clobber one another; the reporter
    OR-merges the bitmaps afterwards.

No sanitizer runtime, no libFuzzer, no sancov tool: just this file and
addr2line. Built non-PIE so a recorded PC is the static address addr2line
expects, with no load-bias arithmetic.
*/
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

static const char *cov_dir(void) {
	const char *d = getenv("ELODIN_COV_DIR");
	return (d && *d) ? d : ".";
}

// A file mmap'd for the lifetime of the process. `base` stays mapped so writes
// keep landing in the file even after the fd is closed.
static void *map_file(const char *suffix, size_t bytes) {
	char path[4096];
	snprintf(path, sizeof path, "%s/cov.%d.%s", cov_dir(), (int)getpid(), suffix);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return 0;
	void *base = 0;
	if (ftruncate(fd, (off_t)bytes) == 0) {
		base = mmap(0, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (base == MAP_FAILED) base = 0;
	}
	close(fd);
	return base;
}

static uint8_t *g_hits;             // one byte per instrumented point
static const uint32_t *g_guards;    // start of the guard array; index = guard - start

// pc-table: the full set of instrumented PCs, known at startup. Persist it so
// the reporter can name every point, hit or not. Every process writes an
// identical copy; the reporter uses whichever it finds first.
// cppcheck-suppress unusedFunction // called by the coverage instrumentation
void __sanitizer_cov_pcs_init(const uintptr_t *beg, const uintptr_t *end) {
	// Entries are pairs: (PC, flags). We only need the PCs.
	size_t npairs = (size_t)(end - beg) / 2;
	if (!npairs) return;
	uint64_t *out = map_file("pcs", (npairs + 1) * sizeof(uint64_t));
	if (!out) return;
	out[0] = npairs;
	for (size_t i = 0; i < npairs; i++) out[i + 1] = (uint64_t)beg[i * 2];
}

// cppcheck-suppress unusedFunction // called by the coverage instrumentation
void __sanitizer_cov_trace_pc_guard_init(const uint32_t *start, const uint32_t *stop) {
	size_t n = (size_t)(stop - start);
	if (!n) return;
	g_guards = start;
	g_hits = map_file("hits", n);
}

// cppcheck-suppress unusedFunction // called at every instrumented edge
void __sanitizer_cov_trace_pc_guard(const uint32_t *guard) {
	if (!g_hits) return;
	size_t idx = (size_t)(guard - g_guards);
	g_hits[idx] = 1;
}
