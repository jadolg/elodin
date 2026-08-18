# Coverage

`mise run coverage` writes `bin/coverage.info` (lcov) and CI uploads it to
Codecov, which posts the pull-request comment and serves the README badge.

## Why it looks like this

Odin has no coverage instrumentation. But `odin build -build-mode:llvm-ir`
emits LLVM IR that clang can instrument — the fuzz targets already rely on this.
The coverage build takes the same route for the server itself:

1. `odin build src/main -build-mode:llvm-ir -debug` emits the IR, with `-debug`
   carrying each `.odin` file and line into it.
2. clang links it with `-fsanitize-coverage=trace-pc-guard,pc-table`. That gives
   two parallel tables: the **pc-table** names every instrumented point (the
   denominator), and a **guard** per point flips the first time it runs (the
   numerator).
3. [`cov_rt.c`](cov_rt.c) is the whole runtime — no sanitizer library is linked.
   It mmaps the hit bitmap to a file so a covered bit is on disk the instant it
   is set, which matters because the integration harness stops most servers with
   SIGKILL (see `src/itest/harness.odin`), and nothing else would survive that.
   The binary is linked non-PIE so a recorded PC is the static address
   `addr2line` reads back, with no load bias to undo.
4. The integration suite runs against the instrumented binary. Each server
   process writes its own `cov.<pid>.{pcs,hits}` under `$ELODIN_COV_DIR`.
5. [`cov_report.py`](cov_report.py) OR-merges the bitmaps, symbolizes the PCs
   with `addr2line`, keeps the points under `src/`, and emits lcov.

## What it measures

The share of the server's own code that the **integration suite** exercises —
the shipped binary end to end. It does **not** include the unit tests: those run
in-process under `odin test`, which builds its own executable and cannot be
instrumented through the IR route. Read the number as a trend, not a target;
`codecov.yml` keeps both Codecov statuses informational for the same reason.
