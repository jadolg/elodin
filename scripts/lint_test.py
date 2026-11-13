#!/usr/bin/env python3
"""Each lint rule fires on what it names and stays quiet on what it allows."""
# Run by `mise run check`.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint  # noqa: E402

PROD, TEST, HTTP = "src/dns/x.odin", "src/dns/x_test.odin", "src/h2/x.odin"

# (rules, path, line, rule expected to fire or None)
LINES = [
    (lint.TREE, PROD, 'if strings.equal_fold(a, "DS") {', "equal-fold"),
    (lint.TREE, TEST, 'testing.expect(t, strings.equal_fold(a, b))', None),
    (lint.TREE, HTTP, "v := strings.trim_space(raw)", "trim-space-http"),
    (lint.TREE, "src/yaml/x.odin", "v := strings.trim_space(raw)", None),
    (lint.TREE, PROD, 'n, ok := strconv.parse_uint(s)', "strconv-int"),
    (lint.TREE, "src/metrics/x.odin", 'n, ok := strconv.parse_u64(s)', None),
    (lint.TREE, PROD, 'v, ok := strconv.parse_f64(s)', None),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) {', "case-map"),
    (lint.TREE, PROD, "// see resolver.odin:12", "line-number"),
    (lint.TREE, PROD, "/* see resolver.odin:12 */", "line-number"),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) { // lint:allow names are ASCII', None),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) { // lint:allow', "case-map"),
    (lint.ADDED, TEST, "x, _ := f()", "discard"),
    (lint.ADDED, TEST, "_ = f()", "discard"),
    (lint.ADDED, PROD, "_ = f()", None),
    (lint.ADDED, TEST, "for _, v in xs {", None),
    (lint.ADDED, TEST, "time.sleep(time.Millisecond)", "sleep"),
    (lint.ADDED, TEST, "start := time.now()", "wall-clock"),
    (lint.ADDED, PROD, "// the fix makes this hold", "narration"),
    (lint.ADDED, PROD, "// it holds no longer than max_ttl", None),
]

SOURCES = [
    ('testing.expect(t, ok, "got %v")\n', True),
    ('testing.expect(t, ok, "got %v") // note\n', True),
    ('testing.expect(\n\tt,\n\tok,\n\t"got %d",\n)\n', True),
    ('testing.expect(t, !os.exists(fmt.tprintf("%s.tmp", p)), "left behind")\n', False),
    ('testing.expect(t, f(")", "%"), "plain")\n', False),
    ('testing.expect(t, ok, "100\\" done")\n', False),
    ('testing.expect(t, ok, "a \\") b %v")\n', True),
    ('testing.expectf(t, ok, "got %v", x)\n', False),
    ('testing.expect(t, ok, "got %v") // lint:allow a literal percent\n', False),
]

failures = []
for rules, path, line, want in LINES:
    hits = []
    lint.check(rules, path, 1, line, hits)
    got = hits[0].split(": ")[1] if hits else None
    if got != want:
        failures.append(f"{path}: {line!r}: got {got}, want {want}")
for source, want in SOURCES:
    hits = []
    lint.expect_formats(TEST, source, hits)
    if bool(hits) != want:
        failures.append(f"expect-format on {source!r}: got {bool(hits)}, want {want}")

for f in failures:
    print(f, file=sys.stderr)
sys.exit(1 if failures else 0)
