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
    (lint.TREE, PROD, 'n, ok := strconv.parse_i64_of_base(s, 10)', "strconv-int"),
    (lint.TREE, PROD, 'n, ok := strconv.parse_u64_maybe_prefixed(s)', "strconv-int"),
    (lint.TREE, PROD, 'n := strconv.atoi(s)', "strconv-int"),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) {', "case-map"),
    (lint.TREE, PROD, 'import "elodin:testkit"', "testkit-import"),
    (lint.TREE, TEST, 'if err == .Timeout || err == .Would_Block {', "timed-out"),
    (lint.TREE, PROD, 'return e == .Would_Block || e == .Timeout', "timed-out"),
    (lint.TREE, "src/netx/addr.odin", 'return err == .Timeout || err == .Would_Block', None),
    (lint.TREE, PROD, 'if err == .Timeout {', None),
    (lint.TREE, PROD, 'import tk "elodin:testkit"', "testkit-import"),
    (lint.TREE, TEST, 'import "elodin:testkit"', None),
    (lint.TREE, PROD, 'import tk "../testkit"', "testkit-import"),
    (lint.TREE, PROD, "// see resolver.odin:12", "line-number"),
    (lint.TREE, PROD, "/* see resolver.odin:12 */", "line-number"),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) { // lint:allow names are ASCII', None),
    (lint.TREE, PROD, 'switch strings.to_lower(s, a) { // lint:allow', "case-map"),
    (lint.ADDED, TEST, "x, _ := f()", "discard"),
    (lint.ADDED, TEST, "_ = f()", "discard"),
    (lint.ADDED, PROD, "_ = f()", None),
    (lint.ADDED, TEST, "for _, v in xs {", None),
    (lint.ADDED, TEST, "time.sleep(time.Millisecond)", "sleep"),
    (lint.ADDED, "src/testkit/x.odin", "x, _ := f()", "discard"),
    (lint.ADDED, TEST, "start := time.now()", "wall-clock"),
    (lint.ADDED, TEST, "n, ok := strconv.parse_int(s)", "strconv-int-test"),
    (lint.ADDED, "src/itest/x.odin", "n := strconv.atoi(s)", "strconv-int-test"),
    (lint.ADDED, TEST, "v, ok := strconv.parse_f64(s)", None),
    (lint.ADDED, TEST, "// `strconv.parse_int` would take a sign", None),
    (lint.ADDED, PROD, "// the fix makes this hold", "narration"),
    (lint.ADDED, PROD, "// it holds no longer than max_ttl", None),
    (lint.ADDED, TEST, "// a reader, since there is now one per socket", "narration"),
    (lint.ADDED, TEST, "// the same bytes as before", None),
    (lint.ADDED, TEST, "// the shape of the finding", "narration"),
    (lint.ADDED, PROD, "// there is no finding", None),
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
    ('// call testing.expect() here\n', False),
    ('// testing.expect(t, ok, "got %v")\n', False),
    ('testing.expect()\n', False),
    ("testing.expect(t, c == '(', \"got %v\")\n", True),
    ("testing.expect(t, c == '\\'', \"got %v\")\n", True),
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

# (source, line checked, size-literal expected)
CODE = [
    ("buf: [512]u8\n", 1, True),
    ("n := 1232\n", 1, True),
    ("if len(m) > 65535 {\n", 1, True),
    ("MAX :: 65535\n", 1, False),
    ("n := 1232 // lint:allow the RFC 9715 figure itself\n", 1, False),
    ("n := f() // fits in 512 bytes\n", 1, False),
    ('s := "512 bytes"\n', 1, False),
    ("/*\nthe 1232 ceiling\n*/\n", 2, False),
    ("x := 5120 + 0.512 + v512\n", 1, False),
    ("MAX : u16 : 65535\n", 1, False),
    ("\tbuf: []u8, limit := 1232,\n", 1, True),
    ("\ta: u8, b: [512]u8,\n", 1, True),
    ("outer: for x in buf[:512] {\n", 1, True),
    ("for i in 512..<n {\n", 1, True),
    ("case 1232..=max:\n", 1, True),
    ("for i in 0..<512 {\n", 1, True),
    ("x := 512.0\n", 1, False),
    ("read_reply :: proc(buf: []u8, limit := 1232) -> int {\n", 1, True),
    ("Frame :: struct { data: [512]u8 }\n", 1, True),
    ("/* outer /* inner */ replies over 512 bytes */\n", 1, False),
    ("/* a /* b */ c */ n := 512\n", 1, True),
    ("c := '\"' // 512\n", 1, False),
]
for source, n, want in CODE:
    hits = []
    lint.check_code(TEST, n, source.splitlines()[n - 1], lint.code_only(source), hits)
    if bool(hits) != want:
        failures.append(f"size-literal on {source!r}: got {bool(hits)}, want {want}")

# (sources, procedures the test-only rule should name)
PROCS = [
    ({"src/dns/a.odin": "used :: proc() {}\n", "src/dns/b.odin": "x := used()\n"}, []),
    ({"src/dns/a.odin": "lonely :: proc() {}\n", "src/dns/a_test.odin": "lonely()\n"}, ["lonely"]),
    ({"src/dns/a.odin": "package dns\nharness :: proc() {}\n", "src/itest/c.odin": "dns.harness()\n"}, []),
    ({"src/dns/a.odin": "package dns\nfuzzed :: proc() {}\n", "src/fuzz/dns/f.odin": "dns.fuzzed()\n"}, ["fuzzed"]),
    ({"src/dns/a.odin": "package dns\nboth :: proc() {}\n", "src/fuzz/dns/f.odin": "dns.both()\n", "src/server/x.odin": "dns.both()\n"}, []),
    ({"src/loop/a.odin": "package loop\nwait :: proc() {}\n", "src/loop/b.odin": "sync.wait()\n"}, ["wait"]),
    ({"src/tlsx/a.odin": "package tlsx\nread :: proc() {}\n", "src/itest/c.odin": "read()\n"}, ["read"]),
    ({"src/main/main.odin": "package main\nmain :: proc() {}\n"}, []),
    ({"src/dns/a.odin": "@(private)\n// what it does\nhelper :: proc() {}\n"}, []),
    ({"src/dns/a.odin": "@(test)\ncheck :: proc() {}\n"}, []),
    ({"src/dns/a.odin": "package dns\nopt :: proc() {}\n", "src/server/x.odin": 'import d "elodin:dns"\nx := d.opt()\n'}, []),
    ({"src/dns/a.odin": "seam :: proc() {} // lint:allow read by another package's tests\n"}, []),
    ({"src/dns/a.odin": "@(private)\nhelper :: proc() {}\n"}, []),
    ({"src/dns/a.odin": "@(init)\nstart :: proc() {}\n"}, []),
    ({"src/dns/a_test.odin": "fixture :: proc() {}\n"}, []),
    ({"src/testkit/a.odin": "package testkit\nshared :: proc() {}\n", "src/dns/a_test.odin": "testkit.shared()\n"}, []),
    ({"src/dns/a.odin": "fast :: #force_inline proc() {}\n", "src/dns/a_test.odin": "fast()\n"}, ["fast"]),
    ({"src/dns/a.odin": "twin :: proc() {}\n", "src/cache/b.odin": "twin :: proc() {}\n"}, ["twin", "twin"]),
    ({"src/dns/a.odin": "named :: proc() {}\n", "src/dns/b.odin": "// see named\nx := \"named\"\n"}, ["named"]),
    ({"src/dns/a.odin": "@(private, thread_local)\ntl: int\n\nopen :: proc() {}\n"}, ["open"]),
    ({"src/dns/a.odin": "@(fini)\nstop :: proc() {}\n"}, []),
    ({"src/dns/a.odin": '@(export, link_name = "elodin_cb")\ncb :: proc "c" () {}\n'}, []),
    ({"src/dns/a.odin": "handler :: proc() {}\n", "src/dns/b.odin": "h := handler\n"}, []),
]
for sources, want in PROCS:
    hits = []
    lint.test_only_procs(sources, hits)
    got = sorted(h.split("test-only: ")[1].split(" ")[0] for h in hits)
    if got != want:
        failures.append(f"test-only on {sources!r}: got {got}, want {want}")

for f in failures:
    print(f, file=sys.stderr)
sys.exit(1 if failures else 0)
