#!/usr/bin/env python3
"""Refuse the code patterns review rounds and the #638 audit kept finding."""
# Two kinds of rule. TREE rules hold for every line in src/ and fail on any hit.
# ADDED rules hold only for lines this branch adds (`git diff` against LINT_BASE,
# by default the merge base with origin/main), because the tree has older
# instances that are correct where they stand. A line carrying `lint:allow`
# followed by a reason is exempt from both. `testing.expect` calls are read
# whole, across lines, since the format sits in the last argument.
import os
import re
import subprocess  # nosec B404: fixed argument lists, no shell
import sys

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()  # nosec B603 B607
ALLOW = re.compile(r"lint:allow\s+\S")


def is_test(path):
    return path.endswith("_test.odin") or path.startswith(("src/itest/", "src/fuzz/"))


def is_http(path):
    name = os.path.basename(path)
    return path.startswith("src/h2/") or (
        path.startswith(("src/upstream/", "src/server/")) and name.startswith(("http", "doh"))
    )


# Files that read integers the kernel wrote (/proc, cgroup), not config or wire.
KERNEL_READERS = ("src/metrics/", "src/config/sizing.odin")

# (name, pattern, applies-to-path, message)
TREE = [
    ("equal-fold", r"\bstrings\.equal_fold\(", lambda p: not is_test(p),
     "strings.equal_fold folds Unicode (ſ matches s); use dns.name_equal_fold"),
    ("trim-space-http", r"\bstrings\.trim_space\(", is_http,
     "strings.trim_space strips NBSP, VT and FF, which are not HTTP OWS; use trim_ows"),
    ("strconv-int", r"\bstrconv\.(parse_(int|uint|i(8|16|32|64|128)|u(8|16|32|64|128))(_of_base|_maybe_prefixed)?|atoi)\(",
     lambda p: not is_test(p) and not p.startswith(KERNEL_READERS),
     "strconv's integer parsers take + and _ and wrap on overflow; read digits-only and bounded (parse_rdata_u16)"),
    ("case-map", r"\bstrings\.to_(lower|upper)\(", lambda p: not is_test(p),
     "strings.to_lower maps non-ASCII letters onto ASCII ones (U+0130 to i); use dns.name_fold"),
    ("line-number", r"\.odin:[0-9]+", lambda p: True,
     "name the symbol, not a line number, which goes stale"),
    ("posix-open-flags",
     r"posix\.(open|openat)\(.*\.(DIRECTORY|NOFOLLOW|DIRECT|LARGEFILE)\b"
     r"|posix\.O_Flags\{.*\.(DIRECTORY|NOFOLLOW|DIRECT|LARGEFILE)\b",
     lambda p: True,
     "core:sys/posix's O_DIRECTORY, O_NOFOLLOW, O_DIRECT and O_LARGEFILE are the x86 values on every architecture; open with core:sys/linux"),
]

ADDED = [
    # Tests only: a fixture that cannot be built must fail the test there. In
    # production a best-effort write or close is a deliberate discard.
    ("discard", r"(,\s*_\s*:?=\s)|^\s*_\s*=\s", is_test,
     "a test never discards an error or ok; check it, or say why with lint:allow"),
    ("sleep", r"\btime\.sleep\(", is_test,
     "wait on an event (sema, cond, wait_for_log), not a duration"),
    ("wall-clock", r"\btime\.now\(", is_test,
     "measure durations with time.tick_now, not the wall clock"),
    ("narration", r"\b(before this (change|fix|PR)|the fix\b|this (change|PR)\b|today\b)", lambda p: True,
     "describe the code as it is, not its history or this PR"),
]


def odin_files():
    out = subprocess.run(["git", "ls-files", "src/*.odin", "scripts/*.odin"], cwd=ROOT,  # nosec B603 B607
                         capture_output=True, text=True, check=True).stdout
    return out.split()


def added_lines(base):
    # Prefixes fixed, so a user's diff.noprefix or diff.mnemonicPrefix can't hide the paths.
    diff = subprocess.run(["git", "diff", "-U0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
                           base, "--", "*.odin"], cwd=ROOT,  # nosec B603 B607
                          capture_output=True, text=True, check=True).stdout
    path, line = None, 0
    for text in diff.splitlines():
        if text.startswith("+++ "):
            path = text[6:] if text.startswith("+++ b/") else None
        elif text.startswith("@@"):
            line = int(re.match(r"@@ -\S+ \+(\d+)", text).group(1))
        elif text.startswith("+") and path:
            yield path, line, text[1:]
            line += 1


def check(rules, path, n, text, hits):
    if ALLOW.search(text):
        return
    for name, pattern, applies, message in rules:
        if applies(path) and re.search(pattern, text):
            hits.append(f"{path}:{n}: {name}: {message}\n    {text.strip()}")


def skip_literal(source, i):
    """The index of the quote closing the literal opened at `i`, escapes and raw strings respected."""
    quote = source[i]
    if quote == "`":
        end = source.find("`", i + 1)
        return len(source) if end < 0 else end
    i += 1
    while i < len(source) and source[i] != quote:
        i += 2 if source[i] == "\\" else 1
    return i


def call_args(source, i):
    """The arguments of the call whose `(` ends just before `i`, as written."""
    depth, args, start = 1, [], i
    while i < len(source) and depth:
        c = source[i]
        if c in "\"'`":
            i = skip_literal(source, i)
        elif c in "([{)]}":
            depth += 1 if c in "([{" else -1
        elif c == "," and depth == 1:
            args.append(source[start:i])
            start = i + 1
        i += 1
    args.append(source[start:i - 1])
    return [a.strip() for a in args if a.strip()]


def expect_formats(path, source, hits):
    """`testing.expect` calls, however many lines they span, whose last argument is a string holding `%`."""
    for m in re.finditer(r"\btesting\.expect\(", source):
        line_start = source.rfind("\n", 0, m.start()) + 1
        if "//" in source[line_start:m.start()]:
            continue
        given = call_args(source, m.end())
        n = source.count("\n", 0, m.start()) + 1
        line = source.splitlines()[n - 1]
        if given and re.fullmatch(r'"(?:[^"\\]|\\.)*%(?:[^"\\]|\\.)*"', given[-1]) and not ALLOW.search(line):
            hits.append(f"{path}:{n}: expect-format: testing.expect does not format its message; use testing.expectf\n    {line.strip()}")


def test_only_procs(sources, hits):
    """Exported procedures outside test files that nothing outside test files calls.

    A procedure only tests use lives in a test file of its package. The itest
    and fuzz packages are callers in their own right: they cannot reach another
    package's test files. `@(private)` procedures and `@(init)` ones the runtime
    calls are left out, and a cross-package test seam says why with lint:allow.
    """
    callers = {path: src for path, src in sources.items() if not path.endswith("_test.odin")}
    for path, source in callers.items():
        if is_test(path):
            continue
        lines = source.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^([a-z_][a-z0-9_]*) :: proc\b", line)
            if not m or ALLOW.search(line):
                continue
            attrs = "\n".join(lines[max(0, i - 3):i])
            if "@(private" in attrs or "@(init" in attrs:
                continue
            word = re.compile(r"\b" + re.escape(m.group(1)) + r"\b")
            uses = sum(len(word.findall(src)) for src in callers.values())
            if uses <= 1:
                hits.append(f"{path}:{i + 1}: test-only: {m.group(1)} has no caller outside test files; "
                            f"move it to a test file of its package\n    {line.strip()}")


def resolve_base():
    base = os.environ.get("LINT_BASE")
    if not base:
        r = subprocess.run(["git", "merge-base", "origin/main", "HEAD"], cwd=ROOT, capture_output=True, text=True)  # nosec B603 B607
        if r.returncode != 0:
            sys.exit("lint: no merge base with origin/main; fetch it or set LINT_BASE")
        base = r.stdout.strip()
    return base


def main():
    hits = []
    sources = {}
    for path in odin_files():
        with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
            source = f.read()
        sources[path] = source
        for n, text in enumerate(source.splitlines(), 1):
            check(TREE, path, n, text, hits)
        expect_formats(path, source, hits)
    test_only_procs(sources, hits)
    for path, n, text in added_lines(resolve_base()):
        check(ADDED, path, n, text, hits)
    for h in hits:
        print(h, file=sys.stderr)
    if hits:
        sys.exit(f"lint: {len(hits)} finding(s); fix each, or mark a deliberate one `{ALLOW} <reason>`")


if __name__ == "__main__":
    main()
