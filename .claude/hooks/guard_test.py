#!/usr/bin/env python3
"""Each guard rule refuses what it names and nothing that only mentions it."""
# Run by `mise run check`. Needs a git checkout: it builds a primary checkout
# and a worktree of it in a temporary directory to judge branch switches.
import os
import subprocess  # nosec B404: fixed argument lists, no shell
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

real_fix_clock = guard.fix_clock
guard.fix_clock = lambda: None  # the clock rule is checked below, apart

with tempfile.TemporaryDirectory() as tmp:
    primary, worktree = os.path.join(tmp, "primary"), os.path.join(tmp, "wt")
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731  # nosec B603
    run("git", "init", "-q", primary)
    run("git", "-C", primary, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x")
    run("git", "-C", primary, "branch", "topic")
    run("git", "-C", primary, "worktree", "add", "-q", "-b", "w", worktree)
    os.makedirs(os.path.join(primary, "src"))
    other = os.path.join(tmp, "other")
    run("git", "init", "-q", other)
    run("git", "-C", other, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x")
    guard.PROJECT_COMMON = guard.git_dirs(primary)[1]

    REFUSED = [
        ("pkill -x elodin", worktree),
        ("sudo killall itest", worktree),
        ("sed -i s/a/b/ f", worktree),
        ("sed -e s/a/b/ -i f", worktree),
        ("sed -E -i.bak s/a/b/ f", worktree),
        ("sed --in-place s/a/b/ f", worktree),
        ("git reset --soft origin/main", worktree),
        ("gh pr merge 5 --merge", worktree),
        ("true && gh pr merge 5", worktree),
        ("git checkout -b x", primary),
        ("git switch foo", primary),
        ("git checkout topic", primary),
        ("git switch foo && git diff -- x", primary),
        (f"git -C {primary} switch foo", worktree),
        ("cd src && git switch foo", primary),
        ("gh pr checkout 5", primary),
        ("mise run leakcheck", worktree),
        ("prlimit --nofile=4096 mise run leakcheck", worktree),
        ("systemd-run --user --scope -- mise run leakcheck", worktree),
        ("./bin/fuzz_dns corpus", worktree),
        ("timeout 300 scripts/leak-check.sh", worktree),
        ("cat <<EOF > f && gh pr merge 5\nbody\nEOF", worktree),
        ("for f in a b; do sed -i s/a/b/ $f; done", worktree),
        ("if true; then pkill elodin; fi", worktree),
        ("sudo -n pkill elodin", worktree),
        ("nice -n 5 pkill elodin", worktree),
        ("env -u FOO pkill elodin", worktree),
        ("[ $# -gt 0 ] && pkill elodin", worktree),
        ("echo a#b; pkill elodin", worktree),
        ("systemd-run --user --scope mise run leakcheck", worktree),
        ("systemd-run --user pkill elodin", worktree),
        (f"(cd {worktree} && git switch x); git switch y", primary),
    ]
    ALLOWED = [
        ("ls", primary),
        ("kill 1234", worktree),
        ("git commit -m 'never pkill elodin, never sed -i'", worktree),
        ("grep -rn leakcheck docs", worktree),
        ("git log --grep='gh pr merge'", worktree),
        ("sed -n 1,5p f", worktree),
        ("git reset --soft abc123", worktree),
        ("scripts/merge-gate.sh 5", worktree),
        ("git checkout -- file", primary),
        ("git checkout .", primary),
        ("git checkout HEAD src", primary),
        ("git checkout -b x", worktree),
        (f"cd {worktree} && git switch foo", primary),
        (f"git -C {worktree} switch foo", primary),
        ("systemd-run --user --scope -p MemoryMax=3G -- mise run leakcheck", worktree),
        ("scripts/push-gate.sh --leak", worktree),
        ("mise run fuzz-regression", worktree),
        ("cat <<'EOF' > notes.md\npkill elodin; gh pr merge 1; sed -i x f\nEOF", worktree),
        ("cat scripts/leak-check.sh", worktree),
        ("ls bin/fuzz_dns && rm bin/fuzz_dns", worktree),
        ("git checkout -b fix", other),
        ("git checkout src/gone.odin", primary),
        ("# pkill elodin", worktree),
    ]
    failures = []
    for command, cwd in REFUSED:
        if not guard.refuse(command, cwd):
            failures.append(f"allowed, should refuse: {command!r} in {os.path.basename(cwd)}")
    for command, cwd in ALLOWED:
        if why := guard.refuse(command, cwd):
            failures.append(f"refused, should allow: {command!r} in {os.path.basename(cwd)}: {why}")

# The clock rule: in sync, stepped back into sync, and still off after a step.
offsets, steps = [], []
guard.clock_offset = lambda: offsets.pop(0)
guard.subprocess.run = lambda args, **kw: steps.append(args)
for seq, refused in (([0.3], False), ([5000.0, 0.2], False), ([5000.0, 4999.0], True)):
    offsets[:] = seq
    if bool(real_fix_clock()) != refused:
        failures.append(f"clock {seq}: refused={not refused}")
if steps != [["sudo", "-n", "chronyc", "makestep"]] * 2:
    failures.append(f"clock steps: {steps}")

for f in failures:
    print(f, file=sys.stderr)
sys.exit(1 if failures else 0)
