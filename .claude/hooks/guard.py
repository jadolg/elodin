#!/usr/bin/env python3
"""Claude Code hook: refuse the shell commands that have cost this repo time."""
# PreToolUse on Bash: reads the hook payload on stdin and exits 2 with the reason
# on stderr to refuse a command. `--session-start` checks the clock only.
# Each rule names the incident behind it in its message.
import json
import os
import re
import shutil
import subprocess
import sys

CLOCK_SENSITIVE = re.compile(r"\bgh\b|\bmise run\b|bin/itest|\bdelv\b|\bdig\b|push-gate|merge-gate")
ASAN = re.compile(r"\bleakcheck\b|leak-check\.sh|elodin-asan|\./bin/fuzz_")
MEMORY_CAP = re.compile(r"\bsystemd-run\b|\bprlimit\b|push-gate")

RULES = [
    (re.compile(r"\b(pkill|killall)\b[^|;&]*\b(elodin|itest|mock)"),
     "other sessions run elodin and itest servers on this box; kill by PID from /proc/<pid>/cmdline"),
    (re.compile(r"\bsed\s+(-[a-zA-Z]*i\b|--in-place|-i)"),
     "sed -i never lands in this tree and strands the edit in an unreadable temp file; use python3 or the Edit tool"),
    (re.compile(r"\bgit\s+reset\s+--soft\s+origin/"),
     "reset --soft origin/main reparents an old tree onto a newer main and reverts its merges; reset to the branch's own base, then rebase"),
    (re.compile(r"\bgh\s+pr\s+merge\b"),
     "merge through scripts/merge-gate.sh <pr>, which refuses a head that is behind main or not green"),
]


def clock_offset():
    """Seconds off NTP, or None when chrony is not there to ask."""
    if not shutil.which("chronyc"):
        return None
    out = subprocess.run(["chronyc", "tracking"], capture_output=True, text=True).stdout
    m = re.search(r"^System time\s*:\s*([0-9.]+)", out, re.M)
    return float(m.group(1)) if m else None


def fix_clock():
    """Step a drifted clock. Returns an error message, or None when it is fine."""
    off = clock_offset()
    if off is None or off <= 1:
        return None
    subprocess.run(["sudo", "-n", "chronyc", "makestep"], capture_output=True)
    after = clock_offset()
    if after is not None and after > 1:
        return f"the clock is {after:.0f}s off NTP and makestep did not fix it; gh TLS, live DNSSEC and deadline tests will fail"
    return None


def is_primary_checkout(cwd):
    r = subprocess.run(["git", "-C", cwd, "rev-parse", "--absolute-git-dir", "--git-common-dir"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False
    git_dir, common = r.stdout.split("\n")[:2]
    return os.path.realpath(git_dir) == os.path.realpath(os.path.join(cwd, common))


def refuse(command, cwd):
    for pattern, message in RULES:
        if pattern.search(command):
            return message
    if ASAN.search(command) and not MEMORY_CAP.search(command):
        return ("an ASan server can grow to gigabytes and the OOM kill takes the user's tmux with it; "
                "run it under: systemd-run --user --scope -p MemoryMax=3G -- <cmd>")
    switch = re.search(r"\bgit\s+(switch|checkout)\b(?!.*\s--(\s|$))|\bgh\s+pr\s+checkout\b", command)
    if switch and not re.search(r"\bgit\s+-C\b", command):
        cd = re.search(r"\bcd\s+(\S+)", command)
        where = os.path.expanduser(cd.group(1)) if cd else cwd
        if os.path.isdir(where) and is_primary_checkout(where):
            return ("the primary checkout is shared with other sessions; never switch its branch. "
                    "Work in a worktree (git worktree add ... origin/main) or use git -C <worktree>")
    if CLOCK_SENSITIVE.search(command):
        return fix_clock()
    return None


def main():
    if sys.argv[1:] == ["--session-start"]:
        problem = fix_clock()
        if problem:
            print(problem)
        return
    payload = json.load(sys.stdin)
    command = payload.get("tool_input", {}).get("command", "")
    problem = refuse(command, payload.get("cwd") or os.getcwd())
    if problem:
        print(f"guard: {problem}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
