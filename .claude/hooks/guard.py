#!/usr/bin/env python3
"""Claude Code hook: refuse the shell commands that have cost this repo time."""
# PreToolUse on Bash: reads the hook payload on stdin and exits 2 with the reason
# on stderr to refuse a command. `--session-start` checks the clock only.
#
# The command is split into simple commands (at ; && || | & and newlines, with
# heredoc bodies dropped) and each is judged by its own words, so a commit
# message or a grep pattern naming a refused command is not itself refused.
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404: fixed argument lists, no shell
import sys

OPERATORS = {";", "&&", "||", "|", "&", "|&", ";;", "(", ")"}
# Words that run the command after them: skipped to find the command itself.
WRAPPERS = {"sudo", "env", "nice", "nohup", "time", "command", "exec", "xargs"}
CLOCK_SENSITIVE = {"gh", "dig", "delv", "itest", "push-gate.sh", "merge-gate.sh"}


def segments(command):
    """The simple commands in `command`, each a list of words."""
    command = re.sub(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(\n|$)", "\n", command, flags=re.S)
    out = []
    for line in command.split("\n"):
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            words = list(lexer)
        except ValueError:  # an unclosed quote: judge the line's words as written
            words = line.split()
        seg = []
        for w in words:
            if w in OPERATORS:
                if seg:
                    out.append(seg)
                seg = []
            else:
                seg.append(w)
        if seg:
            out.append(seg)
    return out


def command_words(seg):
    """`seg` without leading VAR=value assignments and wrappers like sudo or timeout N."""
    i = 0
    while i < len(seg):
        w = seg[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w) or w in WRAPPERS:
            i += 1
        elif w in ("timeout", "prlimit", "taskset"):
            # prlimit is skipped like the rest: RLIMIT_AS breaks ASan's shadow
            # mapping and RLIMIT_RSS does nothing, so it caps nothing here.
            i += 1
            while i < len(seg) and (seg[i].startswith("-") or re.match(r"^[0-9.,x]+[smhd]?$", seg[i])):
                i += 1
        else:
            break
    return seg[i:]


def clock_offset():
    """Seconds off NTP, or None when chrony is not there to ask."""
    if not shutil.which("chronyc"):
        return None
    out = subprocess.run(["chronyc", "tracking"], capture_output=True, text=True).stdout  # nosec B603 B607
    m = re.search(r"^System time\s*:\s*([0-9.]+)", out, re.M)
    return float(m.group(1)) if m else None


def fix_clock():
    """Step a drifted clock. Returns an error message, or None when it is fine."""
    off = clock_offset()
    if off is None or off <= 1:
        return None
    subprocess.run(["sudo", "-n", "chronyc", "makestep"], capture_output=True)  # nosec B603 B607
    after = clock_offset()
    if after is not None and after > 1:
        return f"the clock is {after:.0f}s off NTP and makestep did not fix it; gh TLS, live DNSSEC and deadline tests will fail"
    return None


def is_primary_checkout(path):
    r = subprocess.run(["git", "-C", path, "rev-parse", "--absolute-git-dir", "--git-common-dir"],  # nosec B603 B607
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False
    git_dir, common = r.stdout.split("\n")[:2]
    return os.path.realpath(git_dir) == os.path.realpath(os.path.join(path, common))


def git_switch_dir(words, cwd):
    """The directory a `git switch`/`git checkout` that changes branch runs in, else None."""
    if not words or words[0] != "git":
        return None
    i, where = 1, cwd
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "-C" and i + 1 < len(words):
            where = os.path.join(where, os.path.expanduser(words[i + 1]))
            i += 2
        elif words[i] in ("-c", "--git-dir", "--work-tree"):
            i += 2
        else:
            i += 1
    if i >= len(words):
        return None
    sub, args = words[i], words[i + 1:]
    if sub == "switch":
        return where
    if sub != "checkout" or "--" in args:
        return None
    if any(a in ("-b", "-B", "--detach", "--orphan") for a in args):
        return where
    targets = [a for a in args if not a.startswith("-")]
    # One target that is not a path in the tree is a branch or a commit; a path,
    # or more than one target, is a restore.
    if len(targets) == 1 and not os.path.exists(os.path.join(where, targets[0])):
        return where
    return None


def is_asan_run(words):
    if not words:
        return False
    if words[:3] == ["mise", "run", "leakcheck"] or words[:2] == ["mise", "leakcheck"]:
        return True
    return any(re.search(r"(^|/)(leak-check\.sh|elodin-asan|fuzz_[a-z0-9_]+)$", w) for w in words[:2])


# One rule per hazard: each takes (name, args, words, cwd) and returns a reason
# to refuse, or None.

def no_pkill(name, args, words, cwd):
    if name in ("pkill", "killall") and any(re.search(r"elodin|itest|mock", a) for a in args):
        return "other sessions run elodin and itest servers on this box; kill by PID from /proc/<pid>/cmdline"
    return None


def no_sed_in_place(name, args, words, cwd):
    if name == "sed" and any(a == "--in-place" or a.startswith("--in-place=") or re.match(r"^-[a-zA-Z]*i", a) for a in args):
        return "sed -i never lands in this tree and strands the edit in an unreadable temp file; use python3 or the Edit tool"
    return None


def no_soft_reset_onto_origin(name, args, words, cwd):
    if name == "git" and "reset" in args and "--soft" in args and any(a.startswith("origin/") for a in args):
        return "reset --soft origin/main reparents an old tree onto a newer main and reverts its merges; reset to the branch's own base, then rebase"
    return None


def no_bare_merge(name, args, words, cwd):
    if name == "gh" and args[:2] == ["pr", "merge"]:
        return "merge through scripts/merge-gate.sh <pr>, which refuses a head that is behind main or not green"
    return None


def asan_capped(name, args, words, cwd):
    if name == "systemd-run":
        inner = args[args.index("--") + 1:] if "--" in args else []
        if is_asan_run(inner) and not any("MemoryMax=" in a for a in args):
            return "systemd-run without -p MemoryMax= does not cap an ASan run"
        return None if is_asan_run(inner) else judge(inner, cwd)
    if is_asan_run(words):
        return ("an ASan server can grow to gigabytes and the OOM kill takes the user's tmux with it; "
                "run it under: systemd-run --user --scope -p MemoryMax=3G -- <cmd>")
    return None


def no_switch_in_primary(name, args, words, cwd):
    where = git_switch_dir(words, cwd)
    checkout = name == "gh" and args[:2] == ["pr", "checkout"]
    if (where and os.path.isdir(where) and is_primary_checkout(where)) or (checkout and is_primary_checkout(cwd)):
        return ("the primary checkout is shared with other sessions; never switch its branch. "
                "Work in a worktree (git worktree add ... origin/main)")
    return None


def clock_in_sync(name, args, words, cwd):
    if name in CLOCK_SENSITIVE or words[:2] == ["mise", "run"]:
        return fix_clock()
    return None


RULES = [no_pkill, no_sed_in_place, no_soft_reset_onto_origin, no_bare_merge, asan_capped,
         no_switch_in_primary, clock_in_sync]


def judge(seg, cwd):
    """A reason to refuse one simple command, or None."""
    words = command_words(seg)
    if not words:
        return None
    name = os.path.basename(words[0])
    for rule in RULES:
        if problem := rule(name, words[1:], words, cwd):
            return problem
    return None


def refuse(command, cwd):
    for seg in segments(command):
        words = command_words(seg)
        if words and words[0] == "cd" and len(words) > 1:
            cwd = os.path.join(cwd, os.path.expanduser(words[1]))
            continue
        problem = judge(seg, cwd)
        if problem:
            return problem
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
