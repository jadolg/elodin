#!/usr/bin/env python3
"""Claude Code hook: refuse the shell commands that have cost this repo time."""
# PreToolUse on Bash: reads the hook payload on stdin and exits 2 with the reason
# on stderr to refuse a command. `--session-start` checks the clock only.
#
# The command is split into simple commands (at ; && || | & ( ) and newlines,
# with heredoc bodies dropped) and each is judged by its own words, so a commit
# message or a grep pattern naming a refused command is not itself refused.
#
# It is a tripwire for commands typed out of habit, not a sandbox: it reads the
# shapes such commands take (wrappers, keywords, subshells, heredocs), not every
# way bash can spell one.
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404: fixed argument lists, no shell
import sys

SUBSHELL = {"(", ")"}
# Words that run the command after them, skipped with their options to find the
# command itself. prlimit is one: RLIMIT_AS breaks ASan's shadow mapping and
# RLIMIT_RSS does nothing, so it caps nothing here.
WRAPPERS = {"sudo", "env", "nice", "nohup", "time", "command", "exec", "xargs", "timeout", "prlimit", "taskset", "systemd-run"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "{", "}", "!"}
# Each wrapper's options that take the next word as their value.
VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"},
    "env": {"-u", "-C", "-S"},
    "nice": {"-n"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "prlimit": {"-p", "--pid"},
    "systemd-run": {"-p", "-E", "-u", "--property", "--setenv", "--unit", "--slice", "--description", "--uid", "--gid"},
}
CLOCK_SENSITIVE = {"gh", "dig", "delv", "itest", "push-gate.sh", "merge-gate.sh"}


def segments(command):
    """The simple commands in `command`, each a list of words, with "(" and ")" between them for subshells."""
    # A heredoc's body is data; the line that opens it is still a command.
    command = re.sub(r"(<<-?\s*(['\"]?)(\w+)\2[^\n]*\n).*?\n\s*\3\s*(\n|$)", r"\1", command, flags=re.S)
    out = []
    for line in command.split("\n"):
        if not line.lstrip().startswith("#"):
            out.extend(split_at_operators(line_words(line)))
    return out


def line_words(line):
    """One line's words, operators apart; `#` is a comment only at the start of a line."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # an unclosed quote: judge the line's words as written
        return line.split()


def split_at_operators(words):
    """`words` cut into simple commands at operators, keeping "(" and ")"."""
    out, seg = [], []
    for w in words:
        # shlex keeps a run of punctuation as one word (`);`, `)&&`).
        if w and set(w) <= set(";&|()"):
            out.extend([seg] if seg else [])
            out.extend(c for c in w if c in SUBSHELL)
            seg = []
        else:
            seg.append(w)
    return out + ([seg] if seg else [])


def skip_options(words, i, wrapper):
    """The index of the first word from `i` that is not one of `wrapper`'s options or an option's value."""
    takes_value = VALUE_OPTIONS.get(wrapper, set())
    while i < len(words) and words[i].startswith("-") and words[i] != "--":
        i += 2 if words[i] in takes_value else 1
    return i + 1 if i < len(words) and words[i] == "--" else i


def command_words(seg):
    """`seg` without leading keywords, VAR=value assignments and wrappers with their options."""
    i = 0
    while i < len(seg):
        w = os.path.basename(seg[i])
        if seg[i] in KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]):
            i += 1
        elif w in WRAPPERS:
            i = skip_options(seg, i + 1, w)
            if w in ("timeout", "taskset") and i < len(seg) and re.match(r"^[0-9.,x]+[smhd]?$", seg[i]):
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


def git_dirs(path):
    """`path`'s own git directory and the repository's common one, or None outside a repository."""
    r = subprocess.run(["git", "-C", path, "rev-parse", "--absolute-git-dir", "--git-common-dir"],  # nosec B603 B607
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    git_dir, common = r.stdout.split("\n")[:2]
    return os.path.realpath(git_dir), os.path.realpath(os.path.join(path, common))


# This project's common git directory: the checkout holding it is the shared one.
PROJECT_COMMON = (git_dirs(os.path.dirname(os.path.abspath(__file__))) or (None, None))[1]


def is_primary_checkout(path):
    """Whether `path` is in this project's primary checkout, not a worktree or another repository."""
    dirs = git_dirs(path) if os.path.isdir(path) else None
    return dirs is not None and dirs[0] == dirs[1] == PROJECT_COMMON


def names_a_commit(where, target):
    """Whether `git checkout <target>` would switch to it: a commit, or a branch on origin it would create."""
    for ref in (f"{target}^{{commit}}", f"refs/remotes/origin/{target}"):
        r = subprocess.run(["git", "-C", where, "rev-parse", "--verify", "--quiet", ref],  # nosec B603 B607
                           capture_output=True)
        if r.returncode == 0:
            return True
    return False


def git_subcommand(words, cwd):
    """A git command's directory (after any -C), subcommand and its arguments; None for another command."""
    if not words or words[0] != "git":
        return None
    i, where = 1, cwd
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "-C" and i + 1 < len(words):
            where = os.path.join(where, os.path.expanduser(words[i + 1]))
        i += 2 if words[i] in ("-C", "-c", "--git-dir", "--work-tree") else 1
    return (where, words[i], words[i + 1:]) if i < len(words) else None


NEW_BRANCH = {"-b", "-B", "--detach", "--orphan"}


def changes_branch(where, sub, args):
    """Whether a `switch`/`checkout` changes branch. A checkout with one target naming a commit
    does; a path, a deleted file, `--` or more than one target is a restore."""
    if sub == "switch" or (sub == "checkout" and NEW_BRANCH & set(args)):
        return True
    if sub != "checkout" or "--" in args:
        return False
    targets = [a for a in args if not a.startswith("-")]
    return len(targets) == 1 and os.path.isdir(where) and names_a_commit(where, targets[0])


def git_switch_dir(words, cwd):
    """The directory a `git switch`/`git checkout` that changes branch runs in, else None."""
    git = git_subcommand(words, cwd)
    return git[0] if git and changes_branch(*git) else None


def is_asan_run(words):
    """Whether `words` runs an ASan build: leakcheck, its script, the ASan server or a fuzz target."""
    if words[:3] == ["mise", "run", "leakcheck"] or words[:2] == ["mise", "leakcheck"]:
        return True
    program = words[1:2] if words[:1] in (["bash"], ["sh"]) else words[:1]
    return any(re.search(r"(^|/)(leak-check\.sh|elodin-asan|fuzz_[a-z0-9_]+)$", w) for w in program)


# One rule per hazard: each takes the command's name, its arguments, its words,
# the cwd and the whole simple command with its wrappers, and returns a reason
# to refuse, or None.

def no_pkill(name, args, words, cwd, seg):
    if name in ("pkill", "killall") and any(re.search(r"elodin|itest|mock", a) for a in args):
        return "other sessions run elodin and itest servers on this box; kill by PID from /proc/<pid>/cmdline"
    return None


def no_sed_in_place(name, args, words, cwd, seg):
    if name == "sed" and any(a == "--in-place" or a.startswith("--in-place=") or re.match(r"^-[a-zA-Z]*i", a) for a in args):
        return "sed -i never lands in this tree and strands the edit in an unreadable temp file; use python3 or the Edit tool"
    return None


def no_soft_reset_onto_origin(name, args, words, cwd, seg):
    if name == "git" and "reset" in args and "--soft" in args and any(a.startswith("origin/") for a in args):
        return "reset --soft origin/main reparents an old tree onto a newer main and reverts its merges; reset to the branch's own base, then rebase"
    return None


def no_bare_merge(name, args, words, cwd, seg):
    if name == "gh" and args[:2] == ["pr", "merge"]:
        return "merge through scripts/merge-gate.sh <pr>, which refuses a head that is behind main or not green"
    return None


def asan_capped(name, args, words, cwd, seg):
    if not is_asan_run(words):
        return None
    # command_words skipped the wrappers; only a systemd-run among them with a
    # MemoryMax caps what follows.
    wrappers = seg[:len(seg) - len(words)]
    if "systemd-run" in map(os.path.basename, wrappers) and any("MemoryMax=" in w for w in wrappers):
        return None
    return ("an ASan server can grow to gigabytes and the OOM kill takes the user's tmux with it; "
            "run it under: systemd-run --user --scope -p MemoryMax=3G -- <cmd>")


def no_switch_in_primary(name, args, words, cwd, seg):
    where = git_switch_dir(words, cwd)
    checkout = name == "gh" and args[:2] == ["pr", "checkout"]
    if (where and os.path.isdir(where) and is_primary_checkout(where)) or (checkout and is_primary_checkout(cwd)):
        return ("the primary checkout is shared with other sessions; never switch its branch. "
                "Work in a worktree (git worktree add ... origin/main)")
    return None


def clock_in_sync(name, args, words, cwd, seg):
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
        if problem := rule(name, words[1:], words, cwd, seg):
            return problem
    return None


def refuse(command, cwd):
    outer = []
    for seg in segments(command):
        if seg == "(":
            outer.append(cwd)
            continue
        if seg == ")":
            cwd = outer.pop() if outer else cwd
            continue
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
