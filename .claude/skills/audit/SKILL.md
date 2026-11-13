---
name: audit
description: Code-quality audit of the elodin packages changed since the last audit - duplicated code, stale comments, bad patterns, dead code, and bugs found along the way - filed as one labelled issue. Usage: /audit [<base-sha>]
argument-hint: "[<base-sha>]"
disable-model-invocation: true
---

Audit the Odin code in `src/` that changed since the last audit, the way #638 audited the whole tree, and file the result as one issue. Smaller audits more often: #638 found ~840 findings after ~600 PRs, three of them fail-open security bugs.

`/solve` says when one is due (50 merged PRs since the last). Don't fix anything here; the issue is the output, and its fixes go through `/solve`.

## 1. Scope

- `git fetch origin`. The audit runs at `origin/main`; note its short sha as `$HEAD`.
- The base is `$ARGUMENTS` if given. Otherwise take the newest issue labelled `audit` (`gh issue list --label audit --state all --limit 1 --json number,body`) and the sha on its `Audited at <sha>` line.
- The packages in scope: `git diff --name-only <base>..origin/main -- src | cut -d/ -f2 | sort -u`. Within each, read whole files that changed, not only the diff: stale comments and duplicates sit next to the change, not in it.
- Split the scope into slices of about 20k lines (`wc -l`), keeping a package's tests apart from its production code when that package is large.

## 2. Mechanical inputs (run these yourself, before the readers start)

- `python3 scripts/lint.py` with `LINT_BASE=<base>`: the rule set for lines added since the base.
- Production procs nothing calls, and production procs only tests call:
  ```
  for p in $(grep -rhoE '^[a-z_][a-z0-9_]* :: (#force_inline )?proc' src/<pkg> --include='*.odin' --exclude='*_test.odin' | cut -d' ' -f1 | sort -u); do
    n=$(grep -rwE "$p" src --include='*.odin' --exclude='*_test.odin' | wc -l); t=$(grep -rwE "$p" src --include='*_test.odin' | wc -l)
    [ "$n" -le 1 ] && echo "$p prod=$n tests=$t"
  done
  ```
- `git log --format=%s <base>..origin/main -- src/<pkg>` for each package: what each slice's reader should expect to have moved.

## 3. Readers

One `Agent` per slice, all started together, each in its own detached worktree at `origin/main` (`git worktree add --detach $(dirname $ROOT)/elodin-audit-N origin/main`; the harness's `isolation: "worktree"` fails here). Give each the same brief, saved under `$(dirname $ROOT)/elodin-review-scratch/<date>/audit/brief.md`:

- the slice's files, the base sha, and the mechanical inputs for its files;
- find, with exact `path:line` at `$HEAD` and a recommended fix for each:
  - **DUP**: code that repeats code elsewhere in the tree, or the stdlib, including semantic duplicates a line matcher misses. List every site of a family in one finding.
  - **STALE**: a comment or doc that no longer matches the code: history narration, identifiers that don't exist, counts or claims the code contradicts. Read each comment against the code it describes.
  - **PATTERN**: anything `/solve`'s test rules and code rules (steps 3 and 4) forbid.
  - **DEAD**: unreachable code, or production code only tests call.
  - **BUG**: a defect. Prove it: a failing test or a command with its output, as `/solve` step 10.5 requires of a review finding. An unproven bug is not filed.
- don't edit the tree; repro fixtures go under the scratch dir, not the session scratchpad;
- kill processes by PID only, and use ports from 30000 + 1000*N.

Then check each reader's work yourself: re-read every BUG's proof and a sample of each slice's STALE and DUP claims against the code. A reader's mistakes come back sounding as sure as its findings.

## 4. File it

One issue, labelled `audit`, `enhancement` and `priority:low`. The body's first line is `Audited at <full sha of origin/main>` (the next audit starts there), then:

- the scope: base, head, packages, line count;
- the method (this file, and what the mechanical inputs reported);
- a count table per slice: DUP / STALE / PATTERN / DEAD / BUG;
- the bugs, each also filed as its own issue with `/solve`'s step 8 contents, severity and priority, and linked;
- the themes that cut across slices, and any lint rule worth adding to `scripts/lint.py` (a pattern found in three or more places is one).

Each slice's findings go in a comment of their own. Then set the issue on the Elodin Kanban board (project 4): Status, and Priority P2.

Report the issue link, the counts, and the bugs filed.
