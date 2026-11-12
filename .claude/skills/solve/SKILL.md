---
name: solve
description: Solve a GitHub issue of jadolg/elodin end to end. Reproduce it in a failing test, fix the root cause, open a PR, run the review/fix loop, and merge. Usage: /solve <issue-number>
argument-hint: <issue-number>
disable-model-invocation: true
---

Solve <https://github.com/jadolg/elodin/issues/$ARGUMENTS> now, from reading the issue to merging the fix, without stopping except where this file says to.

If `$ARGUMENTS` isn't a single issue number, or the current repo isn't jadolg/elodin, stop and ask.

**Paths.** Nothing here is tied to one machine. Work out these three once, at the start, and use the real paths from then on (shell variables don't survive between commands):

- `$ROOT`, the primary checkout: `dirname "$(git rev-parse --path-format=absolute --git-common-dir)"`. This works from the primary checkout and from any worktree of it.
- `$WT`, this issue's worktree: `$(dirname "$ROOT")/elodin-$ARGUMENTS`, a sibling of `$ROOT`.
- `$SCRATCH`, repro fixtures that outlive the session: `$(dirname "$ROOT")/elodin-review-scratch`. Don't use the session scratchpad, which other sessions can't read and which is cleaned up.

## 0. Preflight

- Check the clock: `chronyc tracking` (or `timedatectl` where chrony isn't installed). If it's off, step it (`sudo -n chronyc makestep`) first. A skewed clock breaks `gh` TLS, live DNSSEC and every deadline test.
- Record the state of the primary tree (`git -C $ROOT log --oneline -1; git -C $ROOT status --short`). It's shared with other sessions, so never switch its branch or edit it.
- `git fetch origin`, then `gh issue view $ARGUMENTS --comments`.
- Check whether it's already fixed: `git log -S '<guard or symbol>' origin/main` and the recent log over the files involved. Sibling PRs often close holes without linking the issue. If it's fixed, show that at `origin/main` with a test, comment, and close the issue.
- List every request in the issue. Each one must end up done, or declined with a reason posted on the issue.
- **Security mode** is on when the issue has the `security` label, or when you judge it security-relevant (say so when you turn it on without the label). In security mode: fix it correctly and leave no hole behind. After fixing, review your own diff as an attacker would. Check that the fix opens no new hole: a new allocation, a new bound, a new parse, or a new branch an attacker can steer.

## 1. Worktree

Always start from the latest `main` on GitHub. The local `main` ref in the primary tree is routinely behind, and an old worktree or branch is too, so never start from either.

```
git fetch origin main
git worktree add -b fix/$ARGUMENTS-<slug> $WT origin/main
git -C $WT rev-parse HEAD   # must equal:
git ls-remote origin refs/heads/main
```

- The two hashes must match. If they don't, fetch again and recreate the worktree.
- If a worktree or branch for this issue already exists from an earlier attempt, look at it first:
  - Unpushed work worth keeping gets rebased onto the fresh `origin/main`.
  - Otherwise remove it and start over.

  Never continue on its old base.

Do all the work there. Don't use `Agent` with `isolation: "worktree"`, because the sandbox breaks it. Other sessions work in other worktrees at the same time.

## 2. Understand before touching anything

- Trace the whole path, from the socket to the answer. Grep every caller of the function you'll change.
- List the variants of the bug, meaning the same mistake reached by another road:
  - other transports: UDP, TCP, DoT, DoH over h1 and h2, client side and upstream side;
  - the client path and the DNSSEC chain-lookup path;
  - refresh, serve-stale, coalesced followers, rewrites, zone routes;
  - both thread models: the pool, and thread-per-connection.
  All of them get fixed in this PR.
- Make every design choice (behaviour, rcode, limits, what to refuse) in this order:
  1. **RFCs come first, always, and the goal is maximum RFC compliance.** Read the relevant RFC and its updates and errata; MUST/SHOULD beat anything below. Cite the section in code comments, in the PR, and in the Decisions entry. Don't trade compliance for convenience, a smaller diff or a matching competitor.
  2. **If the RFCs don't settle it** (silent, MAY, or implementation-defined), compare how other implementations do it. Read their source or docs, not memory: Unbound, BIND, Knot Resolver and PowerDNS Recursor for resolver behaviour; dnsmasq, CoreDNS, AdGuard Home and blocky for forwarder, blocking and DoH behaviour. The better solution wins, judged as in the feature-request bullet below; elodin is a small, hardened forwarder with safe defaults on small devices. Record which implementations do what, and why you chose yours.
  3. Only if both of those leave it open is it a real design question for the user.
- **Feature requests** (the `enhancement` label, or an issue asking for behaviour elodin doesn't have yet). First check whether the strategy is already decided: by the issue body, by the owner in its comments, or by a linked issue or PR.
  - **Decided:** implement that. If it contradicts an RFC MUST or SHOULD, the RFC wins; say so on the issue, citing the section, and flag it in the report.
  - **Not decided, and an RFC covers it:** the RFC's behaviour is the strategy. Among the options the RFC allows, use the comparison below.
  - **Not decided, and no RFC covers it:** compare the competition, and the better solution wins without asking. Read each one's source or docs, not memory: the resolvers and forwarders in the list above, plus any other project that ships the feature. For each, record how it does it and what it costs.
  - **Judge "better"** in this order:
    1. correctness and security, including fail-closed behaviour on bad input;
    2. safe defaults that need no tuning;
    3. memory and CPU on a small device;
    4. how much configuration it adds for the operator;
    5. interoperability with clients and upstreams.

    Mixing approaches is fine when no single one wins on every count.
  - Post the comparison on the issue as a table (implementation, approach, link to source or docs, verdict), and why the winner won, before you build it. Repeat it in the PR's `## Decisions`.
  - The failing test in step 3 is the new behaviour, written as a test before the feature exists.

## 3. Reproduce it with a failing test

Pick the layer that shows the bug. Often that means more than one:

| Layer | Where | When |
|---|---|---|
| Unit | `src/<pkg>/<topic>_test.odin` | Logic, bounds, codec. Run one test with `-define:ODIN_TEST_NAMES=<pkg>.<test>` |
| Integration | `src/itest/cases_<area>.odin` | Anything visible on the wire from the shipped binary. Mock upstreams need TCP as well as UDP |
| Parity | `src/itest/parity_*.odin`, `testdata/parity-seeds` | Anything lost or changed between the upstream's answer and the client's |
| Fuzz | `testdata/fuzz-corpus/<target>/` | A parser crash or overrun. Commit the reproducer |
| Memory | `mise run leakcheck` | A leak or use-after-free. The baseline is zero, so any report is the finding |

- Run the test and show that it fails for the reason the issue gives, not just that it fails. Assert the premise too: if the bug rests on "the platform or peer does X", the test must observe X.
- Tests run in parallel, so don't mutate package state that other tests read. fd 0 is closed under `odin test`, so a zero socket handle is someone else's socket. Scratch paths carry the pid.

**Test rules.** The #638 audit found every one of these broken across the tree. They apply to every test you write, review-round tests included:

- **Every assertion must be able to fail.** Mutation-prove each new test, not only the headline one: break what it guards, and watch it fail for the stated reason. The audit's vacuous tests:
  - `testing.expect(t, cond, "…%v", x)`: `expect` doesn't format, so use `expectf`;
  - a fixture refused for some other reason (a 30-character secret where 32 are needed), so the code under test is never reached;
  - an assertion that the one before it already implies, or a "premise" loop over a static table;
  - a negative check ("count unchanged", "no log line", "status is not Bogus") with no positive check that the event under test happened;
  - signed data changed without re-signing;
  - `strings.replace` with a needle that may be missing (check `contains` first);
  - a start-or-skip path that turns a failure into a skip, or a skip counted twice.
- **Never discard an error or `ok`**, in tests and fixtures too: no `x, _ :=` or `_ =` on `encode_message`, `decode_message`, `bound_endpoint`, `set_option`, `start_test_loop`, `make` and the like. A fixture that can't be built fails the test right there. After a precondition `expect` fails, return; don't go on to use the nil value.
- **No timing guesses.**
  - Don't use `time.sleep` to order events; wait on an event (`sync.Sema`, a cond, `wait_for_log`).
  - Measure durations with `time.tick_now`, never `time.now`.
  - Give every poll a deadline, and assert that it was met.
  - A randomised assertion needs a computed false-failure rate below 1e-9, or a fixed seed.
- **Clean up on every path.** `defer` the release right after each acquisition (socket, thread, heap string), before any early return.
- **Reuse fixtures.** Before writing a mock, config or helper, grep the package's tests, `src/server/mocks_test.odin` and `src/itest/harness.odin`. If the one you need is private to another file, move it to the shared file instead of copying it.
- **Readable tables.** Table rows with more than one bool use named fields. Look up fixtures by key, not by index.

## 4. Fix

- Fix the root cause, in the shared function every caller goes through.
- Limits: keep them flat, charge them to the part that amplifies, and make sure they survive a decode → re-encode → decode round trip. Bound the wait, not the timeout a member is judged on. Charge every attempt. A bound needs a number for each thread model.
- Every bound or guard the fix adds gets a test of its own. Guards that depend on the clock need a tick clock.
- **Code rules**, again from the #638 audit:
  - **Reuse before writing.** Grep for an existing helper before writing one. The audit found the question-section walk (`dns.records_start`), the record walk (`dns.skip_record`), the OPT search (`dns.find_opt_span`) and ASCII case folding re-implemented 5-7 times each.
  - **Named constants, not literals.** Before writing a number or a repeated string, grep for a constant that already holds it: `65535` is `dns.MAX_MESSAGE`, `512` is `dns.MAX_UDP_SIZE`, and a reason string written six times is a constant. A new limit gets one constant, used everywhere, including tests, metric help text and log text. Package-level values that never change are `::`, not `:=`.
  - **Name arguments.** Pass bool and int arguments to defaulted parameters by name (`cookies = false`), never as a bare positional `false`.
  - **Parse strictly.**
    - Numbers from config or the wire are read digits-only and bounded, like `parse_rdata_u16`, because `strconv.parse_int` and `parse_uint` accept `+` and `_` and wrap around on overflow.
    - A YAML value of the wrong type is an error, not silently skipped.
    - Case folding is ASCII, using `dns.name_equal_fold`; never `strings.equal_fold`.
  - **Format strings are literals.** Never pass prose or `tprintf` output as the format: write `warnf("%s", hint)`.
  - **Siblings move together.** When one member of a family gets a check (the re-encoders' `truncated`, a status table, the `ssl_enter` bracket around OpenSSL calls), give it to every member.
  - **No dead or test-only production code.** A new production procedure needs a production caller; helpers only tests use live in test files. When a change removes the last caller of a procedure, field or enum member, delete it in the same PR.
  - **Mind size.** Keep procedures under Lizard's limits, which Codacy gates on (step 11).
  - **Memory and CPU.** elodin runs on small devices, so every byte, allocation and microsecond saved counts.
    - In the code you write or must change, avoid allocations: reuse the request arena or a caller's buffer, size a buffer once instead of growing it, and don't copy what you can slice. Don't keep memory past its use.
    - **Measure every optimisation, before and after.** Time it on the release build (`mise run release`), never the debug build itest runs. Use `mise run bench -- -only <section>`, with `-binary` pointing at an `origin/main` build for the before row, and compare at equal load. Count allocations and bytes with a tracking allocator around the path, and for RSS diff `/proc/<pid>/smaps`, changing one knob at a time.
    - Put the before and after numbers, with the commands, in the PR's `## Performance` section. A change that measures no gain gets dropped, not kept on faith.
  - **Don't shave the yak.** The ticket has a goal. Optimise what the ticket needs you to change, not older code you happened to read. If you see a better way for code outside the ticket's change, file an issue instead (step 8).
- **Comments: fewer, and only what's needed.**
  - A procedure's doc comment says *what* it does: its contract, meaning what it takes, returns, refuses and guarantees. It doesn't say *how*.
  - Inside a body, comment only a *why* the code can't show: an RFC citation, a non-obvious invariant, the reason for a bound, or a trap being avoided. Never restate the next lines; a comment that mirrors the code goes stale as soon as the code changes.
  - Write in the present tense, about the code as it is. No "used to", "no longer" or "now", and no PR-relative words ("the fix", "the new family", "this change"). That rule covers tests too; the audit found about 270 stale comments, most of them history narration.
  - No line numbers in comments; name the symbol. Every backticked identifier or path must exist, so grep each one.
  - No counts the code nearby can contradict ("four things" followed by three, "16 slots"). Use the constant's name, or drop the number. Check the arithmetic in comments and test names (units, probabilities).
  - No claims of exclusivity or completeness ("only X calls this", "every status is listed", "nothing reaches this") unless a test enforces them.
  - A doc comment sits directly above its declaration. Never insert a declaration between a doc block and its procedure.
  - In every procedure you change, reread its doc comment and the comments inside it. Fix any that no longer hold, and delete any that restate the code.
- Re-run the failing test and show that it passes.
- **Prove the test has teeth:** revert the fix at the call site (not the procedure, since `odin build` compiles test files too), check that the unit test and the itest fail, then restore the fix from a copy you took first. Do this yourself, because a reviewer's sandbox refuses the revert on security code.

## 5. Parity and fuzzing

- Always run `mise run parity-regression`, plus `./bin/itest --parity --parity-scenario all --parity-runs 400` for anything on the answer path.
- If the fix changes what reaches the client, decide whether that's a bug or a new entitled difference. An entitled difference gets an entry in `src/itest/parity_compare.odin`, with its reason and citation.
- If the generator or mock can't produce the shape of this bug, extend them so parity would have caught it. Prove the new check by mutating the code. A seed that finds a divergence goes in `testdata/parity-seeds`.
- The OPT record is checked for the opposite of parity. A dropped upstream NSID or other option is the design, not a bug.
- A changed parser needs `mise run fuzz-regression`, plus a corpus seed for the new shape. A new parser gets a new target under `src/fuzz/`.

## 6. Docs and comments, with every change

Every change updates whatever documents that behaviour, in the same commit. That includes review-round fixes and changes made along the way. Never leave it for a later audit.

**Before every commit,** take each symbol, config key, default, limit, rcode/EDE, log string and metric that the diff changes, renames or removes. Grep `src/`, `docs/`, `examples/` and `README.md` for each one, and fix every comment or doc that still describes the old behaviour, including in files the diff doesn't otherwise touch.

**When a change retires a model** (the thread pool before #547, a setting that reload now applies, a removed key), also grep for the old model's vocabulary (`worker`, `thread per connection`, `fixed for the life of the process`, `RLIMIT_NPROC`, …). Comments written for the old model were the audit's most misleading findings, because they make the cache-soundness reasoning wrong. User-facing text that names a release ("refused from 0.26.0") gets checked against the current version.

The docs are an operator reference. Update each place the change reaches:

- `docs/<topic>.md`: every key, default, limit, rcode/EDE, log string or `detail`, metric and startup warning the change adds or alters. Add a clause of *why* only when it changes what an operator configures. Leave out history, issue archaeology and design argument.
- `docs/metrics.md` and `examples/grafana-dashboard.json` for a metric.
- `examples/*.yaml` (the annotated references) for a config key or default.
- `README.md` only when the feature list or quick start changes. `docs/development.md` when test layout or tasks change.
- Never put test counts or other figures that several in-flight PRs would all touch.
- Check every claim you write against the code.

## 7. Local gates

Run these in the worktree before every push:

```
mise run check
odin check src/<pkg> -collection:elodin=src -vet -strict-style -no-entry-point   # each touched package, including src/itest
mise run test
mise run itest          # serial, never alongside another run; read the total, not just pass/fail
mise run parity-regression
mise run fuzz-regression   # if a parser changed
mise run leakcheck         # if the change allocates or frees
# audit patterns in the lines this branch adds; fix each hit or say in the PR why it stays
git diff -U0 origin/main -- '*.odin' | grep -E '^\+[^+]' | grep -nE 'used to|no longer|\bnow\b|before this|the fix\b|\btoday\b|time\.sleep|time\.now\(|, _ :?=|^\+\s*_ = |testing\.expect\(t, [^)]*%|\.odin:[0-9]+'
```

- **Another session's itest collides on ports.** Check with a `/proc` walk for cmdline starting with `./bin/itest`, not `pgrep -f`, which matches itself. Wait it out, and never kill it.
- **Deadline tests failing in a batch:** check `chronyc tracking`, then run the package on a detached `origin/main` worktree before blaming the diff. If it isn't the diff, it's still a flake to fix, not to rerun past (see step 11.5).
- **Never `pkill` elodin.** Kill only by PID.
- Check for IPv6 egress once: `timeout 4 bash -c 'exec 3<>/dev/tcp/2001:4860:4860::8888/53'`. A v6 route alone doesn't prove it. Without egress, local v6 tests always fail, so probe v6 behaviour from outside with Globalping.

## 8. Other defects found along the way: fix them here

Fix it in this PR by default. A follow-up issue is the exception, and needs a reason you can state.

**Fix in this PR** (with its own test, listed in the PR description) when any of these holds:

- It's a variant of the bug you're fixing (see step 2), or the same mistake in a nearby function, or a missed edge case.
- It's in code this PR already touches, or in code the fix depends on.
- A reviewer found it during the loop and you confirmed it (step 10.5). Confirmed review findings are part of this PR, not follow-ups.
- The fix is self-contained, even if it's in another file. Size alone isn't a reason to defer it. A few hundred lines of fix plus tests is fine.
- The defect would make your fix incomplete, misleading, or easy to bypass.
- An RFC settles what's correct, or comparing other implementations does (step 2). Then it isn't a "design question".

**File a follow-up issue only** when the defect is truly unrelated (a different subsystem and a different root cause) **and** at least one of these holds:

- Fixing it needs a design decision, a behaviour or config change the user should approve, or a new dependency.
- It would grow this PR into a second, independent change that deserves its own review.
- It can't be verified here (it needs IPv6 egress this machine lacks, the production box at elodin.akiel.dev, or a real resolver's live behaviour).

"It's out of scope", "it's a separate concern" or "to keep the PR small" aren't reasons on their own. If you're unsure, fix it.

**Optimisations of code outside the ticket's change are the exception:** they always become an issue, never part of this PR. Label it `enhancement` with a `priority:*` (the repo has no performance label), and give:

- where the waste is, with permalinks;
- your idea for removing it, and what it should save (bytes, allocations, CPU);
- the command that measures it. Add a quick measurement too if one costs minutes; don't build a bench for it.

An optimisation that is a defect (unbounded growth, a leak, work an attacker can multiply) is not an optimisation; it follows the rules above.

A follow-up issue is filed only for a defect you've proven, by the same bar as a review finding (step 10.5). If you can't reproduce it, don't file it; record it as rejected, with what you tried. The issue gets:

- labels: a type (`bug` or `enhancement`), `severity:*`, `priority:*`, and `security` where it applies;
- the `origin/main` commit it was reproduced at;
- steps to reproduce: the exact commands, plus the failing test or script pasted in full so anyone can run it without this machine (also keep the fixture under `$SCRATCH/<date>/`), and the output you observed;
- expected vs actual, and what decides "expected": the RFC section with its rfc-editor.org link, the project doc, or the other implementations' source or docs, each linked;
- permalinks to the code at fault, at that commit;
- the reason it wasn't fixed here.

## 9. Commit and PR

- **Commit subject:** `<pkg>: <the behaviour as it now is> (#$ARGUMENTS)`, e.g. `upstream: a referral is not an answer (#410)`. The body gives the problem and the fix in prose, and ends with the attribution line.
- **Before every push:** `git diff --stat origin/main`. More files than you touched means the base moved. Rebase, and never `reset --soft origin/main`.
- **PR title:** the same as the commit subject.
- **PR body:**
  - `Closes #$ARGUMENTS`, plus a `Closes` line for any other issue it fixes;
  - `## Problem`: the RFC quote if there is one, and each road to the bug;
  - `## Fix`: by symbol;
  - `## Tests`: each test and what it proves, including the revert run;
  - `## Parity`: what was run, and any allowance added;
  - `## Performance`: before and after numbers and the commands behind them, for any change on a hot path or any optimisation;
  - `## Also fixed`: other defects fixed along the way;
  - `## Decisions`: see step 10;
  - a done/declined map of the issue's requests, with links to the comments that decline any.

## 10. Review/fix loop

Each round:

1. Refresh the local `main` ref and record the primary tree's state.
2. Run `/code-review high <PR>`, without `--fix`. Nothing the reviewer says reaches the branch until you've proven it.
3. Afterwards, restore the primary tree exactly as you recorded it, and remove any worktree the agent made. It has used your worktree, a worktree of its own, and the primary tree.
4. **Check whether the round was stale.** If the round's commit count ≠ `git rev-list --count origin/main..HEAD`, or it quotes code you don't have, it reviewed an old head. Reset its worktree to the pushed head and re-run. A stale round doesn't count toward the stopping rule.
5. **Prove each finding before acting on it.** The reviewer makes mistakes: it misreads code, reviews a stale head, assumes how the platform or a peer behaves, or misreads an RFC. For each finding:
   - Grep for the expression it quotes at your head.
   - Reproduce it at your head: a failing test (preferred), or a command or script whose output shows the defect. Assert the premise: if it rests on "the platform, peer or RFC does X", observe X in the test or quote the section.
   - Give it a verdict. **Confirmed** means you hold that evidence; it gets fixed here, or becomes a follow-up issue if step 8's bar is met. **Rejected** means it doesn't hold, and no code changes. A finding you couldn't reproduce is rejected, never fixed "to be safe".
6. Fix only the confirmed findings; the failing test from step 5 is the fix's test. Then remove the fix's main guard again and confirm the unit test and the itest still fail. A refactor can leave the guard untested.
7. Post a round comment on the PR with one entry per finding: the finding, its verdict, and the evidence.
   - Confirmed: the test or command, and its output before and after the fix. A follow-up links its issue.
   - Rejected: why it doesn't hold, shown, not asserted. Link the code that refutes it (`https://github.com/jadolg/elodin/blob/<sha>/<path>#L<n>`), give the test or command that would fail if the claim were true and its passing output, quote the RFC section with its rfc-editor.org link, or name the Decisions entry it contradicts.
8. Update the docs and comments the round's fixes reach (steps 4 and 6). Run the gates, then commit as `<pkg>: review round K - <what changed>` and push.

**Don't go in circles.** The `## Decisions` section in the PR body is the loop's memory:

- Record each decision as you make it: the choice, the RFC section behind it (or, where the RFCs are silent, what the other implementations do), the invariant that makes it safe, and what the rejected option costs.
- A finding that argues against RFC-backed behaviour is declined, citing the section, unless it shows the RFC was misread.
- Before acting on a finding, check it against Decisions. Don't reverse a recorded decision unless there's new evidence.
- On the second finding that contradicts an earlier one, stop changing code. First look for a way both sides can hold (e.g. separate keys or separate budgets). If there isn't one, record the trade-off instead of flipping it back.

**When to stop:**

- Stop after a round with no confirmed high or medium findings. Rejected findings don't count. In that round, fix only confirmed lows that change behaviour or would mislead an operator; the round comment covers the rest.
- If most of a round's findings are defects in the previous round's fix, batch them rather than start another cycle.
- **At round 10, stop and ask the user what to do.** Do not merge.

## 11. Merge

1. `git fetch origin`, then re-read the log over the files you touched. If main has since decided the question the other way, drop your fix.
2. Rebase on `origin/main`, then `git diff --stat origin/main`.
3. Run the gates in step 7 on the rebased head, and push.
4. Wait for every CI check to go green on that head, including Codacy. Codacy gates on Lizard size (file around 1000 NLOC, function over 50 NLOC); read its issue list through the public API.
5. A flake, known or new (every TLS case at once, mock port errors, `tls reload` under ASan, the query-id birthday case, the Package live-DNS step, a deadline test), may get one `gh run rerun <id> --failed`, and only if the diff can't reach that code. That rerun is only a diagnosis, never the fix. Then fix the flake on its own branch off `main`: for a timing flake, take the test off the wall clock with a fake or tick clock, or wait on an event instead of a duration. A longer timeout or a wider margin is not a fix. Say in the report that a pass came from a rerun, and link the flake's fix.
6. Merge only through a gate that fails when the branch is behind:
   ```
   git fetch origin && [ "$(git rev-list --count HEAD..origin/main)" = 0 ] && \
   [ "$(git rev-parse HEAD)" = "$(gh pr view <PR> --json headRefOid -q .headRefOid)" ] && \
   gh pr merge <PR> --merge --delete-branch
   ```
   If it fails, go back to step 1.

After the merge:

- Check that the issue closed. If it didn't, comment on it and close it.
- Remove the worktree (`git worktree remove $WT`) and delete the local branch.
- Report:
  - the PR link;
  - the root cause, in one line;
  - the tests added and the layer each is at;
  - what was fixed along the way;
  - the follow-up issues filed, each with its reason;
  - the number of review rounds, and how many findings were confirmed and how many rejected;
  - any CI reruns.
