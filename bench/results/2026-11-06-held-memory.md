# What a held DoT connection and a query in flight hold

Issue #614: the two per-item figures of the second competition round
(`2026-11-05-competition.md`), split by where the memory is.

4-core arm64 VM (7.7 GiB, Linux 7.0.0-38-generic), glibc's malloc, OpenSSL
3.5.5. elodin release builds of `ee63b15` (main) and of the #614 head. The
held-connection shapes are the harness's: 1,000 clients each ask one cached
name and hold the connection; 1,000 unique names behind a mock that answers
after 1 s, cache off. Per item is (RSS held − RSS before) ÷ 1,000 for a
connection and (`VmHWM` − idle) ÷ 1,000 for a query in flight, read from
`/proc/<pid>` while the load is held. Where the memory sits comes from
`/proc/<pid>/smaps` (by mapping), `/proc/<pid>/pagemap` (which pages of each
fiber stack are resident), a malloc interposer that keeps the live bytes by
call stack, and `malloc_trim(0)` called into the held process with `gdb`.

## A query in flight: 20.7 KB, now 16.7 KB

Three runs each, back to back:

| build | per query in flight |
|---|---|
| main `ee63b15` | 20.7 / 20.7 / 20.7 KB |
| #614 | 16.7 / 16.7 / 16.7 KB |

| where | main | #614 |
|---|---|---|
| fiber stack, resident pages | 16 KB: the top 4 pages of 979 of 1,000 stacks | 12 KB: the top 3 |
| scratch and the loop's small mappings | ~1.3 KB | ~1.3 KB |
| malloc: the fiber, its waiter, the loop's tables | ~0.5 KB | ~0.5 KB |
| glibc arena slack | ~1 KB | ~1 KB |

The stack is the query parked on its upstream socket: `fiber_entry` →
`udp_job` → `handle_query` → `resolve_query` → `exchange_upstream` →
`resolve_insisting` → `resolve_sequential` → `exchange` → `send` →
`recv_udp_armed` → `wait_fd` → `park`. Release-build frames along it summed to
11.3 KB, 3.4 KB of it `resolve_query`'s, which holds `Query_State`, and 2 KiB of
that was two `[cache.KEY_MAX]u8` key buffers (1,040 bytes each) for keys that
are the name and 15 bytes.

With the buffers out of `Query_State` (2,624 → 544 bytes) the parked depth is
~9.3 KB and the stack 3 pages. The stack pointer is in the third, so nothing
resident lies below it and `stack_release` (#596) would give back nothing on
this wait. What is left is spread across ten frames of
inlined code; forcing the cold callees on the path out of line
(`exchange_with_cookie`, `exchange_padded`, `resolve_race`) took 300 bytes off,
far from the ~1.5 KB a page needs.

## An idle DoT connection: 43 KB

Unchanged by #614. Three runs: 43.1-43.5 KB (DoH/2: 43.5 KB; TCP: 8.6 KB).

| where | per connection |
|---|---|
| OpenSSL's live objects for the connection | ~27.5 KB |
| — the `SSL` object | 5.6 KB |
| — its two record layers (structures; the buffers are released, #595) | 8.8 KB |
| — the client's ML-KEM-768 key share, kept for the connection's life | ~6.8 KB (6,144 of it the expanded public key) |
| — cipher contexts, session, BIOs, verify params, the rest | ~6.3 KB |
| handshake memory freed back to glibc and kept in its arenas | ~5.5 KB (what `malloc_trim(0)` returns) |
| fiber stack: the page the parked stack pointer is in | 4 KB |
| malloc overhead, part-used pages, the loop's per-fd tables | ~5 KB |
| elodin's own heap (the fiber, the connection) | ~0.4 KB |

The 5.5 KB is a high-water mark, not a leak: 1,000 handshakes arrive within
150 ms, so the arena grows to hold that many at once, and the next handshakes
reuse it. The key share is OpenSSL's: it is imported in the handshake and stays
live as long as the connection, and the group is X25519MLKEM768 because both
ends prefer it.

## What was not cut, and why

- **The key share.** OpenSSL has no call that drops it from a live connection.
  Preferring X25519 alone would save the 6.8 KB by giving up the hybrid
  post-quantum key exchange for every client that offers it.
- **The handshake's freed memory.** `malloc_trim(0)` returns it, but walks
  every arena under its lock, stalling whichever loops allocate meanwhile, and
  the next burst of handshakes maps it again.
- **A fiber per waiting query.** The 12 KB is the frames the query's own code
  keeps while it waits; a query without them is a state machine instead of a
  call stack, the whole query path rewritten.
