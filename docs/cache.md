# Cache

```yaml
cache:
  enabled: true
  max_entries: 10000
  max_bytes: 64MiB       # a count of entries is not a bound on memory
  min_ttl: 0
  max_ttl: 24h
  negative_ttl: 300      # cap for NXDOMAIN / NODATA (RFC 2308)
  serve_stale: false     # answer from an expired entry if the upstream is down
  stale_timeout: 1.8s    # how long a client waits for the refresh first
  prefetch: true         # refresh a popular entry before it expires
  prefetch_min_ttl: 9    # seconds; shorter-lived entries are left to expire
```

Answers are stored as the wire bytes the upstream sent, with their TTLs
rewritten in place on each hit.

- **Size.** Both bounds apply, because the upstream decides how large an entry
  is (up to 64 KiB over a stream transport). Passing either evicts the least
  recently used entries. `cache_bytes=` in the stats line reports what is held.
- **`max_ttl`** caps every upstream answer, forwarded or cached, and how long an
  entry is kept. It does not touch answers elodin writes itself, which carry
  `blocking.block_ttl` or a rewrite's own `ttl`.
- **`min_ttl`** is a floor on the copies served from an entry.
- **Entry lifetime.** An entry lives for the smallest TTL in its message; a
  negative one for the SOA's figure, capped by `negative_ttl` and by any
  shorter TTL beside it. NODATA after a CNAME or DNAME chain that never reaches
  the type asked for is negative (RFC 2308 section 2.2). A denial with no SOA is
  not kept (RFC 2308 section 5). Each record still goes out with its own
  TTL up to the ceiling, so a client's copy need not expire when this cache's
  does.
- A TTL with its top bit set is read as zero (RFC 2181 section 8), forwarded
  answers included, so it is uncacheable unless `min_ttl` raises it.

## Prefetching

Without it, the first query after a popular name's entry expires waits a whole
upstream round trip, once per TTL. With `prefetch` on, a query that reaches an
entry in the last tenth of its lifetime is answered from the cache at once, and
the entry is refreshed in the background (Unbound's `prefetch` rule).

- **Only names being asked for.** An entry nobody queries near its expiry is not
  refreshed. Each entry gets one refresh: if it leaves the entry unrenewed (no
  answer, or nothing storable) the entry expires as it would have, and with
  `serve_stale` the stale path takes over from there.
- **Caching upstreams.** A public resolver's copy counts down alongside this
  one, so a prefetch can come back with the seconds this entry already had left.
  Such a renewal ends when the old entry would have: it counts as a prefetch
  failure and is not refreshed again. A high failure share against such an
  upstream means it is handing back counted-down TTLs, not that it is failing.
- **Cost.** A name asked for steadily is fetched about 11% more often (at 90% of
  its TTL rather than after it), and at most once per lifetime.
- **`prefetch_min_ttl`** leaves entries stored with a shorter lifetime (after
  `min_ttl`, `max_ttl` and `negative_ttl`) to expire. Short-lived names (CDNs,
  load balancers) cause most of the upstream traffic already, so on a small host
  raising it to `60` removes most of the added load and keeps prefetching for
  everything that lives a minute or more. `0` prefetches every entry. It must not
  be above `max_ttl`.
- RD=0 queries are answered from the entry without starting a refresh.
- **Bounds.** A refresh shares `serve_stale`'s slots: one per name at a time, and
  at most a quarter of the query pool (and 64) at once. With none free, the entry is left
  to expire.
- **Counting.** A prefetch is not a client query: it is in neither
  `elodin_answers_total`, the cache hit and miss counts nor the query log. It
  counts in `elodin_cache_prefetches_total` (and
  `elodin_cache_prefetch_failures_total` when it left the entry unrenewed), and
  its exchange in the upstream and DNSSEC series.

## Identical queries in flight

Identical questions (the same cache key) that miss while the first is still out
go to the upstream once. The first forwards and the rest wait for it:

- **NOERROR or NXDOMAIN** is served to the waiters as a cache hit, even one the
  cache will not keep, such as a zero TTL. TTLs are the upstream's; `min_ttl`
  does not raise them. With the cache off, these are shared only as in the next
  point.
- **Any other outcome** (another rcode, or no answer from any server after every
  attempt, which gives the expired copy or SERVFAIL) goes only to waiters whose
  upstream message was byte for byte the first one's, ID aside. Under DNSSEC
  validation, which rewrites the whole OPT record, most are. Without it the
  payload size and OPT flags stay the client's, so only clients that ask alike
  match; different name spellings or EDNS options never do. The rest ask for
  themselves.
- **A cached refusal** (a DNSSEC failure, or a CNAME into a blocked name) refuses
  the waiters without asking. Exceptions: a list reload during the wait that
  lifted the listing serves the answer; an entry evicted meanwhile makes them ask.
- **Cap.** A query arriving when a quarter of the query pool is already waiting
  asks for itself.
- **Logging.** Queries given the first one's outcome, or refused from its cached
  refusal, count in `elodin_answers_coalesced_total`; those that asked do not.
  The query log shows `outcome=cached detail=coalesced` for a shared answer,
  `outcome=failed detail=upstream-coalesced` for a shared failure, or
  `detail=stale` where an expired copy was served.

## Serving stale answers

With `serve_stale`, an entry is kept for a day past its expiry and used when a
fresh answer cannot be got:

- The query goes upstream as a miss would. If nothing has come back after
  `stale_timeout` (RFC 8767 section 5's client response timer), the expired copy
  goes out with a 30-second TTL, and the refresh carries on in the background and
  caches whatever it gets.
- One refresh per name runs at a time; clients arriving meanwhile get the expired
  copy at once.
- Keep `stale_timeout` under the client's own timeout (glibc gives up at five
  seconds, systemd-resolved sooner). `0` waits out the full upstream budget of
  two `upstream.timeout`s (ten seconds by default), by which time most clients
  have failed.
- An upstream that answers, SERVFAIL included, has answered: the client gets that
  reply. `serve_stale` covers an unreachable upstream, not a refusal.
