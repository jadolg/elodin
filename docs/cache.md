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
```

Answers are stored as untouched wire bytes plus the offsets of their TTL fields,
and those TTLs are rewritten in place on each hit, so name compression stays
intact and there is no decode/encode round trip on the hot path.

Both bounds are needed, because an entry's size is decided by whoever answered
the query — the response as it arrived, up to 64 KiB over a stream transport,
plus an offset and a TTL per record. Eviction is from the least recently used end
whenever either bound is passed, and `cache_bytes=` in the stats line reports
what is held.

`max_ttl` caps every answer passed on from an upstream, forwarded or cached, as
well as how long the entry is kept; it does not touch the answers elodin writes
itself, which carry `blocking.block_ttl` or a rewrite's own `ttl`. `min_ttl` is a
floor on the copies served from an entry. Neither is a promise that a client
drops a record when this cache does: an entry lives for the smallest TTL in the
message it holds, a negative one for the SOA's figure capped by `negative_ttl`
(a denial with no SOA is not kept at all, per RFC 2308 section 5),
while every record still goes out carrying its own TTL up to the ceiling. A TTL
with its top bit set is taken as zero per RFC 2181 section 8, forwarded answers
included, which leaves it uncacheable unless `min_ttl` raises it.

Identical questions that miss the cache while the first is still out are sent
to the upstream once. The first query forwards and the rest wait for it. A
NOERROR or NXDOMAIN answer is then served to them as though found in the cache,
including one the cache will not keep, such as one with a zero TTL. Its TTLs are
the ones the upstream sent, and `min_ttl` does not raise them. With the cache off,
such an answer is shared only as below. Any other
outcome goes only to queries whose message to the upstream was byte for byte
the first one's, apart from the ID. That covers any other rcode, and the
upstream giving nothing after every attempt on every server, in which case they
get the expired copy or SERVFAIL. Under DNSSEC validation, whose rewrite writes
the whole OPT record, most messages are identical. Without it, the payload size
and the OPT flags stay the client's, so only clients that ask alike match.
Different spellings of the name, or different EDNS options, never do. If the
first query cached a refusal instead, a DNSSEC failure or a CNAME into a blocked
name, the waiting queries are refused from it without asking. The exceptions are
a list reload during the wait that lifted the listing, in which case the
answer is served, and an entry evicted in the meantime, in which case they ask. The other waiting
queries ask for themselves, as does any query that arrives when a
quarter of the query pool is already waiting like this. "Identical" means the
same cache key. The queries given the first one's outcome, or refused
from its cached refusal, count in `elodin_answers_coalesced_total`, and those
that asked for themselves do not. The query log
shows a shared answer as `outcome=cached detail=coalesced` and a shared failure
as `outcome=failed detail=upstream-coalesced`, or as `detail=stale` where an
expired copy was served instead.

`serve_stale` keeps an entry for a day past its expiry and answers from it when
a fresh answer cannot be got. What decides *when* is `stale_timeout`, RFC 8767
section 5's client response timer: the query goes to the upstream as a miss
would, and if no answer has come back by then the expired copy goes out with a
30-second TTL while the refresh carries on in the background and writes whatever
it gets to the cache. One refresh per name is in flight at a time, so an expired
name a hundred clients are asking for costs one upstream query rather than a
hundred, and the clients that arrive while it is running are served the expired
copy at once rather than queued behind it.

The timer is measured against the client's own resolver, not against the
upstream. Without it the fallback waits out the upstream budget of two
`upstream.timeout`s — ten seconds with the defaults — by which time a
glibc stub has given up at five and systemd-resolved sooner, so the expired
answer arrived after the client had already failed. Setting it to `0` restores
that: the client waits the whole upstream budget out. An upstream that *answers*
— SERVFAIL included — has answered, and its reply is what the client gets;
`serve_stale` covers an upstream that cannot be reached, not one this server
refused.
