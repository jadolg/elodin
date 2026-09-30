# Logs

Every line is [logfmt](https://brandur.org/logfmt), time and severity included
as fields:

```
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true rebind=false
ts=2026-08-07T09:12:41Z level=info msg=query client=192.0.2.10 port=44188 proto=udp qtype=A qname=example.com outcome=forwarded detail=cloudflare-dot ms=11.7
ts=2026-08-07T09:12:44Z level=warn msg="list steven-black: unavailable, skipping it"
```

The lines meant for machines — `starting`, `sizing`, `ready`, `stats`, `query` —
keep a fixed `msg` and carry the rest in fields. Every other line is one human
sentence in `msg`. In Loki, `| logfmt` is all it takes:

```logql
{job="elodin"} | logfmt | msg="query" | outcome="blocked"
{job="elodin"} | logfmt | msg="stats" | unwrap cache_hits
```

## Stats

Every five minutes, `msg=stats` carries, in order: `queries`, `blocked`,
`cached`, `forwarded`, `failed`, `rewritten`, `dropped`, `refused`,
`conn_refused`, `conn_rate_limited`, `conn_failed`, `accept_backoff`,
`handshakes`, `limited`, `truncated`, `secure`, `bogus`, `rebind`,
`special_use`, `cache_entries`, `cache_bytes`, `cache_hits`, `cache_withheld`,
`cache_misses`, `cache_stale`, `cache_evictions`, `unreadable_rcode`,
`coalesced`, `cache_prefetches`, `cache_prefetch_failures`.

## Query log

`log.queries` adds one `msg=query` line per query.

- The source address and port are separate fields, `client` and `port`, so
  filter on `client` alone.
- The query name is escaped like any other value, so a name holding a quote or
  newline cannot forge a field.

## Repeated refusals

Refusals that repeat — an unauthorised source, a truncation, a connection past
the limit, a rebinding refusal — are logged once at `warn`, naming the setting,
then at `debug`, so a client does not decide how much these refusals write. The stats counters count the
rest.
