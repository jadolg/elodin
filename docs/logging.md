# Logs

Every line is [logfmt](https://brandur.org/logfmt), with the time and severity as
fields rather than a prefix a collector has to be taught to recognise:

```
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true rebind=false
ts=2026-08-07T09:12:41Z level=info msg=query client=192.0.2.10 port=44188 proto=udp qtype=A qname=example.com outcome=forwarded detail=cloudflare-dot ms=11.7
ts=2026-08-07T09:12:44Z level=warn msg="list steven-black: unavailable, skipping it"
```

The lines something is expected to watch — `starting`, `sizing`, `ready`,
`stats`, `query` — keep the same `msg` from one line to the next and carry what
differs in fields beside it; everything else is one human sentence in `msg`. In
Loki that is `| logfmt` and nothing else:

```logql
{job="elodin"} | logfmt | msg="query" | outcome="blocked"
{job="elodin"} | logfmt | msg="stats" | unwrap cache_hits
```

Statistics go to the log every five minutes as `msg=stats`: `queries`,
`blocked`, `cached`, `forwarded`, `failed`, `rewritten`, `dropped`, `refused`,
`conn_refused`, `conn_rate_limited`, `conn_failed`, `accept_backoff`,
`handshakes`, `limited`,
`truncated`, `secure`, `bogus`,
`rebind` and `special_use`, plus `cache_entries`, `cache_bytes`, `cache_hits`,
`cache_withheld`, `cache_misses`, `cache_stale` and `cache_evictions`, then
`unreadable_rcode` and `coalesced`.
`log.queries` adds one `msg=query` line per query. The source address and the
port it sent from are two fields, `client` and `port`, so selecting on a client
is a match on `client` alone rather than a prefix of an address joined to an
ephemeral port. A query name is the one field whose bytes a client chooses; it
is escaped like any other value, so a name holding a quote or a newline cannot
forge a field of its own.

Repeated refusals — an unauthorised source, a truncation, a connection past the
limit, a rebinding refusal — are logged once at `warn`, naming the setting, and
at `debug` after that, so whoever is triggering them does not decide how much
this server writes to disk. The stats counters carry the rest.
