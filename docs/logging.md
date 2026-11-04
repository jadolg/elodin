# Logs

Every line is [logfmt](https://brandur.org/logfmt), time and severity included
as fields:

```
ts=2026-08-07T09:12:33Z level=info msg=ready strategy=Round_Robin upstreams=2 cache=true blocking=true dnssec=true rebind=false
ts=2026-08-07T09:12:41Z level=info msg=query client=192.0.2.10 port=44188 proto=udp qtype=A qname=example.com outcome=forwarded detail=cloudflare-dot ms=11.7
ts=2026-08-07T09:12:44Z level=warn msg="list steven-black: unavailable, skipping it"
```

The lines meant for machines — `starting`, `sizing`, `ready`, `reloaded` ([signals](install.md#signals)), `stats`, `query` —
keep a fixed `msg` and carry the rest in fields. Every other line is one human
sentence in `msg`. In Loki, `| logfmt` is all it takes:

```logql
{job="elodin"} | logfmt | msg="query" | outcome="blocked"
{job="elodin"} | logfmt | msg="stats" | unwrap cache_hits
```

With `log.file` set, elodin creates the file readable and writable by its
owner only (`0600`), since with `log.queries` on it names every client and every
name looked up. A file that already exists keeps its mode, so a shipper's group
is given access the usual way, e.g. logrotate's `create 0640 elodin adm`; one
with the other-read bit set is named in a `warn` at startup and at each reopen
(`log.file: "..." can be read by any account that can reach its directory`).

Under `server.user` the file is opened again on `SIGHUP` as that account
([Privileges](install.md#privileges)). A file elodin creates at startup is
given to that account as it is made; one that was there already is left as it
is, and the account must be able to write it. After a rotation the name must be
creatable by the account too, so give logrotate `create <mode> <user> <group>`
naming it, or a directory it can write. Started as root with `server.user`
set, elodin refuses a `log.file` with a symlink anywhere on its path, a file
with more than one hard link, or anything but a regular file (a FIFO, a device),
and logs to stderr instead (`--check` says so too): a directory the service
account can write would otherwise let it point the next root start at any file,
or hang it. Name the real path (`/run/...`, not
`/var/run/...`). On kernels before 5.6, or under a seccomp profile that
does not allow `openat2`, only a symlink at the file itself is refused.

With `log.file` set, each line is one write to the file, not followed by a
sync: `tail` and a shipper see it at once and a killed process loses none of
it, but a host crash or power loss can lose the last lines the kernel had not
yet written to disk.

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
- A forwarded answer's `detail` is the [name](upstreams.md) of the upstream
  that gave it, the name warnings about that upstream are logged under too.

## Repeated refusals

Refusals that repeat — an unauthorised source, a truncation, a connection past
the limit, a rebinding refusal for a private address — are logged once at `warn`, naming the setting,
then at `debug`, so a client does not decide how much these refusals write. The stats counters count the
rest.

## Repeated failures

Failures that repeat — an upstream error, a query that got no answer, a
DNSSEC refusal, a chain lookup that could not be made, an answer refused for
being unreadable — are logged at `warn`
the first time and then at most once a minute per kind (per zone for a DNSSEC
refusal, through 16 slots zones can share), with `held=<n>` counting the ones
not logged at `warn` since the line before it; the rest are at `debug`. These lines name the query name, so with
`log.queries` off a name that fails still reaches the log about once a minute.
They name the client only at `debug`.

A name that keeps failing can take each minute's line for its kind, and a
later failure of the same kind then shows only in that line's `held=` and at
`debug`. That is the price of the bound: a client choosing the names cannot
make these lines more than a few a minute.
