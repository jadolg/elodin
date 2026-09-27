# Metrics

```yaml
metrics:
  enabled: true
  address: "127.0.0.1"   # loopback by default
  port: 9153             # the port CoreDNS uses for the same thing
  path: /metrics
```

Off by default, and nothing is bound until it is turned on. The endpoint speaks
plain HTTP and serves the Prometheus text exposition format.

```
scrape_configs:
  - job_name: elodin
    static_configs:
      - targets: ["127.0.0.1:9153"]
```

**It is not on the path a query takes.** Every number it publishes is a counter
the resolver already maintains for the `msg=stats` line, read at scrape time from
the atomic it already lives in. There is no latency histogram and no per-name
label, because both would mean measuring on the path being measured. The
isolation is structural: one thread of its own, no work queued on either worker
pool, no thread per connection — so nothing reaching this port can spend the
budget `max_connections` keeps for clients, or the per-prefix arrival budget the
DNS listeners charge — and one request per connection before closing, so a scraper
holding a socket open cannot keep the next scrape out.

It binds loopback rather than the `0.0.0.0` the DNS listeners use: nothing here
is a secret in the way an answer is, but together these numbers describe a
network and there is no authentication in front of them. A wider bind is logged
as a warning at startup.

| metric | type | what it is |
|---|---|---|
| `elodin_build_info{version}` | gauge | a constant 1, carrying the version as a label |
| `elodin_uptime_seconds` | gauge | seconds since this process finished starting |
| `elodin_queries_total` | counter | queries accepted, whatever became of them |
| `elodin_answers_total{outcome}` | counter | `forwarded`, `cached`, `blocked`, `rewritten`, `failed` |
| `elodin_answers_coalesced_total` | counter | queries that waited for an identical one already in flight instead of asking the upstream: its answer, counted as `cached` although the cache never held it (`detail=coalesced`), its failure, counted as `failed` (`detail=upstream-coalesced`) or, where an expired copy was served, as a stale `cached`, or the refusal it cached, logged as that refusal (`detail=dnssec:cache`, or the block detail) |
| `elodin_queries_dropped_total` | counter | turned away before any work: the backlog was full, or the source could not be answered |
| `elodin_queries_refused_total` | counter | turned away by `server.allow_from` |
| `elodin_connections_refused_total` | counter | refused for want of a slot: `server.max_connections` full, or the client's prefix already holding its share |
| `elodin_connections_rate_limited_total` | counter | refused because the prefix was opening connections faster than `rate_limit.responses_per_second` allows |
| `elodin_connections_failed_total` | counter | refused because the OS would not start a thread |
| `elodin_accept_backoffs_total` | counter | times a listener waited before retrying an accept it could not complete; a few while a burst clears, then steadily for as long as it does not — about one a second per listener out of descriptors, about twenty for one meeting a stream of per-connection errors. Read it in the `msg=stats` line rather than here when descriptors are what ran out: this endpoint has an accept loop of its own and cannot be scraped either |
| `elodin_connections_active` / `_max` | gauge | connection threads in use, and what the limit allows |
| `elodin_connections_max_per_prefix` | gauge | how many of those one client prefix may hold; equal to `_max` when there is no share |
| `elodin_tls_handshakes_total` | counter | TLS handshakes completed on the DoT and DoH listeners |
| `elodin_rate_limited_total` | counter | queries the rate limiter withheld an answer from |
| `elodin_rate_limit_slipped_total` | counter | those answered truncated instead, to send a real client to TCP |
| `elodin_dnssec_answers_total{result}` | counter | `secure` and `bogus` |
| `elodin_dnssec_queries_shed_total` | counter | questions whose chain-of-trust walk stopped short of an upstream, because `dnssec.max_chain_walks` were already waiting on one; one per question. Rising alongside SERVFAIL means the shedding is this server's, not an upstream going away — but it cannot tell an attack from honest saturation, and a slow upstream reaches it too. See `dnssec.max_chain_walks` |
| `elodin_dnssec_oversized_key_sets_total` | counter | DNSKEY sets the zone cache declined to store, being larger than the 8 KB one zone may hold. Not a fault: the answer still validated, and what is lost is the caching, so every question about such a zone walks the chain again. A rising figure is a zone that has published something extraordinary, or somebody making the point — see `dnssec.max_cached_zones` |
| `elodin_rebind_refused_total` | counter | answers withheld because a public name was pointed into private space |
| `elodin_special_use_total` | counter | queries answered from the reserved-name table instead of being forwarded |
| `elodin_cache_entries` / `_bytes` | gauge | what the cache holds, against `max_entries` and `max_bytes` |
| `elodin_cache_hits_total` / `_misses_total` / `_evictions_total` | counter | how it is doing |
| `elodin_cache_stale_total` | counter | expired answers served because no fresh one could be got in time |
| `elodin_cache_withheld_total` | counter | answers the cache handed over that were then refused rather than served |
| `elodin_filter_rules{list}` | gauge | rules loaded, `block` and `allow` |
| `elodin_upstream_queries_total{upstream}` | counter | queries sent to each upstream, by its configured name |
| `elodin_upstream_failures_total{upstream}` | counter | exchanges that produced no usable answer |
| `elodin_upstream_failure_kind_total{upstream,error}` | counter | the same exchanges, split by what went wrong: `timeout`, `io_error`, `peer_closed`, `bad_response`, `tls_failed`, `verify_failed`, `dial_failed`, `dial_reset`, `http_error`, `too_large`, `not_resolved`. `peer_closed` on its own does not count towards the failure cooldown, though a sustained run of it does. Only the kinds that have happened; `sum by (upstream)` of this is the family above. The log says each kind once per process, so this is the only continuous account of *which* way an upstream is failing, and that is the half that decides what to do about it |
| `elodin_upstream_latency_seconds_total{upstream}` | counter | cumulative round-trip time; divide by the query counter under `rate()` for the mean |
| `elodin_upstream_up{upstream}` | gauge | 0 while an upstream is in its failure cooldown |
| `elodin_upstream_unreadable_rcode_total{upstream}` | counter | replies from each upstream refused because their rcode is one a client would read as a different rcode — the extended half lives in the OPT record and a stub reads the header. Not counted as a failure above, on purpose: those bytes are forgeable, and a failure would park the group |
| `elodin_upstream_swept_rcode_total{upstream}` | counter | replies from each upstream that another member of its group was asked to answer instead: for a client's question a SERVFAIL, a REFUSED, an unreadable rcode or a referral, and for a DNSSEC chain lookup a referral or anything that is not NOERROR or NXDOMAIN. One per such reply, whether or not there was another member left to ask — a member REFUSING everything beside one in its cooldown breaks every query while both look healthy, and this is what names it. Not a failure either, so this is the only figure naming a member that answers but cannot help |
| `elodin_udp_datagrams_total{reader}` | counter | datagrams each UDP reader took off its socket |
| `elodin_udp_receive_drops_total{reader}` | counter | datagrams the kernel dropped on that reader's receive queue before they could be read; absent where `/proc` cannot be read |
| `elodin_pool_workers{pool}` / `elodin_pool_pending{pool}` | gauge | the `query` and `upstream` pools; `pending` that does not return to zero is `server.workers` set too low |
| `elodin_mobileconfig_signed_total` | counter | Apple configuration profiles signed; one per authority until the certificate is renewed. Published only while the profile endpoint exists |
| `elodin_mobileconfig_refused_total` | counter | profile requests answered 503: the DoH certificate was outside its validity window, or the signing budget was spent. The only signal that a lapsed certificate has taken the endpoint with it |
| `elodin_mobileconfig_unknown_host_total` | counter | profile requests answered 400: an authority this listener could not have been reached at — a host the certificate does not cover, or a port it does not answer on. Climbing usually means a renewal dropped a name devices still ask for |
| `process_cpu_seconds_total` | counter | user plus system CPU |
| `process_resident_memory_bytes` / `_virtual_memory_bytes` | gauge | from `/proc/self/stat` |
| `process_threads`, `process_open_fds`, `process_max_fds` | gauge | thread and descriptor counts |
| `process_start_time_seconds` | gauge | when this process began serving |

`elodin_answers_total` does not sum to `elodin_queries_total`: queries the
backlog or the allow list turned away never reached an outcome, an answer the
rebinding guard withheld is counted in `elodin_rebind_refused_total`, and of the
`outcome=local` answers only the reserved-name table is counted, in
`elodin_special_use_total`. `sum(elodin_upstream_unreadable_rcode_total)` is a
subset of `outcome="failed"` rather than a figure beside it: those queries are
SERVFAILs like any other, and it says how many of them were an upstream
answering something no client could read — the `msg=stats` line carries the same
total as `unreadable_rcode=`. The `process_` family carries the names every
Prometheus client library uses, so a dashboard written against a Go or Python
service works here unchanged.

```promql
sum(rate(elodin_queries_total[5m]))
sum by (outcome) (rate(elodin_answers_total[5m]))
rate(elodin_cache_hits_total[5m]) / rate(elodin_queries_total[5m])
rate(elodin_upstream_latency_seconds_total[5m]) / rate(elodin_upstream_queries_total[5m])
min by (upstream) (elodin_upstream_up) == 0
```

A Grafana dashboard is in
[`examples/grafana-dashboard.json`](../examples/grafana-dashboard.json) — import it
under **Dashboards → New → Import**. It asks for a Prometheus data source and
picks up `job` and `instance` from `elodin_build_info`, so it works against one
instance or a fleet without editing. It covers every series on this page but
`elodin_answers_coalesced_total`, which is worth a check when one is added: a metric nothing graphs is one an operator
finds out about by reading the code.

Two of its panels are there for failures that leave no other trace. *Replies the
group could not use* is the only place an upstream that answers promptly with
something unusable shows up at all, since it keeps a clean failure rate and an
`up` of 1. *Upstream failures by kind* splits the failure rate by what went
wrong, which the log states once per kind per process and so cannot be read as a
rate.
