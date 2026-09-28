# Metrics

```yaml
metrics:
  enabled: true
  address: "127.0.0.1"   # loopback by default
  port: 9153             # the port CoreDNS uses for the same thing
  path: /metrics
```

```
scrape_configs:
  - job_name: elodin
    static_configs:
      - targets: ["127.0.0.1:9153"]
```

- Off by default; nothing is bound until it is enabled.
- Plain HTTP, Prometheus text exposition format, one request per connection.
- Binds loopback by default, since there is no authentication in front of it. A
  wider bind is logged as a warning at startup.
- **Not on the query path.** Every figure is a counter elodin already keeps for
  the `msg=stats` line, read at scrape time. There is no latency histogram and no
  per-name label.
- It runs on one thread of its own: it takes no worker, no `max_connections`
  slot and no rate-limit budget from DNS clients.

| metric | type | what it is |
|---|---|---|
| `elodin_build_info{version}` | gauge | a constant 1, carrying the version as a label |
| `elodin_uptime_seconds` | gauge | seconds since this process finished starting |
| `elodin_queries_total` | counter | queries accepted, whatever became of them |
| `elodin_answers_total{outcome}` | counter | `forwarded`, `cached`, `blocked`, `rewritten`, `failed` |
| `elodin_answers_coalesced_total` | counter | queries answered by waiting on an identical one already in flight. Also counted under the outcome they got: `cached` (`detail=coalesced`, though the cache never held it), `failed` (`detail=upstream-coalesced`, or a stale `cached` if an expired copy was served), or the refusal the first one cached (`detail=dnssec:cache`, or the block detail) |
| `elodin_queries_dropped_total` | counter | turned away before any work: the backlog was full, or the source could not be answered |
| `elodin_queries_refused_total` | counter | turned away by `server.allow_from` |
| `elodin_connections_refused_total` | counter | refused for want of a slot: `server.max_connections` full, or the client's prefix already holding its share |
| `elodin_connections_rate_limited_total` | counter | refused because the prefix was opening connections faster than `rate_limit.responses_per_second` allows |
| `elodin_connections_failed_total` | counter | refused because the OS would not start a thread |
| `elodin_accept_backoffs_total` | counter | times a listener waited before retrying a failed accept. A few while a burst clears; a steady climb is about one a second per listener out of descriptors, about twenty under a stream of per-connection errors. Out of descriptors, read `accept_backoff=` in `msg=stats`: this endpoint cannot accept either |
| `elodin_connections_active` / `_max` | gauge | connection threads in use, and what the limit allows |
| `elodin_connections_max_per_prefix` | gauge | how many of those one client prefix may hold; equal to `_max` when there is no share |
| `elodin_tls_handshakes_total` | counter | TLS handshakes completed on the DoT and DoH listeners |
| `elodin_rate_limited_total` | counter | queries the rate limiter withheld an answer from |
| `elodin_rate_limit_slipped_total` | counter | those answered truncated instead, to send a real client to TCP |
| `elodin_dnssec_answers_total{result}` | counter | `secure` and `bogus` |
| `elodin_dnssec_queries_shed_total` | counter | questions whose chain-of-trust walk was shed because `dnssec.max_chain_walks` were already waiting. One per question. Rising with SERVFAIL means the shedding is this server's, not an upstream failing; it cannot tell an attack from honest load, and a slow upstream can cause it too |
| `elodin_dnssec_oversized_key_sets_total` | counter | DNSKEY sets over the 8 KB per-zone limit, validated but not cached, so each question walks the chain again. Not a fault; a rising figure is a zone publishing something extraordinary, or someone probing. See `dnssec.max_cached_zones` |
| `elodin_rebind_refused_total` | counter | answers withheld because a public name was pointed into private space |
| `elodin_special_use_total` | counter | queries answered from the reserved-name table instead of being forwarded |
| `elodin_cache_entries` / `_bytes` | gauge | what the cache holds, against `max_entries` and `max_bytes` |
| `elodin_cache_hits_total` / `_misses_total` / `_evictions_total` | counter | how it is doing |
| `elodin_cache_stale_total` | counter | expired answers served because no fresh one could be got in time |
| `elodin_cache_withheld_total` | counter | answers the cache handed over that were then refused rather than served |
| `elodin_filter_rules{list}` | gauge | rules loaded, `block` and `allow`, regex rules included |
| `elodin_upstream_queries_total{upstream}` | counter | queries sent to each upstream, by its configured name |
| `elodin_upstream_failures_total{upstream}` | counter | exchanges that produced no usable answer |
| `elodin_upstream_failure_kind_total{upstream,error}` | counter | the same, by cause: `timeout`, `io_error`, `peer_closed`, `bad_response`, `tls_failed`, `verify_failed`, `dial_failed`, `dial_reset`, `http_error`, `too_large`, `not_resolved`. Only kinds that occurred appear. The log names each kind once, so this is the only running record of why an upstream fails. A lone `peer_closed` does not count towards the cooldown; a sustained run does |
| `elodin_upstream_latency_seconds_total{upstream}` | counter | cumulative round-trip time; divide by the query counter under `rate()` for the mean |
| `elodin_upstream_up{upstream}` | gauge | 0 while an upstream is in its failure cooldown |
| `elodin_upstream_unreadable_rcode_total{upstream}` | counter | replies refused because a client would misread their rcode (the extended bits sit in the OPT record). Not counted as a failure: the bytes are forgeable, and a failure would park the group |
| `elodin_upstream_swept_rcode_total{upstream}` | counter | replies passed to another group member: SERVFAIL, REFUSED, an unreadable rcode or a referral for a client question; a referral or anything but NOERROR/NXDOMAIN for a DNSSEC chain lookup. One per such reply, even with no member left to ask. Not a failure, so this is the only figure naming a member that answers but cannot help, such as one REFUSING everything while its partner is in cooldown |
| `elodin_udp_datagrams_total{reader}` | counter | datagrams each UDP reader took off its socket |
| `elodin_udp_receive_drops_total{reader}` | counter | datagrams the kernel dropped on that reader's receive queue before they could be read; absent where `/proc` cannot be read |
| `elodin_pool_workers{pool}` / `elodin_pool_pending{pool}` | gauge | the `query` and `upstream` pools; `pending` that does not return to zero is `server.workers` set too low |
| `elodin_mobileconfig_signed_total` | counter | Apple configuration profiles signed, one per authority per certificate. Present only while the profile endpoint exists |
| `elodin_mobileconfig_refused_total` | counter | profile requests answered 503: the certificate was outside its validity window, or the signing budget was spent. The only sign that a lapsed certificate took the endpoint down |
| `elodin_mobileconfig_unknown_host_total` | counter | profile requests answered 400 for an authority the certificate or listener port does not cover. Climbing usually means a renewal dropped a name devices still use |
| `process_cpu_seconds_total` | counter | user plus system CPU |
| `process_resident_memory_bytes` / `_virtual_memory_bytes` | gauge | from `/proc/self/stat` |
| `process_threads`, `process_open_fds`, `process_max_fds` | gauge | thread and descriptor counts |
| `process_start_time_seconds` | gauge | when this process began serving |

`elodin_answers_total` does not sum to `elodin_queries_total`:

- queries the backlog or the allow list turned away have no outcome;
- answers the rebinding guard withheld are in `elodin_rebind_refused_total`;
- of the `outcome=local` answers, only the reserved-name table is counted, in
  `elodin_special_use_total`.

`sum(elodin_upstream_unreadable_rcode_total)` is part of `outcome="failed"`, not
extra: those queries are SERVFAILs. `msg=stats` carries the same total as
`unreadable_rcode=`.

The `process_` family uses the standard Prometheus client names, so existing
dashboards for those work unchanged.

```promql
sum(rate(elodin_queries_total[5m]))
sum by (outcome) (rate(elodin_answers_total[5m]))
rate(elodin_cache_hits_total[5m]) / rate(elodin_queries_total[5m])
rate(elodin_upstream_latency_seconds_total[5m]) / rate(elodin_upstream_queries_total[5m])
min by (upstream) (elodin_upstream_up) == 0
```

## Grafana

Import [`examples/grafana-dashboard.json`](../examples/grafana-dashboard.json)
under **Dashboards → New → Import**. It asks for a Prometheus data source and
reads `job` and `instance` from `elodin_build_info`, so it works for one instance
or a fleet. It graphs every series on this page.

Two panels show failures nothing else does:

- *Replies the group could not use*: an upstream answering promptly with
  something unusable, which keeps a clean failure rate and `up` of 1.
- *Upstream failures by kind*: the failure rate by cause, which the log states
  only once per kind.
