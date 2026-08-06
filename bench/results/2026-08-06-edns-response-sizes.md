# EDNS response sizes, against a 1232 ceiling

Measured 2026-08-06. The question is the one left open in issue #99: whether
`edns_udp_size` should clamp to 1232 — the DNS Flag Day 2020 figure — instead of
4096, and what that would cost.

The 129 names of `bench/domains.txt`, asked of 9.9.9.9 over TCP with `DO=1` and
an advertised buffer of 4096, so nothing is truncated and the number recorded is
the whole answer a UDP client would have been sent. TCP rather than UDP for
exactly that reason: over UDP the measurement would be capped by the thing being
measured.

## Sizes

| qtype | ≤512 | 513–1232 | 1233–4096 | median | p90 | p99 | max |
|---|---|---|---|---|---|---|---|
| A | 128 | 1 | **0** | 157 | 269 | 443 | 743 |
| AAAA | 121 | 8 | **0** | 169 | 491 | 553 | 711 |
| DNSKEY | 96 | 28 | **5** | 297 | 931 | 1687 | 1793 |

The five DNSKEY answers over 1232:

| name | bytes |
|---|---|
| nasa.gov | 1793 |
| nic.bg | 1687 |
| house.gov | 1649 |
| nic.hr | 1489 |
| weather.gov | 1486 |

Nothing in the survey reaches 4096 at all. The largest signed answer of any type
is 1793 bytes, and the largest address answer is 743.

## What that says about the clamp

The cost of a 1232 ceiling, on this set, is **no A or AAAA answers at all** and
five DNSKEY answers moving onto TCP — and DNSKEY is a query elodin makes of its
upstreams rather than one clients usually ask, so the client-facing cost here
rounds to nothing. The DNSSEC survey's concern, that a lower ceiling would push
signed answers onto TCP, does not show up in the address queries that make up
the traffic.

The benefit is not measured by this table, and that is the point of writing both
down together. The 4096 ceiling is not reached by any real name in the survey;
it is reached by a name an attacker controls, in a zone they stuffed to fill it.
That is what reflection uses, and it is the whole of what the ceiling bounds. So
the two sides of the trade are:

- **against real traffic**, a 1232 ceiling changes nothing that was measured;
- **against a crafted zone**, it cuts the largest datagram this server can be
  made to send at one address from 4096 to 1232 — 3.3x — and with it the per-/24
  budget of `server.rate_limit`, from about 2 MB/s at 500 responses a second to
  about 600 KB/s.

The residual risk is a client on a path with a working 4096 MTU asking for a
signed answer between 1232 and 4096 bytes, which now costs it a TC bit and a TCP
round trip. Five names in 129 produce such an answer, all for DNSKEY, and all of
them resolve over TCP.

## What was done

`server.max_udp_response`, default 1232, refused outside [512, 4096]. The
ceiling is applied in `response_limit` rather than in `dns.edns_udp_size`, which
keeps the codec reading what the protocol allows — up to 4096 — and leaves the
policy where the server can be configured about it.

A truncation caused by the ceiling, rather than by a client's own smaller
buffer, is logged once at `warn` naming the setting, the two sizes and what
raising it costs; every one after that at `debug`. An operator who is on the
network this table does not describe should be able to find the number without
reading the source.

## Reproducing

```sh
grep -v '^#' bench/domains.txt | sed 's/[[:space:]].*//' | sort -u |
while read -r name; do
  dig +tcp +dnssec +bufsize=4096 @9.9.9.9 "$name" A |
    sed -n "s/.*MSG SIZE  rcvd: /$name /p"
done
```

Every name answered; ten needed a retry on the first pass, all with answers
under 250 bytes.
