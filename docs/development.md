# Developing elodin

## Build

- [mise](https://mise.jdx.dev) pins the toolchain (Odin, clang, and Go for the
  benchmark) and runs the tasks; `mise install` fetches them
- OpenSSL 3.x with headers (`openssl-devel` / `libssl-dev`) for DoT, DoH and the
  DNSSEC signature checks

Odin uses `clang` as its linker driver, so mise pins that too. The pinned clang
defaults to conda's sysroot, so the tasks pass `--sysroot=/ -B/usr/bin`
(`ELODIN_LDFLAGS` in `mise.toml`) to link against the system OpenSSL. Drop the
`clang` pin from `[tools]` and those flags are no longer needed.

```sh
mise trust
mise run build            # bin/elodin, with debug info
mise run release          # bin/elodin, optimised
mise run test             # unit tests
mise run itest            # integration tests against the built binary
mise run leakcheck        # the same suite under AddressSanitizer
mise run verify           # check + test + itest
mise run check            # type-check with -vet -strict-style
mise run fuzz             # build the libFuzzer targets in src/fuzz
mise run fuzz-regression  # replay the committed corpus through each of them
mise run parity           # compare answers with the upstream's, synthetic upstream
mise run parity-regression # replay the seeds in testdata/parity-seeds
mise run run              # run locally on port 5354 with examples/dev.yaml
mise run certs            # self-signed certificate for local DoT/DoH testing
mise run bench            # throughput, latency, CPU and memory (see bench/README.md)
mise run deb              # a .deb from this checkout, into dist/
mise run clean            # remove bin/
```

## Layout

```
src/main/      entry point: arguments, startup order, signals, maintenance loop
src/dns/       message codec: names, compression, records, EDNS, TTL patching
src/yaml/      YAML subset parser and typed accessors
src/config/    configuration schema, loading, validation and worker sizing
src/filter/    sink-list matching and list-format parsers
src/cache/     LRU answer cache
src/dnssec/    validation: canonical form, signatures, NSEC/NSEC3, chain of trust
src/upstream/  transports (UDP/TCP/DoT/DoH), pooling, strategies, cookies, HTTP/1.1 and h2 clients
src/server/    resolver, listeners, DoH endpoint, cookies, local zones, list refresh
src/h2/        HTTP/2 framing, HPACK, and the server connection state machine
src/tlsx/      OpenSSL bindings and a small TLS wrapper
src/pool/      worker pool
src/logx/      logging, in logfmt
src/metrics/   Prometheus exposition format, and process figures out of /proc
src/privdrop/  giving up root once the listeners hold their ports
src/itest/     integration suite: harness, mock upstreams (DNS, HTTP, DoH/h2), clients, fixtures,
               and the upstream-parity check with its own independent wire walker
src/fuzz/      libFuzzer targets for the DNS, DNSSEC, HPACK, h2, HTTP/1.1, DoH, blocklist
               and YAML parsers, and their shared harness
testdata/      fuzz corpus and dictionary, committed so a found crash stays
               found, the parity seeds that have found a divergence, plus
               gen/ - the generator behind the DNSSEC fixtures
bench/         benchmark harness and DNSSEC survey, in Go, with committed results
examples/      the annotated reference configuration, one per deployment (local-only,
               lan, small-device, public, container), a development one, and a
               Grafana dashboard
packaging/     systemd unit and the .deb build script
```

There are two worker pools: one answers queries, one races upstreams. A race job
is submitted and waited on by a query handler, so a single pool could deadlock
with every worker waiting on jobs no worker is free to run.

## Testing

`mise run verify` runs the type check, unit and integration tests. Leak checking
and fuzz regression run in CI; `mise run bench` measures rather than asserts.

**Unit tests** (`mise run test`) run per package, so a failure names one. They
cover:

- the message codec: round trips for every modelled RDATA type, compression,
  truncation, EDNS, pointer loops, hostile record counts
- the YAML parser, configuration loading, list parsing and matching, the cache
- the HTTP/2 codec; the HPACK cases use the worked examples in RFC 7541
  appendix C, so the codec is checked against the specification, not itself
- regression tests in `tlsx`, `upstream`, `h2` and `server` for bugs found by
  other means

The DNSSEC cases use real signed traffic captured from a public resolver
(`src/dnssec/fixtures_test.odin`): the root and `com` (RSA/SHA-256),
`example.com` and `www.cloudflare.com` (ECDSA P-256), `ed25519.nl` (Ed25519), an
NSEC denial from the root, an NSEC3 denial from `com`, and an unsigned
delegation. The validator walks each chain in full. The same fixtures are then
tampered with (a flipped address byte, a stripped signature, a corrupted DS
digest, a mismatched anchor, a clock a year later) and each must come back
bogus. The tests pin the validation time, since the signatures expire. Three
cases cover specific attacks, each confirmed to fail against the code before its
fix:

- a DNSKEY set signed by a key sharing the attested key's tag
- an injected RRSIG naming the zone a denial is checked against
- a response built to maximise upstream lookups for one question

**Integration tests** (`mise run itest`) start the built binary as a separate
process against scripted mock upstreams, so they test what ships. The suite is
hermetic: no public resolver is contacted, ports come from a private range, and
the suite generates its own TLS certificate.

```
mise run itest              # summary
./bin/itest -v              # one line per case
./bin/itest --keep          # keep the working directory and server logs
./bin/itest --binary <path> # test a specific build
```

It covers:

- the command line and `--check`, orderly shutdown, and that every log line of a
  real run parses as logfmt
- the wire format: captured fixtures replayed and compared byte for byte, EDNS
  forwarding, 0x20 case preservation, truncation, FORMERR/NOTIMP handling;
  forwarded transaction ids per RFC 5452
- `allow_from` and the UDP answer-size ceiling
- every listener, including DoH over both HTTP versions and the Apple profile
  end to end; h2 upstreams
- blocking and rewrites in every mode: the new record types from their zone-file
  form, additive rules falling through, PTR synthesis in both families and each
  case that gets none
- rate limiting on every budget, including the per-client connection-table share
  and connection-open rate
- the rebinding guard on and off, the cache
- all three upstream strategies with health cooldown and pooling; per-domain
  routes, including nested ones and an anchor that restores validation
- blocklist downloads and their cache directory
- DNSSEC refusal and the CD bypass, the reserved-name table with each key,
  cookies in both directions
- certificate reload over `SIGHUP`, the metrics endpoint

`src/itest/fixtures.odin` holds real DNS responses captured from a public
resolver, including compression pointers, DNSSEC records and types the codec
does not model. The mock replays them verbatim and the suite compares the bytes
the client receives with the bytes the upstream sent. Fixtures generated with
elodin's own encoder would let a codec bug agree with itself.

**Memory** is checked in two places:

- `odin test` wraps each test in a tracking allocator, and
  `ODIN_TEST_FAIL_ON_BAD_MEMORY` (set by `mise run test`) makes a finding fail
  the test. This only catches a procedure that keeps memory it was lent: the
  query path allocates from a per-request arena reset whole, and the rest
  belongs to the running server, not to anything a unit test calls.
- `mise run leakcheck` builds the binary with `-sanitize:address` and runs the
  integration suite against it, asking each server to exit rather than killing
  it, since ASan reports on exit. This reaches the configuration, the listeners'
  TLS contexts, and the answers a race worker allocates on the heap because they
  may outlive the caller's arena. Being ASan, it also catches use-after-free. It
  is not part of `mise run verify`; CI runs it on every change.

**Fuzzing** covers the parsers that read untrusted bytes, one libFuzzer target
each under `src/fuzz/`:

| target | parser |
|---|---|
| `dns` | `dns.decode_message`, and `dns.truncated_response`, which the UDP read loop calls on a rate-limited query without decoding it |
| `h2` | the HPACK decoder |
| `yaml` | the configuration file parser |
| `http` | the HTTP/1.1 response reader used for list downloads and DoH upstreams |
| `list` | the blocklist formats |
| `dnssec` | the DNSSEC RDATA parsers and the DER built from an upstream's keys and signatures |
| `h2conn` | the h2 frame layer and stream state machine, server and client side |
| `doh` | the HTTP/1.1 request parser DoH clients write into |

The two HTTP readers take a socket, so their targets feed them one end of a
socket pair holding the input.

Odin has no `-fsanitize=fuzzer`, so `mise run fuzz` emits LLVM IR per target and
has clang instrument and link it into `bin/fuzz_*`, with ASan on and bounds
checks kept.

- `.github/workflows/fuzz.yml` fuzzes nightly against a corpus cached between
  runs; `workflow_dispatch` runs it on demand after a parser changes.
- `mise run fuzz-regression`, run by CI on every change, replays
  `testdata/fuzz-corpus/` through each target once without generating anything,
  so a found crash stays found.
- A target needing inputs longer than libFuzzer's default cap (4 KB, or its
  largest seed if longer) puts the cap in
  `testdata/fuzz-corpus/<target>.max_len`, next to its optional `.dict`: one
  line holding a bare number, plus only `#` comment lines or empty lines.
  `scripts/fuzz-max-len.sh` reads it and refuses anything else. Such a target
  also runs with `-len_control=0`, so it gets inputs up to the cap from the
  start.
- A target that feeds its input through a socket refuses a cap above
  `harness.MAX_FEED` at start-up, since `feed` truncates anything longer.

**Parity with the upstream** (`mise run parity`) checks that nothing is lost
between the two sides of the resolver, rather than whether a given answer is
right. A seeded generator makes queries nobody wrote a case for: types the codec
has no structure for, unknown EDNS options, names with bytes a hostname never
holds, 0x20 case randomisation, every transport. Every field of every answer is
compared with the upstream's: the full twelve-bit rcode with the extended half
reassembled, each header flag, and each section as a multiset of records with
names inside RDATA expanded. Every allowed difference is listed in
`src/itest/parity_compare.odin` with its reason and citation; any other
difference fails the run.

The OPT record is checked the other way round. RFC 6891 section 6.1.1 forbids
forwarding or caching it, so elodin writes its own (`normalise_client_opt` in
`src/server/resolver.odin`). The check is that nothing of the upstream's
crossed: none of its options reach the client, the DO bit echoes the query, not
the answer, and the reserved flag bits are zero.

There are two modes, of different strength:

- **Synthetic upstream**: the reference is the exact message elodin received,
  from a mock that answers any name and type deterministically from a zone of
  awkward constructs (a compressed name inside the RDATA of every type that may
  carry one; character-strings empty, full-length and in long runs; TTLs at both
  ends of their range; unassigned types with opaque RDATA; answers too large for
  a datagram; an OPT carrying a cookie and an NSID). Hermetic and reproducible,
  so any divergence is elodin's.
- **Real resolver** (`--parity-upstream 1.1.1.1:53`): the reference is a second,
  byte-identical query sent straight to it, retried over TCP if truncated. A
  real resolver rotates RRsets, expires TTLs and answers from different anycast
  nodes, so a name must answer the same way twice before it is used, and a
  difference must survive re-asking. It finds answers no mock would serve.

**Scenarios** (`--parity-scenario <name|all>`, listed in
`src/itest/parity_scenario.odin`) run each mode against configurations closer to
a resolver in service. Each moves several levers at once:

- the upstream transport (UDP, TCP, DoT, DoH)
- the strategy (failover, race, round robin) and a zone routed elsewhere
- the cache; cookies off or required
- the UDP ceiling at 512, 1232 and 4096
- block rules on a name and on a CNAME target, with an allow rule inside them
- clients over UDP, TCP, DoT, and DoH as POST, GET and HTTP/2
- live only: validation and the cache both off, and the upstream reached over
  DoT or DoH at the resolver's own name

What a scenario answers itself is checked, not skipped: a blocked name gets the
configured block response without asking the upstream; a `cookies.require`
client gets BADCOOKIE and a cookie with its own half before its query is held to
parity; a route reaches its own upstream and nothing else; a cached answer's
TTLs have counted down by no more than the entry's age.

Both modes use their own wire walker (`src/itest/parity_wire.odin`), which does
not import `elodin:dns`: a comparator built on the codec under test would lose a
record identically on both sides and report agreement.

**Seeds**: every query in a run derives from one 64-bit seed, printed during the
run and in any failure, so `--parity-seed` reproduces a nightly run locally.
`mise run parity-regression` replays the seeds in `testdata/parity-seeds` (those
that have found something) on every pull request.

**Nightly**: `.github/workflows/parity.yml` runs both modes nightly with a fresh
seed.

- The synthetic job is a gate: its reference is exact, so a divergence is a bug.
- The live job only reports: two queries to one anycast address can hit nodes
  with different data, and elodin's cache can answer without asking. That noise
  runs at about one query in two hundred. Findings are followed up by hand,
  usually by reproducing them against the synthetic upstream.

The live mode has no mise task, so a bare `mise run` never reaches a public
resolver; run `./bin/itest --parity --parity-upstream <host:port>` yourself.

```
mise run parity                                   # 2000 queries per scenario, synthetic upstream
./bin/itest --parity --parity-seed 1 -v           # reproduce one run
./bin/itest --parity --parity-scenario cache      # one scenario; `all` for every one
./bin/itest --parity --parity-explain             # print the allowed differences too
./bin/itest --parity --parity-upstream 1.1.1.1:53 --parity-scenario all # against a real resolver
```

**Against live DNS**: the layers above show that forged answers are refused, but
not that working names keep working; a validator refusing everything would pass
them. From `bench/`, `go run ./cmd/bench -survey 9.9.9.9:53` resolves every name
in `bench/domains.txt` through elodin with validation on and through a reference
validating resolver, and compares rcode and AD bit. The deliberately broken
zones in the list must be refused and everything else must resolve. Names served
without the AD bit are the SHA-1 downgrade described under
[DNSSEC](dnssec.md#dnssec), a property of the host's crypto policy, not the
zone.

**HTTP/2 interop** with a foreign implementation (curl, via nghttp2) is checked
by hand: `curl --http2 -k -H 'content-type: application/dns-message'
--data-binary @query.bin https://127.0.0.1:443/dns-query`.

**CI** (`.github/workflows/ci.yml`) runs on every pull request and every push to
`main`:

- once: `mise run check`, `fuzz-regression`, `parity-regression`, `leakcheck`
- on both architectures: `mise run test`, `itest`, `build`, and `mise run deb`,
  whose package is installed on the runner, made to resolve a handful of names
  through the resolver takeover it performs, then removed, checking the runner
  gets its own resolver back
