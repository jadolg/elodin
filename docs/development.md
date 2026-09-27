# Developing elodin

## Build

- [mise](https://mise.jdx.dev) pins the toolchain (Odin, clang, and Go for the
  benchmark) and runs the tasks; `mise install` fetches them
- OpenSSL 3.x with headers (`openssl-devel` / `libssl-dev`) for DoT, DoH and the
  DNSSEC signature checks

Odin shells out to `clang` as its linker driver, so mise pins that too. The
pinned build defaults to conda's own sysroot, so the tasks pass `--sysroot=/
-B/usr/bin` (`ELODIN_LDFLAGS` in `mise.toml`) to send the linker back to the
system OpenSSL; drop the `clang` pin from `[tools]` and those flags become
unnecessary.

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

Two worker pools run underneath: one answering queries, one dedicated to racing
upstreams. They are separate on purpose — a race job is submitted *by* a query
handler and waited on by it, so one pool could deadlock once every worker was
blocked on jobs nobody was left to run.

## Testing

`mise run verify` runs the first two layers. A third watches what those two do to
memory, fuzzing runs on its own schedule, and `mise run bench` measures rather
than asserts.

**Unit tests** (`mise run test`) cover the message codec — round trips for every
modelled RDATA type, compression, truncation, EDNS, pointer loops, hostile record
counts — plus the YAML parser, configuration loading, list parsing and matching,
the cache, and the HTTP/2 codec, whose HPACK cases run the worked examples from
RFC 7541 appendix C so the codec is checked against the specification's own
vectors rather than against itself. They run per package, so a failure names one.
Much of `tlsx`, `upstream`, `h2` and `server` is the suite grown around bugs
found some other way that had to stay found.

The DNSSEC cases work from real signed traffic captured from a public resolver
(`src/dnssec/fixtures_test.odin`): the root and `com` with RSA/SHA-256,
`example.com` and `www.cloudflare.com` with ECDSA P-256, `ed25519.nl` with
Ed25519, a real NSEC denial from the root, a real NSEC3 denial from `com`, and a
real unsigned delegation. The validator walks those chains the whole distance,
and the same fixtures are then tampered with — a flipped address byte, a stripped
signature, a corrupted DS digest, a mismatched anchor, a clock a year later — and
every one has to come back bogus. Signatures expire, so the tests pin the moment
they are judged against rather than reading the clock. Three cases hold specific
attacks down: a DNSKEY set signed by a key sharing the attested key's tag, an
injected RRSIG naming the zone a denial is checked against, and a response built
to make one question cost as many upstream lookups as possible — each checked
against the code as it stood before its fix, so they are known to fail when the
property they guard does.

**Integration tests** (`mise run itest`) start the built binary as a separate
process against scripted mock upstreams, so what is exercised is the artefact
that ships rather than the library it was compiled from. The suite is hermetic:
no public resolver is contacted, ports come from a private range, and the
certificate for the TLS cases is generated by the suite itself.

```
mise run itest              # summary
./bin/itest -v              # one line per case
./bin/itest --keep          # keep the working directory and server logs
./bin/itest --binary <path> # test a specific build
```

It covers the command line and `--check`, orderly shutdown, that every line of a
real run parses as logfmt, the wire format (captured fixtures replayed and
compared byte for byte, EDNS forwarding, 0x20 case preservation, truncation,
FORMERR/NOTIMP handling), forwarded transaction ids per RFC 5452, `allow_from`,
the UDP answer-size ceiling, every listener including DoH over both HTTP versions
and the Apple profile end to end, h2 upstreams, blocking and rewrites in every
mode — the new record types from their zone-file form, additive rules falling
through, and the PTR synthesis in both families with each of the cases that gets
none — rate limiting on every budget, including the share of the connection table
one client may hold and the rate at which it may open them, the rebinding guard on
and off, the cache,
all three upstream strategies with health cooldown and pooling, per-domain
routes including nested ones and an anchor that puts validation back, blocklist
downloads and their cache directory, DNSSEC refusal and the CD bypass, the
reserved-name table with each key, cookies in both directions, certificate
reload over `SIGHUP`, and the metrics endpoint.

`src/itest/fixtures.odin` holds real DNS responses captured from a public
resolver, including compression pointers, DNSSEC records and types the codec does
not model. The mock replays them verbatim and the suite compares the bytes the
client receives against the bytes the upstream sent — generating the fixtures
with elodin's own encoder would let a codec bug agree with itself and still pass.

**Memory** is checked in two places, because no one place can see all of it.
`odin test` wraps every test in a tracking allocator, and
`ODIN_TEST_FAIL_ON_BAD_MEMORY` — set for `mise run test` — turns what it finds
into a failing test rather than a warning line among the passes. That catches a
procedure which keeps what it was lent, and nothing else: nearly every allocation
on the query path comes from a per-request arena that is reset whole, so a leak
there is invisible by construction, and the memory that is *not* arena-backed
belongs to the running server rather than to any procedure a test calls.

So `mise run leakcheck` builds the binary with `-sanitize:address` and runs the
integration suite against it, asking each server to exit rather than killing it —
a sanitizer reports on its way out, and a killed process never gets there. This
is the layer that reaches the configuration, the listeners' TLS contexts, and the
answers a race worker allocates on the heap because it may outlive the caller's
arena; every one of those has leaked at some point, and none is reachable from a
unit test. Being ASan rather than LSan alone, it also catches a use-after-free —
which is how the certificate reload was found to be freeing a context a
connection was still about to read. It is not part of `mise run verify`, which is
the fast local gate; CI runs it on every change.

**Fuzzing** covers the parsers that read bytes somebody else chose, one
libFuzzer target each under `src/fuzz/`: the DNS wire codec (`dns`:
`dns.decode_message`, plus `dns.truncated_response`, which the UDP read loop
reaches for a rate-limited query without decoding it first), the HPACK decoder
(`h2`), the YAML parser that reads the configuration file (`yaml`), the HTTP/1.1
response reader that list hosts and DoH upstreams write into (`http`), the
blocklist formats (`list`), the DNSSEC RDATA parsers and the DER that signature
checking builds out of an upstream's keys and signatures (`dnssec`), the h2 frame
layer and stream state machine on both the server and client side (`h2conn`),
and the HTTP/1.1 request parser DoH clients write into (`doh`). The two HTTP
readers take a socket, so their targets hand them one end of a socket pair the
input has been written into. Odin has no `-fsanitize=fuzzer`, so `mise run fuzz`
emits LLVM IR per target and has clang instrument and link it into a libFuzzer
binary at `bin/fuzz_*`, with ASan on and bounds checks still in. Running one is
open-ended, so `.github/workflows/fuzz.yml` does it nightly
against a corpus cached between runs, and `workflow_dispatch` runs it on demand
after a parser is touched. A target that needs inputs longer than libFuzzer's
default cap (4 KB, or its largest seed if longer) puts the cap in
`testdata/fuzz-corpus/<target>.max_len`, next to its optional `.dict`: one line
that is a bare number, and only `#` lines for why, or empty ones
(`scripts/fuzz-max-len.sh` reads it, and refuses anything else). Such a target
also runs with `-len_control=0`, so it gets inputs up to the cap from the start
rather than after libFuzzer's slow ramp towards it. A target that feeds its
input through a socket refuses a cap past `harness.MAX_FEED` at start-up, since
`feed` cuts anything longer. What CI runs on every change is
`mise run fuzz-regression`, which replays `testdata/fuzz-corpus/` through each
target once and generates nothing new, so a crash fuzzing has already found stays
found.

**Parity with the upstream** (`mise run parity`) asks the one question none of
the layers above asks: not whether a particular answer is right, but whether
*anything at all* is lost between the two sides of the resolver. A forwarding
resolver is a pipe, and a fixed case can only check the parts of the pipe
somebody thought to check.

So a seeded generator makes queries nobody wrote down — types the codec has no
structure for, EDNS options it does not recognise, names holding bytes a hostname
never holds, the 0x20 case randomisation a stub uses, every transport — and every
field of every answer is held against the upstream's: the full twelve-bit rcode
with the extended half reassembled, each header flag, and each section as a
multiset of records with the names inside RDATA expanded. Every place elodin is
entitled to differ is written down in `src/itest/parity_compare.odin` with the
reason and the citation, and a difference not on that list fails the run. That is
the point of the file: a divergence nobody can name is a divergence nobody
decided on.

The OPT record is the exception, and it is checked the other way round. RFC 6891
section 6.1.1 forbids caching or forwarding one, so the record a client reads is
this server's own statement rather than a copy — see `normalise_client_opt` in
`src/server/resolver.odin`. There the test is that *nothing* of the upstream's
crossed: an option of theirs reaching a client is the failure, the DO bit has to
echo the query rather than the answer, and the reserved flag bits have to be
zero.

It runs in two modes, and they are not equally strong:

- **Against a synthetic upstream**, the reference is the very message elodin was
  handed — a mock that answers any name and type deterministically from a zone
  built to hold the awkward constructs (a compressed name inside the RDATA of
  every type that may carry one, character-strings empty, full-length and in a
  run long enough to catch a miscounted list, TTLs at both ends of their range,
  unassigned types with opaque RDATA, answers too large for a datagram, an OPT
  carrying a cookie and an NSID at once). Hermetic and reproducible, so a
  divergence here is elodin's and nobody else's.
- **Against a real resolver** (`--parity-upstream 1.1.1.1:53`), the reference is
  a second, byte-identical query put straight to it, retried over TCP if the
  datagram would not hold the answer. Weaker by construction — a real resolver
  rotates RRsets, expires TTLs between two datagrams and answers from whichever
  anycast node took the query — so a name has to answer the same way twice before
  it is used as a reference at all, and a difference has to survive asking the
  whole question again. What it buys is answers no mock would think to serve.

Each mode runs under **scenarios** (`--parity-scenario <name|all>`, listed in
`src/itest/parity_scenario.odin`), because a pipe with the cache off and one
plain-UDP upstream is not the pipe a resolver in service is. Each scenario moves
several levers at once: the upstream's transport (UDP, TCP, DoT, DoH), the
strategy (failover, race, round robin) and a zone routed elsewhere, the cache,
cookies off or required, the UDP ceiling at 512, 1232 and 4096, and block rules
on a name and on a CNAME target with an allow rule inside them. Clients ask over
UDP, TCP, DoT and DoH as POST, GET and HTTP/2. What a scenario answers for
itself is checked rather than skipped: a blocked name has to get the configured
block response without the upstream being asked, a `cookies.require` client has
to get BADCOOKIE and a cookie carrying its own half before its query is held to
parity, a route has to reach its own upstream and nothing else, and a cached
answer's TTLs may have counted down by no more than the entry's age. Live
scenarios add validation and the cache both off, and the upstream reached over
DoT or DoH at the resolver's own name.

Both are built on their own wire walker (`src/itest/parity_wire.odin`) which does
not import `elodin:dns`, for the reason the fixtures give: a comparator built on
the codec under test loses a record identically on both sides and reports
agreement.

Every query of a run comes from one 64-bit seed, printed on the way past and
repeated in any failure, so `--parity-seed` reproduces a nightly run on a laptop.
`mise run parity` runs the synthetic mode; the live one has no task, since
one that reaches a public resolver is not one to put behind a bare `mise run`:
run `./bin/itest --parity --parity-upstream <host:port>` yourself. `.github/workflows/parity.yml` runs both nightly against a fresh
seed;
`mise run parity-regression` replays the seeds in `testdata/parity-seeds` — the
ones that have found something — on every pull request, the same division as
fuzzing.

The two nightly jobs are not both gates, and the difference is deliberate. The
synthetic-upstream job fails the run: its reference is exact, so a divergence is
a bug. The live job only reports, because its reference is a resolver nobody here
controls — two queries to one anycast address can be answered by nodes holding
different copies, and elodin's own cache can answer without asking anyone at all.
That residual measures at about one query in two hundred; it is not something a
commit can fix, and a job that goes red that often for reasons nobody can act on
is one people stop reading. A finding there is followed up by hand, usually by
reproducing it against the synthetic upstream where the answer is either a bug or
is not.

```
mise run parity                                   # 2000 queries per scenario, synthetic upstream
./bin/itest --parity --parity-seed 1 -v           # reproduce one run
./bin/itest --parity --parity-scenario cache      # one scenario; `all` for every one
./bin/itest --parity --parity-explain             # print the allowed differences too
./bin/itest --parity --parity-upstream 1.1.1.1:53 --parity-scenario all # against a real resolver
```

**Against live DNS**, because none of the layers above can prove the absence of
false failures: they work from fixtures and generated input, so they can show
that a forged answer is refused and cannot show that validation leaves working
names working — a validator that refused everything would pass the entire suite.
From `bench/`, `go run ./cmd/bench -survey 9.9.9.9:53` asks every name in
`bench/domains.txt` through elodin with validation on, asks a reference
validating resolver the same thing, and compares the rcode and the AD bit: the
deliberately broken zones in that list have to be refused and everything else has
to resolve. Names served without the AD bit are the SHA-1 downgrade described
under [DNSSEC](dnssec.md#dnssec) — a fact about the host's crypto policy rather than about
the zone.

Interoperability with a foreign HTTP/2 implementation is checked by hand with
curl, which uses nghttp2: `curl --http2 -k -H 'content-type:
application/dns-message' --data-binary @query.bin
https://127.0.0.1:443/dns-query`.

CI (`.github/workflows/ci.yml`) runs on every pull request and every push to
`main`: `mise run check` once, `mise run test` and `mise run itest` on both
architectures, `mise run fuzz-regression`, `mise run parity-regression` and
`mise run leakcheck` once, `mise run build` on both, and —
on both — a `mise run deb` that is then installed on the runner, asked to resolve
a handful of names through the takeover it just performed, and removed again with
a check that the runner got its own resolver back.
