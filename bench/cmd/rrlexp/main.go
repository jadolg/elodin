/*
Command rrlexp is an experiment rather than a benchmark: it asks what response
rate limiting does to a bystander.

The claim the feature rests on is that a flood from one client does not stop
another client being served. `src/server/ratelimit.odin` argues it; the
integration suite asserts the mechanism (a flood is cut to the budget, a
datagram flood does not close a prefix's connections). Neither shows the
bystander's own experience under load, which is the thing an operator cares
about: does the query I send while somebody else is flooding come back, and how
long does it take.

So each arm below runs two clients at once against one server - an attacker
flooding and a victim asking at a household rate - and reports what the victim
got. The arms differ in where the two clients sit relative to the budget:

  - a different /24, which is the case the feature promises to handle
  - the same /24, which is the granularity the budget is kept at and therefore
    the case where the bystander is collateral damage by design
  - the same /24 but a different transport, where the two-pool separation is
    what saves the bystander

Every arm has a control with the limiter off, because "the victim was served"
means nothing on its own: a server that was never saturated would serve the
victim with no limiter at all. The pair is what says whether the limiter is
carrying the result.

The `slowloris` arms ask the same question of a different resource. What a
bystander needs is not only an answer but somewhere to ask, and the connection
table is a per-client share of its own: those arms hold connections open and idle
from one prefix - load no response budget can see, since a budget is spent by
queries - and report what a client in another /24 gets while it is happening,
with `server.max_connections_per_prefix` set and unset.

The `handshake-flood` arms take that one step further, to the load neither bound
reaches: a client that connects, completes a TLS handshake, closes, and goes
again. It spends no response budget, because it asks nothing, and it holds no
connection for longer than a handshake takes - while costing the server an
asymmetric key operation per connection. A DoT victim asking at a household rate
is what says whether that matters.

The `v6` arms are the prefix-isolation arms over IPv6, where a prefix is a /64
rather than a /24. One procedure decides both (`client_prefix`), so they ask
whether the second half of it holds up as well as the first, and what the wider
address costs on the read path. They need loopback addresses this harness cannot
create; a machine without them skips those arms and is told what to run.

The soak (`-soak 1h`) is the flood from `other-prefix/limiter-on` for as long as
it is given, with a victim that opens a connection per query, read every
`-soak-sample` rather than once at the end: what accumulates over an hour -
resident memory, a cache under eviction, a connection table lending and
reclaiming - is a shape rather than a final number, and the short arms cannot see
it at all.

The load generator builds and parses DNS messages itself (`internal/dnswire`)
and the upstream is in-process here, for the reason bench/README.md gives: a
generator sharing the codec under test could agree with a bug in it.
*/
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"elodin.bench/internal/procstat"
)

// A client, which is a source address and a way of asking from it.
type clientSpec struct {
	src       string
	transport string // udp, tcp, doh1 or doh2
	// Queries per second offered, in total across sockets. 0 is as fast as the
	// socket accepts, which is what an unthrottled flood is.
	rate int
	// Connections. On DoH this is `MaxConnsPerHost`, so 1 is the single
	// multiplexed connection the h2 arms are about.
	sockets int
	/*
		Requests in flight at once, DoH only.

		The datagram and stream clients have one query in the air per socket,
		which is what those transports do. An h2 client does not: it multiplexes,
		and that is the property the TCP arms could not reach - eight pipelined
		connections offer the limiter about 400 queries a second because each is
		served one at a time, where one h2 connection with this many requests
		outstanding passes the budget on its own.
	*/
	inflight int
	/*
		`unique` asks a name of its own every time, so every query is a cache miss
		and an upstream round trip - the most work a query can cost. `fixed` asks
		one name over and over, which after the first is a cache hit: less work per
		query, and therefore the shape a reflection attack actually takes. What the
		attacker wants is bytes at the victim, and asking a cached name is how you
		get the server to produce them at its own speed rather than its upstream's.
	*/
	qmode string
	/*
		Open `sockets` connections, ask nothing on any of them, and hold them for
		the arm.

		The load `server.max_connections` had no other bound against: the response
		limiter charges queries, so a client that never asks one spends no budget
		however many connections it is holding. Only the stream transports have
		anything to hold, so this is a TCP client; over UDP there is nothing to
		occupy.
	*/
	idle bool
	/*
		Ask each query on a connection of its own, TCP only.

		For the victim of an `idle` client, where the thing being measured is
		whether a connection can be had at all: a client that dialled once at the
		start would report a single refused connection and then stop, and one that
		holds a connection it *was* given says nothing about the next client
		through the door. A connection per query is also what a client with no
		persistent one does, which is most of them.
	*/
	redial bool
	/*
		Connect, complete a TLS handshake, close, and do it again as fast as the
		server allows - asking nothing on any of them.

		The load that neither bound reaches. A response budget is spent by
		answers, so a client that never asks a question is never charged;
		`server.max_connections` and its per-prefix share bound how many
		connections are held at once, and this client holds each for as long as
		a handshake takes. What it buys with that is the most expensive thing a
		stream client can ask for - an ECDHE exchange and a signature, per
		connection, on a thread the server has to start first.

		`transport` picks which listener pays: `dot` is the DoT one, `doh1` and
		`doh2` the DoH one under the matching ALPN. `sockets` is how many
		handshakes are in flight at once, which is the concurrency an attacker
		brings rather than a rate.
	*/
	handshake bool
}

func (c clientSpec) name(idx, seq int, tag string) string {
	if c.qmode == "fixed" {
		return "cached." + tag + ".rrl.test"
	}
	return fmt.Sprintf("q%d-%d.%s.rrl.test", idx, seq, tag)
}

type arm struct {
	name string
	// What this arm is asking, printed with the row so a result is never a
	// number without its question.
	question string
	limiter  bool
	rps      int
	slip     int
	/*
		`server.max_connections` and `server.max_connections_per_prefix` for the
		arm, and how long an idle connection is kept.

		Zero leaves each out of the configuration, which is what every arm about
		the response budget wants: the shipped default, and a share derived from
		it. The connection arms name all three - see `connectionArms`.
	*/
	maxConns      int
	perPrefix     int
	clientTimeout time.Duration
	/*
		What the arm's listeners bind, and so which family its clients are on.

		Empty is 127.0.0.1, which is every arm but the IPv6 ones. See
		`armListen`, and `v6Arms` for what the family is being asked about.
	*/
	listen string
	/*
		How long the arm runs, and how often the server is read while it does.

		Both zero outside the soak arm: `-duration` and no sampling, which is
		what an arm whose result is a single row wants. The soak arm is the one
		whose result is a series - see `soakArms`.
	*/
	dur    time.Duration
	sample time.Duration
	/*
		`listeners.udp.readers` for the arm.

		Zero leaves it out, which derives one per usable CPU - what a deployment
		gets. The reader arms pin it instead, because the pair of them is asking
		what the reader count itself is worth and a figure that depends on the
		machine would make the two rows incomparable on any other one. See
		`readerArms`.
	*/
	readers int
	// `cache.max_entries` for the arm. Zero is the harness's own large figure;
	// see `armCache`.
	cacheEntries int
	// nil for the arms that measure a victim with nobody else on the server.
	attacker *clientSpec
	victim   clientSpec
}

// What one client saw. Counted atomically because the flood's sockets share it.
type stats struct {
	offered   atomic.Int64
	replies   atomic.Int64
	full      atomic.Int64
	truncated atomic.Int64
	badRcode  atomic.Int64
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	// Connections the server closed on us, which is what an over-budget query
	// on a stream transport looks like from out here.
	closed atomic.Int64
	/*
		DoH only, where a refusal is a status rather than a missing datagram.

		`refused` is a request answered with a status other than 200 - 429 is the
		limiter saying so, and `statusSummary` is what says it was. `failed` is a
		request that got no status at all, which is the connection having gone:
		what DoH/1.1 does to a client over its budget. `dials` is connections
		opened, so a refusal that costs a reconnect is visible as one.
	*/
	refused atomic.Int64
	failed  atomic.Int64
	dials   atomic.Int64

	mu       sync.Mutex
	lat      []time.Duration
	rcodes   map[int]int64
	statuses map[int]int64
}

func (s *stats) addStatus(code int) {
	s.mu.Lock()
	if s.statuses == nil {
		s.statuses = map[int]int64{}
	}
	s.statuses[code]++
	s.mu.Unlock()
}

// statusSummary is the DoH half of `rcodeSummary`: which HTTP statuses came
// back, since 429 rather than a rcode is how the limiter answers here.
func (s *stats) statusSummary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return "—"
	}
	keys := make([]int, 0, len(s.statuses))
	for k := range s.statuses {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d×%d", s.statuses[k], k))
	}
	return strings.Join(parts, ", ")
}

func (s *stats) addRcode(c int) {
	s.mu.Lock()
	if s.rcodes == nil {
		s.rcodes = map[int]int64{}
	}
	s.rcodes[c]++
	s.mu.Unlock()
}

// rcodeSummary is for the arms where "answered" is 0 and the reason is in the
// rcode rather than in the count.
func (s *stats) rcodeSummary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rcodes) == 0 {
		return "—"
	}
	names := map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
	keys := make([]int, 0, len(s.rcodes))
	for k := range s.rcodes {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		n, ok := names[k]
		if !ok {
			n = fmt.Sprintf("rcode%d", k)
		}
		parts = append(parts, fmt.Sprintf("%s %d", n, s.rcodes[k]))
	}
	return strings.Join(parts, ", ")
}

func (s *stats) addLatency(d time.Duration) {
	s.mu.Lock()
	s.lat = append(s.lat, d)
	s.mu.Unlock()
}

func (s *stats) pct(q float64) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.lat) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(s.lat))
	copy(sorted, s.lat)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	i := int(q * float64(len(sorted)-1))
	return sorted[i]
}

var (
	binary_    = flag.String("binary", "../bin/elodin", "elodin binary to run")
	duration   = flag.Duration("duration", 8*time.Second, "measured length of each arm")
	warmup     = flag.Duration("warmup", 1*time.Second, "unmeasured lead-in")
	floodRate  = flag.Int("flood-rate", 20000, "queries/s the attacker offers; 0 is flat out")
	victimRate = flag.Int("victim-rate", 50, "queries/s the victim offers")
	rps        = flag.Int("rps", 500, "rate_limit.responses_per_second (the shipped default is 500)")
	slip       = flag.Int("slip", 2, "rate_limit.slip (the shipped default is 2)")
	records    = flag.Int("answer-records", 70, "A records the mock upstream returns, which sets the answer size")
	upDelay    = flag.Duration("upstream-delay", 20*time.Millisecond, "how long the mock upstream takes to answer")
	workers    = flag.Int("workers", 64, "server.workers, pinned rather than derived from this machine")
	only       = flag.String("only", "", "run only arms whose name contains this")
	keep       = flag.Bool("keep", false, "keep the generated configs and server logs")
	serverCPUs = flag.String("server-cpus", "", "run the server under `taskset -c` on these CPUs, keeping it off the generator's (e.g. 0,1)")
	logLevel   = flag.String("log-level", "info", "log.level for the server under test")
	logQueries = flag.Bool("log-queries", false, "log.queries for the server under test")
	out        = flag.String("out", "", "also write the report here")
	/*
		The soak, which is a mode rather than an arm: set it and the matrix is
		the soak arm alone.

		Every other arm is seconds long, and a run of the matrix is minutes. An
		hour-long arm behind the rest of the matrix would be several minutes of
		waiting to find out whether the harness got as far as starting it, and
		the question it answers - what an hour of flooding does to the memory,
		the table and the cache - is not one the arms before it help with.
	*/
	soak       = flag.Duration("soak", 0, "run the soak arm for this long instead of the matrix (e.g. -soak 1h)")
	soakSample = flag.Duration("soak-sample", 30*time.Second, "how often the soak arm reads the server's counters")
)

func main() {
	flag.Parse()

	dir, cleanup := scratchDir()
	defer cleanup()
	bin := resolveBinary()

	mock, err := startMock(*upDelay, *records)
	if err != nil {
		fatal(err)
	}
	defer mock.stop()
	fmt.Printf("mock upstream on %s, answering after %s with %d A records (%d bytes)\n\n",
		mock.addr, *upDelay, *records, mock.answerSize)

	emit(runMatrix(bin, dir, mock.addr, matrix()))
}

// An arm this machine could not run, and what it would have taken. Reported
// rather than dropped: a report with no IPv6 section and no explanation reads
// as one where those arms do not exist.
type skip struct {
	name string
	why  string
}

// scratchDir is where each arm's configuration and server log go. `-keep` names
// it and leaves it behind, which is what a failing arm is diagnosed from.
func scratchDir() (string, func()) {
	dir, err := os.MkdirTemp("", "rrlexp-")
	if err != nil {
		fatal(err)
	}
	if *keep {
		fmt.Printf("configs and logs in %s\n", dir)
		return dir, func() {}
	}
	return dir, func() { os.RemoveAll(dir) }
}

func resolveBinary() string {
	bin, err := filepath.Abs(*binary_)
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		fatal(fmt.Errorf("%s: %w (run `mise run release` first)", bin, err))
	}
	return bin
}

// emit prints the report, and writes it where `-out` asks for it.
func emit(rows []row, skips []skip) {
	report := renderReport(rows, skips)
	fmt.Print("\n" + report)
	if *out == "" {
		return
	}
	if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("written to %s\n", *out)
}

/*
matrix is every arm, in the order they run, grouped by what it claims.

An arm is a claim and the load that tests it, and the ones that claim the limiter
did something are followed by the same load with the limiter off. Read them in
pairs: without the control, "the victim was served" could be a server that was
never saturated.
*/
func matrix() []arm {
	if *soak > 0 {
		return soakArms()
	}
	var arms []arm
	arms = append(arms, baselineArms()...)
	arms = append(arms, prefixArms()...)
	arms = append(arms, transportArms()...)
	arms = append(arms, volumeArms()...)
	arms = append(arms, dohArms()...)
	arms = append(arms, connectionArms()...)
	arms = append(arms, handshakeArms()...)
	arms = append(arms, readerArms()...)
	arms = append(arms, v6Arms()...)
	return arms
}

// The victim alone, which is what every arm below is read against.
func baselineArms() []arm {
	victimUDP := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	return []arm{
		{
			name:     "quiet-baseline",
			question: "what a victim's queries cost when nobody else is here",
			limiter:  true, rps: *rps, slip: *slip,
			victim: withSrc(victimUDP, "127.9.0.1"),
		},
		{
			name:     "quiet-baseline/tcp",
			question: "what a victim's queries cost over TCP with nobody else here, which is what the TCP arms below compare against",
			limiter:  true, rps: *rps, slip: *slip,
			victim: clientSpec{src: "127.9.0.1", transport: "tcp", rate: *victimRate, sockets: 1},
		},
	}
}

// Whether the budget's prefix is the boundary it claims to be: a victim outside
// the flooded /24, and one inside it.
func prefixArms() []arm {
	flood := &clientSpec{transport: "udp", rate: *floodRate, sockets: 4}
	victimUDP := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	return []arm{
		{
			name:     "other-prefix/limiter-on",
			question: "does a flood from another /24 reach a victim's answers",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(flood, "127.0.0.1"),
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			name:     "other-prefix/limiter-off",
			question: "the same flood with no limiter, which is the control",
			limiter:  false,
			attacker: withSrcP(flood, "127.0.0.1"),
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			name:     "same-prefix/limiter-on",
			question: "a victim inside the flooded /24, where the budget is shared by design",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(flood, "127.0.0.2"),
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
		{
			name:     "same-prefix/limiter-off",
			question: "the same, with no limiter",
			limiter:  false,
			attacker: withSrcP(flood, "127.0.0.2"),
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
	}
}

// Whether the datagram and stream budgets are spendable from each other's side,
// tested in both directions.
func transportArms() []arm {
	flood := &clientSpec{transport: "udp", rate: *floodRate, sockets: 4}
	victimUDP := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	return []arm{
		{
			name:     "same-prefix/victim-on-tcp",
			question: "the slip's invitation: the victim retries over TCP, which is the other pool",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(flood, "127.0.0.2"),
			victim:   clientSpec{src: "127.0.0.3", transport: "tcp", rate: *victimRate, sockets: 1},
		},
		{
			name:     "same-prefix/victim-on-tcp/limiter-off",
			question: "the same victim on TCP with no limiter, which is what makes the row above the limiter's doing",
			limiter:  false,
			attacker: withSrcP(flood, "127.0.0.2"),
			victim:   clientSpec{src: "127.0.0.3", transport: "tcp", rate: *victimRate, sockets: 1},
		},
		{
			name:     "same-prefix/tcp-flood-udp-victim",
			question: "the separation the other way round: a pipelined TCP flood against a UDP victim",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: &clientSpec{src: "127.0.0.2", transport: "tcp", rate: *floodRate, sockets: 8},
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
		{
			/*
				Sixty-four connections rather than the eight the first TCP arm used.

				Eight never reached the budget: a connection is served a query at a
				time and an upstream round trip is 20 ms, so eight of them offer the
				limiter about 400 queries a second - under the 500 it would refuse
				at. `limited=0` in that arm is that, and it is worth keeping both
				rows: the first says what serialisation alone bounds a pipelining
				client to, this one says what happens once a prefix brings enough
				connections to pass the budget anyway.
			*/
			name:     "same-prefix/tcp-flood-64-conns",
			question: "a TCP flood with enough connections to actually reach the stream budget",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: &clientSpec{src: "127.0.0.2", transport: "tcp", rate: 0, sockets: 64},
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
	}
}

/*
The two things only DoH reaches.

Multiplexing: every other stream client here is served a query at a time, so
eight pipelined TCP connections offered the limiter about 400 queries a second
and never reached the budget at all. One h2 connection with sixty-four requests
outstanding is not bounded that way, and whether the stream budget holds against
it is the first question.

The refusal: TCP and DoT end the connection, DoH/1.1 answers 429 and then ends
it, and DoH/2 answers 429 and keeps going - so a flood there is refused without
being cut off, and keeps paying for HPACK and frame work per request. Whether
that costs a client somewhere else is the second, and it is the shape the slip
finding took on UDP.
*/
func dohArms() []arm {
	victimUDP := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	// One connection, sixty-four requests in the air, as fast as they complete.
	h2flood := clientSpec{transport: "doh2", rate: 0, sockets: 1, inflight: 64}
	return []arm{
		{
			name:     "doh2/one-connection-flood",
			question: "can one multiplexed connection reach the stream budget, where eight pipelined TCP ones could not",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(&h2flood, "127.0.0.2"),
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
		{
			name:     "doh2/flood-vs-doh-victim",
			question: "a DoH victim inside the flooded /24, where both clients spend the same stream budget",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(&h2flood, "127.0.0.2"),
			victim:   clientSpec{src: "127.0.0.3", transport: "doh2", rate: *victimRate, sockets: 1, inflight: 4},
		},
		{
			name:     "doh2/flood-vs-doh-victim-other-prefix",
			question: "and a DoH victim outside it, which is whether the stream budget's prefix is a boundary too",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(&h2flood, "127.0.0.2"),
			victim:   clientSpec{src: "127.1.0.1", transport: "doh2", rate: *victimRate, sockets: 1, inflight: 4},
		},
		{
			name:     "doh2/flood-vs-other-prefix",
			question: "what the 429-and-stay-open refusal costs a client in another /24",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: withSrcP(&h2flood, "127.0.0.1"),
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			name:     "doh2/flood-vs-other-prefix/limiter-off",
			question: "the same flood with no limiter, which is what makes the row above the limiter's doing",
			limiter:  false,
			attacker: withSrcP(&h2flood, "127.0.0.1"),
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			/*
				HTTP/1.1, where the refusal used to end the connection.

				Sixty-four connections, for the reason the TCP flood needed
				sixty-four: an h1 client is served a request at a time per
				connection, so four of them offer about 200 requests a second
				against a 20 ms upstream and never reach a 500/s budget at all -
				which is what a first run of this arm measured, `limited=0` and
				nothing refused.

				What the arm is for is what a refusal costs. `dials` counts the
				TLS handshakes the flood provoked and the CPU column is what the
				server paid for them, which is how the closing refusal was
				measured at 263 us against the h2 path's 10.5 - see
				`bench/results/2026-09-03-doh1-refusal-keeps-the-connection.md`.
				With the connection kept, `dials` should stay at the socket count
				above however long the flood runs; a regression that closes again
				shows up here as tens of thousands.
			*/
			name:     "doh1/flood-reconnects",
			question: "what an over-budget HTTP/1.1 client costs, and whether a refusal still costs a handshake",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: &clientSpec{src: "127.0.0.2", transport: "doh1", rate: 0, sockets: 64, inflight: 64},
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
	}
}

/*
Who gets the connection table, which is a different question from who gets the
answers.

Every arm above measures a client asking too much. This one measures a client
asking nothing: `sockets` connections opened from one /24 and held idle for the
whole arm. Nothing charges for them - the budget is spent by queries, and these
have none - so before `server.max_connections_per_prefix` existed the only bound
was the table's own size, and one client could hold all of it.

The victim is on TCP because that is where the occupancy is. A UDP client is not
affected by a full connection table at all, which is worth saying rather than
demonstrating: the read loop has no per-client state and no connection to be
refused. So a resolver whose table is full is one that has lost its TCP, DoT and
DoH clients while its datagram service looks perfectly healthy - and the ones
lost are the clients that proved their address by handshake.

A table of 64 rather than the shipped 512, and a share of 32 rather than the
derived 256. Filling 512 slots would measure this load generator's sockets more
than the server's share-out, and the property is scale-free: what the pair shows
is a client held to half the table where it used to have all of it. The
`client_timeout` is raised past the arm's own length so that a slot reclaimed
from an idle holder is never what serves the victim - that reclamation is real,
and it is a ten-second delay rather than a bound.
*/
func connectionArms() []arm {
	const table, share = 64, 32
	// More connections than the table has, so the attacker is bounded by
	// something in every arm: by the share where there is one, and by the table
	// itself where there is not.
	slowloris := clientSpec{transport: "tcp", sockets: table + 32, idle: true}
	// A query every 20 ms on a connection of its own, from another /24.
	victim := clientSpec{src: "127.1.0.1", transport: "tcp", rate: *victimRate, sockets: 1, redial: true}
	return []arm{
		{
			name:     "slowloris/no-share",
			question: "what one client holding idle connections does to a client in another /24 when nothing bounds its share",
			limiter:  true, rps: *rps, slip: *slip,
			maxConns: table, perPrefix: table, clientTimeout: time.Minute,
			attacker: withSrcP(&slowloris, "127.0.0.2"),
			victim:   victim,
		},
		{
			name:     "slowloris/share",
			question: "the same load with a share of half the table, which is the shipped default in miniature",
			limiter:  true, rps: *rps, slip: *slip,
			maxConns: table, perPrefix: share, clientTimeout: time.Minute,
			attacker: withSrcP(&slowloris, "127.0.0.2"),
			victim:   victim,
		},
		{
			/*
				And the same share against a client that is asking questions.

				A share is only worth having if it costs an ordinary client
				nothing, and an ordinary client is one connection per device
				rather than 96 of them. This arm is the regression: a victim on
				TCP, a flood on UDP from its own /24, and a share that neither of
				them comes close to.
			*/
			name:     "slowloris/share-costs-a-normal-client-nothing",
			question: "whether a share that bounds a holder is felt by a client holding one connection",
			limiter:  true, rps: *rps, slip: *slip,
			maxConns: table, perPrefix: share, clientTimeout: time.Minute,
			attacker: &clientSpec{src: "127.0.0.2", transport: "udp", rate: *floodRate, sockets: 4},
			victim:   victim,
		},
	}
}

// What a flood actually delivers to the address it named, and what the slip
// costs on top of the budget.
func volumeArms() []arm {
	flood := &clientSpec{transport: "udp", rate: *floodRate, sockets: 4}
	victimUDP := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	return []arm{
		{
			/*
				The reflection case proper: one cached name, asked over and over.

				Every other arm has the flood asking names of its own, which makes
				each query a cache miss and an upstream round trip - so with the
				limiter off the flood is bounded by this server's own throughput
				rather than by the attacker's bandwidth, and the amplification the
				limiter prevents is understated. A cached name takes that ceiling
				away: the server can answer as fast as it can write datagrams, which
				is what an attacker aiming bytes at a victim would ask for.
			*/
			name:     "cached-flood/limiter-off",
			question: "the reflection an unlimited resolver delivers when the flood asks a name it already has",
			limiter:  false,
			attacker: &clientSpec{src: "127.0.0.1", transport: "udp", rate: 0, sockets: 4, qmode: "fixed"},
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			name:     "cached-flood/limiter-on",
			question: "the same flood against the shipped default, which is the bound the feature exists to put on it",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: &clientSpec{src: "127.0.0.1", transport: "udp", rate: 0, sockets: 4, qmode: "fixed"},
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			/*
				The same two floods against `slip: 0`, which is the other half of
				the trade-off the default makes.

				`slip: 2` answers at most every second over-budget datagram with a
				40-byte truncated reply, and those replies are charged to a pool of
				their own - an eighth of `responses_per_second` - so their number is
				the pool's rather than a fraction of the arrival rate. Comparing the
				two rows is what says so: they now sit within 0.01 MB/s of each
				other. Before that pool existed, the truncated replies were the bulk
				of what an over-limit flood drew and scaled with the attack, which
				is what these two rows measured 33x apart. Turning the slip off
				still drops the flood in silence, at the cost of the invitation a
				real client behind a busy NAT depends on, which the same-prefix row
				is here to show going away.
			*/
			name:     "cached-flood/slip-0",
			question: "what the reflected volume becomes with the slip turned off",
			limiter:  true, rps: *rps, slip: 0,
			attacker: &clientSpec{src: "127.0.0.1", transport: "udp", rate: 0, sockets: 4, qmode: "fixed"},
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
		{
			name:     "same-prefix/slip-0",
			question: "what a bystander in the flooded /24 loses when the slip is off",
			limiter:  true, rps: *rps, slip: 0,
			attacker: withSrcP(flood, "127.0.0.2"),
			victim:   withSrc(victimUDP, "127.0.0.3"),
		},
		{
			name:     "other-prefix/flat-out",
			question: "the same isolation when the flood is not throttled at all",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: &clientSpec{src: "127.0.0.1", transport: "udp", rate: 0, sockets: 4},
			victim:   withSrc(victimUDP, "127.1.0.1"),
		},
	}
}

/*
The load that neither bound sees: a client doing nothing but handshakes.

`cmd/bench -transport=handshake` already says what a fresh handshake costs, as a
throughput figure from a server with nobody else on it. What no arm asked is what
that load does to somebody trying to resolve, and it is the load with the least
standing in the way of it: the response budget is spent by answers, so a client
that sends no query is charged nothing however fast it arrives, and the
connection share bounds how many connections are held rather than how many are
made. A handshake holds one for a millisecond or two and gives it back.

So the flood here is `sockets` workers dialling, handshaking, closing and going
again, and the victim is a DoT client of the ordinary kind: one connection, a
query every 20 ms, latency measured. Read every row against
`handshake-flood/quiet-baseline-dot`, which is that victim with the server to
itself.

Both TLS listeners get an arm, because the two do not accept a connection by the
same code and a difference in what a handshake costs would be the arm's to find.
Neither reaches the h2 path itself: the flood closes as soon as the handshake is
up, so no preface, no frames and no HPACK - what an over-budget h2 client costs
is a question the `doh2` arms above answer with requests.

The last pair is what a share can and cannot do about it. `slowloris` showed the
share holding a prefix to half the table; a handshake flood is not holding
anything, so the share bounds only how many of its handshakes are in flight at
once - and only once the flood brings more workers than the share allows, which
is why that pair pins a small table and dials with as many workers as it has
slots. It pins the same table, share and `client_timeout` the `slowloris` pair
uses, so the two pairs are read against each other; the timeout has nothing to
reclaim here, since a handshake flood gives every slot back on its own. The
victim there arrives per query rather than holding a connection, since what the
pair is about is whether a client can still get in.
*/
func handshakeArms() []arm {
	var arms []arm
	arms = append(arms, handshakeDefaultArms()...)
	arms = append(arms, handshakeShareArms()...)
	return arms
}

/*
Concurrency, not a rate: there is nothing to pace, and this many dialers is
enough to keep the server handshaking flat out.

`hsDialers` rather than `workers` because that is the flag for the server's own
thread pool, and the two figures have nothing to do with each other. The table
and the share are the small ones the `slowloris` arms use, for the same reason
those do: what `handshakeShareArms` shows is a client held to half a table, and
the property is scale-free.
*/
const (
	hsDialers = 32
	hsTable   = 64
	hsShare   = 32
)

// The DoT client every handshake arm is measured at: one connection, a query
// every 20 ms, latency tracked.
func handshakeVictim() clientSpec {
	return clientSpec{src: "127.1.0.1", transport: "dot", rate: *victimRate, sockets: 1}
}

/*
A client turning up while the flood is happening, asking on a connection of its
own each time.

The plain TCP one from `connectionArms`, for the same reason that group uses it:
what is being measured is whether a connection can be had at all, and a client
that dialled once at the start would say nothing about the next one through the
door.
*/
func arrivingVictim() clientSpec {
	return clientSpec{src: "127.1.0.1", transport: "tcp", rate: *victimRate, sockets: 1, redial: true}
}

// handshakeFlood is `n` workers dialling, handshaking and closing against the
// listener `transport` names.
func handshakeFlood(src, transport string, n int) *clientSpec {
	return &clientSpec{src: src, transport: transport, sockets: n, handshake: true}
}

// The four arms that run the shipped connection table, which is the
// configuration a public instance would meet this load with.
func handshakeDefaultArms() []arm {
	victimDoT := handshakeVictim()
	return []arm{
		{
			/*
				Named for the group rather than beside the other two quiet
				baselines, so that `-only handshake-flood` brings it along.

				`-only` is a substring of the arm's name, and a group whose
				control does not match its own selector is a group that can be
				run without the row every other row is read against - which is
				six numbers and nothing to compare them with.
			*/
			name:     "handshake-flood/quiet-baseline-dot",
			question: "what a DoT victim's queries cost with the server to itself, which is what the handshake arms compare against",
			limiter:  true, rps: *rps, slip: *slip,
			victim: victimDoT,
		},
		{
			name:     "handshake-flood/dot",
			question: "what a client doing only DoT handshakes does to a DoT client in another /24",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: handshakeFlood("127.0.0.2", "dot", hsDialers),
			victim:   victimDoT,
		},
		{
			name:     "handshake-flood/dot/same-prefix",
			question: "the same flood with the victim inside its /24, where they share a connection share as well as a budget",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: handshakeFlood("127.0.0.2", "dot", hsDialers),
			victim:   withSrc(victimDoT, "127.0.0.3"),
		},
		{
			name:     "handshake-flood/doh",
			question: "the same load against the DoH listener, which accepts a connection by its own code - the flood closes before any h2 frame, so this is the handshake alone",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: handshakeFlood("127.0.0.2", "doh2", hsDialers),
			victim:   victimDoT,
		},
		{
			name:     "handshake-flood/arriving-client",
			question: "whether a client turning up mid-flood can get a connection and an answer",
			limiter:  true, rps: *rps, slip: *slip,
			attacker: handshakeFlood("127.0.0.2", "dot", hsDialers),
			victim:   arrivingVictim(),
		},
	}
}

// And the pair that pins a table small enough for a share to reach a flood
// holding nothing: as many dialers as the table has slots, with and without one.
func handshakeShareArms() []arm {
	return []arm{
		{
			name:     "handshake-flood/no-share",
			question: "a flood with as many workers as the table has slots, and nothing bounding its share of them",
			limiter:  true, rps: *rps, slip: *slip,
			maxConns: hsTable, perPrefix: hsTable, clientTimeout: time.Minute,
			attacker: handshakeFlood("127.0.0.2", "dot", hsTable),
			victim:   arrivingVictim(),
		},
		{
			name:     "handshake-flood/share",
			question: "the same load held to half the table, which is what the share does and does not do about handshakes",
			limiter:  true, rps: *rps, slip: *slip,
			maxConns: hsTable, perPrefix: hsShare, clientTimeout: time.Minute,
			attacker: handshakeFlood("127.0.0.2", "dot", hsTable),
			victim:   arrivingVictim(),
		},
	}
}

/*
The same isolation question over IPv6, where the prefix is a /64.

Every arm above is IPv4 loopback, and the budget is kept per /24 there and per
/64 here - one procedure deciding both (`client_prefix`), so the arms are asking
whether the second half of it works as well as the first. `src/itest` has the
case that matters most, a `::` listener keeping the families apart after issue
#170; what it cannot show is a bystander's answer rate, which is what these are
for.

The other half of the question is what a v6 flood costs on the read path. The
CPU column answers it: the same offered rate as the IPv4 arms, so the pair of
rows is the comparison, and an address twice the size hashed into the same table
should not be visible in it.

The sources are ULAs on the loopback interface rather than the 127/8 the IPv4
arms help themselves to. There is only one IPv6 loopback address, so a machine
has to be told about the others before an arm can send from two /64s at once; a
run on a machine that has not been skips these with the command that fixes it.
See `bindHint`, and the *IPv6* section of bench/README.md.
*/
func v6Arms() []arm {
	flood := &clientSpec{transport: "udp", rate: *floodRate, sockets: 4}
	victim := clientSpec{transport: "udp", rate: *victimRate, sockets: 1}
	return []arm{
		{
			name:     "v6/other-prefix/limiter-on",
			question: "does a flood from another /64 reach a victim's answers",
			limiter:  true, rps: *rps, slip: *slip,
			listen:   v6Listen,
			attacker: withSrcP(flood, v6FloodSrc),
			victim:   withSrc(victim, v6OtherSrc),
		},
		{
			name:     "v6/other-prefix/limiter-off",
			question: "the same flood with no limiter, which is the control",
			limiter:  false,
			listen:   v6Listen,
			attacker: withSrcP(flood, v6FloodSrc),
			victim:   withSrc(victim, v6OtherSrc),
		},
		{
			name:     "v6/same-prefix/limiter-on",
			question: "a victim inside the flooded /64, where the budget is shared by design",
			limiter:  true, rps: *rps, slip: *slip,
			listen:   v6Listen,
			attacker: withSrcP(flood, v6FloodSrc),
			victim:   withSrc(victim, v6SameSrc),
		},
	}
}

/*
Where the IPv6 arms send from and to.

Two /64s inside fc00::/7, which `server.allow_from` allows by default the way it
allows 127.0.0.0/8, and a listener on `::1` - which is a third prefix, so the
readiness probes spend neither client's budget.
*/
const (
	v6Listen   = "::1"
	v6FloodSrc = "fd00:1::2"
	v6SameSrc  = "fd00:1::3"
	v6OtherSrc = "fd00:2::1"
)

/*
The soak: one flood, for as long as `-soak` says, read while it runs.

Every other arm is eight seconds and reports what the server had done by the end
of them. Nothing said what an hour of the same load does to the things that
accumulate rather than settle, which is the question a deployment asks: the
resident memory, the cache under eviction, the connection table as clients come
and go, and whether the answers the limiter does allow are still being served at
the end.

The load is deliberately the arm that already has a known-good result - a flood
from one /24 with a victim in another - so a run of this is read against
`other-prefix/limiter-on` above rather than against nothing. Three things are
changed for the length:

  - the cache is the shipped 10,000 entries rather than the harness's 400,000.
    Over eight seconds the large figure keeps the generator's own unique names
    from evicting anything, which is the right choice for an arm about the
    limiter; over an hour eviction is not an artefact to be avoided but the
    thing being watched.
  - the connection table is pinned at the shipped 512 and 256 rather than left
    unwritten, so the sampled `connections_active` has figures beside it that
    the report can name.
  - the victim asks on a connection of its own each time, so the connection
    manager is churning for the whole arm rather than holding one connection
    opened at the start. 180,000 connections over an hour is what the table has
    to hand back without drifting.

The limiter's own table needs nothing from the arm: `RRL_BUCKETS` is a fixed
16,384 buckets allocated at startup and never grown, so what an hour of flooding
can do to it is visible in the resident memory beside it and nowhere else. There
is no occupancy series to sample, and a bucket handed from one prefix to another
is what `ratelimit_test.odin` asserts directly.
*/
func soakArms() []arm {
	return []arm{
		{
			name:     "soak/other-prefix",
			question: "what an hour of flooding does to the memory, the cache and the connection table around a limiter that is holding",
			limiter:  true, rps: *rps, slip: *slip,
			dur: *soak, sample: *soakSample,
			cacheEntries:  10000,
			maxConns:      512,
			perPrefix:     256,
			clientTimeout: 10 * time.Second,
			attacker:      &clientSpec{src: "127.0.0.2", transport: "udp", rate: *floodRate, sockets: 4},
			victim:        clientSpec{src: "127.1.0.1", transport: "tcp", rate: *victimRate, sockets: 1, redial: true},
		},
	}
}

// runMatrix runs the arms `-only` selects, printing each result as it lands so a
// long run is readable before it finishes.
func runMatrix(bin, dir, upstream string, arms []arm) ([]row, []skip) {
	var rows []row
	var skips []skip
	for _, a := range arms {
		if *only != "" && !strings.Contains(a.name, *only) {
			continue
		}
		/*
			Skipped rather than failed, and skipped rather than quietly dropped.

			An arm names the addresses it sends from, and the IPv6 ones name
			addresses a machine has to be told about first. A run on a machine
			without them is a run of the IPv4 arms, which is worth having - but
			the report must not read as though the IPv6 question had been asked
			and answered, so the skip is printed with the command that would
			have let it run.
		*/
		if why := unusable(a); why != "" {
			fmt.Printf("%-34s skipped: %s\n", a.name, why)
			skips = append(skips, skip{name: a.name, why: why})
			continue
		}
		r, err := runArm(bin, dir, upstream, a)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", a.name, err))
		}
		rows = append(rows, r)
		fmt.Println(r.line())
	}
	return rows, skips
}

/*
unusable is why this machine cannot run the arm, or "" when it can.

Every address the arm needs: the one its listeners bind, and the one each of its
clients sends from. Asked by binding a socket, which is the same question the arm
itself would ask a moment later and the only one that gives a true answer - an
address on the interface but in a namespace this process cannot use is not an
address it can send from.
*/
func unusable(a arm) string {
	needed := []string{armListen(a), a.victim.src}
	if a.attacker != nil {
		needed = append(needed, a.attacker.src)
	}
	for _, addr := range needed {
		if addr == "" || bindable(addr) {
			continue
		}
		return fmt.Sprintf("this machine cannot send from %s (%s)", addr, bindHint(addr))
	}
	return ""
}

// bindable reports whether a socket can be opened on `addr`, which is what
// sending from it needs.
func bindable(addr string) bool {
	conn, err := net.ListenPacket("udp", net.JoinHostPort(addr, "0"))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

/*
bindHint is what to run to make an address available.

Only the IPv6 arms need it in practice: 127.0.0.0/8 is local in its entirety on
Linux, so the IPv4 arms can pick addresses out of it freely, and IPv6 has one
loopback address and no equivalent range. The addresses are ULAs on `lo`, which
is the smallest thing that gives this harness two /64s to send from - and, being
loopback, keeps the arms as local as the IPv4 ones.
*/
func bindHint(addr string) string {
	if !isV6(addr) {
		return "no local address"
	}
	return fmt.Sprintf("sudo ip -6 addr add %s/128 dev lo", addr)
}

// armDuration is how long the arm's measured window is: `-duration`, or the
// arm's own length where it has one. Only the soak arm has one.
func armDuration(a arm) time.Duration {
	if a.dur > 0 {
		return a.dur
	}
	return *duration
}

func withSrc(c clientSpec, src string) clientSpec {
	c.src = src
	return c
}

func withSrcP(c *clientSpec, src string) *clientSpec {
	d := *c
	d.src = src
	return &d
}

type row struct {
	arm      arm
	victim   *stats
	attacker *stats
	elapsed  time.Duration
	cpu      time.Duration
	peakRSS  int64
	// The server's own counters as of the end of the arm. See `counters`.
	srv map[string]int64
	// What the server looked like while the arm was still running. Empty
	// except in the soak arm, which is the only one long enough for the
	// difference between a series and an end state to be the point.
	samples []sample
}

func (r row) line() string {
	v := r.victim
	offered, full := v.offered.Load(), v.full.Load()
	pct := 0.0
	if offered > 0 {
		pct = 100 * float64(full) / float64(offered)
	}
	extra := ""
	if r.attacker != nil {
		secs := r.elapsed.Seconds()
		switch {
		case r.arm.attacker.handshake:
			// No queries and no bytes of DNS: what this flood offered is
			// handshakes, and what it got is how many the server did.
			extra = fmt.Sprintf("   flood %.0f handshakes/s offered, %.0f completed/s, %.0f refused/s",
				float64(r.attacker.offered.Load())/secs,
				float64(r.attacker.full.Load())/secs,
				float64(r.attacker.closed.Load())/secs)
		default:
			extra = fmt.Sprintf("   flood %.0f q/s offered, %.0f answered/s + %.0f truncated/s, %.1f MB/s back",
				float64(r.attacker.offered.Load())/secs,
				float64(r.attacker.full.Load())/secs,
				float64(r.attacker.truncated.Load())/secs,
				float64(r.attacker.bytesIn.Load())/secs/1e6)
		}
	}
	return fmt.Sprintf("%-34s victim %3.0f%% answered (%d/%d) [%s], p50 %6s p99 %7s%s",
		r.arm.name, pct, full, offered, outcomes(r.arm.victim, v), round(v.pct(0.5)), round(v.pct(0.99)), extra)
}

func round(d time.Duration) time.Duration {
	if d >= time.Millisecond {
		return d.Round(100 * time.Microsecond)
	}
	return d.Round(time.Microsecond)
}

func runArm(bin, dir, upstream string, a arm) (row, error) {
	srv, err := startServer(bin, dir, upstream, a)
	if err != nil {
		return row{}, err
	}
	defer srv.stop()

	r := row{arm: a, victim: &stats{}}
	if a.attacker != nil {
		r.attacker = &stats{}
	}

	// Warm-up under the same load as the measured window, so the arm reports a
	// server already in the state the flood puts it in rather than the first
	// moment of it. A fresh bucket holds two seconds of budget; spending it here
	// is what keeps the measured window from being a burst allowance.
	if a.attacker != nil {
		warm := &stats{}
		stopWarm := runClient(srv, *a.attacker, *warmup, "warm", false, warm)
		time.Sleep(*warmup)
		stopWarm()
	} else {
		time.Sleep(*warmup)
	}

	dur := armDuration(a)
	sampler := procstat.NewSampler(srv.pid)
	sampler.Start()
	start := time.Now()

	var stopAttack func()
	if a.attacker != nil {
		stopAttack = runClient(srv, *a.attacker, dur, "atk", false, r.attacker)
	}
	stopVictim := runClient(srv, a.victim, dur, "vic", true, r.victim)
	// Reads the server while the load is on it, for an arm long enough that
	// what it looked like at the end is not what it looked like throughout.
	soaking := startSoakSampler(srv, a, &r)

	time.Sleep(dur)
	r.elapsed = time.Since(start)
	// The victim's last queries are still in flight, and a drop is only a drop
	// once it has had as long as a real client would give it.
	time.Sleep(500 * time.Millisecond)
	stopVictim()
	if stopAttack != nil {
		stopAttack()
	}
	soaking()
	sampler.Stop()
	r.cpu = sampler.CPUUsed()
	r.peakRSS = sampler.PeakRSS

	r.srv = srv.counters()
	srv.stop()
	return r, nil
}
