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

The load generator builds and parses DNS messages itself (`internal/dnswire`)
and the upstream is in-process here, for the reason bench/README.md gives: a
generator sharing the codec under test could agree with a bug in it.
*/
package main

import (
	"flag"
	"fmt"
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
	logLevel   = flag.String("log-level", "info", "log.level for the server under test")
	logQueries = flag.Bool("log-queries", false, "log.queries for the server under test")
	out        = flag.String("out", "", "also write the report here")
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
func emit(rows []row) {
	report := renderReport(rows)
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
	var arms []arm
	arms = append(arms, baselineArms()...)
	arms = append(arms, prefixArms()...)
	arms = append(arms, transportArms()...)
	arms = append(arms, volumeArms()...)
	arms = append(arms, dohArms()...)
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

				`slip: 2` answers every second over-budget datagram with a 40-byte
				truncated reply, and those replies are the bulk of what an
				over-limit flood draws: they scale with the attack rather than with
				the budget. Turning the slip off drops the flood in silence, so what
				reaches the named address is the budget and nothing else - at the
				cost of the invitation a real client behind a busy NAT depends on,
				which the same-prefix row is here to show going away.
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

// runMatrix runs the arms `-only` selects, printing each result as it lands so a
// long run is readable before it finishes.
func runMatrix(bin, dir, upstream string, arms []arm) []row {
	var rows []row
	for _, a := range arms {
		if *only != "" && !strings.Contains(a.name, *only) {
			continue
		}
		r, err := runArm(bin, dir, upstream, a)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", a.name, err))
		}
		rows = append(rows, r)
		fmt.Println(r.line())
	}
	return rows
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
		extra = fmt.Sprintf("   flood %.0f q/s offered, %.0f answered/s + %.0f truncated/s, %.1f MB/s back",
			float64(r.attacker.offered.Load())/secs,
			float64(r.attacker.full.Load())/secs,
			float64(r.attacker.truncated.Load())/secs,
			float64(r.attacker.bytesIn.Load())/secs/1e6)
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

	sampler := procstat.NewSampler(srv.pid)
	sampler.Start()
	start := time.Now()

	var stopAttack func()
	if a.attacker != nil {
		stopAttack = runClient(srv, *a.attacker, *duration, "atk", false, r.attacker)
	}
	stopVictim := runClient(srv, a.victim, *duration, "vic", true, r.victim)

	time.Sleep(*duration)
	r.elapsed = time.Since(start)
	// The victim's last queries are still in flight, and a drop is only a drop
	// once it has had as long as a real client would give it.
	time.Sleep(500 * time.Millisecond)
	stopVictim()
	if stopAttack != nil {
		stopAttack()
	}
	sampler.Stop()
	r.cpu = sampler.CPUUsed()
	r.peakRSS = sampler.PeakRSS

	r.srv = srv.counters()
	srv.stop()
	return r, nil
}
