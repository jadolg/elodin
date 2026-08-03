package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"elodin.bench/internal/procstat"
)

// Result mirrors the JSON loadgen prints.
type Result struct {
	Transport    string           `json:"transport"`
	Clients      int              `json:"clients"`
	Concurrency  int              `json:"concurrency"`
	Answered     int64            `json:"answered"`
	Errors       int64            `json:"errors"`
	Rcodes       map[string]int64 `json:"rcodes"`
	Seconds      float64          `json:"seconds"`
	QPS          float64          `json:"qps"`
	P50ms        float64          `json:"p50_ms"`
	P99ms        float64          `json:"p99_ms"`
	MinPerClient int64            `json:"min_per_client"`
	MaxPerClient int64            `json:"max_per_client"`
}

// sample is what was true of the server process while the run happened.
type sample struct {
	PeakRSS    int64
	CPU        time.Duration
	MaxThreads int
	// Spread is the relative gap between the fastest and slowest of the repeated
	// runs, so a reader can tell a real difference from the machine's noise.
	Spread float64
}

// CPUPerQuery is the figure the Resource use table reports.
func (s sample) CPUPerQuery(answered int64) time.Duration {
	if answered == 0 {
		return 0
	}
	return s.CPU / time.Duration(answered)
}

type loadOpts struct {
	transport   string
	clients     int
	concurrency int
	qmode       string
	qname       string
	rate        int
	duration    time.Duration
	// repeat runs the scenario this many times and keeps the median by
	// throughput. Run-to-run spread on a machine with other things on it is
	// about ten percent, which is larger than several of the differences these
	// tables are meant to show. 0 takes the value of -repeat.
	repeat int
}

// load runs a scenario `repeat` times and returns the median run, the sample
// taken alongside it, and how far the fastest and slowest runs were apart.
func (h *harness) load(s *server, o loadOpts) (Result, sample, error) {
	n := o.repeat
	if n == 0 {
		n = *repeat
	}
	if n < 1 {
		n = 1
	}

	type run struct {
		r  Result
		sm sample
	}
	runs := make([]run, 0, n)
	for range n {
		// Idle between runs rather than going straight into the next: back to
		// back, a thermally limited machine reports the third run slower than
		// the first for reasons that have nothing to do with elodin.
		time.Sleep(*cooldown)
		r, sm, err := h.loadOnce(s, o)
		if err != nil {
			return Result{}, sample{}, err
		}
		runs = append(runs, run{r, sm})
	}
	slices.SortFunc(runs, func(a, b run) int {
		switch {
		case a.r.QPS < b.r.QPS:
			return -1
		case a.r.QPS > b.r.QPS:
			return 1
		}
		return 0
	})
	med := runs[len(runs)/2]
	med.sm.Spread = 0
	if lo := runs[0].r.QPS; lo > 0 {
		med.sm.Spread = (runs[len(runs)-1].r.QPS - lo) / lo
	}
	return med.r, med.sm, nil
}

func (h *harness) loadOnce(s *server, o loadOpts) (Result, sample, error) {
	if o.clients == 0 {
		o.clients = 100
	}
	if o.concurrency == 0 {
		o.concurrency = 1
	}
	if o.qmode == "" {
		o.qmode = "fixed"
	}
	if o.qname == "" {
		o.qname = "cached.bench.test"
	}
	if o.duration == 0 {
		o.duration = *duration
	}

	args := []string{
		"-server", s.addrFor(o.transport),
		"-transport", o.transport,
		"-clients", strconv.Itoa(o.clients),
		"-concurrency", strconv.Itoa(o.concurrency),
		"-qmode", o.qmode,
		"-qname", o.qname,
		"-duration", o.duration.String(),
		"-warmup", warmup.String(),
	}
	if o.rate > 0 {
		args = append(args, "-rate", strconv.Itoa(o.rate))
	}

	cmd := exec.Command(h.loadgen, args...)
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	sampler := procstat.NewSampler(s.pid)
	sampler.Start()
	err := cmd.Run()
	sampler.Stop()
	if err != nil {
		return Result{}, sample{}, fmt.Errorf("loadgen %s: %w", strings.Join(args, " "), err)
	}

	var r Result
	if err := json.Unmarshal([]byte(stdout.String()), &r); err != nil {
		return Result{}, sample{}, fmt.Errorf("parsing loadgen output: %w", err)
	}
	sm := sample{
		PeakRSS:    sampler.PeakRSS,
		CPU:        sampler.CPUUsed(),
		MaxThreads: sampler.MaxThreads,
	}
	return r, sm, nil
}

type section struct {
	title string
	body  string
}

func (h *harness) runAll(filter string) (string, error) {
	var sections []section
	want := func(name string) bool {
		return filter == "" || strings.Contains(name, filter)
	}

	steps := []struct {
		name string
		fn   func() (section, error)
	}{
		{"workloads", h.workloads},
		{"transports", h.transports},
		{"h1h2", h.h1VersusH2},
		{"cpu", h.cpuPerQuery},
		{"handshake", h.handshakes},
		{"memory", h.memory},
		{"shedding", h.shedding},
		{"logging", h.loggingCost},
	}

	for _, st := range steps {
		if !want(st.name) {
			continue
		}
		log.Printf("bench: %s (cores at %.0f MHz)", st.name, avgMHz())
		sec, err := st.fn()
		if err != nil {
			return "", fmt.Errorf("%s: %w", st.name, err)
		}
		sections = append(sections, sec)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# elodin benchmark\n\n")
	fmt.Fprintf(&sb, "%s\n\n", describeMachine())
	fmt.Fprintf(&sb, "Mock upstream held at %s. DNSSEC off. Each run %s measured after %s of warmup, "+
		"median of %d, %s idle between runs.\n\n",
		*upstreamRTT, *duration, *warmup, *repeat, *cooldown)
	fmt.Fprintf(&sb, "Cores were averaging %.0f MHz when the run finished. This is a 15 W laptop part "+
		"that cannot hold its boost clock through the whole matrix, so treat the absolute figures as "+
		"the shape of the thing rather than a specification.\n\n", avgMHz())
	for _, s := range sections {
		fmt.Fprintf(&sb, "## %s\n\n%s\n", s.title, s.body)
	}
	return sb.String(), nil
}

// workloads is the README's first Capacity table: what the server costs when
// the answer comes from the cache, from a rule, and from the upstream.
func (h *harness) workloads() (section, error) {
	var sb strings.Builder
	sb.WriteString("| workload | throughput | p50 | p99 | peak RSS |\n|---|---|---|---|---|\n")

	// Cache hits and misses share one server: the cache is what separates them.
	s, err := h.start(serverOpts{name: "workloads", cache: true, blockRules: 1})
	if err != nil {
		return section{}, err
	}
	defer s.stop()

	r, sm, err := h.load(s, loadOpts{transport: "udp", clients: 200})
	if err != nil {
		return section{}, err
	}
	row(&sb, "cache hits", r, sm.PeakRSS)

	rb, smb, err := h.load(s, loadOpts{transport: "udp", clients: 200, qname: "blocked.bench.test"})
	if err != nil {
		return section{}, err
	}
	// A name missing from the list would be forwarded instead, and the row
	// would quietly report the cost of something else.
	if err := expectRcode(rb, "nxdomain"); err != nil {
		return section{}, fmt.Errorf("blocked row: %w", err)
	}
	row(&sb, "blocked", rb, smb.PeakRSS)

	rw, smw, err := h.load(s, loadOpts{transport: "udp", clients: 200, qname: "rewritten.bench.test"})
	if err != nil {
		return section{}, err
	}
	if err := expectRcode(rw, "noerror"); err != nil {
		return section{}, fmt.Errorf("rewritten row: %w", err)
	}
	row(&sb, "rewritten", rw, smw.PeakRSS)

	rl, sml, err := h.load(s, loadOpts{transport: "udp", clients: 20})
	if err != nil {
		return section{}, err
	}
	row(&sb, "light mixed load (20 in flight)", rl, sml.PeakRSS)

	// Held at the worker count: this row is the sustained rate, and offering
	// more than the workers can carry would report queueing delay as if it were
	// the cost of a miss.
	rm, smm, err := h.load(s, loadOpts{transport: "udp", clients: 128, qmode: "unique"})
	if err != nil {
		return section{}, err
	}
	if err := expectRcode(rm, "noerror"); err != nil {
		return section{}, fmt.Errorf("cache-miss row: %w", err)
	}
	row(&sb, "sustained cache misses", rm, smm.PeakRSS)

	return section{title: "Workloads", body: sb.String()}, nil
}

// transports is the README's second table: every listener, each client holding
// its own connection, answering from the cache.
func (h *harness) transports() (section, error) {
	s, err := h.start(serverOpts{name: "transports", cache: true})
	if err != nil {
		return section{}, err
	}
	defer s.stop()

	var sb strings.Builder
	sb.WriteString("| transport | clients | throughput | p50 | p99 | answered per client (min–max) | errors |\n|---|---|---|---|---|---|---|\n")

	for _, t := range []string{"udp", "tcp", "dot", "doh1", "doh2"} {
		r, _, err := h.load(s, loadOpts{transport: t, clients: 100})
		if err != nil {
			return section{}, err
		}
		fmt.Fprintf(&sb, "| %s | %d | %s qps | %s | %s | %d – %d | %d |\n",
			label(t), r.Clients, thousands(r.QPS), ms(r.P50ms), ms(r.P99ms),
			r.MinPerClient, r.MaxPerClient, r.Errors)
	}

	// The connection cap is 512, so 500 is the most that can be held at once.
	r, _, err := h.load(s, loadOpts{transport: "tcp", clients: 500})
	if err != nil {
		return section{}, err
	}
	fmt.Fprintf(&sb, "| TCP | %d | %s qps | %s | %s | %d – %d | %d |\n",
		r.Clients, thousands(r.QPS), ms(r.P50ms), ms(r.P99ms),
		r.MinPerClient, r.MaxPerClient, r.Errors)

	return section{title: "Transports, one connection per client", body: sb.String()}, nil
}

// h1VersusH2 is the comparison that justifies serving HTTP/2 at all: the same
// concurrent misses over each protocol.
func (h *harness) h1VersusH2() (section, error) {
	s, err := h.start(serverOpts{name: "h1h2", cache: true})
	if err != nil {
		return section{}, err
	}
	defer s.stop()

	var sb strings.Builder
	sb.WriteString("10 clients, 8 concurrent requests each, every one a cache miss.\n\n")
	sb.WriteString("| | throughput | p50 | p99 |\n|---|---|---|---|\n")
	for _, t := range []string{"doh1", "doh2"} {
		r, _, err := h.load(s, loadOpts{
			transport: t, clients: 10, concurrency: 8, qmode: "unique",
		})
		if err != nil {
			return section{}, err
		}
		fmt.Fprintf(&sb, "| %s | %s qps | %s | %s |\n",
			label(t), thousands(r.QPS), ms(r.P50ms), ms(r.P99ms))
	}
	return section{title: "HTTP/1.1 against HTTP/2 under concurrency", body: sb.String()}, nil
}

// cpuPerQuery measures the server process alone while it is saturated.
func (h *harness) cpuPerQuery() (section, error) {
	s, err := h.start(serverOpts{name: "cpu", cache: true})
	if err != nil {
		return section{}, err
	}
	defer s.stop()

	var sb strings.Builder
	sb.WriteString("| transport | CPU per query | at 5,000 qps |\n|---|---|---|\n")
	for _, t := range []string{"tcp", "udp", "dot", "doh1", "doh2"} {
		r, sm, err := h.load(s, loadOpts{transport: t, clients: 100})
		if err != nil {
			return section{}, err
		}
		per := sm.CPUPerQuery(r.Answered)
		cores := per.Seconds() * 5000
		fmt.Fprintf(&sb, "| %s | %d µs | %.2f core |\n", label(t), per.Microseconds(), cores)
	}
	return section{title: "CPU per query", body: sb.String()}, nil
}

// handshakes measures what a client that reconnects for every query costs,
// against one that holds its connection.
func (h *harness) handshakes() (section, error) {
	var sb strings.Builder
	sb.WriteString("| key | handshakes/s | CPU per handshake | p50 |\n|---|---|---|---|\n")

	for _, kind := range []string{"ecdsa", "rsa"} {
		s, err := h.start(serverOpts{name: "handshake-" + kind, cache: true, certKind: kind})
		if err != nil {
			return section{}, err
		}
		r, sm, err := h.load(s, loadOpts{transport: "handshake", clients: 16})
		s.stop()
		if err != nil {
			return section{}, err
		}
		per := sm.CPUPerQuery(r.Answered)
		fmt.Fprintf(&sb, "| %s | %s /s | %d µs | %s |\n",
			strings.ToUpper(kind), thousands(r.QPS), per.Microseconds(), ms(r.P50ms))
	}
	return section{title: "Fresh TLS handshakes", body: sb.String()}, nil
}

// memory takes each row of the memory table from a difference between two
// servers that differ in one thing.
func (h *harness) memory() (section, error) {
	var sb strings.Builder
	sb.WriteString("| | |\n|---|---|\n")

	idle, err := h.idleRSS(serverOpts{name: "mem-idle", cache: true})
	if err != nil {
		return section{}, err
	}
	fmt.Fprintf(&sb, "| idle, no lists | %s |\n", mib(idle))

	// Worker arenas: the only difference between these two is the worker count,
	// and the arena is allocated per worker on first use, so they have to be
	// put to work before the difference shows.
	small, err := h.loadedRSS(serverOpts{name: "mem-w8", cache: true, workers: 8})
	if err != nil {
		return section{}, err
	}
	big, err := h.loadedRSS(serverOpts{name: "mem-w128", cache: true, workers: 128})
	if err != nil {
		return section{}, err
	}
	perWorker := float64(big-small) / 120
	fmt.Fprintf(&sb, "| worker scratch arenas | %.2f MB per worker (%s at 128) |\n",
		perWorker/(1<<20), mib(int64(perWorker*128)))

	const rules = 250000
	withList, err := h.idleRSS(serverOpts{name: "mem-lists", cache: true, blockRules: rules})
	if err != nil {
		return section{}, err
	}
	perRule := float64(withList-idle) / rules
	fmt.Fprintf(&sb, "| blocklists | ~%.0f B per rule (%s for %s rules) |\n",
		perRule, mib(withList-idle), thousands(rules))

	// The cache row is a difference between two runs that differ only in
	// max_entries. Taking it from one run would charge the cache for the worker
	// arenas the same load brings up.
	smallCache, err := h.cacheFilledRSS(serverOpts{
		name: "mem-cache-small", cache: true, cacheEntries: 1000, blockRules: rules,
	})
	if err != nil {
		return section{}, err
	}
	bigCache, err := h.cacheFilledRSS(serverOpts{
		name: "mem-cache-big", cache: true, cacheEntries: 200000, blockRules: rules,
	})
	if err != nil {
		return section{}, err
	}
	perEntry := float64(bigCache.total-smallCache.total) /
		float64(bigCache.entries-smallCache.entries)
	fmt.Fprintf(&sb, "| answer cache | ~%.0f B per entry (%s at the default 10,000) |\n",
		perEntry, mib(int64(perEntry*10000)))
	fmt.Fprintf(&sb, "| realistic total under load | %s with %s rules and %s cached answers |\n",
		mib(bigCache.total), thousands(rules), thousands(float64(bigCache.entries)))

	return section{title: "Memory", body: sb.String()}, nil
}

func (h *harness) idleRSS(o serverOpts) (int64, error) {
	s, err := h.start(o)
	if err != nil {
		return 0, err
	}
	defer s.stop()
	// Lists are parsed at startup; let allocation settle before reading.
	time.Sleep(2 * time.Second)
	return s.rss(), nil
}

func (h *harness) loadedRSS(o serverOpts) (int64, error) {
	s, err := h.start(o)
	if err != nil {
		return 0, err
	}
	defer s.stop()
	_, sm, err := h.load(s, loadOpts{transport: "udp", clients: 100, duration: 5 * time.Second})
	if err != nil {
		return 0, err
	}
	return sm.PeakRSS, nil
}

type cacheFill struct {
	entries int64
	delta   int64
	total   int64
}

// cacheFilledRSS drives unique names until the cache is as full as it will get,
// and reports what the process weighed at the end.
func (h *harness) cacheFilledRSS(o serverOpts) (cacheFill, error) {
	s, err := h.start(o)
	if err != nil {
		return cacheFill{}, err
	}
	defer s.stop()
	time.Sleep(2 * time.Second)
	before := s.rss()

	r, sm, err := h.load(s, loadOpts{
		transport: "udp", clients: 128, qmode: "unique", duration: 30 * time.Second,
	})
	if err != nil {
		return cacheFill{}, err
	}
	entries := min(r.Answered, int64(o.cacheEntries))
	return cacheFill{entries: entries, delta: sm.PeakRSS - before, total: sm.PeakRSS}, nil
}

// shedding is what happens past capacity: the server drops rather than queues.
func (h *harness) shedding() (section, error) {
	// The offered load has to exceed what the workers can carry by enough that
	// the queue, not the client count, is what bounds it: 6000 clients against
	// 128 workers on a 20 ms upstream is about a thousandfold more demand than
	// supply, so an unbounded queue has room to become the latency.
	const clients = 6000

	var sb strings.Builder
	fmt.Fprintf(&sb, "Cache misses from %s clients at once, against a worker pool that can carry about %.0f/s.\n\n",
		thousands(clients), float64(128)/upstreamRTT.Seconds())
	sb.WriteString("| max_pending | served | p50 | p99 | dropped |\n|---|---|---|---|---|\n")

	for _, mp := range []struct {
		name  string
		label string
		value int
	}{
		{"default", "default (workers × 8)", 0},
		{"unbounded", "effectively unbounded", 1000000},
	} {
		s, err := h.start(serverOpts{
			name: "shed-" + mp.name, cache: true, maxPending: mp.value,
		})
		if err != nil {
			return section{}, err
		}
		r, _, err := h.load(s, loadOpts{
			transport: "udp", clients: clients, qmode: "unique", duration: 20 * time.Second,
		})
		s.stop()
		if err != nil {
			return section{}, err
		}
		fmt.Fprintf(&sb, "| %s | %s qps | %s | %s | %s |\n",
			mp.label, thousands(r.QPS), ms(r.P50ms), ms(r.P99ms), thousands(float64(r.Errors)))
	}
	sb.WriteString("\nA dropped query gets no answer at all, so it shows up as a client timeout rather than an error code.\n")
	return section{title: "Past capacity", body: sb.String()}, nil
}

// loggingCost is the throughput `log.queries` costs, which the README warns
// about because it is also the one thing that writes to disk in steady state.
func (h *harness) loggingCost() (section, error) {
	var sb strings.Builder
	sb.WriteString("| log.queries | throughput | run-to-run spread | cost |\n|---|---|---|---|\n")

	var base float64
	for _, on := range []bool{false, true} {
		// Both runs log at info so the only difference between them is whether
		// a line is written per query.
		s, err := h.start(serverOpts{
			name: fmt.Sprintf("log-%t", on), cache: true, logQueries: on, logLevel: "info",
		})
		if err != nil {
			return section{}, err
		}
		r, sm, err := h.load(s, loadOpts{transport: "udp", clients: 200})
		s.stop()
		if err != nil {
			return section{}, err
		}
		cost := ""
		if !on {
			base = r.QPS
		} else if base > 0 {
			cost = fmt.Sprintf("%.0f%%", (base-r.QPS)/base*100)
		}
		fmt.Fprintf(&sb, "| %t | %s qps | ±%.0f%% | %s |\n",
			on, thousands(r.QPS), sm.Spread*100, cost)
	}

	// What it writes is the part that matters regardless of what it costs: this
	// is the one thing that touches the disk in steady state.
	s, err := h.start(serverOpts{
		name: "log-bytes", cache: true, logQueries: true, logLevel: "info",
	})
	if err != nil {
		return section{}, err
	}
	before := fileSize(s.logPath)
	r, _, err := h.load(s, loadOpts{transport: "udp", clients: 200, repeat: 1})
	s.stop()
	if err != nil {
		return section{}, err
	}
	written := fileSize(s.logPath) - before
	fmt.Fprintf(&sb, "\nAt %s qps it wrote %.0f MB/s — %.0f bytes per query.\n",
		thousands(r.QPS), float64(written)/r.Seconds/(1<<20), float64(written)/float64(r.Answered))

	return section{title: "Cost of query logging", body: sb.String()}, nil
}

// expectRcode fails a scenario whose answers are not the kind it meant to
// measure, so a misconfigured row cannot be reported as a result.
func expectRcode(r Result, want string) error {
	if r.Answered == 0 {
		return fmt.Errorf("nothing was answered")
	}
	got := r.Rcodes[want]
	if got*10 < r.Answered*9 {
		return fmt.Errorf("only %d of %d answers were %s: %v", got, r.Answered, want, r.Rcodes)
	}
	return nil
}

func row(sb *strings.Builder, name string, r Result, rss int64) {
	fmt.Fprintf(sb, "| %s | %s qps | %s | %s | %s |\n",
		name, thousands(r.QPS), ms(r.P50ms), ms(r.P99ms), mib(rss))
}

func label(t string) string {
	switch t {
	case "udp":
		return "UDP"
	case "tcp":
		return "TCP"
	case "dot":
		return "DoT"
	case "doh1":
		return "DoH over HTTP/1.1"
	case "doh2":
		return "DoH over HTTP/2"
	}
	return t
}

func ms(v float64) string {
	if v < 1 {
		return fmt.Sprintf("%.2f ms", v)
	}
	return fmt.Sprintf("%.1f ms", v)
}

func mib(b int64) string {
	if b == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
}

func thousands(v float64) string {
	s := strconv.FormatFloat(v, 'f', 0, 64)
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
