package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"elodin.bench/internal/dnswire"
)

// compare is elodin against every server in -servers on the rows that decide
// which to run: what it weighs, what a cache hit and a miss cost, and what a
// held connection and a waiting query cost. Throughput rows pin the server to
// two cores and the generator to the other two, each server given two
// threads, so a server that spends more cores than another cannot pass for a
// faster one; CPU per query is the efficiency figure either way.
//
// A cell that fails reads "failed" and the reason is listed under the table,
// so one server's bad night does not lose the other nine.
func (h *harness) compare() (section, error) {
	if runtime.NumCPU() < 4 {
		return section{title: "Against the competition", body: "Skipped: needs four CPUs.\n"}, nil
	}
	if err := checkReceiveBuffer(); err != nil {
		return section{}, err
	}
	var notes []string
	fail := func(kind, what string, err error) string {
		notes = append(notes, fmt.Sprintf("- %s, %s: %v", h.serverLabel(kind), what, oneLine(err)))
		return "failed"
	}
	var sb strings.Builder
	h.compareMemory(&sb, fail)
	h.compareHits(&sb, fail)
	h.compareMisses(&sb, fail)
	if err := h.compareHeld(&sb, fail); err != nil {
		return section{}, err
	}
	if len(notes) > 0 {
		sb.WriteString("\nCells that failed:\n\n" + strings.Join(notes, "\n") + "\n")
	}
	return section{title: "Against the competition", body: sb.String()}, nil
}

// equalReceiveBuffer is the UDP receive buffer elodin asks for
// (listeners.udp.receive_buffer). Most of the other servers have no setting
// for theirs and take net.core.rmem_default, 208 KiB untuned, which a burst of
// a thousand queries overflows: each query the kernel drops is a client
// waiting out its timeout, and the row then measures the timeout. With the
// default at elodin's figure every server reads from the same size of buffer.
const equalReceiveBuffer = 1 << 20

func checkReceiveBuffer() error {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_default")
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	if n < equalReceiveBuffer {
		return fmt.Errorf("net.core.rmem_default is %d; the comparison needs every server's UDP buffer at elodin's %d: sudo sysctl net.core.rmem_default=%d", n, equalReceiveBuffer, equalReceiveBuffer)
	}
	return nil
}

// failer records why a cell failed and returns what the cell reads.
type failer func(kind, what string, err error) string

// compareMemory is the memory table: idle, with the list, per rule, per
// cached answer.
func (h *harness) compareMemory(sb *strings.Builder, fail failer) {
	sb.WriteString("### Memory\n\nIdle is the server started with its cache on and nothing asked. " +
		fmt.Sprintf("Lists is %s names, each in the server's own list format, read once "+
			"`blocked.bench.test` answers NXDOMAIN. Per cache entry is two servers whose caches hold "+
			"1,000 and 200,000 answers, each given 40 s of unique names at 128 clients: the difference "+
			"in RSS over the difference in entries held, so a cache allocated up front counts.\n\n", thousands(listRules)))
	sb.WriteString("| server | idle RSS | with the list | per rule | per cache entry |\n|---|---|---|---|---|\n")
	for _, kind := range h.kinds {
		idle, err := h.idleRSS(serverOpts{name: "cmp-idle", kind: kind, cache: true})
		idleCell := mib(idle)
		if err != nil {
			idleCell = fail(kind, "idle", err)
		}
		listCell, ruleCell := "—", "—"
		if supports(kind, "block") {
			if rss, err := h.listRSS(kind); err != nil {
				listCell = fail(kind, "list", err)
			} else {
				listCell = mib(rss)
				if idle > 0 {
					ruleCell = fmt.Sprintf("%.0f B", float64(rss-idle)/listRules)
				}
			}
		}
		entryCell := "failed"
		if per, n, err := h.perCacheEntry(kind); err != nil {
			entryCell = fail(kind, "cache entry", err)
		} else {
			entryCell = fmt.Sprintf("%.0f B", per)
			if n < 200000 {
				entryCell += fmt.Sprintf(" (filled %s)", thousands(float64(n)))
			}
		}
		fmt.Fprintf(sb, "| %s | %s | %s | %s | %s |\n", h.serverLabel(kind), idleCell, listCell, ruleCell, entryCell)
	}
}

// compareHits is cache hits on two cores, a cell per transport the server
// serves and one for answers from the list.
func (h *harness) compareHits(sb *strings.Builder, fail failer) {
	sb.WriteString("\n### Cache hits on two cores\n\nServer on CPUs 0-1 with two threads, generator on 2-3, " +
		"100 clients each holding its connection, every answer from the cache. Each cell is " +
		"throughput / p99 / CPU per query. A blocked answer is the UDP row's name on the list.\n\n")
	sb.WriteString("| server | UDP | TCP | DoT | DoH/1.1 | DoH/2 | blocked (UDP) |\n|---|---|---|---|---|---|---|\n")
	for _, kind := range h.kinds {
		fmt.Fprintf(sb, "| %s", h.serverLabel(kind))
		s, err := h.startServer(serverOpts{name: "cmp-hits", kind: kind, cache: true, loops: 2, cpus: "0-1"})
		if err != nil {
			fmt.Fprintf(sb, " | %s |||||\n", fail(kind, "start", err))
			continue
		}
		// Asked once before the clients start, so the rows measure answers from
		// the cache rather than a hundred clients at once asking a name the
		// server has not seen: BIND drops the copies of one question past
		// clients-per-query (10) while the first is upstream.
		_ = waitReady(s.dnsAddr, 5*time.Second, "cached.bench.test")
		for _, t := range []string{"udp", "tcp", "dot", "doh1", "doh2"} {
			sb.WriteString(" | " + h.hitCell(s, kind, t, fail))
		}
		s.stop()
		fmt.Fprintf(sb, " | %s |\n", h.blockedCell(kind, fail))
	}
}

// hitCell is one transport's cache hits against a running server.
func (h *harness) hitCell(s *server, kind, t string, fail failer) string {
	if !supports(kind, t) {
		return "—"
	}
	r, sm, err := h.load(s, loadOpts{transport: t, clients: 100, cpus: "2-3"})
	if err == nil {
		err = expectRcode(r, "noerror")
	}
	if err != nil {
		return fail(kind, label(t), err)
	}
	cpu := forkedCell
	if !forked(kind, t) {
		cpu = fmt.Sprintf("%d µs", sm.CPUPerQuery(r.Answered).Microseconds())
	}
	return fmt.Sprintf("%s / %s / %s%s", thousands(r.QPS), ms(r.P99ms), cpu, timedOut(r))
}

// missLadder is the offered cache-miss rates compareMisses climbs, and
// missClients enough clients that none of them is the limit: at 100,000 a
// second and a 20 ms upstream, 2,000 queries are waiting at once.
var missLadder = []int{2000, 5000, 10000, 25000, 50000, 75000, 100000}

const missClients = 4000

// missClean is the share of queries a step may lose and still count as
// carried: a server that answers half its queries faster is not faster.
const missClean = 0.001

// compareMisses is the cache-miss ceiling on two cores, as offered load rather
// than as many clients as fast as they can: a closed loop of clients measures
// the generator's timeout as soon as a server drops one query, since that
// client then waits the timeout out. Each server climbs missLadder until a
// step loses more than missClean or falls 3% short of the rate offered; the
// row is the last step it carried, and the first step, which every server is
// asked at, is the equal-load comparison.
func (h *harness) compareMisses(sb *strings.Builder, fail failer) {
	fmt.Fprintf(sb, "\n### Cache misses on two cores\n\nAs above, every name unique, upstream at %s, the "+
		"in-flight bound raised to 4,096 wherever the server has one. The load is offered at a fixed rate "+
		"and climbs %s qps until a step loses more than %.1f%% of its queries or answers under 97%% of "+
		"the rate; sustained is the last step carried, with its latency and CPU. At %s qps is every "+
		"server at the same load, median of %d.\n\n",
		*upstreamRTT, ladderText(), missClean*100, thousands(float64(missLadder[0])), *repeat)
	fmt.Fprintf(sb, "| server | sustained | p50 / p99 there | CPU per miss there | at %s qps: p50 / p99 / CPU | lost at the next step |\n|---|---|---|---|---|---|\n",
		thousands(float64(missLadder[0])))
	for _, kind := range h.kinds {
		s, err := h.startServer(serverOpts{name: "cmp-miss", kind: kind, cache: true, loops: 2, cpus: "0-1", maxPending: 4096})
		if err != nil {
			fmt.Fprintf(sb, "| %s | %s |||||\n", h.serverLabel(kind), fail(kind, "start", err))
			continue
		}
		row, err := h.missRow(s)
		s.stop()
		if err != nil {
			fmt.Fprintf(sb, "| %s | %s |||||\n", h.serverLabel(kind), fail(kind, "misses", err))
			continue
		}
		fmt.Fprintf(sb, "| %s | %s |\n", h.serverLabel(kind), row)
	}
}

func ladderText() string {
	parts := make([]string, len(missLadder))
	for i, r := range missLadder {
		parts[i] = thousands(float64(r))
	}
	return strings.Join(parts, ", ")
}

// missRow climbs the ladder against a running server and formats its cells.
func (h *harness) missRow(s *server) (string, error) {
	type step struct {
		rate int
		r    Result
		sm   sample
	}
	run := func(rate, n int) (step, error) {
		r, sm, err := h.load(s, loadOpts{transport: "udp", clients: missClients, qmode: "unique", rate: rate, cpus: "2-3", repeat: n})
		if err == nil && r.Answered > 0 {
			err = expectRcode(r, "noerror")
		}
		return step{rate, r, sm}, err
	}
	carried := func(st step) bool {
		asked := st.r.Answered + st.r.Errors
		return asked > 0 && float64(st.r.Errors) <= missClean*float64(asked) && st.r.QPS >= 0.97*float64(st.rate)
	}
	lost := func(st step) string {
		asked := st.r.Answered + st.r.Errors
		if asked == 0 {
			return "all"
		}
		return fmt.Sprintf("%.1f%% at %s (answered %s qps)", 100*float64(st.r.Errors)/float64(asked),
			thousands(float64(st.rate)), thousands(st.r.QPS))
	}
	// A fresh server's first seconds of misses are slower than the rest (its
	// upstream sockets, timers and tables coming up), which the equal-load
	// cell is not about; a short run it does not count is taken first.
	if _, _, err := h.load(s, loadOpts{transport: "udp", clients: missClients, qmode: "unique", rate: missLadder[0],
		cpus: "2-3", repeat: 1, duration: 5 * time.Second}); err != nil {
		return "", err
	}
	first, err := run(missLadder[0], 0)
	if err != nil {
		return "", err
	}
	equal := fmt.Sprintf("%s / %s / %d µs", ms(first.r.P50ms), ms(first.r.P99ms), first.sm.CPUPerQuery(first.r.Answered).Microseconds())
	if !carried(first) {
		return fmt.Sprintf("under %s | — | — | %s | %s", thousands(float64(first.rate)), equal, lost(first)), nil
	}
	best, next := first, "— (carried every step)"
	for _, rate := range missLadder[1:] {
		st, err := run(rate, 1)
		if err != nil {
			return "", err
		}
		if !carried(st) {
			next = lost(st)
			break
		}
		best = st
	}
	return fmt.Sprintf("%s qps | %s / %s | %d µs | %s | %s", thousands(float64(best.rate)), ms(best.r.P50ms), ms(best.r.P99ms),
		best.sm.CPUPerQuery(best.r.Answered).Microseconds(), equal, next), nil
}

// heldN is how many connections, and how many queries in flight, the held
// table measures.
const heldN = 1000

// compareHeld is what a held connection and a waiting query cost.
func (h *harness) compareHeld(sb *strings.Builder, fail failer) error {
	// Long enough for the sampler to see every query waiting at once, and no
	// longer: BIND retransmits after 800 ms and backs off, dropping the late
	// replies, so behind 1.5 s it answers after five; Blocky gives up on an
	// attempt after about three.
	mock, err := h.startMock(time.Second)
	if err != nil {
		return err
	}
	fmt.Fprintf(sb, "\n### What a held connection and a waiting query cost\n\n%s clients each ask one "+
		"cached name and hold the connection idle; (RSS held − RSS before) ÷ N. In flight is %s unique "+
		"names behind a 1 s upstream, cache off; (peak − idle) ÷ N, with how many were answered.\n\n",
		thousands(heldN), thousands(heldN))
	sb.WriteString("| server | per idle TCP | per idle DoT | per idle DoH/2 | per query in flight |\n|---|---|---|---|---|\n")
	for _, kind := range h.kinds {
		fmt.Fprintf(sb, "| %s", h.serverLabel(kind))
		for _, t := range []string{"tcp", "dot", "doh2"} {
			sb.WriteString(" | " + h.heldCell(kind, t, fail))
		}
		fmt.Fprintf(sb, " | %s |\n", h.inflightCell(kind, mock, fail))
	}
	return nil
}

// heldCell is the memory per idle connection over one transport.
func (h *harness) heldCell(kind, t string, fail failer) string {
	if !supports(kind, t) {
		return "—"
	}
	s, err := h.startServer(serverOpts{name: "cmp-conns", kind: kind, cache: true,
		maxConnections: heldN + 64, clientTimeout: 120 * time.Second})
	if err != nil {
		return fail(kind, label(t)+" held", err)
	}
	time.Sleep(time.Second)
	before := s.rss()
	r, held, _, err := h.once(s, t, heldN, "fixed")
	s.stop()
	if err != nil {
		return fail(kind, label(t)+" held", err)
	}
	// A forking server's memory is not measured, but how many of the clients
	// it answered still is: past its connection limit, the rest wait in the
	// listen backlog unanswered.
	if forked(kind, t) {
		return forkedCell + " (" + answeredOf(r, heldN) + " answered)"
	}
	cell := perItem(held-before, heldN)
	if r.Answered != heldN {
		cell += " (" + answeredOf(r, heldN) + ")"
	}
	return cell
}

// inflightCell is the memory per query waiting on the slow mock.
func (h *harness) inflightCell(kind, mock string, fail failer) string {
	s, err := h.startServer(serverOpts{name: "cmp-inflight", kind: kind, maxPending: heldN + 256, upstreamAddr: mock})
	if err != nil {
		return fail(kind, "in flight", err)
	}
	time.Sleep(time.Second)
	idle := s.rss()
	r, _, peak, err := h.once(s, "udp", heldN, "unique")
	s.stop()
	if err != nil {
		return fail(kind, "in flight", err)
	}
	return fmt.Sprintf("%s (%s answered)", perItem(peak-idle, heldN), answeredOf(r, heldN))
}

// listRSS starts kind with the list on two cores, waits until it blocks, and
// reads what it weighs.
func (h *harness) listRSS(kind string) (int64, error) {
	s, err := h.startServer(serverOpts{name: "cmp-list", kind: kind, cache: true, blockRules: listRules})
	if err != nil {
		return 0, err
	}
	defer s.stop()
	if err := waitBlocked(s.dnsAddr, 120*time.Second); err != nil {
		return 0, err
	}
	time.Sleep(2 * time.Second)
	return s.rss(), nil
}

// blockedCell is the throughput of answers from the list on two cores.
func (h *harness) blockedCell(kind string, fail failer) string {
	if !supports(kind, "block") {
		return "—"
	}
	s, err := h.startServer(serverOpts{name: "cmp-blocked", kind: kind, cache: true, blockRules: listRules, loops: 2, cpus: "0-1"})
	if err != nil {
		return fail(kind, "blocked", err)
	}
	defer s.stop()
	if err := waitBlocked(s.dnsAddr, 120*time.Second); err != nil {
		return fail(kind, "blocked", err)
	}
	r, sm, err := h.load(s, loadOpts{transport: "udp", clients: 100, qname: "blocked.bench.test", cpus: "2-3"})
	if err == nil {
		err = expectRcode(r, "nxdomain")
	}
	if err != nil {
		return fail(kind, "blocked", err)
	}
	return fmt.Sprintf("%s / %s / %d µs%s", thousands(r.QPS), ms(r.P99ms), sm.CPUPerQuery(r.Answered).Microseconds(), timedOut(r))
}

// perCacheEntry is what one more cached answer weighs: two servers that
// differ only in their cache's capacity, 1,000 and 200,000 answers, each
// filled with unique names for 40 s, and the difference over the entries
// between. The threads and buffers the load brings up are in both and
// cancel, and a server that allocates its cache up front is charged for it.
// It returns the entries the larger cache reached as well.
func (h *harness) perCacheEntry(kind string) (float64, int64, error) {
	const small, big = 1000, 200000
	fill := func(entries int) (int64, int64, error) {
		s, err := h.startServer(serverOpts{name: "cmp-cache", kind: kind, cache: true, cacheEntries: entries})
		if err != nil {
			return 0, 0, err
		}
		defer s.stop()
		time.Sleep(2 * time.Second)
		r, _, err := h.load(s, loadOpts{transport: "udp", clients: 128, qmode: "unique", duration: 40 * time.Second, repeat: 1})
		if err == nil {
			err = expectRcode(r, "noerror")
		}
		if err != nil {
			return 0, 0, err
		}
		time.Sleep(time.Second)
		return s.rss(), min(r.Answered, int64(entries)), nil
	}
	a, na, err := fill(small)
	if err != nil {
		return 0, 0, err
	}
	b, nb, err := fill(big)
	if err != nil {
		return 0, 0, err
	}
	return float64(b-a) / float64(nb-na), nb, nil
}

// waitBlocked polls until the list is loaded: some servers answer before
// they have read it.
func waitBlocked(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	last := "no answer"
	for time.Now().Before(deadline) {
		conn, err := net.Dial("udp", addr)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(dnswire.Query(7, "blocked.bench.test", dnswire.TypeA, 0))
			buf := make([]byte, 4096)
			n, rerr := conn.Read(buf)
			conn.Close()
			if rerr == nil {
				if r, perr := dnswire.ParseReply(buf[:n]); perr == nil {
					if r.Rcode == 3 {
						return nil
					}
					last = fmt.Sprintf("rcode %d", r.Rcode)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("blocked.bench.test never answered NXDOMAIN (last: %s)", last)
}

func oneLine(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// timedOut marks a cell whose server dropped queries, so one that sheds
// cannot read as one that is merely slower.
func timedOut(r Result) string {
	switch {
	case r.Reconnects > 0:
		return fmt.Sprintf(" (**%s failed, %s reconnects**)", thousands(float64(r.Errors)), thousands(float64(r.Reconnects)))
	case r.Errors > 0:
		return fmt.Sprintf(" (**%s timed out**)", thousands(float64(r.Errors)))
	}
	return ""
}
