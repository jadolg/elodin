package main

import (
	"fmt"
	"net"
	"runtime"
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
	return fmt.Sprintf("%s / %s / %d µs%s", thousands(r.QPS), ms(r.P99ms), sm.CPUPerQuery(r.Answered).Microseconds(), timedOut(r))
}

// compareMisses is the cache-miss ceiling on two cores.
func (h *harness) compareMisses(sb *strings.Builder, fail failer) {
	const missClients = 1000
	fmt.Fprintf(sb, "\n### Cache misses on two cores\n\nAs above, %s clients over UDP, every name unique, "+
		"upstream at %s, the in-flight bound raised to 4,096 wherever the server has one. "+
		"The generator cannot ask faster than %s qps.\n\n",
		thousands(missClients), *upstreamRTT, thousands(missClients/upstreamRTT.Seconds()))
	sb.WriteString("| server | cache misses | p50 | p99 | timed out | CPU per miss |\n|---|---|---|---|---|---|\n")
	for _, kind := range h.kinds {
		s, err := h.startServer(serverOpts{name: "cmp-miss", kind: kind, cache: true, loops: 2, cpus: "0-1", maxPending: 4096})
		if err != nil {
			fmt.Fprintf(sb, "| %s | %s |||||\n", h.serverLabel(kind), fail(kind, "start", err))
			continue
		}
		r, sm, err := h.load(s, loadOpts{transport: "udp", clients: missClients, qmode: "unique", cpus: "2-3"})
		s.stop()
		if err == nil {
			err = expectRcode(r, "noerror")
		}
		if err != nil {
			fmt.Fprintf(sb, "| %s | %s |||||\n", h.serverLabel(kind), fail(kind, "misses", err))
			continue
		}
		fmt.Fprintf(sb, "| %s | %s qps | %s | %s | %s | %d µs |\n", h.serverLabel(kind), thousands(r.QPS),
			ms(r.P50ms), ms(r.P99ms), thousands(float64(r.Errors)), sm.CPUPerQuery(r.Answered).Microseconds())
	}
}

// heldN is how many connections, and how many queries in flight, the held
// table measures.
const heldN = 1000

// compareHeld is what a held connection and a waiting query cost.
func (h *harness) compareHeld(sb *strings.Builder, fail failer) error {
	mock, err := h.startMock(3 * time.Second)
	if err != nil {
		return err
	}
	fmt.Fprintf(sb, "\n### What a held connection and a waiting query cost\n\n%s clients each ask one "+
		"cached name and hold the connection idle; (RSS held − RSS before) ÷ N. In flight is %s unique "+
		"names behind a 3 s upstream, cache off; (peak − idle) ÷ N, with how many were answered.\n\n",
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
	if r.Errors == 0 {
		return ""
	}
	return fmt.Sprintf(" (**%s timed out**)", thousands(float64(r.Errors)))
}
