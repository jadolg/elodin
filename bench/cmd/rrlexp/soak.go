package main

import (
	"fmt"
	"strings"
	"time"
)

/*
The soak: reading the server while the load is still on it.

Every other arm reports one state, taken once the clients have stopped, and for
eight seconds that is the whole of what there is to say. Over an hour it is the
least interesting part: what a deployment wants to know is whether the resident
memory settles or climbs, whether a cache under eviction stays the size it was
told to be, whether the connection table gives back what it lends, and whether
the answers the limiter allows are still arriving at the end. None of those is a
final number - each is a shape, and a shape needs samples.

So the soak arm reads the server's own counters every `-soak-sample` and keeps
what it read. The clients' counters are read at the same moment and from the same
atomics the report uses, so a window's answer rate is the difference between two
readings rather than an average over the arm - which is the distinction the whole
mode exists for. An arm that answered nothing for its last ten minutes and
everything before them has the same average as one that behaved throughout.
*/

// One reading of the server, and of the clients, while the arm was running.
type sample struct {
	at time.Duration
	/*
		Whether the server answered when it was asked.

		`counters` cannot distinguish a scrape it could not make from a server
		with nothing to report - both are an empty map - so the distinction is
		made here, once, where the reading happens. A missed scrape rendered as
		zeros is the one thing a series about drift must not do: it would show
		the memory falling to nothing and then the window after it climbing back
		from it.
	*/
	ok bool
	// The server's `/metrics`, whole: what to read out of it is the report's
	// business, and a sample that kept only today's columns would have to be
	// re-taken to answer tomorrow's question.
	srv map[string]int64
	// The victim as of the same moment, so a window can be a difference rather
	// than a rate averaged over everything so far. What the flood got is the
	// server's own `queries_total` in the same row, which is the figure the
	// limiter decided rather than the one a socket buffer delivered.
	victimOffered int64
	victimFull    int64
	victimClosed  int64
}

/*
startSoakSampler starts the sampling for an arm that asked for it and returns
the function that stops it.

A no-op for every other arm, returned rather than branched on at the call site:
`runArm` reads better for having one path, and an arm with no sampling interval
is most of them.
*/
func startSoakSampler(srv *server, a arm, r *row) func() {
	if a.sample <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	start := time.Now()

	/*
		The first reading is taken now, before any of the measured window has
		run, and it is the baseline the first window's rates are differences
		from rather than a row of its own.

		Without it the first row would divide everything the server had done
		since it started - the warm-up flood and the readiness probes included -
		by the time since the arm began, and read as a window that refused fifty
		per cent more datagrams than any window after it. Which it did not: the
		warm-up did.
	*/
	r.samples = append(r.samples, takeSample(srv, r, 0))

	go func() {
		defer close(stopped)
		tick := time.NewTicker(a.sample)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				r.samples = append(r.samples, takeSample(srv, r, time.Since(start)))
			}
		}
	}()

	return func() {
		close(done)
		<-stopped
	}
}

/*
takeSample reads the server and both clients at one moment.

Appended by the sampling goroutine alone and read only after it has stopped, so
the slice needs no lock; the client counters it reads are atomics the clients are
still writing, which is what makes the reading safe to do while they run.
*/
func takeSample(srv *server, r *row, at time.Duration) sample {
	got := srv.counters()
	s := sample{
		at:            at,
		ok:            len(got) > 0,
		srv:           got,
		victimOffered: r.victim.offered.Load(),
		victimFull:    r.victim.full.Load(),
		victimClosed:  r.victim.closed.Load(),
	}
	return s
}

/*
soakTable is the series, one row per sample.

The gauges are read as they were at the sample - resident memory, threads, open
descriptors, cache entries, connections being served - and the counters as what
happened since the sample before, which is the only way a rate says anything
about the window rather than about the average since the arm began.

`victim answered` is the pair the whole arm is for: the share of the queries
offered in that window that came back with an answer. A limiter that stops
holding after fifty minutes, a connection table that stops handing slots back, a
cache that starts refusing to evict - each of those arrives here as that column
falling while the rest of the row explains why.
*/
func soakTable(b *strings.Builder, rows []row) {
	if !hasSamples(rows) {
		return
	}
	b.WriteString("\n## The soak: what changed while it ran\n\n")
	for _, r := range rows {
		if len(r.samples) < 2 {
			continue
		}
		fmt.Fprintf(b, "### %s — %s, sampled every %s\n\n", r.arm.name, armDuration(r.arm), r.arm.sample)
		b.WriteString("| at | RSS | threads | fds | cache entries | cache bytes | conns active | conns refused | answers/s | limited/s | victim answered | victim refused |\n")
		b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
		// The reading taken before the window opened is the baseline rather
		// than a row: see `startSoakSampler`.
		prev := r.samples[0]
		for _, s := range r.samples[1:] {
			soakRow(b, s, prev)
			// A missed scrape is not a baseline. The window after it is a
			// difference from the last reading that happened, over the longer
			// interval that separates them, which the counters being cumulative
			// makes correct.
			if s.ok {
				prev = s
			}
		}
		fmt.Fprintf(b, "\nRead the gauges as of the sample and the rates over the window before it. %s\n",
			soakVerdict(r))
	}
}

func soakRow(b *strings.Builder, s, prev sample) {
	if !s.ok {
		// Everything in the row but the clock came from a scrape that did not
		// happen. The clients' own counters did arrive, but a row half read as
		// a reading is worse than one that says it is not one.
		fmt.Fprintf(b, "| %s | — | — | — | — | — | — | — | — | — | the server could not be read | — |\n",
			s.at.Round(time.Second))
		return
	}
	window := (s.at - prev.at).Seconds()
	if window <= 0 {
		window = 1
	}
	offered := s.victimOffered - prev.victimOffered
	answered := s.victimFull - prev.victimFull
	victim := "—"
	if offered > 0 {
		victim = fmt.Sprintf("%.0f%% (%d/%d)", 100*float64(answered)/float64(offered), answered, offered)
	}
	fmt.Fprintf(b, "| %s | %d MB | %d | %d | %d | %d MB | %d | %d | %.0f | %.0f | %s | %d |\n",
		s.at.Round(time.Second),
		s.srv["process_resident_memory_bytes"]/(1<<20),
		s.srv["process_threads"],
		s.srv["process_open_fds"],
		s.srv["elodin_cache_entries"],
		s.srv["elodin_cache_bytes"]/(1<<20),
		s.srv["elodin_connections_active"],
		s.srv["elodin_connections_refused_total"],
		float64(s.srv["elodin_queries_total"]-prev.srv["elodin_queries_total"])/window,
		float64(s.srv["elodin_rate_limited_total"]-prev.srv["elodin_rate_limited_total"])/window,
		victim,
		s.victimClosed-prev.victimClosed)
}

/*
soakVerdict is the one thing a reader of a long table needs said out loud: how
the last window compares with the first.

Not a pass or a fail. A drift of a few megabytes over an hour is a cache filling
to the size it was configured for, and the arm cannot tell that from the start of
a leak - what it can do is put the two numbers next to each other so that the
question is asked rather than left to whoever scrolls furthest.
*/
func soakVerdict(r row) string {
	first, last := goodSample(r.samples, false), goodSample(r.samples, true)
	if first.at == last.at || !first.ok || !last.ok {
		return "Fewer than two readings the server answered, so there is no drift to report."
	}
	rssFirst := first.srv["process_resident_memory_bytes"] / (1 << 20)
	rssLast := last.srv["process_resident_memory_bytes"] / (1 << 20)
	return fmt.Sprintf(
		"Resident memory went %d MB → %d MB, threads %d → %d, descriptors %d → %d, cache entries %d → %d over %s of load.",
		rssFirst, rssLast,
		first.srv["process_threads"], last.srv["process_threads"],
		first.srv["process_open_fds"], last.srv["process_open_fds"],
		first.srv["elodin_cache_entries"], last.srv["elodin_cache_entries"],
		(last.at - first.at).Round(time.Second))
}

/*
goodSample is the first or the last reading the server answered.

The ends of the series, for the drift line, and they have to be readings rather
than positions: a scrape that failed at either end would otherwise be compared
against a real one and report the whole of the server's memory as having
appeared or gone.
*/
func goodSample(samples []sample, last bool) sample {
	for i := range samples {
		s := samples[i]
		if last {
			s = samples[len(samples)-1-i]
		}
		if s.ok {
			return s
		}
	}
	return sample{}
}

// hasSamples asks whether any arm produced a series: the baseline reading and at
// least one window after it, which is the least the table can be read from.
func hasSamples(rows []row) bool {
	for _, r := range rows {
		if len(r.samples) > 1 {
			return true
		}
	}
	return false
}
