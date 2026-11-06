package main

import (
	"fmt"
	"strings"
	"time"
)

/*
The `upstream-fail` arms: no hostile client, an upstream that stops.

Every other arm is about what one client does to another. The commonest thing
that goes wrong for a forwarder in production is neither: a resolver it forwards
to stops answering. The integration suite covers the mechanism (each strategy,
the failure cooldown, pooling) with one client at a time; these arms measure
what clients see while it happens, under traffic.

Each arm runs two clients for `failArm`:

  - the victim asks one name over and over, so after its first query every
    answer it is owed is in the cache. Whether those answers are delayed while
    an upstream is gone is the claim the arms exist for: a dead upstream should
    cost nothing to a query that never needed it.
  - a miss stream asks a new name every time, `failMissRate` a second, which is
    the traffic that does need an upstream and the load that fills whatever a
    held query holds.

`failBefore` into the measured window the first upstream fails, and `failFor`
later it comes back, so each arm reports the transition and the recovery rather
than a server that started without it. Long enough to cover the failure
threshold, the cooldown and the probe after it. The server is read every
second, which is the series `upstreamTable` prints.

Two ways of failing, because they cost a forwarder very differently:
`blackhole` reads every query and answers none, so each costs the full
`upstream.timeout`; `refused` is the port gone, which the kernel says in a
syscall. The gap between them is what holding a query costs.

The first six arms put the failing upstream first of two, once per strategy,
because that is the comparison an operator choosing one needs and the one the
strategies make most differently. The last four make it the only upstream, with
`cache.serve_stale` off (the default) and on, and a 2-second TTL on every answer
so the victim's name expires during the failure: that is the situation serve-
stale exists for, and with a second upstream there is nothing for it to do.

The last arm is the claim the others cannot reach on a machine this size: what
happens once held misses fill `server.max_pending`. The derived figure is in the
thousands here, more than `failMissRate` held for a timeout comes to, so the arm
pins 256 and keeps the victim's answers fresh: whatever it loses is a cache hit
turned away because queries that did need the upstream were holding every slot.

The rate limiter is off: the question is the upstream, and both clients are
asking from their own /24 anyway. `upstream.attempts` is the shipped default.
*/

const (
	failBefore   = 3 * time.Second
	failFor      = 15 * time.Second
	failArm      = failBefore + failFor + 7*time.Second
	failMissRate = 200
)

// failSpec is the upstream an `upstream-fail` arm takes away, and how.
type failSpec struct {
	mode     int32 // mockBlackhole or mockRefused
	strategy string
	// The failing upstream is the only one, rather than first of two.
	alone bool
	stale bool
	ttl   uint32
}

func upstreamFailArms() []arm {
	misses := &clientSpec{src: "127.0.0.2", transport: "udp", rate: failMissRate, sockets: 1}
	victim := clientSpec{src: "127.1.0.1", transport: "udp", rate: *victimRate, sockets: 1, qmode: "fixed"}
	modes := []struct {
		name string
		mode int32
	}{{"blackhole", mockBlackhole}, {"refused", mockRefused}}
	var arms []arm
	for _, m := range modes {
		for _, strategy := range []string{"failover", "round-robin", "race"} {
			arms = append(arms, arm{
				name:     "upstream-fail/" + m.name + "/" + strategy,
				question: fmt.Sprintf("what clients see while the first of two upstreams is %s, under %s", m.name, strategy),
				dur:      failArm, sample: time.Second,
				fail:     &failSpec{mode: m.mode, strategy: strategy, ttl: 300},
				attacker: misses,
				victim:   victim,
			})
		}
	}
	for _, m := range modes {
		for _, stale := range []bool{false, true} {
			arms = append(arms, arm{
				name:     "upstream-fail/" + m.name + "/only-upstream/stale-" + onOff(stale),
				question: fmt.Sprintf("the only upstream %s, with answers expiring during it and serve_stale %s", m.name, onOff(stale)),
				dur:      failArm, sample: time.Second,
				fail:     &failSpec{mode: m.mode, strategy: "failover", alone: true, stale: stale, ttl: 2},
				attacker: misses,
				victim:   victim,
			})
		}
	}
	return append(arms, arm{
		name:     "upstream-fail/blackhole/only-upstream/pending-full",
		question: "whether cache hits are turned away once misses held by a blackhole fill server.max_pending (pinned to 256)",
		dur:      failArm, sample: time.Second,
		maxPending: 256,
		fail:       &failSpec{mode: mockBlackhole, strategy: "failover", alone: true, ttl: 300},
		attacker:   misses,
		victim:     victim,
	})
}

// outage is an arm's upstreams and the schedule that takes the first away.
type outage struct {
	spec    failSpec
	failing *mock
	steady  *mock // nil when the failing one is alone
	done    chan struct{}
	// From the start of the measured window; written before `done` closes.
	downAt, upAt time.Duration
	err          error
}

func startOutage(f failSpec) (*outage, error) {
	o := &outage{spec: f, done: make(chan struct{})}
	var err error
	if o.failing, err = startMock(*upDelay, *records, f.ttl); err != nil {
		return nil, err
	}
	if !f.alone {
		if o.steady, err = startMock(*upDelay, *records, f.ttl); err != nil {
			o.failing.stop()
			return nil, err
		}
	}
	return o, nil
}

func (o *outage) block() string {
	members := []member{{"failing", o.failing.addr}}
	if o.steady != nil {
		members = append(members, member{"steady", o.steady.addr})
	}
	return upstreamBlock(o.spec.strategy, 0, members)
}

// schedule fails the first upstream `failBefore` after `start` and restores it
// `failFor` later.
func (o *outage) schedule(start time.Time) {
	go func() {
		defer close(o.done)
		time.Sleep(time.Until(start.Add(failBefore)))
		if err := o.failing.fail(o.spec.mode); err != nil {
			o.err = fmt.Errorf("the failing upstream could not hold its port: %w", err)
		}
		o.downAt = time.Since(start)
		time.Sleep(time.Until(start.Add(failBefore + failFor)))
		if err := o.failing.restore(); err != nil && o.err == nil {
			// Returned by `wait` rather than fatal here, so the arm's server is
			// stopped on the way out instead of orphaned by an exit.
			o.err = fmt.Errorf("the failing upstream could not come back: %w", err)
		}
		o.upAt = time.Since(start)
	}()
}

func (o *outage) wait() (time.Duration, time.Duration, error) {
	<-o.done
	return o.downAt, o.upAt, o.err
}

func (o *outage) stop() {
	o.failing.stop()
	if o.steady != nil {
		o.steady.stop()
	}
}

/*
upstreamTable is the `upstream-fail` arms: a summary row each, then each arm's
series.

`victim` is the cache-hit client, so any loss or delay in its columns during the
failure is a dead upstream reaching queries that never needed one. `misses` is
the traffic that did. A window's answered share can pass 100% when replies held
by a timeout arrive in a later window than the queries that asked them.
*/
func upstreamTable(b *strings.Builder, rows []row) {
	var fails []row
	for _, r := range rows {
		if r.arm.fail != nil && len(r.samples) > 1 {
			fails = append(fails, r)
		}
	}
	if len(fails) == 0 {
		return
	}
	b.WriteString("\n## Upstream failure: what clients see while one goes away\n\n")
	fmt.Fprintf(b, "The first upstream fails %s into the window and returns %s later. The victim asks one cached name at %d q/s; the misses are %d q/s of new names.\n\n",
		failBefore, failFor, *victimRate, failMissRate)
	b.WriteString("| arm | victim answered during | victim answers' p50 / p99 during | misses answered during | peak in flight / max_pending | shed during | stale served during | `upstream_up` 0 → 1 | misses back |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---|---|\n")
	for _, r := range fails {
		failSummary(b, r)
	}
	for _, r := range fails {
		failSeries(b, r)
	}
}

func failSummary(b *strings.Builder, r row) {
	from, to := sampleAt(r.samples, r.downAt), sampleAt(r.samples, r.upAt)
	vo, vf := to.victimOffered-from.victimOffered, to.victimFull-from.victimFull
	mo, mf := to.attackerOffered-from.attackerOffered, to.attackerFull-from.attackerFull
	var peak int64
	for _, s := range r.samples {
		peak = max(peak, s.srv["elodin_queries_inflight"])
	}
	fmt.Fprintf(b, "| %s | %s | %s / %s | %s | %d / %d | %d | %d | %s | %s |\n",
		r.arm.name, share(vf, vo),
		windowPct(r.victim, from, to, 0.5), windowPct(r.victim, from, to, 0.99),
		share(mf, mo), peak, r.srv["elodin_queries_inflight_max"],
		to.srv["elodin_queries_dropped_total"]-from.srv["elodin_queries_dropped_total"],
		to.srv["elodin_cache_stale_total"]-from.srv["elodin_cache_stale_total"],
		parked(r), recovered(r))
}

func failSeries(b *strings.Builder, r row) {
	fmt.Fprintf(b, "\n### %s — down at +%s, back at +%s\n\n", r.arm.name, r.downAt.Round(100*time.Millisecond), r.upAt.Round(100*time.Millisecond))
	b.WriteString("| at | failing up | steady up | in flight | shed/s | stale/s | victim answered | victim p50 | victim p99 | misses answered |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	prev := r.samples[0]
	for _, s := range r.samples[1:] {
		if !s.ok {
			fmt.Fprintf(b, "| %s | the server could not be read |||||||||\n", s.at.Round(time.Second))
			continue
		}
		window := (s.at - prev.at).Seconds()
		fmt.Fprintf(b, "| %s | %s | %s | %d | %.0f | %.0f | %s | %s | %s | %s |\n",
			s.at.Round(time.Second),
			upGauge(s, "failing"), upGauge(s, "steady"),
			s.srv["elodin_queries_inflight"],
			float64(s.srv["elodin_queries_dropped_total"]-prev.srv["elodin_queries_dropped_total"])/window,
			float64(s.srv["elodin_cache_stale_total"]-prev.srv["elodin_cache_stale_total"])/window,
			share(s.victimFull-prev.victimFull, s.victimOffered-prev.victimOffered),
			windowPct(r.victim, prev, s, 0.5),
			windowPct(r.victim, prev, s, 0.99),
			share(s.attackerFull-prev.attackerFull, s.attackerOffered-prev.attackerOffered))
		prev = s
	}
}

// windowPct is the victim's percentile over the replies answered between two
// samples, or "—" when none were: a window that answered nothing is not 0s.
// Only NOERROR replies have a latency (see `record`), so a SERVFAIL after the
// full upstream budget shows in the answered share, not here.
func windowPct(st *stats, from, to sample, q float64) string {
	if to.victimLat <= from.victimLat {
		return "—"
	}
	return round(st.pctOf(from.victimLat, to.victimLat, q)).String()
}

func share(n, of int64) string {
	if of <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(of))
}

func upGauge(s sample, name string) string {
	v, ok := s.srv[`elodin_upstream_up{upstream="`+name+`"}`]
	if !ok {
		return "—"
	}
	return fmt.Sprint(v)
}

// sampleAt is the first reading the server answered at or after `t`, allowing
// for the ticker landing a little early, or the last one it answered.
func sampleAt(samples []sample, t time.Duration) sample {
	for _, s := range samples {
		if s.ok && s.at >= t-200*time.Millisecond {
			return s
		}
	}
	return goodSample(samples, true)
}

// parked is when the failing upstream's `elodin_upstream_up` went to 0 and when
// it came back to 1, or that it never left service.
func parked(r row) string {
	var down, up time.Duration
	for _, s := range r.samples {
		v, ok := s.srv[`elodin_upstream_up{upstream="failing"}`]
		switch {
		case !s.ok || !ok:
		case v == 0 && down == 0:
			down = s.at
		case v == 1 && down != 0 && up == 0:
			up = s.at
		}
	}
	switch {
	case down == 0:
		return "never parked"
	case up == 0:
		return fmt.Sprintf("+%s → still 0", down.Round(time.Second))
	}
	return fmt.Sprintf("+%s → +%s", down.Round(time.Second), up.Round(time.Second))
}

// recovered is how long after the upstream returned the misses were answered
// again: the first window after `upAt` from which every window answered 95%.
// "never lost" when no window of the outage fell below that, as under `race`.
func recovered(r row) string {
	var at time.Duration
	lost := false
	prev := r.samples[0]
	for _, s := range r.samples[1:] {
		if !s.ok {
			continue
		}
		mo, mf := s.attackerOffered-prev.attackerOffered, s.attackerFull-prev.attackerFull
		healthy := mo > 0 && float64(mf) >= 0.95*float64(mo)
		if !healthy && prev.at >= r.downAt-200*time.Millisecond && prev.at < r.upAt-200*time.Millisecond {
			lost = true
		}
		switch {
		case prev.at < r.upAt-200*time.Millisecond:
		case healthy && at == 0:
			at = s.at
		case !healthy:
			at = 0
		}
		prev = s
	}
	switch {
	case !lost:
		return "never lost"
	case at == 0:
		return "not within the arm"
	}
	return fmt.Sprintf("within %s", (at - r.upAt).Round(time.Second))
}
