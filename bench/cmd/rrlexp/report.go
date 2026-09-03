package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// -------------------------------------------------------------- the reporting

func renderReport(rows []row, skips []skip) string {
	var b strings.Builder
	b.WriteString("# Response rate limiting: what a bystander gets\n\n")
	if *soak > 0 {
		fmt.Fprintf(&b, "A soak run: the soak arm alone, %s of load after %s of the same, with the server read every %s.\n",
			*soak, *warmup, *soakSample)
	} else {
		fmt.Fprintf(&b, "Each arm: one server, two clients at once, %s measured after %s of the same load.\n",
			*duration, *warmup)
	}
	fmt.Fprintf(&b, "The victim offers %d q/s; the flood offers %d q/s (0 = flat out). Limit: %d responses/s per client prefix - a /24, or a /64 in the IPv6 arms - slip %d.\n",
		*victimRate, *floodRate, *rps, *slip)
	fmt.Fprintf(&b, "Every name is asked once, so every query is a cache miss and a %s upstream round trip.\n", *upDelay)
	fmt.Fprintf(&b, "server.workers %d, upstream_workers %d, and the shipped default for everything an arm does not name.\n\n", *workers, *workers/2)

	victimTable(&b, rows)
	floodTable(&b, rows)
	dohTable(&b, rows)
	connTable(&b, rows)
	handshakeTable(&b, rows)
	soakTable(&b, rows)
	serverTable(&b, rows)

	b.WriteString("\n## What each arm was asking\n\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "- **%s** — %s\n", r.arm.name, r.arm.question)
	}
	skipList(&b, skips)
	return b.String()
}

// skipList names the arms this machine could not run, so a missing section is
// an answer the run did not have rather than a question it never asked.
func skipList(b *strings.Builder, skips []skip) {
	if len(skips) == 0 {
		return
	}
	b.WriteString("\n## Arms this run could not take\n\n")
	for _, s := range skips {
		fmt.Fprintf(b, "- **%s** — %s\n", s.name, s.why)
	}
}

func victimTable(b *strings.Builder, rows []row) {
	b.WriteString("## The victim\n\n")
	b.WriteString("| arm | victim | via | offered | answered | truncated | no reply | p50 | p99 | rcodes seen |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---:|---:|---:|---|\n")
	for _, r := range rows {
		v := r.victim
		offered := v.offered.Load()
		noReply := max(offered-v.replies.Load(), 0)
		pct := 0.0
		if offered > 0 {
			pct = 100 * float64(v.full.Load()) / float64(offered)
		}
		closed := ""
		if v.closed.Load() > 0 {
			closed = fmt.Sprintf(" (connection closed %dx)", v.closed.Load())
		}
		fmt.Fprintf(b, "| %s | %s | %s%s | %d | %d (%.0f%%) | %d | %d | %s | %s | %s |\n",
			r.arm.name, r.arm.victim.src, r.arm.victim.transport, closed, offered,
			v.full.Load(), pct, v.truncated.Load(), noReply,
			round(v.pct(0.5)), round(v.pct(0.99)), outcomes(r.arm.victim, v))
	}
}

/*
outcomes is what came back, in the terms the transport answers in.

A rate-limited datagram is a missing reply and a rate-limited DoH request is a
429, so a single column cannot be read as one thing across the arms: it names the
statuses where those are the answer and the rcodes where they are.
*/
func outcomes(c clientSpec, st *stats) string {
	if isDoH(c) {
		return st.statusSummary()
	}
	return st.rcodeSummary()
}

func isDoH(c clientSpec) bool {
	return c.transport == "doh1" || c.transport == "doh2"
}

/*
dohTable is the arms where a refusal has a shape the other tables cannot show.

`429/s` is the limiter refusing a request that the connection then survives -
what DoH/2 does - and `no status/s` is a request whose connection went away
instead, which is what DoH/1.1 and the stream transports do. `connections` is how
many the client had to open: one for a flood that is refused and stays, and one
per refusal for a flood that is cut off.

`CPU per refused request` is why the two matter. A datagram over the budget costs
a hash and a drop; an h2 request over it costs the frames, the HPACK and a
response, and the connection staying open is what lets the client keep asking at
that price.

The CPU column is the whole arm's, so it includes the 500 answers a second the
budget does allow - about 0.1 of a core, going by the arms where that is all the
server is doing. It is worth subtracting before reading the per-refusal figure as
the price of a refusal, and worth not bothering when the figures either side of it
differ by more than an order of magnitude.
*/
func dohTable(b *strings.Builder, rows []row) {
	if !hasDoH(rows) {
		return
	}

	b.WriteString("\n## The DoH arms: what a refusal looks like, and what it costs\n\n")
	b.WriteString("| arm | client | via | offered/s | answered/s | 429/s | no status/s | connections | CPU | CPU per refused request |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		dohRow(b, r, "flood", specOf(r.arm.attacker), r.attacker)
		dohRow(b, r, "victim", r.arm.victim, r.victim)
	}
}

func hasDoH(rows []row) bool {
	for _, r := range rows {
		if isDoH(r.arm.victim) {
			return true
		}
		if a := r.arm.attacker; a != nil && isDoH(*a) && !a.handshake {
			return true
		}
	}
	return false
}

func dohRow(b *strings.Builder, r row, what string, c clientSpec, st *stats) {
	// A handshake flood offers a TLS handshake and no request, so it has no
	// status, no answer and no connection it kept: `handshakeTable` is where a
	// flood against the DoH port on those terms is read.
	if st == nil || !isDoH(c) || c.handshake {
		return
	}
	secs := r.elapsed.Seconds()
	refusedPerSec := float64(st.refused.Load()) / secs
	perRefusal := "—"
	if refusedPerSec > 0 {
		perRefusal = fmt.Sprintf("%.1f µs", r.cpu.Seconds()/secs/refusedPerSec*1e6)
	}
	fmt.Fprintf(b, "| %s | %s | %s | %.0f | %.0f | %.0f | %.0f | %d | %.2f | %s |\n",
		r.arm.name, what, c.transport,
		float64(st.offered.Load())/secs,
		float64(st.full.Load())/secs,
		refusedPerSec,
		float64(st.failed.Load())/secs,
		st.dials.Load(), r.cpu.Seconds()/secs, perRefusal)
}

// specOf is the zero spec for an arm with no flood, so one loop can walk both
// sides of every arm.
func specOf(c *clientSpec) clientSpec {
	if c == nil {
		return clientSpec{}
	}
	return *c
}

func floodTable(b *strings.Builder, rows []row) {
	b.WriteString("\n## The flood: what it drew, and what the address it named received\n\n")
	b.WriteString("| arm | limiter | flood | via | offered/s | answered/s | truncated/s | bytes/s at the source | amplification |\n")
	b.WriteString("|---|---|---|---|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		// Handshake floods send no queries at all, so every column here would
		// be a zero standing where a rate belongs. `handshakeTable` is theirs.
		if r.attacker == nil || r.arm.attacker.handshake {
			continue
		}
		secs := r.elapsed.Seconds()
		a := r.attacker
		/*
			Left out over DoH, where it would be two kinds of wrong: a handshake
			settled that the client is where it says it is, so there is no third
			party for an answer to be aimed at and nothing to amplify - and these
			byte counters are DNS payloads, which over DoH ignore the TLS records
			and HTTP framing the transport wraps them in.
		*/
		amp := "n/a"
		if out := a.bytesOut.Load(); out > 0 && !isDoH(*r.arm.attacker) {
			amp = fmt.Sprintf("x%.1f", float64(a.bytesIn.Load())/float64(out))
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %.0f | %.0f | %.0f | %.2f MB | %s |\n",
			r.arm.name, onOff(r.arm.limiter), r.arm.attacker.src, r.arm.attacker.transport,
			float64(a.offered.Load())/secs, float64(a.full.Load())/secs,
			float64(a.truncated.Load())/secs,
			float64(a.bytesIn.Load())/secs/1e6, amp)
	}
}

/*
connTable is the arms where what a client takes is the connection table itself.

`held` is what the holder is occupying and `refused` is what the server turned
away, both counted from the holder's side: a connection it opened and was not
closed on is one of the server's slots gone until the client gives it back. The
victim column beside them is the point of the pair - the same load, a share
away from locking a client in another /24 out of a resolver whose datagram
service is still answering.

`conn_refused` is the server's own count, and it is the larger of the two on
purpose: it counts every connection this server had no room for, which is the
holder's refusals plus the victim's plus the warm-up's. Read it as the total
turned away in the arm rather than as a check on `refused` beside it.
*/
func connTable(b *strings.Builder, rows []row) {
	if !hasIdle(rows) {
		return
	}

	b.WriteString("\n## The connection table: who is holding it\n\n")
	b.WriteString("| arm | table | share | opened | held | refused | conn_refused | victim answered | victim p50 |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		if r.arm.attacker == nil || !r.arm.attacker.idle {
			continue
		}
		a := r.attacker
		opened, refused := a.dials.Load(), a.closed.Load()
		v := r.victim
		answered := 0.0
		if offered := v.offered.Load(); offered > 0 {
			answered = 100 * float64(v.full.Load()) / float64(offered)
		}
		share := "none"
		if r.arm.perPrefix > 0 && r.arm.perPrefix < r.arm.maxConns {
			share = fmt.Sprintf("%d", r.arm.perPrefix)
		}
		fmt.Fprintf(b, "| %s | %d | %s | %d | %d | %d | %d | %.0f%% (%d/%d) | %s |\n",
			r.arm.name, r.arm.maxConns, share, opened, opened-refused, refused,
			r.srv["elodin_connections_refused_total"],
			answered, v.full.Load(), v.offered.Load(), round(v.pct(0.5)))
	}
}

func hasIdle(rows []row) bool {
	for _, r := range rows {
		if r.arm.attacker != nil && r.arm.attacker.idle {
			return true
		}
	}
	return false
}

/*
handshakeTable is the arms where the flood never asks a question.

`attempted` against `completed` is what the server let through: a handshake the
client began and the server had no thread for arrives as a connection that went
away, counted here as `refused` - the connection slot is taken before the
handshake starts, so a full table is a failed handshake rather than a refused
query. `dial failed` is the listen backlog overflowing, which is the harness
running out rather than the server deciding anything, and is worth watching only
because it caps what the arm can offer.

`CPU per handshake` is the price the flood is paying for, and the reason these
arms exist: it is asymmetric key work, it is charged to no budget, and the whole
of what bounds it is how many the server will do at once. The victim columns
beside it are what that cost buys the attacker.

`conn_refused` is the server's own count of connections it had no room for, next
to the flood's own view of the same thing. It is the larger of the two: it counts
the victim's refusals and the warm-up's as well. Read it as the total turned away
in the arm rather than as a check on the column beside it.

`table` and `share` are written where the arm pinned them. Most of these arms do
not: a handshake flood holds nothing for long, so the shipped share is not what
stands between it and the server, and the pair at the end is what says so.
*/
func handshakeTable(b *strings.Builder, rows []row) {
	if !hasHandshakeFlood(rows) {
		return
	}
	b.WriteString("\n## The handshake floods: a client that only connects\n\n")
	b.WriteString("| arm | flood via | table | share | attempted/s | completed/s | refused/s | dial failed/s | conn_refused | handshake p50 | CPU/s | CPU per handshake | victim answered | victim p50 |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		if r.attacker == nil || !r.arm.attacker.handshake {
			continue
		}
		handshakeRow(b, r)
	}
}

func handshakeRow(b *strings.Builder, r row) {
	secs := r.elapsed.Seconds()
	a := r.attacker
	done := float64(a.full.Load()) / secs
	perHandshake := "—"
	if done > 0 {
		perHandshake = fmt.Sprintf("%.0f µs", r.cpu.Seconds()/secs/done*1e6)
	}
	v := r.victim
	answered := "—"
	if offered := v.offered.Load(); offered > 0 {
		answered = fmt.Sprintf("%.0f%% (%d/%d)", 100*float64(v.full.Load())/float64(offered), v.full.Load(), offered)
	}
	fmt.Fprintf(b, "| %s | %s | %s | %s | %.0f | %.0f | %.0f | %.0f | %d | %s | %.2f | %s | %s | %s |\n",
		r.arm.name, r.arm.attacker.transport,
		figure(r.arm.maxConns), figure(r.arm.perPrefix),
		float64(a.offered.Load())/secs, done,
		float64(a.closed.Load())/secs, float64(a.failed.Load())/secs,
		r.srv["elodin_connections_refused_total"],
		round(a.pct(0.5)), r.cpu.Seconds()/secs, perHandshake,
		answered, round(v.pct(0.5)))
}

// figure is a setting the arm pinned, or a dash where it left the shipped
// default in place - which is not the same thing as a zero.
func figure(n int) string {
	if n <= 0 {
		return "shipped"
	}
	return fmt.Sprintf("%d", n)
}

func hasHandshakeFlood(rows []row) bool {
	for _, r := range rows {
		if r.arm.attacker != nil && r.arm.attacker.handshake {
			return true
		}
	}
	return false
}

func serverTable(b *strings.Builder, rows []row) {
	b.WriteString("\n## What the server spent, and what it says it did\n\n")
	b.WriteString("| arm | CPU/s | peak RSS | queries | limited | slipped | shed | forwarded |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		c := r.srv
		fmt.Fprintf(b, "| %s | %.2f | %d MB | %d | %d | %d | %d | %d |\n",
			r.arm.name, r.cpu.Seconds()/r.elapsed.Seconds(), r.peakRSS/(1<<20),
			c["elodin_queries_total"], c["elodin_rate_limited_total"], c["elodin_rate_limit_slipped_total"],
			c["elodin_queries_dropped_total"], c[`elodin_answers_total{outcome="forwarded"}`])
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "rrlexp: %v\n", err)
	os.Exit(1)
}
