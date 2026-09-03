package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// -------------------------------------------------------------- the reporting

func renderReport(rows []row) string {
	var b strings.Builder
	b.WriteString("# Response rate limiting: what a bystander gets\n\n")
	fmt.Fprintf(&b, "Each arm: one server, two clients at once, %s measured after %s of the same load.\n",
		*duration, *warmup)
	fmt.Fprintf(&b, "The victim offers %d q/s; the flood offers %d q/s (0 = flat out). Limit: %d responses/s per /24, slip %d.\n",
		*victimRate, *floodRate, *rps, *slip)
	fmt.Fprintf(&b, "Every name is asked once, so every query is a cache miss and a %s upstream round trip.\n", *upDelay)
	fmt.Fprintf(&b, "server.workers %d, upstream_workers %d, everything else the shipped default.\n\n", *workers, *workers/2)

	victimTable(&b, rows)
	floodTable(&b, rows)
	serverTable(&b, rows)

	b.WriteString("\n## What each arm was asking\n\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "- **%s** — %s\n", r.arm.name, r.arm.question)
	}
	return b.String()
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
			round(v.pct(0.5)), round(v.pct(0.99)), v.rcodeSummary())
	}
}

func floodTable(b *strings.Builder, rows []row) {
	b.WriteString("\n## The flood: what it drew, and what the address it named received\n\n")
	b.WriteString("| arm | limiter | flood | via | offered/s | answered/s | truncated/s | bytes/s at the source | amplification |\n")
	b.WriteString("|---|---|---|---|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		if r.attacker == nil {
			continue
		}
		secs := r.elapsed.Seconds()
		a := r.attacker
		amp := 0.0
		if out := a.bytesOut.Load(); out > 0 {
			amp = float64(a.bytesIn.Load()) / float64(out)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %.0f | %.0f | %.0f | %.2f MB | x%.1f |\n",
			r.arm.name, onOff(r.arm.limiter), r.arm.attacker.src, r.arm.attacker.transport,
			float64(a.offered.Load())/secs, float64(a.full.Load())/secs,
			float64(a.truncated.Load())/secs,
			float64(a.bytesIn.Load())/secs/1e6, amp)
	}
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
