package main

import (
	"slices"
	"testing"
	"time"

	"elodin.bench/internal/dnsperf"
)

func TestCPUCount(t *testing.T) {
	for list, want := range map[string]int{"2-3": 2, "0": 1, "0,2,4-5": 4, "1-1": 1, "3-2": 1, "x": 1} {
		if got := cpuCount(list); got != want {
			t.Errorf("cpuCount(%q) = %d, want %d", list, got, want)
		}
	}
}

// Only one name over UDP, TCP or DoT goes to dnsperf; everything it cannot
// drive stays with loadgen.
func TestDnsperfDrives(t *testing.T) {
	for _, c := range []struct {
		o    loadOpts
		want bool
	}{
		{loadOpts{transport: "udp", qmode: "fixed", concurrency: 1}, true},
		{loadOpts{transport: "dot", qmode: "fixed", concurrency: 1}, true},
		{loadOpts{transport: "udp", qmode: "unique", concurrency: 1}, false},
		{loadOpts{transport: "doh2", qmode: "fixed", concurrency: 1}, false},
		{loadOpts{transport: "handshake", qmode: "fixed", concurrency: 1}, false},
		{loadOpts{transport: "tcp", qmode: "fixed", concurrency: 8}, false},
	} {
		if got := dnsperfDrives(c.o); got != c.want {
			t.Errorf("dnsperfDrives(%+v) = %v", c.o, got)
		}
	}
}

// dnsperf quietly runs fewer clients than asked when one thread would hold more
// than 256, so a 500-client row pinned to one CPU needs two threads.
func TestDnsperfArgsThreads(t *testing.T) {
	for _, c := range []struct {
		clients int
		cpus    string
		want    string
	}{{500, "0", "2"}, {100, "2-3", "2"}, {1, "2-3", "1"}, {513, "0", "3"}} {
		a := dnsperfArgs(loadOpts{transport: "tcp", clients: c.clients, cpus: c.cpus}, "127.0.0.1", "53", "d", time.Second)
		if got := a[slices.Index(a, "-T")+1]; got != c.want {
			t.Errorf("%d clients on %q: -T %s, want %s", c.clients, c.cpus, got, c.want)
		}
	}
}

// dnsperf exits 0 having sent nothing when no connection opens: that is a
// failed run, not a row of zeros. Connections past one per client are redials.
func TestDnsperfResult(t *testing.T) {
	o := loadOpts{transport: "dot", clients: 100}
	if _, err := dnsperfResult(dnsperf.Report{Connections: 86154}, o, "127.0.0.1:853"); err == nil {
		t.Error("a run that sent nothing was a result")
	}
	r, err := dnsperfResult(dnsperf.Report{Sent: 10, Completed: 9, Lost: 1, Connections: 103}, o, "127.0.0.1:853")
	if err != nil || r.Answered != 9 || r.Errors != 1 || r.Reconnects != 3 || r.Clients != 100 {
		t.Errorf("got %+v, %v", r, err)
	}
}

// A dnsperf row has answers and no per-client counts; a loadgen row that
// answered nothing still reads as zero, not as uncounted.
func TestPerClient(t *testing.T) {
	for _, c := range []struct {
		r    Result
		want string
	}{
		{Result{Answered: 10}, "—"},
		{Result{}, "0 – 0"},
		{Result{Answered: 10, MinPerClient: 4, MaxPerClient: 6}, "4 – 6"},
	} {
		if got := perClient(c.r); got != c.want {
			t.Errorf("perClient(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}
