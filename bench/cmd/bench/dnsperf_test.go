package main

import "testing"

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
