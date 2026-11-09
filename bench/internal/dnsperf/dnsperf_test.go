package dnsperf

import (
	"os"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The fixtures are dnsperf 2.15.0's own output. The expected percentiles were
// worked out from each file's answer histogram with awk, not with this code.
func TestParse(t *testing.T) {
	us := time.Microsecond
	cases := []struct {
		file                  string
		sent, completed, lost int64
		qps                   float64
		p50, p99              time.Duration
		conns                 int64
		rcodes                map[string]int64
	}{
		// The connection block's own histogram (handshakes, 16-52 ms) must not
		// reach the query percentiles.
		{"dot.txt", 335937, 335937, 0, 335898.371687, 123 * us, 783 * us, 100, map[string]int64{"noerror": 335937}},
		{"udp-mixed.txt", 2000, 2000, 0, 1999.928003, 55 * us, 97 * us, 0, map[string]int64{"noerror": 1000, "nxdomain": 1000}},
		// num-queries-per-conn=100 over 4 clients: every client dialled again.
		{"tcp-reconnect.txt", 1604, 1604, 0, 1552.572586, 97 * us, 47103 * us, 20, map[string]int64{"noerror": 1604}},
		// Nothing answered: no histogram, no rcodes, every query lost.
		{"udp-lost.txt", 8, 0, 8, 0, 0, 0, 0, map[string]int64{}},
	}
	for _, c := range cases {
		r, err := Parse(load(t, c.file))
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if r.Sent != c.sent || r.Completed != c.completed || r.Lost != c.lost || r.QPS != c.qps ||
			r.P50 != c.p50 || r.P99 != c.p99 || r.Connections != c.conns || r.Seconds == 0 {
			t.Errorf("%s: got %+v", c.file, r)
		}
		if len(r.Rcodes) != len(c.rcodes) {
			t.Errorf("%s: rcodes %v, want %v", c.file, r.Rcodes, c.rcodes)
		}
		for k, v := range c.rcodes {
			if r.Rcodes[k] != v {
				t.Errorf("%s: rcodes %v, want %v", c.file, r.Rcodes, c.rcodes)
			}
		}
	}
}

// A run without -O latency-histogram has no percentiles to give, and a report
// cut short has no totals; both are refused rather than read as zero.
func TestParseRefusesWhatItCannotRead(t *testing.T) {
	dot := load(t, "dot.txt")
	noHist, _, _ := strings.Cut(dot, "  Latency bucket (s):")
	cases := map[string]string{
		"no histogram":  noHist,
		"no run time":   strings.Replace(dot, "Run time (s)", "Run tame (s)", 1),
		"bad count":     strings.Replace(dot, "Queries lost:         0", "Queries lost:         x", 1),
		"bad rcodes":    strings.Replace(dot, "NOERROR 335937 (100.00%)", "NOERROR", 1),
		"empty output":  "",
		"short buckets": strings.Replace(dot, "0.000007 - 0.000007:  6\n", "", 1),
	}
	for name, out := range cases {
		if _, err := Parse(out); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// 0.000065 s times 1e9 is 64999.99... ns in floating point; the edge is 65 µs.
func TestParseRoundsBucketEdges(t *testing.T) {
	out := `Statistics:
  Queries sent:         2
  Queries completed:    2 (100.00%)
  Queries lost:         0 (0.00%)
  Response codes:       NOERROR 2 (100.00%)
  Run time (s):         1.0
  Queries per second:   2.0
  Latency bucket (s):   answer count
  0.000065 - 0.000065:  2
`
	r, err := Parse(out)
	if err != nil || r.P50 != 65*time.Microsecond || r.P99 != 65*time.Microsecond {
		t.Fatalf("got %+v, %v", r, err)
	}
}
