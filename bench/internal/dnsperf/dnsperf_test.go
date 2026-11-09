package dnsperf

import (
	"os"
	"reflect"
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
		file string
		want Report
	}{
		// The connection block's own histogram (handshakes, 16-52 ms) must not
		// reach the query percentiles.
		{"dot.txt", Report{Sent: 335937, Completed: 335937, Rcodes: map[string]int64{"noerror": 335937},
			Seconds: 1.000115, QPS: 335898.371687, P50: 123 * us, P99: 783 * us, Connections: 100}},
		{"udp-mixed.txt", Report{Sent: 2000, Completed: 2000, Rcodes: map[string]int64{"noerror": 1000, "nxdomain": 1000},
			Seconds: 1.000036, QPS: 1999.928003, P50: 55 * us, P99: 97 * us}},
		// num-queries-per-conn=100 over 4 clients: every client dialled again.
		{"tcp-reconnect.txt", Report{Sent: 1604, Completed: 1604, Rcodes: map[string]int64{"noerror": 1604},
			Seconds: 1.033124, QPS: 1552.572586, P50: 97 * us, P99: 47103 * us, Connections: 20}},
		// Nothing answered: no histogram, no rcodes, every query lost.
		{"udp-lost.txt", Report{Sent: 8, Lost: 8, Rcodes: map[string]int64{}, Seconds: 1.008171}},
	}
	for _, c := range cases {
		if r, err := Parse(load(t, c.file)); err != nil || !reflect.DeepEqual(r, c.want) {
			t.Errorf("%s: got %+v, %v\nwant %+v", c.file, r, err, c.want)
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
