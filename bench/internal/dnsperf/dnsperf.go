// Package dnsperf reads the report DNS-OARC's dnsperf prints when it is run
// with -O latency-histogram, so the harness can drive UDP, TCP and DoT rows
// with a generator that is not written in Go (see bench/README.md for why).
package dnsperf

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Report is what one dnsperf run measured.
type Report struct {
	Sent, Completed, Lost int64
	// Rcodes is keyed by the lower-cased name dnsperf prints (noerror,
	// nxdomain, ...), the names loadgen uses for the ones it knows.
	Rcodes  map[string]int64
	Seconds float64
	QPS     float64
	P50     time.Duration
	P99     time.Duration
	// Connections is how many connections were opened, 0 over UDP. More than
	// one per client means a client lost its connection and dialled again.
	Connections int64
}

type bucket struct {
	hi time.Duration
	n  int64
}

// Parse reads dnsperf's output. The first block, under "Statistics:", is the
// queries; a second, under "Connection Statistics:" (TCP and DoT only), is
// the handshakes and has a histogram of its own, which is not query latency.
// Output missing a figure the harness reports is refused rather than read as
// zero, so a dnsperf that printed something else cannot pass as a result.
func Parse(out string) (Report, error) {
	r := Report{Rcodes: map[string]int64{}}
	var buckets []bucket
	inConn, inHist := false, false
	seen := map[string]bool{}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		key, val, hasColon := strings.Cut(line, ":")
		val = strings.TrimSpace(val)
		switch {
		case line == "Connection Statistics:":
			inConn, inHist = true, false
		case inConn:
			if key == "Connection attempts" {
				n, err := firstInt(val)
				if err != nil {
					return Report{}, fmt.Errorf("connection attempts %q: %w", val, err)
				}
				r.Connections = n
			}
		case strings.HasPrefix(line, "Latency bucket (s):"):
			inHist = true
		case inHist && hasColon && strings.Contains(key, " - "):
			_, hi, _ := strings.Cut(key, " - ")
			secs, err := strconv.ParseFloat(strings.TrimSpace(hi), 64)
			if err != nil {
				return Report{}, fmt.Errorf("latency bucket %q: %w", line, err)
			}
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return Report{}, fmt.Errorf("latency bucket %q: %w", line, err)
			}
			// Rounded: 0.000065 s times 1e9 is 64999.99... ns.
			buckets = append(buckets, bucket{time.Duration(math.Round(secs * float64(time.Second))), n})
		default:
			inHist = false
			var err error
			switch key {
			case "Queries sent":
				r.Sent, err = firstInt(val)
			case "Queries completed":
				r.Completed, err = firstInt(val)
			case "Queries lost":
				r.Lost, err = firstInt(val)
			case "Run time (s)":
				r.Seconds, err = strconv.ParseFloat(val, 64)
			case "Queries per second":
				r.QPS, err = strconv.ParseFloat(val, 64)
			case "Response codes":
				err = parseRcodes(val, r.Rcodes)
			default:
				continue
			}
			if err != nil {
				return Report{}, fmt.Errorf("%s %q: %w", key, val, err)
			}
			seen[key] = true
		}
	}
	for _, k := range []string{"Queries sent", "Queries completed", "Queries lost", "Run time (s)", "Queries per second", "Response codes"} {
		if !seen[k] {
			return Report{}, fmt.Errorf("dnsperf printed no %q", k)
		}
	}
	var total int64
	for _, b := range buckets {
		total += b.n
	}
	if total != r.Completed {
		return Report{}, fmt.Errorf("latency histogram holds %d answers, dnsperf completed %d (is it run with -O latency-histogram?)", total, r.Completed)
	}
	r.P50, r.P99 = quantile(buckets, total, 0.50), quantile(buckets, total, 0.99)
	return r, nil
}

// quantile is the upper edge of the bucket holding the sample at q, the same
// rank internal/hist takes from its sorted samples. dnsperf's buckets are a
// microsecond wide below 64 µs and double at each power of two above it (16 µs
// between 0.5 and 1 ms), so the edge reads at most about 3% high.
func quantile(buckets []bucket, total int64, q float64) time.Duration {
	if total == 0 {
		return 0
	}
	idx := min(int64(q*float64(total)), total-1)
	var seen int64
	for _, b := range buckets {
		seen += b.n
		if seen > idx {
			return b.hi
		}
	}
	return buckets[len(buckets)-1].hi
}

// parseRcodes reads "NOERROR 1000 (50.00%), NXDOMAIN 1000 (50.00%)", which is
// empty when nothing was answered.
func parseRcodes(val string, into map[string]int64) error {
	if val == "" {
		return nil
	}
	for part := range strings.SplitSeq(val, ",") {
		f := strings.Fields(part)
		if len(f) < 2 {
			return fmt.Errorf("rcode %q", part)
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return err
		}
		into[strings.ToLower(f[0])] += n
	}
	return nil
}

// firstInt reads the count that leads "335937 (100.00%)".
func firstInt(val string) (int64, error) {
	f := strings.Fields(val)
	if len(f) == 0 {
		return 0, fmt.Errorf("no count")
	}
	return strconv.ParseInt(f[0], 10, 64)
}
