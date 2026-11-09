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

// required is every line of the totals a report must carry.
var required = []string{"Queries sent", "Queries completed", "Queries lost", "Run time (s)", "Queries per second", "Response codes"}

// Parse reads dnsperf's output. The first block, under "Statistics:", is the
// queries; a second, under "Connection Statistics:" (TCP and DoT only), is
// the handshakes and has a histogram of its own, which is not query latency.
// Output missing a figure the harness reports is refused rather than read as
// zero, so a dnsperf that printed something else cannot pass as a result.
func Parse(out string) (Report, error) {
	queries, conns, _ := strings.Cut(out, "Connection Statistics:")
	r := Report{Rcodes: map[string]int64{}}
	var err error
	if r.Connections, err = connectionAttempts(conns); err != nil {
		return Report{}, err
	}
	var buckets []bucket
	inHist := false
	seen := map[string]bool{}
	for line := range strings.SplitSeq(queries, "\n") {
		line = strings.TrimSpace(line)
		key, val, hasColon := strings.Cut(line, ":")
		val = strings.TrimSpace(val)
		switch {
		case key == "Latency bucket (s)":
			inHist = true
		case inHist && hasColon && strings.Contains(key, " - "):
			var b bucket
			b, err = parseBucket(key, val)
			buckets = append(buckets, b)
		default:
			inHist = false
			seen[key], err = r.total(key, val)
		}
		if err != nil {
			return Report{}, fmt.Errorf("%q: %w", line, err)
		}
	}
	if err := r.finish(seen, buckets); err != nil {
		return Report{}, err
	}
	return r, nil
}

// connectionAttempts reads the count from the connection block, which UDP
// runs do not print.
func connectionAttempts(conns string) (int64, error) {
	for line := range strings.SplitSeq(conns, "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), ":")
		if key == "Connection attempts" {
			n, err := firstInt(strings.TrimSpace(val))
			if err != nil {
				return 0, fmt.Errorf("connection attempts %q: %w", val, err)
			}
			return n, nil
		}
	}
	return 0, nil
}

// parseBucket reads "0.000046 - 0.000047:  12" as its upper edge and count.
func parseBucket(key, val string) (bucket, error) {
	_, hi, _ := strings.Cut(key, " - ")
	secs, err := strconv.ParseFloat(strings.TrimSpace(hi), 64)
	if err != nil {
		return bucket{}, err
	}
	n, err := strconv.ParseInt(val, 10, 64)
	// Rounded: 0.000065 s times 1e9 is 64999.99... ns.
	return bucket{time.Duration(math.Round(secs * float64(time.Second))), n}, err
}

// total reads one line of the totals into r, and says whether it was one.
func (r *Report) total(key, val string) (bool, error) {
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
		return false, nil
	}
	return true, err
}

// finish refuses a report missing a total or whose histogram does not hold
// every answer, and takes the percentiles from the histogram.
func (r *Report) finish(seen map[string]bool, buckets []bucket) error {
	for _, k := range required {
		if !seen[k] {
			return fmt.Errorf("dnsperf printed no %q", k)
		}
	}
	var total int64
	for _, b := range buckets {
		total += b.n
	}
	if total != r.Completed {
		return fmt.Errorf("latency histogram holds %d answers, dnsperf completed %d (is it run with -O latency-histogram?)", total, r.Completed)
	}
	r.P50, r.P99 = quantile(buckets, total, 0.50), quantile(buckets, total, 0.99)
	return nil
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
