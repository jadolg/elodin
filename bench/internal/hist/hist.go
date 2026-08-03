// Package hist collects per-query latencies and reports percentiles.
package hist

import (
	"slices"
	"sync"
	"time"
)

// Recorder keeps every sample rather than bucketing them. A sixty-second run at
// 200k qps is 12 million int64s — about 96 MB, which is affordable here and
// avoids the bucket-width error that would otherwise show up in p99.
type Recorder struct {
	mu      sync.Mutex
	samples []time.Duration
}

func New(expected int) *Recorder {
	return &Recorder{samples: make([]time.Duration, 0, expected)}
}

// AddBatch appends one client's samples in a single lock acquisition. Locking
// per sample would put the generator's own contention into the measurement.
func (r *Recorder) AddBatch(s []time.Duration) {
	r.mu.Lock()
	r.samples = append(r.samples, s...)
	r.mu.Unlock()
}

func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.samples)
}

// Percentiles returns the requested quantiles, sorting in place.
func (r *Recorder) Percentiles(qs ...float64) []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]time.Duration, len(qs))
	if len(r.samples) == 0 {
		return out
	}
	slices.Sort(r.samples)
	for i, q := range qs {
		idx := int(q * float64(len(r.samples)))
		if idx >= len(r.samples) {
			idx = len(r.samples) - 1
		}
		out[i] = r.samples[idx]
	}
	return out
}
