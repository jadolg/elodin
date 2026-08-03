// Package procstat reads resident memory and CPU time for a running process.
//
// Measuring the server process alone matters: the load generator and the mock
// upstream share this machine, so anything taken from the whole system would be
// mostly them.
package procstat

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ClockTicks is the kernel's USER_HZ. It is 100 on every Linux port Go builds
// for; reading it properly needs cgo and sysconf(_SC_CLK_TCK).
const ClockTicks = 100

// RSSBytes reports the process's resident set size.
func RSSBytes(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("cannot parse %q", line)
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("no VmRSS for pid %d", pid)
}

// CPUTime reports user+system time consumed by the process so far.
func CPUTime(pid int) (time.Duration, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The second field is the executable name in parentheses and may itself
	// contain spaces, so fields are counted from the closing one.
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return 0, fmt.Errorf("cannot parse /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data)[end+1:])
	// After the state field, utime and stime are fields 14 and 15 of the whole
	// line, which are indices 11 and 12 here.
	if len(fields) < 13 {
		return 0, fmt.Errorf("cannot parse /proc/%d/stat", pid)
	}
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	ticks := utime + stime
	return time.Duration(ticks) * time.Second / ClockTicks, nil
}

// ThreadCount reports how many threads the process has.
func ThreadCount(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "Threads:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("cannot parse %q", line)
		}
		return strconv.Atoi(fields[1])
	}
	return 0, fmt.Errorf("no Threads for pid %d", pid)
}

// Sampler watches a process for the length of a run, keeping the peak RSS and
// the CPU time consumed between Start and Stop.
type Sampler struct {
	pid        int
	stop       chan struct{}
	done       chan struct{}
	PeakRSS    int64
	CPUStart   time.Duration
	CPUEnd     time.Duration
	MaxThreads int
}

func NewSampler(pid int) *Sampler {
	return &Sampler{pid: pid, stop: make(chan struct{}), done: make(chan struct{})}
}

func (s *Sampler) Start() {
	s.CPUStart, _ = CPUTime(s.pid)
	go func() {
		defer close(s.done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				if rss, err := RSSBytes(s.pid); err == nil && rss > s.PeakRSS {
					s.PeakRSS = rss
				}
				if n, err := ThreadCount(s.pid); err == nil && n > s.MaxThreads {
					s.MaxThreads = n
				}
			}
		}
	}()
}

func (s *Sampler) Stop() {
	close(s.stop)
	<-s.done
	s.CPUEnd, _ = CPUTime(s.pid)
}

// CPUUsed is the process time consumed over the sampled window.
func (s *Sampler) CPUUsed() time.Duration { return s.CPUEnd - s.CPUStart }
