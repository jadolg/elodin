package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"elodin.bench/internal/dnsperf"
	"elodin.bench/internal/procstat"
)

// dnsperfDrives says whether a scenario runs under dnsperf rather than
// loadgen: one name asked over and over, over UDP, TCP or DoT. Go's scheduler
// puts a tail of its own into loadgen's latency there (#610), the size of the
// one being measured. loadgen keeps DoH, because dnsperf speaks only HTTP/2
// and the DoH rows set HTTP/1.1 beside it on the same generator, and unique
// names, because dnsperf's data file would have to hold every name a run asks.
func dnsperfDrives(o loadOpts) bool {
	return o.qmode == "fixed" && o.concurrency == 1 &&
		(o.transport == "udp" || o.transport == "tcp" || o.transport == "dot")
}

// dnsperfOnce runs a scenario as two dnsperf runs, the warmup and then the
// measured one, with the server sampled over the second alone. Each opens its
// connections afresh: a hundred handshakes in a ten-second run.
func (h *harness) dnsperfOnce(s *server, o loadOpts) (Result, sample, error) {
	host, port, err := net.SplitHostPort(s.addrFor(o.transport))
	if err != nil {
		return Result{}, sample{}, err
	}
	data := filepath.Join(h.dir, "dnsperf-"+o.qname+".txt")
	if err := os.WriteFile(data, []byte(o.qname+" A\n"), 0o644); err != nil {
		return Result{}, sample{}, err
	}
	args := func(d time.Duration) []string { return dnsperfArgs(o, host, port, data, d) }
	if *warmup > 0 {
		if _, err := runDnsperf(o.cpus, args(*warmup)); err != nil {
			return Result{}, sample{}, err
		}
	}
	sampler := procstat.NewSampler(s.pid)
	sampler.Start()
	out, err := runDnsperf(o.cpus, args(o.duration))
	sampler.Stop()
	if err != nil {
		return Result{}, sample{}, err
	}
	rep, err := dnsperf.Parse(out)
	if err != nil {
		return Result{}, sample{}, fmt.Errorf("parsing dnsperf output: %w", err)
	}
	r := Result{
		Transport:   o.transport,
		Clients:     o.clients,
		Concurrency: 1,
		Answered:    rep.Completed,
		Errors:      rep.Lost,
		Rcodes:      rep.Rcodes,
		Seconds:     rep.Seconds,
		QPS:         rep.QPS,
		P50ms:       float64(rep.P50) / float64(time.Millisecond),
		P99ms:       float64(rep.P99) / float64(time.Millisecond),
		// dnsperf counts queries per run, not per client: MinPerClient and
		// MaxPerClient stay 0, which the tables print as "—".
	}
	if rep.Connections > int64(o.clients) {
		r.Reconnects = rep.Connections - int64(o.clients)
	}
	return r, sample{PeakRSS: sampler.PeakRSS, CPU: sampler.CPUUsed(), MaxThreads: sampler.MaxThreads}, nil
}

// dnsperfArgs is one dnsperf run of the scenario, d long.
func dnsperfArgs(o loadOpts, host, port, data string, d time.Duration) []string {
	// loadgen's own limits: a UDP query is lost after 5 s, a stream one after 10.
	timeout := "10"
	if o.transport == "udp" {
		timeout = "5"
	}
	a := []string{
		"-m", o.transport, "-s", host, "-p", port, "-d", data,
		// As many queries outstanding as clients: one each, as loadgen keeps.
		"-c", strconv.Itoa(o.clients), "-q", strconv.Itoa(o.clients),
		// A thread per generator CPU, so the generator is not the limit.
		"-T", strconv.Itoa(min(cpuCount(o.cpus), o.clients)),
		"-t", timeout,
		"-l", strconv.FormatFloat(d.Seconds(), 'f', -1, 64),
		"-O", "latency-histogram",
	}
	if o.rate > 0 {
		a = append(a, "-Q", strconv.Itoa(o.rate))
	}
	return a
}

func runDnsperf(cpus string, args []string) (string, error) {
	cmd := exec.Command("dnsperf", args...)
	if cpus != "" {
		cmd = exec.Command("taskset", append([]string{"-c", cpus, "dnsperf"}, args...)...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("dnsperf %s: %w: %s", strings.Join(args, " "), err, lastLine(string(out)))
	}
	return string(out), nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	return s[strings.LastIndexByte(s, '\n')+1:]
}

// cpuCount is how many CPUs a taskset -c list names ("2-3", "0,2,4-5"), or
// every CPU when there is no list.
func cpuCount(list string) int {
	if list == "" {
		return runtime.NumCPU()
	}
	n := 0
	for part := range strings.SplitSeq(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, errA := strconv.Atoi(lo)
		b, errB := strconv.Atoi(hi)
		switch {
		case isRange && errA == nil && errB == nil && b >= a:
			n += b - a + 1
		default:
			n++
		}
	}
	return max(n, 1)
}
