package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"elodin.bench/internal/dnswire"
	"elodin.bench/internal/procstat"
)

// serverOpts is everything a scenario is allowed to vary. Anything not named
// here is left at the shipped default, so the numbers describe the defaults.
type serverOpts struct {
	name string

	workers         int
	upstreamWorkers int
	maxConnections  int
	maxPending      int

	cache        bool
	cacheEntries int

	blockRules int    // synthesised rules in a local list; 0 means no blocking
	certKind   string // ecdsa or rsa
	logQueries bool
	// Query lines are emitted at info, so a run measuring what they cost has to
	// raise the level or the lines are filtered before they reach the disk.
	logLevel string

	// noUpstream points the resolver at a dead address, for the rows that must
	// never reach one.
	noUpstream bool

	// dnssec turns validation on. Only the survey does: the mock upstream serves
	// an unsigned zone with no chain to the root, so every answer would be
	// SERVFAIL and the tables would describe a failing resolver.
	dnssec bool
	// upstreamAddr replaces the mock with a real resolver, which validation
	// needs since it has to fetch DS and DNSKEY records for itself.
	upstreamAddr string
	// attempts per query. The benchmarks want 1 so a failure shows up as one
	// rather than being retried into a slower success; the survey wants the
	// default 2, because against a public resolver a single lost datagram is
	// not a verdict and three of them park the upstream for ten seconds.
	attempts int
}

type server struct {
	cmd     *exec.Cmd
	dnsAddr string
	dotAddr string
	dohAddr string
	logPath string
	pid     int
}

func (h *harness) start(o serverOpts) (*server, error) {
	if o.workers == 0 {
		o.workers = 128
	}
	if o.upstreamWorkers == 0 {
		o.upstreamWorkers = 64
	}
	if o.maxConnections == 0 {
		o.maxConnections = 512
	}
	if o.cacheEntries == 0 {
		o.cacheEntries = 10000
	}
	if o.certKind == "" {
		o.certKind = "ecdsa"
	}
	if o.logLevel == "" {
		o.logLevel = "warn"
	}
	if o.attempts == 0 {
		o.attempts = 1
	}

	dnsPort, err := freePort()
	if err != nil {
		return nil, err
	}
	dotPort, err := freePort()
	if err != nil {
		return nil, err
	}
	dohPort, err := freePort()
	if err != nil {
		return nil, err
	}

	upstream := h.mockAddr
	if o.upstreamAddr != "" {
		upstream = o.upstreamAddr
	}
	if o.noUpstream {
		// A port nothing listens on: a query that reaches an upstream fails
		// rather than quietly being served, so a row claiming not to forward
		// cannot pass by accident.
		p, err := freePort()
		if err != nil {
			return nil, err
		}
		upstream = fmt.Sprintf("127.0.0.1:%d", p)
	}
	host, portStr, _ := net.SplitHostPort(upstream)

	blockPath := filepath.Join(h.dir, o.name+"-block.txt")
	if o.blockRules > 0 {
		var sb strings.Builder
		sb.WriteString("blocked.bench.test\n")
		for i := range o.blockRules {
			fmt.Fprintf(&sb, "sink-%d.bench.invalid\n", i)
		}
		if err := os.WriteFile(blockPath, []byte(sb.String()), 0o644); err != nil {
			return nil, err
		}
	}

	cfg := fmt.Sprintf(`log:
  level: %s
  queries: %t
  file: %s

server:
  workers: %d
  upstream_workers: %d
  max_connections: %d
  # The whole table to one prefix, for the same reason the limiter is off below:
  # every client here is 127.0.0.1, so all of them are one client to a per-prefix
  # share, and the shipped default of half the table would refuse the second half
  # of the 500-connection TCP row rather than measure it. A real deployment keeps
  # the share; see bench/results/2026-09-03-connection-table-share.md.
  max_connections_per_prefix: %d
  max_pending: %d
  client_timeout: 10s
  # The load generator is one address sending as fast as it can, which is
  # exactly the shape response rate limiting exists to stop. Measuring the
  # server's ceiling means taking that limit off; a real deployment keeps it.
  rate_limit:
    enabled: false

listeners:
  udp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  tcp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  dot:
    enabled: true
    address: "127.0.0.1"
    port: %d
    cert_file: %s
    key_file: %s
  doh:
    enabled: true
    address: "127.0.0.1"
    port: %d
    path: /dns-query
    cert_file: %s
    key_file: %s

upstream:
  strategy: failover
  timeout: 5s
  attempts: %d
  bootstrap: [127.0.0.1]
  servers:
    - name: mock
      type: udp
      address: %s
      port: %s

cache:
  enabled: %t
  max_entries: %d

dnssec:
  enabled: %t

rewrites:
  - domain: rewritten.bench.test
    answer: 192.0.2.10
`,
		o.logLevel, o.logQueries, filepath.Join(h.dir, o.name+".log"),
		o.workers, o.upstreamWorkers, o.maxConnections, o.maxConnections, o.maxPending,
		dnsPort, dnsPort, dotPort,
		filepath.Join(h.dir, o.certKind+"-cert.pem"), filepath.Join(h.dir, o.certKind+"-key.pem"),
		dohPort,
		filepath.Join(h.dir, o.certKind+"-cert.pem"), filepath.Join(h.dir, o.certKind+"-key.pem"),
		o.attempts, host, portStr,
		o.cache, o.cacheEntries, o.dnssec)

	if o.blockRules > 0 {
		cfg += fmt.Sprintf(`
blocking:
  enabled: true
  response: nxdomain
  refresh: 0
  cache_dir: %s
  lists:
    - name: bench
      file: %s
      format: domains
`, filepath.Join(h.dir, "listcache"), blockPath)
	} else {
		cfg += "\nblocking:\n  enabled: false\n"
	}

	cfgPath := filepath.Join(h.dir, o.name+".yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, err
	}

	s := &server{
		dnsAddr: fmt.Sprintf("127.0.0.1:%d", dnsPort),
		dotAddr: fmt.Sprintf("127.0.0.1:%d", dotPort),
		dohAddr: fmt.Sprintf("127.0.0.1:%d", dohPort),
		logPath: filepath.Join(h.dir, o.name+".log"),
	}
	s.cmd = exec.Command(h.binary, "--config", cfgPath, "--no-fetch")
	s.cmd.Stdout = nil
	s.cmd.Stderr = nil
	if err := s.cmd.Start(); err != nil {
		return nil, err
	}
	s.pid = s.cmd.Process.Pid

	if err := waitReady(s.dnsAddr, 10*time.Second); err != nil {
		s.stop()
		return nil, fmt.Errorf("%s did not come up: %w", o.name, err)
	}
	return s, nil
}

// waitReady polls until a query is answered, so a run never starts against a
// server that is still binding its listeners.
func waitReady(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		q := dnswire.Query(1, "ready.bench.test", dnswire.TypeA, 0)
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(q); err != nil {
			last = err
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if _, err := dnswire.ParseReply(buf[:n]); err == nil {
			return nil
		}
	}
	if last == nil {
		last = fmt.Errorf("timed out")
	}
	return last
}

func (s *server) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	// SIGTERM rather than SIGKILL: the orderly path is the one that releases
	// the listeners, and a killed process can leave a port bound long enough to
	// upset the next scenario.
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = s.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
}

func (s *server) addrFor(transport string) string {
	switch transport {
	case "dot", "handshake":
		return s.dotAddr
	case "doh1", "doh2":
		return s.dohAddr
	default:
		return s.dnsAddr
	}
}

// rss reads the server's resident memory once it has settled.
func (s *server) rss() int64 {
	v, err := procstat.RSSBytes(s.pid)
	if err != nil {
		return 0
	}
	return v
}
