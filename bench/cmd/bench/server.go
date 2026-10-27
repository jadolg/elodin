package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// kind is the server under test: "elodin" (the default, -binary) or
	// "unbound". Both are given the same listeners, certificate, upstream and
	// limits, so a row differs between them in the server and nothing else.
	kind string

	// loops is `listeners.udp.readers`, which is also the number of event loops;
	// Unbound gets it as `num-threads`. 0 lets elodin derive it (one per usable
	// CPU, to eight), and Unbound is given that same figure.
	loops int
	// maxPending is `server.max_pending`, written as given, so 0 is the figure
	// derived from memory.
	maxPending     int
	maxConnections int
	// clientTimeout is how long an idle client connection is held. The rows
	// that hold thousands of idle connections raise it, so the first connection
	// opened is still there when the last one has been answered.
	clientTimeout time.Duration
	// cpus pins the server to these CPUs with taskset, in its -c syntax, so a
	// run can describe a small machine on a large one.
	cpus string

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
	// upstreamAddr replaces the harness's mock, with a real resolver for the
	// survey or with a mock at another delay for the rows that vary it.
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
	// caPath is the certificate the server presents, which the generator trusts.
	caPath  string
	logPath string
	pid     int
}

func (h *harness) start(o serverOpts) (*server, error) {
	if o.kind == "" {
		o.kind = "elodin"
	}
	if o.maxConnections == 0 {
		o.maxConnections = 512
	}
	if o.clientTimeout == 0 {
		o.clientTimeout = 10 * time.Second
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
	p := ports{dns: dnsPort, dot: dotPort, doh: dohPort, upHost: host, upPort: portStr}

	s := &server{
		dnsAddr: fmt.Sprintf("127.0.0.1:%d", dnsPort),
		dotAddr: fmt.Sprintf("127.0.0.1:%d", dotPort),
		dohAddr: fmt.Sprintf("127.0.0.1:%d", dohPort),
		caPath:  filepath.Join(h.dir, o.certKind+"-cert.pem"),
		logPath: filepath.Join(h.dir, o.name+"-"+o.kind+".log"),
	}
	var argv []string
	switch o.kind {
	case "elodin":
		argv, err = h.elodinConfig(o, p, s.logPath)
	case "unbound":
		argv, err = h.unboundConfig(o, p, s.logPath)
	default:
		err = fmt.Errorf("unknown server kind %q", o.kind)
	}
	if err != nil {
		return nil, err
	}
	if o.cpus != "" {
		// taskset execs the server in its own place, so the pid sampled below
		// is still the server's.
		argv = append([]string{"taskset", "-c", o.cpus}, argv...)
	}
	s.cmd = exec.Command(argv[0], argv[1:]...)
	// What a server says before its own log is open - a config it refuses, a
	// file it may not read - goes here, and into the error if it never answers.
	stderr, err := os.Create(filepath.Join(h.dir, o.name+"-"+o.kind+".stderr"))
	if err != nil {
		return nil, err
	}
	defer stderr.Close()
	s.cmd.Stdout = nil
	s.cmd.Stderr = stderr
	if err := s.cmd.Start(); err != nil {
		return nil, err
	}
	s.pid = s.cmd.Process.Pid

	if err := waitReady(s.dnsAddr, 15*time.Second); err != nil {
		s.stop()
		said, _ := os.ReadFile(stderr.Name())
		return nil, fmt.Errorf("%s (%s) did not come up: %w\n%s", o.name, o.kind, err, strings.TrimSpace(string(said)))
	}
	return s, nil
}

// ports is where a server listens and where its upstream is.
type ports struct {
	dns, dot, doh  int
	upHost, upPort string
}

// elodinConfig writes elodin's configuration and returns the command that
// runs it. The template names only keys the thread-model releases also
// accept, so -binary can point at one of them and run the same matrix.
func (h *harness) elodinConfig(o serverOpts, p ports, logPath string) ([]string, error) {
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

	cfg := fmt.Sprintf(elodinTemplate,
		o.logLevel, o.logQueries, logPath,
		o.maxConnections, o.maxConnections, o.maxPending, o.clientTimeout,
		p.dns, o.loops, p.dns, p.dot,
		filepath.Join(h.dir, o.certKind+"-cert.pem"), filepath.Join(h.dir, o.certKind+"-key.pem"),
		p.doh,
		filepath.Join(h.dir, o.certKind+"-cert.pem"), filepath.Join(h.dir, o.certKind+"-key.pem"),
		o.attempts, p.upHost, p.upPort,
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
	return []string{h.binary, "--config", cfgPath, "--no-fetch"}, nil
}

// unboundThreads is what elodin derives its loop count as when it is left
// unset, so the two servers get the same number of threads unless a row says
// otherwise.
func unboundThreads(loops int) int {
	if loops > 0 {
		return loops
	}
	return min(runtime.NumCPU(), 8)
}

// unboundConfig writes an unbound.conf equivalent to elodin's configuration as
// far as the two overlap, and returns the command that runs it in the
// foreground.
func (h *harness) unboundConfig(o serverOpts, p ports, logPath string) ([]string, error) {
	if o.blockRules > 0 || o.dnssec || o.noUpstream {
		// Each of these would need Unbound configured in a way the rows that
		// use them do not compare, so a row asking for one is a mistake.
		return nil, fmt.Errorf("%s: blocklists, validation and a dead upstream are elodin-only rows", o.name)
	}
	threads := unboundThreads(o.loops)
	// Unbound allocates its TCP handlers per thread, a message buffer each, and
	// starts closing idle connections early once fewer than half of a thread's
	// handlers are free. SO_REUSEPORT spreads connections across the threads
	// unevenly, so each thread gets three times its even share: enough that no
	// thread passes half, and the held-connection rows measure holding rather
	// than Unbound's busy-time idle cut.
	perThreadTCP := 3*((o.maxConnections+threads-1)/threads) + 64
	// num-queries-per-thread is Unbound's bound on queries in flight, the
	// counterpart of max_pending. It is per thread and Unbound's own default is
	// 1024 or 512, so it is raised past anything a row puts in flight.
	inflight := max(4096, o.maxPending)
	maxTTL := ""
	if !o.cache {
		// Unbound has no switch for the cache; a zero ceiling on what it keeps
		// is the nearest thing.
		maxTTL = "  cache-max-ttl: 0\n"
	}
	logQueries := "no"
	if o.logQueries {
		logQueries = "yes"
	}
	cert := filepath.Join(h.dir, o.certKind+"-cert.pem")
	key := filepath.Join(h.dir, o.certKind+"-key.pem")

	cfg := fmt.Sprintf(unboundTemplate,
		threads, p.dns, p.dot, p.doh, p.dns, p.dot, p.doh, key, cert,
		maxTTL, inflight, 2*inflight, perThreadTCP, o.clientTimeout.Milliseconds(),
		h.dir, logPath, logQueries, p.upHost, p.upPort)

	cfgPath := filepath.Join(h.dir, o.name+"-unbound.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, err
	}
	return []string{h.unbound, "-d", "-c", cfgPath}, nil
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
		// Long enough for the slowest mock a row starts (three seconds): a
		// server that coalesces answers a later probe from the first one's
		// question, but one that does not answers only the probe that asked.
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
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

// elodinTemplate is the configuration elodinConfig fills in, kept out of the
// function so the function reads as what varies.
const elodinTemplate = `log:
  level: %s
  queries: %t
  file: %s

server:
  max_connections: %d
  # The whole table to one prefix, for the same reason the limiter is off below:
  # every client here is 127.0.0.1, so all of them are one client to a per-prefix
  # share, and the shipped default of half the table would refuse the second half
  # of the 500-connection TCP row rather than measure it. A real deployment keeps
  # the share; see bench/results/2026-09-03-connection-table-share.md.
  max_connections_per_prefix: %d
  max_pending: %d
  client_timeout: %s
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
    readers: %d
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
`

// unboundTemplate is the unbound.conf unboundConfig fills in; see there.
const unboundTemplate = `server:
  verbosity: 0
  num-threads: %d
  so-reuseport: yes
  interface: 127.0.0.1@%d
  interface: 127.0.0.1@%d
  interface: 127.0.0.1@%d
  port: %d
  tls-port: %d
  https-port: %d
  http-endpoint: "/dns-query"
  tls-service-key: %s
  tls-service-pem: %s
  do-ip6: no
  access-control: 127.0.0.0/8 allow
  # The mock is on loopback, which Unbound refuses to forward to by default.
  do-not-query-localhost: no
  # Unbound answers test. itself (RFC 6761 section 6.2), NXDOMAIN for every
  # name; the mock's zone is under it, so it has to be forwarded instead.
  local-zone: "test." nodefault
  # DNSSEC off, as for elodin: the mock's zone has no chain to the root.
  module-config: "iterator"
  qname-minimisation: no
  # No rate limiting, for the reason elodin's is off: every client is one
  # address asking as fast as it can.
  ratelimit: 0
  ip-ratelimit: 0
  # Room for elodin's 10,000 cached answers several times over, so the cache
  # is never what separates the two.
  msg-cache-size: 32m
  rrset-cache-size: 64m
%s  num-queries-per-thread: %d
  outgoing-range: %d
  outgoing-num-tcp: 64
  incoming-num-tcp: %d
  tcp-idle-timeout: %d
  # Unbound times out an upstream it has no round-trip figure for after 376 ms
  # and retransmits, which against the long-delay mock would turn one query
  # into four. elodin waits upstream.timeout (5s) for one attempt; so does this.
  unknown-server-time-limit: 5000
  # Unbound drops the reply to a client that has waited past this (1,900 ms by
  # default) on the view that it has retried by now; the generator does not
  # retry, and the in-flight rows hold queries for three seconds.
  discard-timeout: 0
  infra-cache-min-rtt: 5000
  username: ""
  chroot: ""
  directory: %s
  pidfile: ""
  use-syslog: no
  logfile: %s
  log-queries: %s

remote-control:
  control-enable: no

forward-zone:
  name: "."
  forward-addr: %s@%s
`
