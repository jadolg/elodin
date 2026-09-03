package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"elodin.bench/internal/dnswire"
)

// ----------------------------------------------------------------- the server

type server struct {
	cmd     *exec.Cmd
	pid     int
	udpAddr string
	tcpAddr string
	dotAddr string
	dohAddr string
	/*
		Where `waitReady` probes from, which is the arm's family rather than one
		address: an IPv4 probe cannot reach a listener bound to `::1`, and the
		IPv6 arms have one.
	*/
	probeSrc string
	// The certificate the DoH listener serves, so a DoH client can verify what
	// it connects to rather than being told to skip it.
	certPath    string
	metricsAddr string
	logPath     string
	stopOnce    sync.Once
}

// armPorts takes the four ports an arm's server binds. Fresh per arm, so a
// listener from the arm before cannot still be holding one.
func armPorts() (dns, dot, doh, metrics int, err error) {
	for _, port := range []*int{&dns, &dot, &doh, &metrics} {
		if *port, err = freePort(); err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return dns, dot, doh, metrics, nil
}

// rateLimitBlock is the arm's `server.rate_limit`, indented for the template.
func rateLimitBlock(a arm) string {
	if !a.limiter {
		return "    enabled: false"
	}
	return fmt.Sprintf("    enabled: true\n    responses_per_second: %d\n    slip: %d", a.rps, a.slip)
}

/*
connectionBlock is the arm's connection-table settings, indented for the template.

Empty for every arm that is about the response budget, which is what leaves them
on the shipped 512 with a share derived from it. The connection arms name all
three, since what they are about is the relationship between the three numbers.

Each figure is written only when the arm set it. A zero `client_timeout` emitted
as `0s` is not the default - it is no read timeout at all, so an idle connection
would be held for the run whatever the arm meant - and an arm that pins one
figure and not another should get the shipped value for the rest rather than a
zero that reads as a decision.
*/
func connectionBlock(a arm) string {
	var b strings.Builder
	if a.maxConns > 0 {
		fmt.Fprintf(&b, "  max_connections: %d\n", a.maxConns)
	}
	if a.perPrefix > 0 {
		fmt.Fprintf(&b, "  max_connections_per_prefix: %d\n", a.perPrefix)
	}
	if a.clientTimeout > 0 {
		fmt.Fprintf(&b, "  client_timeout: %s\n", a.clientTimeout)
	}
	return b.String()
}

// armServer is what one arm's configuration is filled in from.
type armServer struct {
	logPath     string
	rateLimit   string
	connections string
	cert, key   string
	upHost      string
	upPort      string
	// What the DNS listeners bind, which is also the family the arm's clients
	// are on. See `armListen`.
	listen       string
	port         int
	dotPort      int
	dohPort      int
	cacheEntries int
	metrics      int
}

// serverConfig is the configuration one arm runs against. The arguments are
// indexed rather than positional: the listener address is written into four
// blocks, and a template with seventeen `%s` in it is one a reader has to count.
func serverConfig(a armServer) string {
	return fmt.Sprintf(configTemplate,
		*logLevel, *logQueries, a.logPath, *workers, *workers/2, a.connections, a.rateLimit,
		a.listen, a.port, a.dotPort, a.dohPort, a.cert, a.key,
		a.upHost, a.upPort, a.cacheEntries, a.metrics)
}

/*
armListen is the address an arm's listeners bind.

127.0.0.1 unless the arm names another, which only the IPv6 arms do. One figure
for every listener rather than one each: an arm asks what a client of one family
gets from a server serving that family, and a wildcard bind would be a different
question - the one `src/itest/cases_ratelimit.odin` asks, about whether a `::`
listener tells the families apart.
*/
func armListen(a arm) string {
	if a.listen == "" {
		return "127.0.0.1"
	}
	return a.listen
}

/*
probeSrcFor is where `waitReady` asks from: a prefix no arm's clients use, in the
arm's own family.

`::1` for the IPv6 arms, which is its own /64 and so not a prefix any of their
budgets are kept under - the same reasoning that keeps the IPv4 probes in
127.8.0.0/24.
*/
func probeSrcFor(listen string) string {
	if isV6(listen) {
		return "::1"
	}
	return "127.8.0.1"
}

// isV6 reports whether an address literal is IPv6, which decides the family
// every socket in the arm is opened in.
func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

/*
armCache is `cache.max_entries` for the arm.

Large by default, for the reason the template gives: every name in a run is
asked once, so a run's worth of misses has to fit or the arm measures eviction
the generator caused. The soak arm sets the shipped figure instead, because over
an hour eviction is not an artefact - it is the thing being watched.
*/
func armCache(a arm) int {
	if a.cacheEntries > 0 {
		return a.cacheEntries
	}
	return 400000
}

/*
Everything not named here is the shipped default, including
`max_udp_response`, which is the figure the budget is denominated in, and the
connection table, which only the `slowloris` arms pin.

`workers` and `upstream_workers` are pinned instead of derived from this
machine, for the reason the integration suite pins them: an arm whose flood
was shed by a queue this machine happened to size differently would be
measuring the machine rather than the limiter. `log.level: info` is so the
stats line the report reads `limited=`/`slipped=` off is written.
*/
const configTemplate = `log:
  level: %[1]s
  queries: %[2]t
  file: %[3]s

server:
  workers: %[4]d
  upstream_workers: %[5]d
%[6]s  rate_limit:
%[7]s

listeners:
  udp:
    enabled: true
    address: "%[8]s"
    port: %[9]d
  tcp:
    enabled: true
    address: "%[8]s"
    port: %[9]d
  # DoT and DoH are on in every arm rather than only the arms that use them, so
  # a listener an arm does not use is still there to be sure it costs nothing: a
  # bystander's result would mean less if the DoH arms ran against a differently
  # configured server. The DoT one is also where a TLS handshake is reachable
  # without HTTP on top of it, which is what the handshake-flood arms need.
  dot:
    enabled: true
    address: "%[8]s"
    port: %[10]d
    cert_file: %[12]s
    key_file: %[13]s
  doh:
    enabled: true
    address: "%[8]s"
    port: %[11]d
    path: /dns-query
    cert_file: %[12]s
    key_file: %[13]s

upstream:
  strategy: failover
  timeout: 5s
  attempts: 1
  bootstrap: [127.0.0.1]
  servers:
    - name: mock
      type: udp
      address: %[14]s
      port: %[15]s

cache:
  enabled: true
  # Every query in a run asks about a name of its own, so a run's worth of
  # misses has to fit without evicting: a cache churning is a cost of the
  # generator's making rather than of the load. The soak arm asks for the
  # shipped figure instead - see armCache in server.go.
  max_entries: %[16]d

blocking:
  enabled: false

dnssec:
  enabled: false

# Off by default; on here because the limiter's own counters are the server's
# side of the story, and reading them from the process beats inferring them
# from what the clients saw. On 127.0.0.1 whatever the listeners bind - it is
# the harness reading the server rather than part of the load, and loopback
# IPv4 is on every machine that can run the IPv4 arms at all.
metrics:
  enabled: true
  address: "127.0.0.1"
  port: %[17]d
  path: /metrics
`

func startServer(bin, dir, upstream string, a arm) (*server, error) {
	port, dotPort, dohPort, metricsPort, err := armPorts()
	if err != nil {
		return nil, err
	}
	cert, key, err := makeCert(dir)
	if err != nil {
		return nil, err
	}
	host, upPort, _ := net.SplitHostPort(upstream)
	name := strings.NewReplacer("/", "-").Replace(a.name)
	logPath := filepath.Join(dir, name+".log")

	listen := armListen(a)
	cfg := serverConfig(armServer{
		logPath:      logPath,
		rateLimit:    rateLimitBlock(a),
		connections:  connectionBlock(a),
		cert:         cert,
		key:          key,
		upHost:       host,
		upPort:       upPort,
		listen:       listen,
		port:         port,
		dotPort:      dotPort,
		dohPort:      dohPort,
		cacheEntries: armCache(a),
		metrics:      metricsPort,
	})

	cfgPath := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, err
	}

	s := &server{
		udpAddr:     joinPort(listen, port),
		tcpAddr:     joinPort(listen, port),
		dotAddr:     joinPort(listen, dotPort),
		dohAddr:     joinPort(listen, dohPort),
		probeSrc:    probeSrcFor(listen),
		certPath:    cert,
		metricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort),
		logPath:     logPath,
	}
	s.cmd = exec.Command(bin, "--config", cfgPath, "--no-fetch")
	if err := s.cmd.Start(); err != nil {
		return nil, err
	}
	s.pid = s.cmd.Process.Pid
	if err := waitReady(s.udpAddr, s.probeSrc, 10*time.Second); err != nil {
		s.stop()
		return nil, fmt.Errorf("did not come up: %w", err)
	}
	return s, nil
}

// joinPort is the address a client dials, in the form the family needs: IPv6
// carries brackets, and `net.JoinHostPort` is what puts them there.
func joinPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

/*
waitReady polls until a query is answered.

From `src`, which is a prefix no arm asks from - 127.8.0.1, or `::1` in the IPv6
arms: the probes spend budget, and spending the victim's or the attacker's would
put an arm's first result inside a bucket the harness had already drawn from.
*/
func waitReady(addr, src string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		conn, err := dialUDP(addr, src)
		if err != nil {
			last = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(dnswire.Query(1, "ready.rrl.test", dnswire.TypeA, ednsSize)); err != nil {
			last = err
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		buf := make([]byte, 65535)
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
		last = errors.New("timed out")
	}
	return last
}

func (s *server) stop() {
	s.stopOnce.Do(func() {
		if s.cmd == nil || s.cmd.Process == nil {
			return
		}
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = s.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = s.cmd.Process.Kill()
			<-done
		}
	})
}

/*
counters reads the server's own view of the arm off its metrics endpoint.

Scraped rather than parsed out of the log: the stats line is written on a timer
longer than an arm, so a run this short would read a line from before it. The
endpoint is a value as of the moment it is asked, which is what the arm wants,
and it is read before the process is signalled.
*/
func (s *server) counters() map[string]int64 {
	got := map[string]int64{}
	conn, err := net.DialTimeout("tcp", s.metricsAddr, 2*time.Second)
	if err != nil {
		return got
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /metrics HTTP/1.0\r\nHost: %s\r\n\r\n", s.metricsAddr)
	body, err := io.ReadAll(conn)
	if err != nil {
		return got
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		var v int64
		if _, err := fmt.Sscanf(f[1], "%d", &v); err == nil {
			got[f[0]] = v
		}
	}
	return got
}
