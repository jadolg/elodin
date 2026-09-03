package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	dohAddr string
	// The certificate the DoH listener serves, so a DoH client can verify what
	// it connects to rather than being told to skip it.
	certPath    string
	metricsAddr string
	logPath     string
	stopOnce    sync.Once
}

// armPorts takes the three ports an arm's server binds. Fresh per arm, so a
// listener from the arm before cannot still be holding one.
func armPorts() (dns, doh, metrics int, err error) {
	if dns, err = freePort(); err != nil {
		return 0, 0, 0, err
	}
	if doh, err = freePort(); err != nil {
		return 0, 0, 0, err
	}
	if metrics, err = freePort(); err != nil {
		return 0, 0, 0, err
	}
	return dns, doh, metrics, nil
}

// rateLimitBlock is the arm's `server.rate_limit`, indented for the template.
func rateLimitBlock(a arm) string {
	if !a.limiter {
		return "    enabled: false"
	}
	return fmt.Sprintf("    enabled: true\n    responses_per_second: %d\n    slip: %d", a.rps, a.slip)
}

// armServer is what one arm's configuration is filled in from.
type armServer struct {
	logPath   string
	rateLimit string
	cert, key string
	upHost    string
	upPort    string
	port      int
	dohPort   int
	metrics   int
}

// serverConfig is the configuration one arm runs against.
func serverConfig(a armServer) string {
	return fmt.Sprintf(configTemplate,
		*logLevel, *logQueries, a.logPath, *workers, *workers/2, a.rateLimit,
		a.port, a.port, a.dohPort, a.cert, a.key, a.upHost, a.upPort, a.metrics)
}

/*
Everything not named here is the shipped default, including
`max_udp_response`, which is the figure the budget is denominated in.

`workers` and `upstream_workers` are pinned instead of derived from this
machine, for the reason the integration suite pins them: an arm whose flood
was shed by a queue this machine happened to size differently would be
measuring the machine rather than the limiter. `log.level: info` is so the
stats line the report reads `limited=`/`slipped=` off is written.
*/
const configTemplate = `log:
  level: %s
  queries: %t
  file: %s

server:
  workers: %d
  upstream_workers: %d
  rate_limit:
%s

listeners:
  udp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  tcp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  # On in every arm rather than only the DoH ones, so the listener an arm does
  # not use is still there to be sure it costs nothing: a bystander's result
  # would mean less if the DoH arms ran against a differently configured server.
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
  attempts: 1
  bootstrap: [127.0.0.1]
  servers:
    - name: mock
      type: udp
      address: %s
      port: %s

cache:
  enabled: true
  # Every query in a run asks about a name of its own, so a run's worth of
  # misses has to fit without evicting: a cache churning is a cost of the
  # generator's making rather than of the load.
  max_entries: 400000

blocking:
  enabled: false

dnssec:
  enabled: false

# Off by default; on here because the limiter's own counters are the server's
# side of the story, and reading them from the process beats inferring them
# from what the clients saw.
metrics:
  enabled: true
  address: "127.0.0.1"
  port: %d
  path: /metrics
`

func startServer(bin, dir, upstream string, a arm) (*server, error) {
	port, dohPort, metricsPort, err := armPorts()
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

	cfg := serverConfig(armServer{
		logPath:   logPath,
		rateLimit: rateLimitBlock(a),
		cert:      cert,
		key:       key,
		upHost:    host,
		upPort:    upPort,
		port:      port,
		dohPort:   dohPort,
		metrics:   metricsPort,
	})

	cfgPath := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return nil, err
	}

	s := &server{
		udpAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		tcpAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		dohAddr:     fmt.Sprintf("127.0.0.1:%d", dohPort),
		certPath:    cert,
		metricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort),
		logPath:     logPath,
	}
	s.cmd = exec.Command(bin, "--config", cfgPath, "--no-fetch")
	if err := s.cmd.Start(); err != nil {
		return nil, err
	}
	s.pid = s.cmd.Process.Pid
	if err := waitReady(s.udpAddr, 10*time.Second); err != nil {
		s.stop()
		return nil, fmt.Errorf("did not come up: %w", err)
	}
	return s, nil
}

/*
waitReady polls until a query is answered.

From 127.8.0.1, which is a prefix no arm asks from: the probes spend budget, and
spending the victim's or the attacker's would put an arm's first result inside a
bucket the harness had already drawn from.
*/
func waitReady(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		conn, err := dialUDP(addr, "127.8.0.1")
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
