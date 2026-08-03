// Command bench runs the whole measurement matrix behind the README's Capacity
// and Resource use sections and prints it as markdown.
//
// It owns everything the numbers depend on: it starts its own mock upstream at
// a fixed delay, writes each configuration itself, starts the release binary,
// waits for it to answer, and samples the server process alone. Nothing is left
// to the machine's state, so two runs are comparable and a run on another
// machine is comparable to this one.
//
// DNSSEC is off throughout. The mock upstream serves an unsigned zone that has
// no chain to the root, so with validation on every answer would be SERVFAIL
// and the figures would describe a failing resolver. What DNSSEC costs is a
// separate question from what the transports cost.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	binary      = flag.String("binary", "", "elodin binary (default: ../bin/elodin)")
	only        = flag.String("only", "", "run only scenarios whose name contains this")
	duration    = flag.Duration("duration", 10*time.Second, "measured length of each run")
	warmup      = flag.Duration("warmup", 2*time.Second, "unmeasured length before each run")
	upstreamRTT = flag.Duration("upstream-rtt", 20*time.Millisecond, "delay the mock upstream answers after")
	workdir     = flag.String("workdir", "", "where to put configs and logs (default: a temp dir)")
	out         = flag.String("out", "", "write the markdown report here as well as to stdout")
	repeat      = flag.Int("repeat", 3, "run each measured scenario this many times and keep the median")
	survey      = flag.String("survey", "", "instead of benchmarking, run the DNSSEC survey against this reference resolver (e.g. 9.9.9.9:53)")
	cooldown    = flag.Duration("cooldown", 15*time.Second, "idle time between runs, so a thermally limited machine does not drift across the matrix")
)

func main() {
	flag.Parse()
	log.SetFlags(0)

	root, err := repoRoot()
	if err != nil {
		log.Fatalf("bench: %v", err)
	}
	if *binary == "" {
		*binary = filepath.Join(root, "bin", "elodin")
	}
	if _, err := os.Stat(*binary); err != nil {
		log.Fatalf("bench: %s is not there — run `mise run release` first", *binary)
	}

	dir := *workdir
	if dir == "" {
		dir, err = os.MkdirTemp("", "elodin-bench-*")
		if err != nil {
			log.Fatalf("bench: %v", err)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("bench: %v", err)
	}
	log.Printf("bench: work dir %s", dir)

	h := &harness{root: root, dir: dir, binary: *binary}
	if err := h.setup(); err != nil {
		log.Fatalf("bench: %v", err)
	}
	defer h.teardown()

	var report string
	if *survey != "" {
		report, err = h.dnssecSurvey(*survey)
	} else {
		report, err = h.runAll(*only)
	}
	if err != nil {
		log.Fatalf("bench: %v", err)
	}

	fmt.Print(report)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
			log.Fatalf("bench: %v", err)
		}
		log.Printf("bench: wrote %s", *out)
	}
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; d != "/"; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "mise.toml")); err == nil {
			return d, nil
		}
	}
	return "", fmt.Errorf("no mise.toml above %s", wd)
}

type harness struct {
	root     string
	dir      string
	binary   string
	loadgen  string
	mock     *exec.Cmd
	mockAddr string
}

func (h *harness) setup() error {
	// The generator and the mock are built from this module so a run needs
	// nothing installed beyond a Go toolchain.
	for _, cmd := range []string{"loadgen", "mockdns"} {
		bin := filepath.Join(h.dir, cmd)
		build := exec.Command("go", "build", "-o", bin, "./cmd/"+cmd)
		build.Dir = filepath.Join(h.root, "bench")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			return fmt.Errorf("building %s: %w", cmd, err)
		}
		if cmd == "loadgen" {
			h.loadgen = bin
		}
	}

	if err := h.makeCerts(); err != nil {
		return err
	}

	port, err := freePort()
	if err != nil {
		return err
	}
	h.mockAddr = fmt.Sprintf("127.0.0.1:%d", port)
	h.mock = exec.Command(filepath.Join(h.dir, "mockdns"),
		"-addr", h.mockAddr, "-delay", upstreamRTT.String())
	h.mock.Stderr = nil
	if err := h.mock.Start(); err != nil {
		return fmt.Errorf("starting mockdns: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	return nil
}

func (h *harness) teardown() {
	if h.mock != nil && h.mock.Process != nil {
		_ = h.mock.Process.Kill()
		_ = h.mock.Wait()
	}
}

// makeCerts writes the two certificates the TLS scenarios need. ECDSA is what
// `mise run certs` produces and what a deployment should use; RSA is here only
// so the handshake cost of the two can be compared.
func (h *harness) makeCerts() error {
	specs := []struct{ name, args string }{
		{"ecdsa", "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1"},
		{"rsa", "-newkey rsa:2048"},
	}
	for _, s := range specs {
		cert := filepath.Join(h.dir, s.name+"-cert.pem")
		key := filepath.Join(h.dir, s.name+"-key.pem")
		if _, err := os.Stat(cert); err == nil {
			continue
		}
		args := append(strings.Fields("req -x509 "+s.args+" -nodes"),
			"-keyout", key, "-out", cert,
			"-days", "30", "-subj", "/CN=elodin.bench",
			"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
		cmd := exec.Command("openssl", args...)
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("generating the %s certificate: %w", s.name, err)
		}
	}
	return nil
}

// describeMachine records what the numbers are numbers for. A throughput
// figure without it is not reproducible by anyone else.
func describeMachine() string {
	model := "unknown CPU"
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if name, ok := strings.CutPrefix(line, "model name"); ok {
				if _, v, found := strings.Cut(name, ":"); found {
					model = strings.TrimSpace(v)
					break
				}
			}
		}
	}
	mem := ""
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if kb, err := strconv.ParseFloat(f[1], 64); err == nil {
						mem = fmt.Sprintf(", %.0f GB RAM", kb/(1<<20))
					}
				}
				break
			}
		}
	}
	kernel := ""
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = ", Linux " + strings.TrimSpace(string(data))
	}
	version := "unknown"
	if outb, err := exec.Command(*binary, "--version").Output(); err == nil {
		version = strings.TrimSpace(string(outb))
	}
	return fmt.Sprintf("Measured on %s (%d logical cores%s%s), %s.",
		model, runtime.NumCPU(), mem, kernel, version)
}

// avgMHz reports the mean clock across all cores right now. A laptop part
// cannot hold its boost clock through a matrix like this one, and a run that
// started at 4.7 GHz and finished at 2.0 GHz would otherwise look like a
// difference between the things being measured.
func avgMHz() float64 {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	var sum float64
	var n int
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu MHz") {
			continue
		}
		_, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			continue
		}
		sum += f
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
