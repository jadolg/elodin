// Command loadgen drives one scenario against a running elodin and reports
// what it measured as JSON.
//
// Every client holds its own connection for the whole run, which is what the
// per-transport numbers are meant to describe: the cost of answering on an
// established connection, not the cost of establishing one. Handshake cost is
// measured separately, by -transport=handshake.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"elodin.bench/internal/dnswire"
	"elodin.bench/internal/hist"
)

type config struct {
	server      string
	transport   string
	clients     int
	concurrency int
	duration    time.Duration
	warmup      time.Duration
	qmode       string
	qname       string
	path        string
	rate        int
}

// Result is the JSON the orchestrator reads back.
type Result struct {
	Transport    string           `json:"transport"`
	Clients      int              `json:"clients"`
	Concurrency  int              `json:"concurrency"`
	Answered     int64            `json:"answered"`
	Errors       int64            `json:"errors"`
	Rcodes       map[string]int64 `json:"rcodes"`
	Seconds      float64          `json:"seconds"`
	QPS          float64          `json:"qps"`
	P50ms        float64          `json:"p50_ms"`
	P99ms        float64          `json:"p99_ms"`
	MinPerClient int64            `json:"min_per_client"`
	MaxPerClient int64            `json:"max_per_client"`
}

func main() {
	var c config
	flag.StringVar(&c.server, "server", "127.0.0.1:5354", "elodin address")
	flag.StringVar(&c.transport, "transport", "udp", "udp|tcp|dot|doh1|doh2|handshake")
	flag.IntVar(&c.clients, "clients", 100, "concurrent clients, each with its own connection")
	flag.IntVar(&c.concurrency, "concurrency", 1, "in-flight requests per client (DoH only above 1)")
	flag.DurationVar(&c.duration, "duration", 10*time.Second, "measured run length")
	flag.DurationVar(&c.warmup, "warmup", 2*time.Second, "unmeasured run length before it")
	flag.StringVar(&c.qmode, "qmode", "fixed", "fixed|unique")
	flag.StringVar(&c.qname, "qname", "cached.bench.test", "name to ask about in fixed mode")
	flag.StringVar(&c.path, "path", "/dns-query", "DoH path")
	flag.IntVar(&c.rate, "rate", 0, "total queries per second to offer; 0 is as fast as possible")
	flag.Parse()

	if c.concurrency > 1 && c.transport != "doh1" && c.transport != "doh2" {
		fmt.Fprintln(os.Stderr, "loadgen: concurrency above 1 needs doh1 or doh2; raise -clients instead")
		os.Exit(2)
	}

	res, err := run(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadgen: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

func run(c config) (Result, error) {
	if c.transport == "handshake" {
		return runHandshake(c)
	}

	rec := hist.New(1 << 20)
	var answered, errors atomic.Int64
	perClient := make([]atomic.Int64, c.clients)
	var rcodeMu sync.Mutex
	rcodes := map[string]int64{}

	// One token bucket shared by every client when a rate is asked for. Without
	// it the generator runs open-loop and the numbers describe the generator.
	var ticker *time.Ticker
	if c.rate > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(c.rate))
		defer ticker.Stop()
	}

	start := make(chan struct{})
	measureFrom := time.Now()
	deadline := time.Now()

	var wg sync.WaitGroup
	errCh := make(chan error, c.clients)

	for i := range c.clients {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cl, err := dial(c)
			if err != nil {
				errCh <- err
				return
			}
			defer cl.Close()

			<-start

			// Requests in flight at once on this one connection. Above 1 this
			// is what h2 multiplexes and http/1.1 queues.
			var inner sync.WaitGroup
			for slot := range c.concurrency {
				inner.Add(1)
				go func(slot int) {
					defer inner.Done()
					local := make([]time.Duration, 0, 1<<14)
					var counter uint64
					for time.Now().Before(deadline) {
						if ticker != nil {
							<-ticker.C
						}
						name := c.qname
						if c.qmode == "unique" {
							name = fmt.Sprintf("q-%d-%d-%d.bench.test", id, slot, counter)
						}
						counter++

						t0 := time.Now()
						rc, err := cl.Query(name)
						lat := time.Since(t0)
						if err != nil {
							errors.Add(1)
							continue
						}
						if t0.After(measureFrom) {
							local = append(local, lat)
							answered.Add(1)
							perClient[id].Add(1)
							rcodeMu.Lock()
							rcodes[rcodeName(rc)]++
							rcodeMu.Unlock()
						}
					}
					rec.AddBatch(local)
				}(slot)
			}
			inner.Wait()
		}(i)
	}

	// Connections are established before the clock starts, so dialling and
	// handshakes stay out of the throughput figure.
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-errCh:
		return Result{}, err
	default:
	}

	measureFrom = time.Now().Add(c.warmup)
	deadline = measureFrom.Add(c.duration)
	runStart := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(runStart) - c.warmup

	select {
	case err := <-errCh:
		return Result{}, err
	default:
	}

	ps := rec.Percentiles(0.50, 0.99)
	minC, maxC := int64(-1), int64(0)
	for i := range perClient {
		n := perClient[i].Load()
		if minC < 0 || n < minC {
			minC = n
		}
		if n > maxC {
			maxC = n
		}
	}
	return Result{
		Transport:    c.transport,
		Clients:      c.clients,
		Concurrency:  c.concurrency,
		Answered:     answered.Load(),
		Errors:       errors.Load(),
		Rcodes:       rcodes,
		Seconds:      elapsed.Seconds(),
		QPS:          float64(answered.Load()) / elapsed.Seconds(),
		P50ms:        float64(ps[0].Microseconds()) / 1000,
		P99ms:        float64(ps[1].Microseconds()) / 1000,
		MinPerClient: minC,
		MaxPerClient: maxC,
	}, nil
}

func rcodeName(rc int) string {
	switch rc {
	case 0:
		return "noerror"
	case 2:
		return "servfail"
	case 3:
		return "nxdomain"
	case 5:
		return "refused"
	default:
		return fmt.Sprintf("rcode%d", rc)
	}
}

// client is one connection held for the run.
type client interface {
	Query(name string) (rcode int, err error)
	Close()
}

func dial(c config) (client, error) {
	switch c.transport {
	case "udp":
		return dialUDP(c)
	case "tcp":
		return dialTCP(c)
	case "dot":
		return dialDoT(c)
	case "doh1", "doh2":
		return dialDoH(c)
	}
	return nil, fmt.Errorf("unknown transport %q", c.transport)
}

type udpClient struct {
	conn *net.UDPConn
	buf  []byte
}

func dialUDP(c config) (client, error) {
	addr, err := net.ResolveUDPAddr("udp", c.server)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &udpClient{conn: conn, buf: make([]byte, 65535)}, nil
}

func (u *udpClient) Query(name string) (int, error) {
	id := uint16(rand.Uint32())
	q := dnswire.Query(id, name, dnswire.TypeA, 1232)
	if err := u.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := u.conn.Write(q); err != nil {
		return 0, err
	}
	for {
		n, err := u.conn.Read(u.buf)
		if err != nil {
			return 0, err
		}
		reply, err := dnswire.ParseReply(u.buf[:n])
		if err != nil {
			return 0, err
		}
		// A late answer to a previous query would otherwise be charged to this
		// one; the socket is connected, so nothing else can arrive on it.
		if reply.ID != id {
			continue
		}
		return reply.Rcode, nil
	}
}

func (u *udpClient) Close() { u.conn.Close() }

// streamClient covers TCP and DoT, which differ only in the transport under
// the two-byte length prefix.
type streamClient struct {
	conn net.Conn
	buf  []byte
}

func dialTCP(c config) (client, error) {
	conn, err := net.Dial("tcp", c.server)
	if err != nil {
		return nil, err
	}
	return &streamClient{conn: conn, buf: make([]byte, 65535)}, nil
}

func dialDoT(c config) (client, error) {
	conn, err := tls.Dial("tcp", c.server, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"dot"},
	})
	if err != nil {
		return nil, err
	}
	return &streamClient{conn: conn, buf: make([]byte, 65535)}, nil
}

func (s *streamClient) Query(name string) (int, error) {
	id := uint16(rand.Uint32())
	q := dnswire.Query(id, name, dnswire.TypeA, 1232)
	out := make([]byte, 2+len(q))
	out[0] = byte(len(q) >> 8)
	out[1] = byte(len(q))
	copy(out[2:], q)

	if err := s.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := s.conn.Write(out); err != nil {
		return 0, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, err
	}
	size := int(hdr[0])<<8 | int(hdr[1])
	if size > len(s.buf) {
		return 0, fmt.Errorf("answer of %d bytes is too large", size)
	}
	if _, err := io.ReadFull(s.conn, s.buf[:size]); err != nil {
		return 0, err
	}
	reply, err := dnswire.ParseReply(s.buf[:size])
	if err != nil {
		return 0, err
	}
	if reply.ID != id {
		return 0, fmt.Errorf("answer carries id %d, asked with %d", reply.ID, id)
	}
	return reply.Rcode, nil
}

func (s *streamClient) Close() { s.conn.Close() }

type dohClient struct {
	http *http.Client
	url  string
}

func dialDoH(c config) (client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		// One connection per client, so a "client" means what it means on the
		// other transports. For HTTP/1.1 this is also what makes its requests
		// queue, which is the whole point of comparing it with h2.
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	if c.transport == "doh2" {
		tlsCfg.NextProtos = []string{"h2"}
		tr.ForceAttemptHTTP2 = true
	} else {
		tlsCfg.NextProtos = []string{"http/1.1"}
		tr.ForceAttemptHTTP2 = false
	}
	cl := &dohClient{
		http: &http.Client{Transport: tr, Timeout: 30 * time.Second},
		url:  "https://" + c.server + c.path,
	}
	// Fail here rather than mid-run if the listener is not up or ALPN did not
	// give us the protocol asked for.
	if err := cl.probe(c.transport); err != nil {
		return nil, err
	}
	return cl, nil
}

func (d *dohClient) probe(want string) error {
	q := dnswire.Query(1, "probe.bench.test", dnswire.TypeA, 0)
	req, err := http.NewRequest("POST", d.url, bytes.NewReader(q))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/dns-message")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	gotH2 := resp.ProtoMajor == 2
	if want == "doh2" && !gotH2 {
		return fmt.Errorf("asked for h2, negotiated %s", resp.Proto)
	}
	if want == "doh1" && gotH2 {
		return fmt.Errorf("asked for http/1.1, negotiated %s", resp.Proto)
	}
	return nil
}

func (d *dohClient) Query(name string) (int, error) {
	id := uint16(rand.Uint32())
	q := dnswire.Query(id, name, dnswire.TypeA, 0)
	req, err := http.NewRequest("POST", d.url, bytes.NewReader(q))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/dns-message")
	resp, err := d.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	reply, err := dnswire.ParseReply(body)
	if err != nil {
		return 0, err
	}
	if reply.ID != id {
		return 0, fmt.Errorf("answer carries id %d, asked with %d", reply.ID, id)
	}
	return reply.Rcode, nil
}

func (d *dohClient) Close() { d.http.CloseIdleConnections() }

// runHandshake measures fresh TLS handshakes rather than queries: every
// iteration dials, handshakes, asks one question and closes.
func runHandshake(c config) (Result, error) {
	rec := hist.New(1 << 16)
	var done, errs atomic.Int64

	deadline := time.Now().Add(c.duration)
	var wg sync.WaitGroup
	for range c.clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 1<<10)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				conn, err := tls.Dial("tcp", c.server, &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"dot"},
					// A resumed session would measure the wrong thing.
					ClientSessionCache: nil,
				})
				if err != nil {
					errs.Add(1)
					continue
				}
				cl := &streamClient{conn: conn, buf: make([]byte, 4096)}
				if _, err := cl.Query(c.qname); err != nil {
					errs.Add(1)
					conn.Close()
					continue
				}
				conn.Close()
				local = append(local, time.Since(t0))
				done.Add(1)
			}
			rec.AddBatch(local)
		}()
	}
	runStart := time.Now()
	wg.Wait()
	elapsed := time.Since(runStart)

	ps := rec.Percentiles(0.50, 0.99)
	return Result{
		Transport: c.transport,
		Clients:   c.clients,
		Answered:  done.Load(),
		Errors:    errs.Load(),
		Seconds:   elapsed.Seconds(),
		QPS:       float64(done.Load()) / elapsed.Seconds(),
		P50ms:     float64(ps[0].Microseconds()) / 1000,
		P99ms:     float64(ps[1].Microseconds()) / 1000,
	}, nil
}
