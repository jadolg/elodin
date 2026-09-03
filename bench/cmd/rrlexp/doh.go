package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"elodin.bench/internal/dnswire"
)

/*
DoH clients, for the arms the other transports cannot reach.

Two things are only true here. The first is multiplexing: an HTTP/2 client has
many requests in flight on one connection, where a TCP or DoT client is served a
query at a time - so the stream budget, which eight pipelined TCP connections
could not reach, is reachable from a single DoH/2 connection. The second is the
refusal. TCP and DoT end the connection when a client is over its budget; DoH/1.1
answers 429 and then ends it, and DoH/2 answers 429 and keeps going
(`src/server/doh2.odin`), so a flood there keeps paying for HPACK and frame work
per refused request rather than being cut off. Whether that costs a bystander is
the same question the slip raised on UDP.

Go's own HTTP stack is the client, which keeps the independence the rest of the
harness has: elodin's h2 and HPACK implementation is the thing under test, and a
generator that shared it could agree with a bug in it.
*/

type counter struct {
	mu sync.Mutex
	n  int64
}

func (c *counter) add() {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}

func (c *counter) load() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

/*
dohClient is one DoH client: where it points, what it asks, and what it counts.

A struct rather than the eight-odd arguments the request path would otherwise
carry from the worker down to the query.
*/
type dohClient struct {
	http  *http.Client
	url   string
	spec  clientSpec
	tag   string
	track bool
	st    *stats
	seq   *counter
	dials *counter
}

/*
newDoHClient builds the connection pool for one client.

`MaxConnsPerHost` is what an arm varies: at 1 a DoH/2 flood is a single
connection multiplexing, which is the case worth measuring, and an HTTP/1.1
client is one whose requests queue.

The certificate is verified rather than skipped. It is self-signed and this run
generated it, so the arm holds the only copy that matters and can hand it to the
client as a root - which is both closer to what a deployment does and one less
thing to explain away in a security scan. `ServerName` is the SAN `makeCert`
writes, since the connection is made to an address rather than a name.
*/
func newDoHClient(addr, certPath string, c clientSpec, tag string, track bool, st *stats) (*dohClient, error) {
	pem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading the arm's certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", certPath)
	}

	dials := &counter{}
	dialer := &net.Dialer{
		// The source address is the whole point: it is the prefix whose budget
		// the queries are charged to.
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(c.src)},
		Timeout:   5 * time.Second,
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxConnsPerHost:     max(c.sockets, 1),
		MaxIdleConnsPerHost: max(c.sockets, 1),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.add()
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if c.transport == "doh1" {
		tlsCfg.NextProtos = []string{"http/1.1"}
		tr.ForceAttemptHTTP2 = false
	} else {
		tlsCfg.NextProtos = []string{"h2"}
		tr.ForceAttemptHTTP2 = true
	}

	return &dohClient{
		http:  &http.Client{Transport: tr, Timeout: 20 * time.Second},
		url:   "https://" + addr + "/dns-query",
		spec:  c,
		tag:   tag,
		track: track,
		st:    st,
		seq:   &counter{},
		dials: dials,
	}, nil
}

/*
runDoH starts one DoH client and returns the function that stops it.

`inflight` requests are in the air at once, which is what an h2 flood is: without
it a client offering as fast as it can is still one request at a time, and one
request at a time is what already failed to reach the budget over TCP.
*/
func runDoH(addr, certPath string, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	d, err := newDoHClient(addr, certPath, c, tag, track, st)
	if err != nil {
		fatal(fmt.Errorf("doh from %s: %w", c.src, err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	/*
		A token per query the arm wants sent, so the offered rate is the arm's
		rather than however fast the requests happen to complete.

		Closed immediately when the arm offers flat out, which is what the
		workers read as "do not wait for one".
	*/
	tokens := make(chan struct{}, 1024)
	if c.rate > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dohPacer(ctx, c.rate, dur, tokens)
		}()
	} else {
		close(tokens)
	}

	for i := 0; i < max(c.inflight, 1); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d.work(ctx, dur, idx, tokens)
		}(i)
	}

	return func() {
		cancel()
		wg.Wait()
		d.http.CloseIdleConnections()
		st.dials.Store(d.dials.load())
	}
}

func dohPacer(ctx context.Context, rate int, dur time.Duration, tokens chan struct{}) {
	defer close(tokens)
	pace(rate, dur, func() bool {
		select {
		case tokens <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	})
}

// work keeps one request in flight at a time; `inflight` of these are what make
// an h2 flood a flood.
func (d *dohClient) work(ctx context.Context, dur time.Duration, idx int, tokens chan struct{}) {
	end := time.Now().Add(dur)
	for time.Now().Before(end) {
		if d.spec.rate > 0 {
			select {
			case _, ok := <-tokens:
				if !ok {
					return
				}
			case <-ctx.Done():
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		d.seq.add()
		d.query(ctx, idx, int(d.seq.load()))
	}
}

// query sends one and files what came back: the HTTP status as well as the DNS
// reply, because over DoH a refusal is a status rather than a dropped datagram.
func (d *dohClient) query(ctx context.Context, idx, seq int) {
	id := uint16(seq)
	q := dnswire.Query(id, d.spec.name(idx, seq, d.tag), dnswire.TypeA, ednsSize)

	req, err := http.NewRequestWithContext(ctx, "POST", d.url, bytes.NewReader(q))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/dns-message")

	started := time.Now()
	d.st.offered.Add(1)
	d.st.bytesOut.Add(int64(len(q)))

	resp, err := d.http.Do(req)
	if err != nil {
		// A request that never got a status is the connection having gone, which
		// over DoH/1.1 is what an over-budget client is answered with.
		d.st.failed.Add(1)
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	d.st.addStatus(resp.StatusCode)
	d.st.bytesIn.Add(int64(len(body)))
	if err != nil {
		d.st.failed.Add(1)
		return
	}
	if resp.StatusCode != http.StatusOK {
		// 429 is the limiter: the client asked and was told to come back, which
		// is a refusal rather than an answer.
		d.st.refused.Add(1)
		return
	}
	rep, err := dnswire.ParseReply(body)
	if err != nil {
		d.st.failed.Add(1)
		return
	}
	d.st.replies.Add(1)
	d.st.addRcode(rep.Rcode)
	if rep.Rcode != 0 {
		d.st.badRcode.Add(1)
		return
	}
	d.st.full.Add(1)
	if d.track {
		d.st.addLatency(time.Since(started))
	}
}

/*
makeCert writes the self-signed certificate the DoH listener needs.

Through openssl, the way `mise run certs` and `cmd/bench` both do it, rather than
crypto/x509 here: it is the same certificate a developer would generate by hand,
and openssl is already a dependency of the build. ECDSA P-256 for the reason
`mise.toml` gives - a handshake costs the server about half what RSA-2048 does,
and the DoH arms open enough connections for that to be part of what they measure.
*/
func makeCert(dir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}
	args := append(strings.Fields("req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"),
		"-keyout", keyPath, "-out", certPath,
		"-days", "30", "-subj", "/CN=elodin.rrlexp",
		"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	cmd := exec.Command("openssl", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("openssl: %w: %s", err, out)
	}
	return certPath, keyPath, nil
}
