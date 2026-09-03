package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

/*
The TLS clients: a DoT client that holds a connection and asks, and a client
that does nothing but handshake.

Both are here because the second is the reason the first exists. `cmd/bench
-transport=handshake` already measures what a fresh handshake costs, as a
throughput figure taken from a quiet server; what nothing measured is a client
doing only handshakes while somebody else is trying to resolve. That load is
invisible to the response limiter - a budget is spent by answers, and a client
that never sends a query is never charged - and only half visible to
`server.max_connections`, since a handshake takes a slot and gives it straight
back. So the bystander needs a transport where a handshake is the whole cost,
which is DoT, and a victim on it to ask what the flood did to them.

The certificate is verified rather than skipped, the way the DoH clients verify
it: the arm generated it, so the harness holds the only copy that matters and
can hand it over as a root.
*/

/*
tlsConfig is the arm's certificate as a root, with the ALPN the transport needs.

`ServerName` is the SAN `makeCert` writes rather than the address dialled, since
these connections are made to 127.0.0.1 or ::1 and a certificate for an address
would have to name both. No session cache, which is what keeps a handshake flood
a flood: a resumed session skips the asymmetric work that is the whole cost being
measured.
*/
func tlsConfig(certPath string, alpn ...string) (*tls.Config, error) {
	pem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading the arm's certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no certificate", certPath)
	}
	return &tls.Config{
		RootCAs:            pool,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
		NextProtos:         alpn,
		ClientSessionCache: nil,
	}, nil
}

/*
runDoT is the TCP client with a handshake in front of it.

The same reader and writer as `runTCP` - a DoT connection is DNS on a stream, and
the length prefix, the pipelining and the way a refusal arrives as the connection
ending are all the same. What differs is what it cost to get the connection, which
is the arm's subject rather than the client's.
*/
func runDoT(dst, certPath string, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	cfg, err := tlsConfig(certPath, "dot")
	if err != nil {
		fatal(fmt.Errorf("dot from %s: %w", c.src, err))
	}
	return runStream(func() (net.Conn, error) { return dialDoT(dst, c.src, cfg) }, c, dur, tag, track, st)
}

/*
dialDoT is one DoT connection from `src`, handshake included: `tls.Client`
defers it, and a client that has not handshaked has not yet cost the server the
thing these arms are about.

Bounded, for the reason `handshakeWorker` bounds its own: the kernel completes
the TCP handshake out of the listen backlog, so this dial succeeds against a
server with no thread to spare and then waits in `Handshake` for one. That wait
has no natural end - the victim of a handshake flood is dialling into exactly
that - and an unbounded one here would hang the arm before it started rather
than report what the arm found.
*/
func dialDoT(dst, src string, cfg *tls.Config) (net.Conn, error) {
	raw, err := dialTCP(dst, src)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	// Cleared once it is up: the deadline was for getting the connection, and
	// the queries that follow are paced by the arm rather than by a clock here.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

/*
How long a handshake is given before the client gives up on it.

One figure for the victim's handshake and the flood's, so that a run where the
server is too busy to handshake reads the same way from both sides. Five seconds
is far past what an idle loopback handshake costs (single-digit milliseconds in
every arm here) and far short of an arm, so it bounds a wedge without truncating
a slow success.
*/
const handshakeDeadline = 5 * time.Second

/*
runHandshakeFlood is a client that connects, handshakes, closes, and does it
again as fast as the server will let it.

Not a query in the whole arm. The response budget is spent by answers, so a
client that asks nothing is charged nothing however fast it arrives - and what it
is buying with that is the most expensive thing a stream client can ask for: an
ECDHE exchange and a signature, per connection, on a thread out of
`server.max_connections`. The slot is taken before the handshake starts
(`accept_loop` in src/server/listeners.odin), so a share of the table is the one
bound that reaches this load at all, which is why the arms run with one and
without.

`sockets` is how many of these run at once, which is the concurrency an attacker
brings rather than a rate: there is nothing to pace, and the interesting figure is
how many handshakes a second the server can be made to do.

What each counter means here:

  - `offered` is a handshake attempted, `full` one completed. The gap is the
    refusals.
  - `closed` is a connection the server took and then let go without finishing a
    handshake, which is what a full connection table looks like from out here:
    the kernel completes the TCP handshake out of the listen backlog, so the dial
    succeeds and the TLS handshake is what fails.
  - `failed` is a dial that never connected, which on loopback is the backlog
    overflowing rather than a decision of the server's - plus a handshake this
    client abandoned, at its own deadline or because the arm ended. The numbers
    here that say the harness ran out rather than the server refusing.
  - the latencies are how long a completed handshake took, which is the server's
    own cost coming back as the flood's own experience of it.
*/
func runHandshakeFlood(dst, certPath string, c clientSpec, dur time.Duration, st *stats) func() {
	cfg, err := tlsConfig(certPath, alpnFor(c.transport))
	if err != nil {
		fatal(fmt.Errorf("handshake flood from %s: %w", c.src, err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < max(c.sockets, 1); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handshakeWorker(ctx, dst, c.src, dur, cfg, st)
		}()
	}
	return func() {
		cancel()
		wg.Wait()
	}
}

// alpnFor is what a handshake flood offers, which decides which listener it is
// against: the DoT one, or the DoH one over either HTTP version.
func alpnFor(transport string) string {
	switch transport {
	case "doh1":
		return "http/1.1"
	case "doh2":
		return "h2"
	}
	return "dot"
}

func handshakeWorker(ctx context.Context, dst, src string, dur time.Duration, cfg *tls.Config, st *stats) {
	end := time.Now().Add(dur)
	for time.Now().Before(end) && ctx.Err() == nil {
		st.offered.Add(1)
		started := time.Now()
		raw, err := dialTCP(dst, src)
		if err != nil {
			st.failed.Add(1)
			continue
		}
		conn := tls.Client(raw, cfg)
		// A deadline rather than none: a handshake against a server with no
		// thread to spare can sit in the backlog for as long as the arm lasts,
		// and a worker parked there is one not measuring anything.
		_ = raw.SetDeadline(time.Now().Add(handshakeDeadline))
		if err := conn.HandshakeContext(ctx); err != nil {
			/*
				A refusal only if the server decided it.

				`closed` is rendered as the server's refusals, so the two ways
				this can fail without the server having refused anything have to
				be kept out of it: the arm ending under the client's feet, and
				the deadline above expiring. Both are the harness's own, and
				`failed` is where the harness's own belong.
			*/
			if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
				st.failed.Add(1)
			} else {
				st.closed.Add(1)
			}
			raw.Close()
			continue
		}
		st.full.Add(1)
		st.addLatency(time.Since(started))
		/*
			Closed the moment it is up, which is the load being described: the
			connection is not wanted, the handshake was. `Close` writes a TLS
			close_notify, so the server is told rather than left to a read
			timeout - a flood that vanished instead would be measuring the
			client timeout as well as the handshake.
		*/
		conn.Close()
	}
}
