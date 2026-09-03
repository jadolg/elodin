package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"elodin.bench/internal/dnswire"
)

// ---------------------------------------------------------------- the clients

// runClient starts one client and returns the function that stops it. Sending
// runs for dur; the returned stop closes the sockets, which is also what ends
// the readers.
func runClient(s *server, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	switch {
	case c.idle:
		return runIdle(s.tcpAddr, c, dur, st)
	case c.redial:
		return runTCPRedial(s.tcpAddr, c, dur, tag, track, st)
	}
	switch c.transport {
	case "tcp":
		return runTCP(s.tcpAddr, c, dur, tag, track, st)
	case "doh1", "doh2":
		return runDoH(s.dohAddr, s.certPath, c, dur, tag, track, st)
	default:
		return runUDP(s.udpAddr, c, dur, tag, track, st)
	}
}

/*
The EDNS buffer every query here advertises.

One figure for every client and every transport, TCP included. It has to be the
same everywhere or the arms stop being comparable: `src/upstream/plain.odin`
sizes its receive buffer from what the client's query asked for and retries over
TCP when the answer overflows it, so a client advertising less than the mock's
answer size would cost the server two upstream round trips per query where the
others cost one. 1232 is the figure a real client sends, and the shipped
`max_udp_response`.
*/
const ednsSize = 1232

/*
tracker matches a reply to the query that asked it, for the client whose latency
is being measured.

Only the victim tracks. A flood's ids wrap around inside a run, so its map would
match replies to the wrong queries and grow without bound; `on` is what keeps it
out of the flood's path rather than a second code path.
*/
type tracker struct {
	mu   sync.Mutex
	sent map[uint16]time.Time
	on   bool
}

func newTracker(on bool) *tracker {
	return &tracker{sent: map[uint16]time.Time{}, on: on}
}

func (t *tracker) put(id uint16) {
	if !t.on {
		return
	}
	t.mu.Lock()
	t.sent[id] = time.Now()
	t.mu.Unlock()
}

// took reports how long a reply took, and whether this client is tracking the
// query it answers at all.
func (t *tracker) took(id uint16) (time.Duration, bool) {
	if !t.on {
		return 0, false
	}
	t.mu.Lock()
	at, ok := t.sent[id]
	delete(t.sent, id)
	t.mu.Unlock()
	if !ok {
		return 0, false
	}
	return time.Since(at), true
}

/*
record files one reply: what it was, how many bytes it delivered, and how long
it took.

Shared by both readers, so the transports cannot drift into counting
differently - which matters because several results are read as a UDP row
against a TCP one.

A truncated answer is not counted as answered. It carries no records: over UDP it
is the slip telling the client to come back over TCP, and counting it would
report a rate limit as service.
*/
func record(st *stats, size int, rep dnswire.Reply, t *tracker) {
	st.replies.Add(1)
	st.bytesIn.Add(int64(size))
	st.addRcode(rep.Rcode)
	switch {
	case rep.Truncated:
		st.truncated.Add(1)
	case rep.Rcode != 0:
		st.badRcode.Add(1)
	default:
		st.full.Add(1)
	}
	if d, ok := t.took(rep.ID); ok && !rep.Truncated && rep.Rcode == 0 {
		st.addLatency(d)
	}
}

func runUDP(dst string, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	var conns []*net.UDPConn
	var wg sync.WaitGroup

	for i := 0; i < c.sockets; i++ {
		conn, err := dialUDP(dst, c.src)
		if err != nil {
			fatal(fmt.Errorf("udp from %s: %w", c.src, err))
		}
		conns = append(conns, conn)
		t := newTracker(track)

		wg.Add(2)
		go func() {
			defer wg.Done()
			udpReader(conn, st, t)
		}()
		go func(idx int) {
			defer wg.Done()
			udpWriter(conn, c, dur, tag, idx, st, t)
		}(i)
	}

	return func() {
		for _, conn := range conns {
			conn.Close()
		}
		wg.Wait()
	}
}

// udpReader counts replies until the socket is closed, which is how the harness
// stops it.
func udpReader(conn *net.UDPConn, st *stats, t *tracker) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		rep, err := dnswire.ParseReply(buf[:n])
		if err != nil {
			continue
		}
		record(st, n, rep, t)
	}
}

func udpWriter(conn *net.UDPConn, c clientSpec, dur time.Duration, tag string, idx int, st *stats, t *tracker) {
	seq := 0
	pace(c.rate/max(c.sockets, 1), dur, func() bool {
		seq++
		id := uint16(seq)
		q := dnswire.Query(id, c.name(idx, seq, tag), dnswire.TypeA, ednsSize)
		t.put(id)
		n, err := conn.Write(q)
		if err != nil {
			return false
		}
		st.offered.Add(1)
		st.bytesOut.Add(int64(n))
		return true
	})
}

func runTCP(dst string, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	var conns []net.Conn
	var wg sync.WaitGroup
	// Closed by the stop function, so a reader can tell the harness ending the
	// run from the server ending the connection. See `tcpReader`.
	stopped := make(chan struct{})

	for i := 0; i < c.sockets; i++ {
		conn, err := dialTCP(dst, c.src)
		if err != nil {
			fatal(fmt.Errorf("tcp from %s: %w", c.src, err))
		}
		conns = append(conns, conn)
		t := newTracker(track)

		wg.Add(2)
		go func() {
			defer wg.Done()
			tcpReader(conn, st, t, stopped)
		}()
		go func(idx int) {
			defer wg.Done()
			tcpWriter(conn, c, dur, tag, idx, st, t)
		}(i)
	}

	return func() {
		close(stopped)
		for _, conn := range conns {
			conn.Close()
		}
		wg.Wait()
	}
}

/*
tcpReader counts replies until the connection ends, and records how it ended.

An EOF after `stopped` is the harness closing the socket. Before it, the server
stopped serving this connection, which is what an over-budget query on a stream
transport looks like from out here - there is nothing to truncate on a stream, so
the budget running out shows up as the connection ending.
*/
func tcpReader(conn net.Conn, st *stats, t *tracker, stopped <-chan struct{}) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if isClose(err) {
				select {
				case <-stopped:
				default:
					st.closed.Add(1)
				}
			}
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		rep, err := dnswire.ParseReply(msg)
		if err != nil {
			continue
		}
		record(st, len(msg)+2, rep, t)
	}
}

func tcpWriter(conn net.Conn, c clientSpec, dur time.Duration, tag string, idx int, st *stats, t *tracker) {
	seq := 0
	pace(c.rate/max(c.sockets, 1), dur, func() bool {
		seq++
		id := uint16(seq)
		q := frame(dnswire.Query(id, c.name(idx, seq, tag), dnswire.TypeA, ednsSize))
		t.put(id)
		if _, err := conn.Write(q); err != nil {
			return false
		}
		st.offered.Add(1)
		st.bytesOut.Add(int64(len(q)))
		return true
	})
}

/*
runIdle opens connections and holds them, asking nothing on any of them.

The whole client. There is no writer, because writing is the thing this load does
not do: what it occupies is a slot in `server.max_connections` and a thread behind
it, and the response limiter never sees a client that asks no questions.

Each connection gets a reader, and the reader is the measurement. A connection the
server had no room for is closed on accept - the kernel completed the handshake out
of the listen backlog first, so the dial succeeded either way - and the read is
what finds that out. So `dials` is what was opened and `closed` is what the server
refused; the difference is what this client is holding.

`failed` counts a dial that never connected at all, which on loopback is the
listen backlog overflowing rather than anything the server decided. Worth keeping
apart: it is the one number here that says the harness, not the server, ran out.
*/
func runIdle(dst string, c clientSpec, dur time.Duration, st *stats) func() {
	var conns []net.Conn
	var wg sync.WaitGroup
	stopped := make(chan struct{})

	for i := 0; i < c.sockets; i++ {
		conn, err := dialTCP(dst, c.src)
		if err != nil {
			st.failed.Add(1)
			continue
		}
		st.dials.Add(1)
		conns = append(conns, conn)

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			buf := make([]byte, 1)
			// Blocks for the arm on a connection the server kept. A refusal
			// arrives here as an EOF or a reset, and only counts as one if the
			// harness had not already asked the client to stop.
			if _, err := conn.Read(buf); err != nil {
				select {
				case <-stopped:
				default:
					st.closed.Add(1)
				}
			}
		}(conn)
	}

	return func() {
		close(stopped)
		for _, conn := range conns {
			conn.Close()
		}
		wg.Wait()
	}
}

/*
runTCPRedial asks each query on a connection of its own.

For the victim of a client holding the table: what is being measured is whether a
connection can be had, so the client has to ask for one per query. A client that
dialled once at the start would report one refused connection and then fall
silent, and one that was given a connection would keep answering out of it and
say nothing about the next client to arrive.

`offered` is counted before the dial rather than after it, so a query that could
not be sent for want of a connection is still a query this client wanted answered.
That is the whole of the victim's experience here: the refusal is not a rcode or a
truncated answer, it is the absence of anywhere to ask.
*/
func runTCPRedial(dst string, c clientSpec, dur time.Duration, tag string, track bool, st *stats) func() {
	stopped := make(chan struct{})
	var wg sync.WaitGroup
	t := newTracker(track)

	wg.Add(1)
	go func() {
		defer wg.Done()
		seq := 0
		pace(c.rate, dur, func() bool {
			select {
			case <-stopped:
				return false
			default:
			}
			seq++
			id := uint16(seq)
			st.offered.Add(1)
			conn, err := dialTCP(dst, c.src)
			if err != nil {
				st.failed.Add(1)
				return true
			}
			st.dials.Add(1)
			defer conn.Close()
			// One round trip and no more, so a connection is never held past
			// the query it was opened for.
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			q := frame(dnswire.Query(id, c.name(0, seq, tag), dnswire.TypeA, ednsSize))
			t.put(id)
			if _, err := conn.Write(q); err != nil {
				st.closed.Add(1)
				return true
			}
			st.bytesOut.Add(int64(len(q)))
			var hdr [2]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				// No answer and no connection: the server closed it, which is
				// what a refusal on accept looks like from out here.
				st.closed.Add(1)
				return true
			}
			msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(conn, msg); err != nil {
				return true
			}
			rep, perr := dnswire.ParseReply(msg)
			if perr != nil {
				return true
			}
			record(st, len(msg)+2, rep, t)
			return true
		})
	}()

	return func() {
		close(stopped)
		wg.Wait()
	}
}

// frame prefixes a message with its length, which is how DNS travels on a
// stream.
func frame(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

func isClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

func dialUDP(dst, src string) (*net.UDPConn, error) {
	ra, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return nil, err
	}
	la := &net.UDPAddr{IP: net.ParseIP(src)}
	conn, err := net.DialUDP("udp", la, ra)
	if err != nil {
		return nil, err
	}
	// Room for the replies of a flood, so a datagram this client fails to read
	// in time is not counted as one the server withheld.
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)
	return conn, nil
}

func dialTCP(dst, src string) (net.Conn, error) {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	return d.Dial("tcp", dst)
}

// pace calls send at `rate` per second until `dur` is up, or flat out when rate
// is 0, which is what an unthrottled flood is.
func pace(rate int, dur time.Duration, send func() bool) {
	end := time.Now().Add(dur)
	if rate <= 0 {
		paceFlatOut(end, send)
		return
	}
	paceAt(rate, end, send)
}

/*
paceFlatOut sends as fast as the socket accepts.

Sixty-four sends between clock reads: at two million queries a second a
`time.Now` per query is a measurable share of the loop, and the only thing the
clock decides here is when to stop.
*/
func paceFlatOut(end time.Time, send func() bool) {
	for time.Now().Before(end) {
		for i := 0; i < 64; i++ {
			if !send() {
				return
			}
		}
	}
}

/*
paceAt holds an offered rate.

A millisecond quantum with a fractional carry rather than a ticker per query:
twenty thousand queries a second is a query every fifty microseconds, which is
shorter than the timer this would need, so a millisecond's worth goes out at a
time and the sleep is what the batches wait on. The carry is what keeps a rate
that is not a multiple of a thousand honest over the run.
*/
func paceAt(rate int, end time.Time, send func() bool) {
	perTick := float64(rate) / 1000.0
	credit := 0.0
	next := time.Now()
	for time.Now().Before(end) {
		credit += perTick
		for credit >= 1 {
			if !send() {
				return
			}
			credit--
		}
		next = next.Add(time.Millisecond)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
}
