package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"elodin.bench/internal/dnswire"
)

// --------------------------------------------------------- the mock upstream

/*
What the mock does with a query. Only the `upstream-fail` arms change it.

`mockBlackhole` reads every query and answers none, over both transports, which
is an upstream behind a firewall that drops: the forwarder learns nothing until
its own timeout. `mockRefused` closes both sockets, so the kernel answers a
datagram with port unreachable and a connection with a reset - an upstream whose
process has gone, which a forwarder can learn in a syscall.
*/
const (
	mockUp int32 = iota
	mockBlackhole
	mockRefused
)

type mock struct {
	mu sync.Mutex
	pc *net.UDPConn
	ln net.Listener
	// Holds the UDP port while `mockRefused`; see `fail`.
	hold       *net.UDPConn
	addr       string
	delay      time.Duration
	records    int
	ttl        uint32
	answerSize int
	served     atomic.Int64
	mode       atomic.Int32
}

func startMock(delay time.Duration, records int, ttl uint32) (*mock, error) {
	m := &mock{addr: "127.0.0.1:0", delay: delay, records: records, ttl: ttl}
	if err := m.listen(); err != nil {
		return nil, err
	}
	probe, _ := answer(dnswire.Query(1, "size.rrl.test", dnswire.TypeA, 0), records, ttl)
	m.answerSize = len(probe)
	return m, nil
}

// listen binds both sockets on `m.addr` and serves them, which is how the mock
// starts and how it comes back from `mockRefused` on the port it had.
func (m *mock) listen() error {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(m.addr)))
	if err != nil {
		return err
	}
	_ = pc.SetReadBuffer(8 << 20)
	_ = pc.SetWriteBuffer(8 << 20)
	/*
		TCP as well as UDP, on the same port.

		A forwarder that receives a datagram larger than the buffer the query
		advertised retries the same question over TCP - `src/upstream/plain.odin`
		says so - and an upstream that only listens on UDP turns that retry into a
		dial failure, three of which park the upstream for ten seconds. Which is
		how this was found: a mock with no TCP side made an arm read as a server
		failing every query, and the failure was the harness's.
	*/
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return err
	}
	m.mu.Lock()
	m.pc, m.ln, m.addr = pc, ln, pc.LocalAddr().String()
	m.mu.Unlock()
	go m.serveTCP(ln)
	go m.serveUDP(pc)
	return nil
}

/*
fail puts the mock into `mode`; `restore` takes it back out.

`mockRefused` keeps the UDP port with a socket connected to a peer nobody sends
from: a datagram from anywhere else matches no socket, so the kernel still
answers it with port unreachable, but no other socket can take the port in the
meantime. Without it the forwarder's own per-exchange sockets, a thousand or
more of them held by the outage, bind random ports and one landing on this one
makes `restore` fail.
*/
func (m *mock) fail(mode int32) {
	m.mode.Store(mode)
	if mode != mockRefused {
		return
	}
	m.closeSockets()
	hold, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(m.addr)), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err == nil {
		m.mu.Lock()
		m.hold = hold
		m.mu.Unlock()
	}
}

// restore is up before the sockets are, so the first datagram the new ones read
// is answered rather than dropped as still failing.
func (m *mock) restore() error {
	refused := m.mode.Load() == mockRefused
	m.mode.Store(mockUp)
	if !refused {
		return nil
	}
	m.mu.Lock()
	if m.hold != nil {
		m.hold.Close()
		m.hold = nil
	}
	m.mu.Unlock()
	return m.listen()
}

func (m *mock) closeSockets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pc.Close()
	m.ln.Close()
	if m.hold != nil {
		m.hold.Close()
	}
}

func (m *mock) serveUDP(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if m.mode.Load() != mockUp {
			continue
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		// One goroutine per query, so the delay is a round trip rather than a
		// queue: the upstream is meant to be slow, not serialised.
		go func(q []byte, peer *net.UDPAddr) {
			resp, err := m.reply(q)
			if err != nil || m.mode.Load() != mockUp {
				return
			}
			_, _ = pc.WriteToUDP(resp, peer)
		}(q, peer)
	}
}

func (m *mock) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go m.serveConn(conn)
	}
}

func (m *mock) serveConn(c net.Conn) {
	defer c.Close()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		// A connection opened before the mock went away is reset with it, the
		// way the kernel would for a process that exited.
		switch m.mode.Load() {
		case mockRefused:
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			return
		case mockBlackhole:
			continue
		}
		resp, err := m.reply(q)
		if err != nil {
			return
		}
		if _, err := c.Write(frame(resp)); err != nil {
			return
		}
	}
}

// reply is one upstream round trip: the delay, then the answer.
func (m *mock) reply(query []byte) ([]byte, error) {
	time.Sleep(m.delay)
	resp, err := answer(query, m.records, m.ttl)
	if err != nil {
		return nil, err
	}
	m.served.Add(1)
	return resp, nil
}

func (m *mock) stop() {
	m.closeSockets()
}

/*
answer builds a reply carrying `records` A records.

Several rather than one because the size of an answer is the amplification
factor: the budget is a count of responses, and what one response costs the
address it is aimed at is however many bytes this returns. Seventy A records is
about 1180 bytes, which is what fits under the shipped `max_udp_response` of
1232 - so the arms measure the largest answer the default configuration will
send rather than the smallest one a mock could return.
*/
func answer(query []byte, records int, ttl uint32) ([]byte, error) {
	out, err := dnswire.AnswerA(query, [4]byte{203, 0, 113, 1}, ttl)
	if err != nil {
		return nil, err
	}
	for i := 1; i < records; i++ {
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, dnswire.TypeA)
		out = binary.BigEndian.AppendUint16(out, dnswire.ClassIN)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, 203, 0, 113, byte(1+i%250))
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(records))
	return out, nil
}
