package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"time"

	"elodin.bench/internal/dnswire"
)

// --------------------------------------------------------- the mock upstream

type mock struct {
	pc         *net.UDPConn
	ln         net.Listener
	addr       string
	delay      time.Duration
	records    int
	answerSize int
	served     atomic.Int64
}

func startMock(delay time.Duration, records int) (*mock, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
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
		return nil, err
	}
	m := &mock{pc: pc, ln: ln, addr: pc.LocalAddr().String(), delay: delay, records: records}

	probe, _ := answer(dnswire.Query(1, "size.rrl.test", dnswire.TypeA, 0), records)
	m.answerSize = len(probe)

	go m.serveTCP()
	go m.serveUDP()
	return m, nil
}

func (m *mock) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, peer, err := m.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		// One goroutine per query, so the delay is a round trip rather than a
		// queue: the upstream is meant to be slow, not serialised.
		go func(q []byte, peer *net.UDPAddr) {
			resp, err := m.reply(q)
			if err != nil {
				return
			}
			_, _ = m.pc.WriteToUDP(resp, peer)
		}(q, peer)
	}
}

func (m *mock) serveTCP() {
	for {
		conn, err := m.ln.Accept()
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
	resp, err := answer(query, m.records)
	if err != nil {
		return nil, err
	}
	m.served.Add(1)
	return resp, nil
}

func (m *mock) stop() {
	m.pc.Close()
	m.ln.Close()
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
func answer(query []byte, records int) ([]byte, error) {
	out, err := dnswire.AnswerA(query, [4]byte{203, 0, 113, 1}, 300)
	if err != nil {
		return nil, err
	}
	for i := 1; i < records; i++ {
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, dnswire.TypeA)
		out = binary.BigEndian.AppendUint16(out, dnswire.ClassIN)
		out = binary.BigEndian.AppendUint32(out, 300)
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, 203, 0, 113, byte(1+i%250))
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(records))
	return out, nil
}
