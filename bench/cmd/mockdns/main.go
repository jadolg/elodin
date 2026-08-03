// Command mockdns is a DNS upstream that answers everything after a fixed
// delay.
//
// The delay is the point of it. A real upstream is tens of milliseconds away,
// and that latency is what decides how many workers a cache miss occupies; an
// upstream answering instantly would measure a server nobody runs.
package main

import (
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"

	"elodin.bench/internal/dnswire"
)

var served atomic.Int64

func main() {
	addr := flag.String("addr", "127.0.0.1:5399", "address to listen on")
	delay := flag.Duration("delay", 20*time.Millisecond, "delay before answering")
	ttl := flag.Uint("ttl", 300, "TTL of the answers")
	flag.Parse()

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("mockdns: %v", err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("mockdns: %v", err)
	}
	// The server forwards the client's advertised EDNS0 size, so answers can be
	// asked for in datagrams larger than the usual 4096.
	_ = pc.SetReadBuffer(4 << 20)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("mockdns: %v", err)
	}

	go serveTCP(ln, *delay, uint32(*ttl))

	log.Printf("mockdns: listening on %s, answering after %s", *addr, *delay)
	serveUDP(pc, *delay, uint32(*ttl))
}

func serveUDP(pc *net.UDPConn, delay time.Duration, ttl uint32) {
	for {
		buf := make([]byte, 65535)
		n, peer, err := pc.ReadFromUDP(buf)
		if err != nil {
			log.Printf("mockdns: udp read: %v", err)
			return
		}
		// One goroutine per query, so the delay is concurrent rather than a
		// queue: the upstream is meant to be slow, not serialised.
		go func(query []byte, peer *net.UDPAddr) {
			resp, err := answer(query, delay, ttl)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(resp, peer)
		}(buf[:n:n], peer)
	}
}

func serveTCP(ln net.Listener, delay time.Duration, ttl uint32) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				var hdr [2]byte
				if _, err := readFull(c, hdr[:]); err != nil {
					return
				}
				size := int(hdr[0])<<8 | int(hdr[1])
				query := make([]byte, size)
				if _, err := readFull(c, query); err != nil {
					return
				}
				resp, err := answer(query, delay, ttl)
				if err != nil {
					return
				}
				out := make([]byte, 2+len(resp))
				out[0] = byte(len(resp) >> 8)
				out[1] = byte(len(resp))
				copy(out[2:], resp)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}(conn)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}

func answer(query []byte, delay time.Duration, ttl uint32) ([]byte, error) {
	_, qtype, err := dnswire.Question(query)
	if err != nil {
		return nil, err
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	served.Add(1)
	if qtype != dnswire.TypeA {
		return dnswire.AnswerEmpty(query)
	}
	return dnswire.AnswerA(query, [4]byte{93, 184, 216, 34}, ttl)
}
