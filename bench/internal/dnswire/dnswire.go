// Package dnswire builds and reads the few DNS messages the benchmark needs.
//
// Hand-rolled rather than taken from a library, and deliberately independent of
// elodin's own codec: a load generator that shared the encoder under test could
// agree with a bug in it and still report success. The same reasoning the
// integration suite applies to its fixtures.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	TypeA    = 1
	TypeAAAA = 28
	ClassIN  = 1
)

// Query builds a standard recursive query for name/qtype.
//
// udpSize > 0 appends an EDNS0 OPT record advertising that payload size, which
// is what a real client does and what the server echoes upstream.
func Query(id uint16, name string, qtype uint16, udpSize uint16) []byte {
	return query(id, name, qtype, udpSize, false)
}

// QueryDO is the same with the DO bit set, which is how a client says it wants
// DNSSEC records and, in turn, how it can be told whether the answer was
// authenticated.
func QueryDO(id uint16, name string, qtype uint16, udpSize uint16) []byte {
	return query(id, name, qtype, udpSize, true)
}

func query(id uint16, name string, qtype uint16, udpSize uint16, do bool) []byte {
	buf := make([]byte, 0, 64)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // RD
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // NSCOUNT
	arcount := uint16(0)
	if udpSize > 0 {
		arcount = 1
	}
	buf = binary.BigEndian.AppendUint16(buf, arcount)

	buf = appendName(buf, name)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, ClassIN)

	if udpSize > 0 {
		buf = append(buf, 0) // root name
		buf = binary.BigEndian.AppendUint16(buf, 41)
		buf = binary.BigEndian.AppendUint16(buf, udpSize)
		flags := uint16(0)
		if do {
			flags = 0x8000 // DO
		}
		buf = append(buf, 0, 0) // extended rcode, version
		buf = binary.BigEndian.AppendUint16(buf, flags)
		buf = binary.BigEndian.AppendUint16(buf, 0) // rdlength
	}
	return buf
}

func appendName(buf []byte, name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	return append(buf, 0)
}

// Reply is what the generator checks per answer: enough to know the response
// belongs to the query that was sent and says what was expected.
type Reply struct {
	ID        uint16
	Rcode     int
	AnCount   int
	Truncated bool
	// AD is the resolver's assertion that it authenticated the data. It is what
	// the DNSSEC survey compares: an answer can be correct and still not carry
	// it, and that difference is the whole question.
	AD bool
}

func ParseReply(msg []byte) (Reply, error) {
	if len(msg) < 12 {
		return Reply{}, fmt.Errorf("short message: %d bytes", len(msg))
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return Reply{}, errors.New("not a response")
	}
	return Reply{
		ID:        binary.BigEndian.Uint16(msg[0:2]),
		Rcode:     int(flags & 0x000F),
		AnCount:   int(binary.BigEndian.Uint16(msg[6:8])),
		Truncated: flags&0x0200 != 0,
		AD:        flags&0x0020 != 0,
	}, nil
}

// Question reports the name and type a query asks about, so the mock upstream
// can answer it. Compression never appears in a question section.
func Question(msg []byte) (name string, qtype uint16, err error) {
	if len(msg) < 12 {
		return "", 0, fmt.Errorf("short message: %d bytes", len(msg))
	}
	off := 12
	var sb strings.Builder
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name runs past the message")
		}
		n := int(msg[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 {
			return "", 0, errors.New("compression pointer in a question")
		}
		if off+n > len(msg) {
			return "", 0, errors.New("label runs past the message")
		}
		sb.Write(msg[off : off+n])
		sb.WriteByte('.')
		off += n
	}
	if off+4 > len(msg) {
		return "", 0, errors.New("question truncated")
	}
	return sb.String(), binary.BigEndian.Uint16(msg[off : off+2]), nil
}

// AnswerA builds a reply to query carrying one A record, reusing the query's
// question section verbatim so the name compression stays trivial.
func AnswerA(query []byte, ip [4]byte, ttl uint32) ([]byte, error) {
	qEnd, err := questionEnd(query)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, qEnd+16)
	out = append(out, query[:qEnd]...)

	binary.BigEndian.PutUint16(out[2:4], 0x8180) // QR, RD, RA
	binary.BigEndian.PutUint16(out[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], 1)      // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)     // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0)    // ARCOUNT

	out = append(out, 0xC0, 0x0C) // pointer to the question's name
	out = binary.BigEndian.AppendUint16(out, TypeA)
	out = binary.BigEndian.AppendUint16(out, ClassIN)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, 4)
	out = append(out, ip[0], ip[1], ip[2], ip[3])
	return out, nil
}

// AnswerEmpty builds a NOERROR reply with no answer records, which is what the
// mock returns for types it does not synthesise.
func AnswerEmpty(query []byte) ([]byte, error) {
	qEnd, err := questionEnd(query)
	if err != nil {
		return nil, err
	}
	out := make([]byte, qEnd)
	copy(out, query[:qEnd])
	binary.BigEndian.PutUint16(out[2:4], 0x8180)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out, nil
}

func questionEnd(msg []byte) (int, error) {
	if len(msg) < 12 {
		return 0, fmt.Errorf("short message: %d bytes", len(msg))
	}
	off := 12
	for {
		if off >= len(msg) {
			return 0, errors.New("name runs past the message")
		}
		n := int(msg[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 {
			return 0, errors.New("compression pointer in a question")
		}
		off += n
	}
	off += 4
	if off > len(msg) {
		return 0, errors.New("question truncated")
	}
	return off, nil
}
