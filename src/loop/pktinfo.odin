package loop

import "base:intrinsics"
import "core:net"
import "core:sys/linux"

/*
The local end of a datagram: the address it was sent to, and for IPv6 the
interface it came in on. A reply sent from it leaves from the address the client
asked (RFC 1122 section 4.1.3.5, RFC 1123 section 2.3), where a plain `sendto`
on a wildcard socket leaves from whichever address the route picks.

A nil `address` is unknown, and a reply leaves as a plain `sendto` would.
*/
Udp_Local :: struct {
	address: net.Address,
	ifindex: u32,
}

/*
Linux's numbers, from `<linux/in.h>` and `<linux/in6.h>`, which
`core:sys/linux` does not carry. Stable ABI.
*/
@(private)
IPPROTO_IP :: 0
@(private)
IP_PKTINFO :: 8
@(private)
IPPROTO_IPV6 :: 41
@(private = "file")
IPV6_RECVPKTINFO :: 49
@(private)
IPV6_PKTINFO :: 50

// `struct in_pktinfo`.
@(private)
In_Pktinfo :: struct {
	ifindex:  i32,
	spec_dst: [4]u8,
	addr:     [4]u8,
}

// `struct in6_pktinfo`.
@(private)
In6_Pktinfo :: struct {
	addr:    [16]u8,
	ifindex: u32,
}

// `struct cmsghdr`, whose data starts at the next `size_t` boundary.
@(private = "file")
Cmsg_Hdr :: struct {
	len:   uint,
	level: i32,
	type:  i32,
}

@(private = "file")
cmsg_align :: #force_inline proc "contextless" (n: uint) -> uint {
	return (n + size_of(uint) - 1) & ~uint(size_of(uint) - 1)
}

@(private)
CMSG_DATA :: uint(size_of(Cmsg_Hdr) + size_of(uint) - 1) & ~uint(size_of(uint) - 1)

/*
Room for both kinds at once: an IPv6 socket is told about an IPv4 datagram in
an `IP_PKTINFO` and in an `IPV6_PKTINFO` holding the mapped address. In words,
so the buffer is `size_t` aligned as the kernel writes it.
*/
@(private)
CONTROL_WORDS :: 16

/*
Ask the kernel to report each datagram's local end to `recv_udp`. An IPv6
socket asks for both kinds: a dual-stack one receives IPv4 datagrams too, and
for those `IP_PKTINFO` is what names the local address the kernel would answer
from. The errno is the kernel's refusal, `.NONE` when both were set.
*/
want_destination :: proc(socket: net.UDP_Socket, v6: bool) -> linux.Errno {
	on: i32 = 1
	fd := linux.Fd(socket)
	if errno := linux.setsockopt_base(fd, IPPROTO_IP, IP_PKTINFO, &on); errno != .NONE {
		return errno
	}
	if v6 {
		return linux.setsockopt_base(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on)
	}
	return .NONE
}

/*
One `recvmsg`: the datagram, its source, and its local end from the control
messages `want_destination` asked for. A socket that never asked reports a nil
local address.
*/
@(private)
recvmsg_udp :: proc(socket: net.UDP_Socket, buf: []u8) -> (n: int, from: net.Endpoint, local: Udp_Local, err: net.UDP_Recv_Error) {
	addr: linux.Sock_Addr_Any
	control: [CONTROL_WORDS]uint
	iov := [1]linux.IO_Vec{{base = raw_data(buf), len = uint(len(buf))}}
	hdr := linux.Msg_Hdr {
		name    = &addr,
		namelen = size_of(addr),
		iov     = iov[:],
		control = ([^]u8)(&control)[:size_of(control)],
	}
	got, errno := linux.recvmsg(linux.Fd(socket), &hdr, {})
	switch {
	case errno == .EAGAIN:
		return 0, {}, {}, .Would_Block
	case errno != .NONE:
		return 0, {}, {}, .Unknown
	case .TRUNC in hdr.flags:
		return len(buf), {}, {}, .Excess_Truncated
	}
	#partial switch addr.family {
	case .INET:
		from = {address = net.IP4_Address(addr.sin_addr), port = int(addr.sin_port)}
	case .INET6:
		from = {address = transmute(net.IP6_Address)addr.sin6_addr, port = int(addr.sin6_port)}
	case:
		return 0, {}, {}, .Unknown
	}
	return got, from, local_of(hdr.control), nil
}

/*
The local end the control messages name. An `IP_PKTINFO` gives `ipi_spec_dst`,
the local address the kernel itself would answer from, which is the destination
for a unicast datagram and the interface's address for a broadcast one. An
`IPV6_PKTINFO` gives the destination and the interface, and is passed over for
a mapped IPv4 address, which the `IP_PKTINFO` beside it names, and for a
multicast one, which is no source for a reply (RFC 1122 section 4.1.3.5).
*/
@(private)
local_of :: proc(control: []u8) -> (local: Udp_Local) {
	rest := control
	for uint(len(rest)) >= CMSG_DATA {
		h := intrinsics.unaligned_load((^Cmsg_Hdr)(raw_data(rest)))
		if h.len < CMSG_DATA || h.len > uint(len(rest)) {
			break
		}
		data := rest[CMSG_DATA:h.len]
		switch {
		case h.level == IPPROTO_IP && h.type == IP_PKTINFO && len(data) >= size_of(In_Pktinfo):
			info := intrinsics.unaligned_load((^In_Pktinfo)(raw_data(data)))
			local = {address = net.IP4_Address(info.spec_dst)}
		case h.level == IPPROTO_IPV6 && h.type == IPV6_PKTINFO && len(data) >= size_of(In6_Pktinfo):
			info := intrinsics.unaligned_load((^In6_Pktinfo)(raw_data(data)))
			if !v4_mapped(info.addr) && info.addr[0] != 0xff {
				local = {address = transmute(net.IP6_Address)info.addr, ifindex = info.ifindex}
			}
		}
		step := cmsg_align(h.len)
		if step >= uint(len(rest)) {
			break
		}
		rest = rest[step:]
	}
	return
}

@(private = "file")
v4_mapped :: proc(a: [16]u8) -> bool {
	a := a
	for b in a[:10] {
		if b != 0 {
			return false
		}
	}
	return a[10] == 0xff && a[11] == 0xff
}

/*
One `sendmsg` to `to`, from `from` when its address is known: an IPv4 one as
`IP_PKTINFO`'s `ipi_spec_dst`, an IPv6 one as `IPV6_PKTINFO`. The interface is
left to the route, except where `send_ifindex` says otherwise. An IPv4 source
suits a mapped `to` on an IPv6 socket as well: the kernel sends that datagram
as IPv4 and reads the `IP_PKTINFO` there.
*/
@(private)
sendmsg_udp :: proc(socket: net.UDP_Socket, buf: []u8, to: net.Endpoint, from: Udp_Local) -> (int, net.UDP_Send_Error) {
	addr: linux.Sock_Addr_Any
	namelen: i32
	switch a in to.address {
	case net.IP4_Address:
		addr.ipv4 = {sin_family = .INET, sin_port = u16be(to.port), sin_addr = ([4]u8)(a)}
		namelen = size_of(linux.Sock_Addr_In)
	case net.IP6_Address:
		addr.ipv6 = {sin6_family = .INET6, sin6_port = u16be(to.port), sin6_addr = transmute([16]u8)a}
		namelen = size_of(linux.Sock_Addr_In6)
	case:
		return 0, .Invalid_Argument
	}
	control: [CONTROL_WORDS]uint
	bytes := ([^]u8)(&control)
	used: uint
	switch a in from.address {
	case net.IP4_Address:
		used = put_cmsg(bytes, IPPROTO_IP, IP_PKTINFO, In_Pktinfo{spec_dst = ([4]u8)(a)})
	case net.IP6_Address:
		info := In6_Pktinfo {
			addr    = transmute([16]u8)a,
			ifindex = send_ifindex(from, to.address),
		}
		used = put_cmsg(bytes, IPPROTO_IPV6, IPV6_PKTINFO, info)
	}
	iov := [1]linux.IO_Vec{{base = raw_data(buf), len = uint(len(buf))}}
	hdr := linux.Msg_Hdr {
		name    = &addr,
		namelen = namelen,
		iov     = iov[:],
		control = bytes[:used],
	}
	n, errno := linux.sendmsg(linux.Fd(socket), &hdr, {.NOSIGNAL})
	#partial switch errno {
	case .NONE:
		return n, nil
	case .EAGAIN:
		return 0, .Would_Block
	}
	return 0, .Unknown
}

/*
The interface an IPv6 reply names: the one its query came in on when either end
is link-local (fe80::/10), which is ambiguous without it, and otherwise 0, so
the routing table still picks the way out.
*/
@(private)
send_ifindex :: proc(from: Udp_Local, to: net.Address) -> u32 {
	link_local :: proc(a: net.Address) -> bool {
		x, v6 := a.(net.IP6_Address)
		return v6 && u16(x[0]) & 0xffc0 == 0xfe80
	}
	return from.ifindex if link_local(from.address) || link_local(to) else 0
}

// Write one control message at the start of `bytes`, and say how much it took.
@(private)
put_cmsg :: proc(bytes: [^]u8, level, type: i32, data: $T) -> uint {
	length := CMSG_DATA + size_of(T)
	intrinsics.unaligned_store((^Cmsg_Hdr)(bytes), Cmsg_Hdr{len = length, level = level, type = type})
	intrinsics.unaligned_store((^T)(&bytes[CMSG_DATA]), data)
	return cmsg_align(length)
}
