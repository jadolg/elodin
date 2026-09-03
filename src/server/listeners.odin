package server

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "elodin:config"
import "elodin:dns"
import "elodin:logx"
import "elodin:metrics"
import "elodin:pool"
import "elodin:tlsx"

Listeners :: struct {
	/*
	The UDP readers, one per thread, each with a socket of its own.

	Empty when UDP is off, and one entry long unless `listeners.udp.readers`
	says otherwise. Allocated once at startup and never resized, because each
	loop holds a pointer into it for the life of the process.
	*/
	udp:            []Udp_Reader,
	// What the UDP sockets actually bound - one endpoint, since every reader
	// binds the same one. Read once: `plausible_source` needs it for every
	// datagram, and asking the kernel each time is a syscall per query for an
	// answer that cannot change.
	udp_bound:      net.Endpoint,
	tcp_socket:     net.TCP_Socket,
	dot_socket:     net.TCP_Socket,
	doh_socket:     net.TCP_Socket,
	// The Prometheus endpoint, which is not a DNS listener but is a socket with
	// the same lifetime: opened by `start_listeners`, closed by
	// `stop_listeners`, and its loop joined with the rest.
	metrics_socket: net.TCP_Socket,
	tcp_open:       bool,
	dot_open:       bool,
	doh_open:       bool,
	metrics_open:   bool,
	dot_ctx:        ^tlsx.Context,
	doh_ctx:        ^tlsx.Context,
	/*
	Guards the two above against the reload that replaces them.

	`reload_tls` frees the context it displaces, and a connection thread that
	has read the pointer but not yet started its session is holding a pointer to
	exactly that. The two are not otherwise ordered - the reload runs on the
	maintenance loop and the read on a thread per connection - so an atomic on
	the pointer settles which context a connection gets and says nothing about
	whether the one it got is still there. See `accept_tls`.
	*/
	tls_mu:         sync.RW_Mutex,
	conns:          Conn_Manager,
	stop:           bool,
	/*
	What the read and accept loops were given, held here rather than by the
	loops themselves.

	A loop hands its context to every job it queues and every connection thread
	it starts, and those outlive it: a queued query still runs while the pool
	drains, and a connection thread sits in a client read for as long as its
	timeout allows. A loop that released its own context on the way out would
	pull the ground from under both. `destroy_listeners` releases them instead,
	once there is nothing left that could be holding one.

	The UDP loops' contexts are held the same way and in the same place as their
	sockets, in `udp` above, since there is now one of each per reader.
	*/
	stream_loop_ctx:  [dynamic]^Stream_Context,
	metrics_loop_ctx: ^Metrics_Context,
}

/*
How long a loop may sit in a blocking call before it gets a chance to notice
that it has been told to stop.

Closing a socket does not reliably wake a thread already blocked reading or
accepting on it - the same reason `upstream/h2client.odin` polls rather than
trusting close to cut a read short - so the loops carry a timeout and come up
for air instead. Without it `conn_manager_shutdown` joins a thread that is
never going to return. One wakeup a second per listener costs nothing next to
the queries going through them.
*/
@(private)
LISTENER_POLL :: time.Second

@(private)
parse_bind :: proc(address: string, port: int) -> (endpoint: net.Endpoint, ok: bool) {
	addr := net.parse_address(address)
	if addr == nil {
		return {}, false
	}
	return net.Endpoint{address = addr, port = port}, true
}

/*
Explain a bind failure in terms of what to do about it.

The two that actually happen are a privileged port without the capability to
use it, and something already listening — usually the system resolver.
*/
@(private)
report_bind_failure :: proc(setting: string, address: string, port: int, err: net.Network_Error) {
	logx.errorf("%s: cannot bind %s:%d (%v)", setting, address, port, err)

	#partial switch e in err {
	case net.Bind_Error:
		#partial switch e {
		case .Insufficient_Permissions_For_Address:
			logx.errorf("ports below 1024 need privileges: either grant them once with")
			logx.errorf("sudo setcap 'cap_net_bind_service=+ep' ./bin/elodin")
			logx.errorf("or use a high port, as examples/dev.yaml does")
		case .Address_In_Use:
			logx.errorf("something is already listening there; on most systems that is systemd-resolved:")
			logx.errorf("sudo systemctl stop systemd-resolved")
		}
	}
}

start_listeners :: proc(s: ^Server, l: ^Listeners) -> bool {
	conn_manager_init(&l.conns, s.cfg.server.max_connections, s.cfg.server.max_connections_per_prefix)
	// Said only where it applies: with every stream listener off there are no
	// client connections for the table to bound, and the line would be about a
	// limit nothing in this run can reach.
	if config.stream_listeners_enabled(s.cfg.listeners) {
		logx.infof(
			"%s",
			connection_limits_line(s.cfg.server.max_connections, s.cfg.server.max_connections_per_prefix),
		)
	}

	if s.cfg.listeners.udp.enabled {
		if !start_udp(s, l) {
			return false
		}
	}
	if s.cfg.listeners.tcp.enabled {
		if !start_tcp(s, l) {
			return false
		}
	}
	if s.cfg.listeners.dot.enabled {
		if !start_dot(s, l) {
			return false
		}
	}
	if s.cfg.listeners.doh.enabled {
		if !start_doh(s, l) {
			return false
		}
	}
	// Last, so that a port clash on an endpoint nobody queries cannot stop the
	// ones they do from coming up first — and still fatal, because an operator
	// who turned it on is about to be told the resolver is unmonitored.
	if s.cfg.metrics.enabled {
		if !start_metrics(s, l) {
			return false
		}
	}
	return true
}

stop_listeners :: proc(l: ^Listeners) {
	sync.atomic_store(&l.stop, true)
	for reader in l.udp {
		net.close(reader.socket)
	}
	if l.tcp_open {
		net.close(l.tcp_socket)
	}
	if l.dot_open {
		net.close(l.dot_socket)
	}
	if l.doh_open {
		net.close(l.doh_socket)
	}
	if l.metrics_open {
		net.close(l.metrics_socket)
	}
	conn_manager_shutdown(&l.conns)
	tlsx.context_destroy(l.dot_ctx)
	tlsx.context_destroy(l.doh_ctx)
}

/*
Release what the loops were given.

Separate from `stop_listeners` because stopping is not the same as being
finished with: a query queued before the sockets closed still runs while the
worker pool drains, and it reads the context of the loop that queued it. The
caller drains the pools between the two.
*/
destroy_listeners :: proc(l: ^Listeners) {
	for &reader in l.udp {
		if reader.ctx != nil {
			free(reader.ctx)
			reader.ctx = nil
		}
	}
	delete(l.udp)
	l.udp = nil
	for ctx in l.stream_loop_ctx {
		free(ctx)
	}
	delete(l.stream_loop_ctx)
	l.stream_loop_ctx = nil
	if l.metrics_loop_ctx != nil {
		free(l.metrics_loop_ctx)
		l.metrics_loop_ctx = nil
	}
}

// --- UDP ------------------------------------------------------------------

/*
One reader: a socket, the thread that drains it, and what it has drained.

They exist because everything a datagram costs before the rate limiter sees it
happens on the thread that read it, so a single reader is one core's worth of
drain rate for the whole server, and past that rate the kernel drops datagrams
in the receive queue - where no configuration and no budget can reach them. See
`listeners.udp.readers`, and the measurement it points at.
*/
Udp_Reader :: struct {
	socket:   net.UDP_Socket,
	/*
	This socket's inode, as `/proc/net/udp` names it, or 0 when it could not be
	read.

	Kept so the drop counter the kernel keeps for this socket can be found
	again: the file is keyed by inode, and matching on the bound address instead
	would pick up every other socket on the port - which, with `SO_REUSEPORT`,
	is precisely the other readers.
	*/
	inode:    u64,
	// Datagrams this reader has taken off its socket, whatever became of them.
	// Read by the metrics endpoint; incremented by the loop.
	received: u64,
	// The context handed to the loop. Released by `destroy_listeners`, not by
	// the loop, for the reason the field comment on `stream_loop_ctx` gives.
	ctx:      ^Udp_Context,
}

@(private)
Udp_Context :: struct {
	server:    ^Server,
	listeners: ^Listeners,
	// The reader this loop is, in `listeners.udp`. A pointer rather than an
	// index because the loop touches it per datagram; the slice is allocated
	// once and never resized, so it stays valid for the life of the process.
	reader:    ^Udp_Reader,
}

@(private)
Udp_Job :: struct {
	ctx:    ^Udp_Context,
	data:   []u8,
	client: net.Endpoint,
	// The socket the datagram arrived on, which is the one the answer goes back
	// out of. Every reader's socket is bound to the same address and port, so
	// any of them would put the same thing on the wire; replying on the one
	// that received keeps a query's send queue and its receive queue together.
	socket: net.UDP_Socket,
}

@(private)
start_udp :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.udp
	endpoint, ok := parse_bind(cfg.address, cfg.port)
	if !ok {
		logx.errorf("listeners.udp: %q is not a valid bind address", cfg.address)
		return false
	}
	// Both guards are for a `Listeners` built by hand rather than loaded from a
	// file - the tests do that. A loaded configuration has been through
	// `validate`, which derives the reader count and refuses a receive buffer
	// outside its bounds, so neither branch is reachable from a running server.
	readers := max(cfg.readers, 1)
	buffer := cfg.receive_buffer if cfg.receive_buffer > 0 else config.DEFAULT_UDP_RECEIVE_BUFFER

	/*
	Nobody else is already on this port.

	`SO_REUSEPORT` is what lets the readers share a port with each other, and it
	would let them share one with anybody else running as the same effective
	user - which, for the port this server binds before it drops privileges,
	means a second elodin. A stale process, a unit started twice, a
	configuration being tried out beside the running one: without this the
	kernel would take the second listener into the group and hand it half the
	datagrams, and the operator would have a resolver answering half its queries
	from a configuration nobody meant to be serving. Before the readers existed
	the second bind was refused outright, and it still is.

	Asked with a plain bind, which is refused by exactly the case the readers
	must not join and is refused by everything that would have refused them
	anyway - systemd-resolved on port 53 holds it without `SO_REUSEPORT`, and a
	reuse-port bind is turned away from that too. The probe is closed again
	before the readers bind; UDP has no lingering state to leave behind.

	Only for a port the file named. An ephemeral bind has no port to ask about
	until the first reader has one, and a probe would take a different one.
	*/
	if endpoint.port != 0 {
		probe, perr := net.make_bound_udp_socket(endpoint.address, endpoint.port)
		if perr != nil {
			report_bind_failure("listeners.udp", cfg.address, cfg.port, perr)
			return false
		}
		net.close(probe)
	}

	/*
	Bound into a list of their own before `l.udp` exists.

	So that a bind that fails halfway leaves `l.udp` empty rather than half
	filled: `stop_listeners` closes every socket it finds there, and a reader
	that was never bound holds a zero, which is descriptor 0 and somebody else's.
	Nothing is published to the listener until every socket is open.
	*/
	sockets := make([dynamic]net.UDP_Socket, 0, readers, context.temp_allocator)
	granted := 0
	bound_port := endpoint.port
	for i in 0 ..< readers {
		/*
		The first socket binds what the file asked for and the rest bind what
		the first got.

		The two differ only when the port is 0, which is an ephemeral bind - what
		every test uses. Asking the kernel for 0 again would hand each reader a
		port of its own, which is one listener per reader on ports nobody knows
		rather than one listener with several readers.
		*/
		socket, got, err := bind_udp_reader(endpoint.address, bound_port, buffer)
		if err != nil {
			// Closed before anything is logged. `sockets` lives in this
			// thread's temp arena, and the reporting helpers in this file -
			// `report_refusal`, `report_shed` - reset that arena on their way
			// out; a line written while descriptors are still only in there
			// would be one release of `logx` away from closing whatever the
			// arena handed out next.
			for open in sockets {
				net.close(open)
			}
			report_bind_failure("listeners.udp", cfg.address, bound_port, err)
			return false
		}
		append(&sockets, socket)
		if i == 0 {
			granted = got
			/*
			Read once, from the first socket, and used for the rest: they all
			bind the same endpoint, and `plausible_source` asks about the
			endpoint rather than about any one socket.

			Fatal when it cannot be read, rather than carried on from. The port
			the rest of the readers ask for is this one, so an unknown port with
			`port: 0` in the file would send every reader back to the kernel for
			an ephemeral port of its own - the listener-per-reader this loop
			exists to avoid, and silently. `plausible_source` would be comparing
			against a zero endpoint besides, which is a check that has stopped
			checking.
			*/
			b, berr := net.bound_endpoint(socket)
			if berr != nil {
				// Closed before the line, for the reason the bind failure
				// above gives.
				for open in sockets {
					net.close(open)
				}
				logx.errorf("listeners.udp: cannot read the port the first reader bound (%v)", berr)
				return false
			}
			l.udp_bound = b
			bound_port = b.port
		}
	}

	l.udp = make([]Udp_Reader, len(sockets))
	for socket, i in sockets {
		l.udp[i].socket = socket
		l.udp[i].inode = metrics.socket_inode(int(socket))
	}

	for i in 0 ..< len(l.udp) {
		ctx := new(Udp_Context)
		ctx.server = s
		ctx.listeners = l
		ctx.reader = &l.udp[i]
		if conn_spawn(&l.conns, ctx, udp_loop, counted = false) != .Started {
			logx.errorf("listeners.udp: cannot start read loop %d of %d", i + 1, len(l.udp))
			// Nothing was ever handed this one, so it is ours to release. The
			// loops already started are holding their own, and are left to
			// `stop_listeners`, which is also what closes the sockets: closing
			// them here would leave it closing descriptors this process has
			// already given back. The flag is what those loops come out on,
			// within one `LISTENER_POLL`.
			free(ctx)
			sync.atomic_store(&l.stop, true)
			return false
		}
		l.udp[i].ctx = ctx
	}

	// The port that was bound rather than the one that was asked for. They are
	// the same figure everywhere but `port: 0`, where the file names no port at
	// all and this line is the only place the one the kernel chose is said.
	logx.infof(
		"listening for DNS on %s:%d/udp (%s)",
		cfg.address,
		l.udp_bound.port,
		udp_readers_line(len(l.udp), buffer, granted),
	)
	return true
}

/*
Bind one reader's socket.

`SO_REUSEPORT` before the bind, because it is what lets the second and later
readers bind a port the first already has: the kernel then gives each socket its
own receive queue and picks between them by a hash of the datagram's 4-tuple.
It is set even for a single reader, so that the socket a lone reader binds is
the same socket the first of several would bind, rather than a case that only
the default configuration exercises.

What that opens is bounded by the kernel: Linux requires every socket sharing a
port to have been bound by the same effective uid, so a share of this server's
datagrams is available to whoever can already run as this server's user - who
could read the answers off the wire in any case.

`net.set_option` cannot set either of the two options here - it knows the name
`Reuse_Port` but refuses it, and `Receive_Buffer_Size` it does set without
saying what the kernel granted - so both go through `setsockopt` directly.
*/
@(private)
bind_udp_reader :: proc(
	address: net.Address,
	port: int,
	buffer: int,
) -> (
	socket: net.UDP_Socket,
	granted: int,
	err: net.Network_Error,
) {
	socket = net.make_unbound_udp_socket(net.family_from_address(address)) or_return
	if !set_reuse_port(socket) {
		net.close(socket)
		// Not a bind error, but reported as one: the operator sees it beside
		// the address it was for, and the socket is no more usable than one
		// whose bind failed.
		return {}, 0, net.Bind_Error.Unknown
	}
	// A large receive buffer absorbs query bursts that arrive while every
	// worker is busy. What the kernel actually granted is reported at startup:
	// it clamps this to `net.core.rmem_max`, which is 208 KiB by default.
	granted = set_receive_buffer(socket, buffer)
	// So the read loop wakes up now and then and can see `stop`.
	_ = net.set_option(socket, .Receive_Timeout, LISTENER_POLL)
	if berr := net.bind(socket, {address, port}); berr != nil {
		net.close(socket)
		return {}, 0, berr
	}
	return socket, granted, nil
}

/*
What the kernel dropped on each reader's receive queue, in reader order.

One place, because both callers ask the same question of the same sockets and
differ only in what they do with the answer: the scrape publishes a sample per
reader and the five-minute line adds them up. `false` is "cannot be measured
here" and not "none" - see `metrics.socket_drops`, which is where the counter
comes from and where the difference is argued out.
*/
@(private)
udp_reader_drops :: proc(l: ^Listeners, allocator := context.temp_allocator) -> (drops: []u64, ok: bool) {
	if len(l.udp) == 0 {
		return nil, false
	}
	drops = make([]u64, len(l.udp), allocator)
	inodes := make([]u64, len(l.udp), allocator)
	for reader, i in l.udp {
		inodes[i] = reader.inode
	}
	if !metrics.socket_drops(inodes, drops) {
		return nil, false
	}
	return drops, true
}

/*
Datagrams the kernel dropped on the readers' receive queues, added up.

`false` is "cannot be measured here" and not "none", for the reason
`udp_reader_drops` above gives. The metrics endpoint publishes the per-reader
figures instead, since which reader is dropping says whether one client is
flooding one 4-tuple or the listener as a whole is behind.
*/
udp_receive_drops :: proc(l: ^Listeners) -> (total: u64, ok: bool) {
	drops, measured := udp_reader_drops(l)
	if !measured {
		return 0, false
	}
	for n in drops {
		total += n
	}
	return total, true
}

/*
What the readers add up to, in one line.

Written once and used twice, so that startup and `--check` cannot come to
different views of the same configuration - the same reason
`connection_limits_line` exists.

The granted receive buffer is said rather than the requested one, and both when
they differ, because the difference is a sysctl an operator has not set: asking
for a megabyte and being given 208 KiB is the ordinary case on an untuned Linux,
and a server that reported only what it asked for would be describing a burst
tolerance it does not have. `granted` is 0 where there is no socket to ask -
`--check`, which parses a file and binds nothing - and the line then says what
was asked for and does not claim it was given.
*/
udp_readers_line :: proc(readers, asked, granted: int) -> string {
	// "1 reader" rather than "1 readers", which is the single-core machine and
	// the configuration everything had before this setting existed - so it is
	// the wording most installations will read.
	count := "1 reader" if readers == 1 else fmt.tprintf("%d readers", readers)
	if granted <= 0 {
		return fmt.tprintf("%s, asking for %.0M of receive buffer each", count, asked)
	}
	if granted < asked {
		return fmt.tprintf(
			"%s, %.0M of receive buffer each of the %.0M asked for; net.core.rmem_max is the ceiling",
			count,
			granted,
			asked,
		)
	}
	return fmt.tprintf("%s, %.0M of receive buffer each", count, granted)
}

@(private)
udp_loop :: proc(data: rawptr) {
	ctx := cast(^Udp_Context)data
	l := ctx.listeners
	// This loop's own socket and its own buffer. Neither is shared with the
	// other readers: that is the whole of what having several of them buys.
	socket := ctx.reader.socket
	buf := make([]u8, 65535)
	defer delete(buf)

	// Labelled for the submit below, whose `break` would otherwise leave only
	// the switch it sits in.
	loop: for !sync.atomic_load(&l.stop) {
		n, client, err := net.recv_udp(socket, buf)
		if err != nil {
			if sync.atomic_load(&l.stop) {
				break
			}
			continue
		}
		/*
		Counted here, before anything can turn the datagram away.

		It is what says whether the readers are sharing the load: the kernel
		picks between them by a hash of the 4-tuple, so a flood from one source
		port lands entirely on one reader while ordinary traffic spreads. An
		operator watching one reader's count climb while the others sit still is
		looking at that, and no other counter in this process can show it -
		everything else is charged after the datagram has been read, by whichever
		thread read it.
		*/
		sync.atomic_add(&ctx.reader.received, 1)
		if n < dns.HEADER_SIZE {
			continue
		}

		/*
		Before the message is parsed, before the limiter and before the queue:
		a source this server does not answer should cost a prefix compare and
		nothing else.

		Dropped rather than refused. A REFUSED is a datagram sent to whatever
		address the query claimed, which is a reflection of its own - small, but
		free to whoever asked for it - and the source on a datagram is not
		evidence of anything. The stream listeners, where a handshake has
		established who is there, close the connection instead.

		Not charged to the rate limiter, though the limiter is the next thing
		here. That budget is kept per /24, so a denied source in the same /24 as
		an allowed one would be spending its neighbour's: charging refusals
		would turn a narrowed allow list into a way to have the clients beside
		it dropped. Nothing is sent, so there is nothing a response budget is
		bounding.
		*/
		if !config.source_allowed(ctx.server.cfg.server.allow_from, client.address) {
			sync.atomic_add(&ctx.server.stats.refused, 1)
			report_refusal(client, .UDP)
			continue
		}

		if !plausible_source(l, client) {
			sync.atomic_add(&ctx.server.stats.dropped, 1)
			continue
		}

		/*
		Charged before the work rather than after the answer.

		A response this server will not send is a query it need not resolve, and
		under a flood the upstream round trips and the cache churn are as much of
		the damage as the traffic. It costs a strictly conservative limiter: the
		reply that never gets built is charged for anyway, and a query that turns
		out to be answerable from cache costs the same as one that is not.
		*/
		switch rate_check(ctx.server.limiter, client, time.tick_now()) {
		case .Allow:
		case .Truncate:
			if tc, built := dns.truncated_response(buf[:n], context.temp_allocator); built {
				_, _ = net.send_udp(socket, tc, client)
			}
			free_all(context.temp_allocator)
			continue
		case .Drop:
			continue
		}

		/*
		Shed rather than queue once the backlog is past what the workers can
		work through. A query added here would be answered long after its client
		stopped waiting, and the effort spent on it is taken from queries that
		could still have been answered in time.

		Asked here as well as at the submit below, which is where it is decided:
		this loop is what a flood arrives at, and the copy of the datagram the
		job needs is worth not making for a query about to be shed.
		*/
		limit := ctx.server.cfg.server.max_pending
		if limit > 0 && pool.pending(ctx.server.handler_pool) >= limit {
			sync.atomic_add(&ctx.server.stats.dropped, 1)
			report_shed(client, limit)
			continue
		}

		job := new(Udp_Job)
		job.ctx = ctx
		job.client = client
		job.socket = socket
		job.data = make([]u8, n)
		copy(job.data, buf[:n])

		switch pool.try_submit(ctx.server.handler_pool, udp_job, job, limit) {
		case .Accepted:
		case .Full:
			// The backlog filled up between the check above and here, from this
			// loop's own last datagram or from a DoH connection's reader.
			sync.atomic_add(&ctx.server.stats.dropped, 1)
			report_shed(client, limit)
			delete(job.data)
			free(job)
		case .Stopped:
			delete(job.data)
			free(job)
			break loop
		}
	}
	// `ctx` is not released here: jobs queued above still hold it, and they run
	// on while the pool drains. `destroy_listeners` has it.
}

/*
Whether a refusal is worth the line it would cost, and whether it is the first.

Every refusal in this file is reached by a peer that chose to be refused, so how
many of them there are is the peer's to decide and the log has to be bounded by
something else. The first one since start is a `warn` naming the setting, so an
operator has one line to grep for; every one after it is `debug`, where somebody
who has gone looking will find it and nobody else pays for it. Without that, a
peer sending refused traffic decides how much this server writes to disk.

Costs one atomic load per refusal while debug is off, which is the case that
matters - the callers are an attacker's send loop and an accept loop, and
formatting an address for every packet is a thing to be made to do only on
purpose.

`say` is false when nothing should be logged at all; `first` is true exactly
once per flag, on the call that turned it. `every` is whether the levels below
`warn` are being written - the callers pass `logx.enabled(.Debug)`, and it is a
parameter rather than a call in here so that what this decides can be asked both
ways without moving a level the whole process shares.
*/
@(private)
report_once :: proc(reported: ^bool, every: bool) -> (say: bool, first: bool) {
	if sync.atomic_load(reported) && !every {
		return false, false
	}
	return true, !sync.atomic_exchange(reported, true)
}

/*
What a refusal on this transport turned away.

UDP refuses a datagram, which is a query. The stream transports refuse on
accept, before a byte has been read, so a connection is all there ever was, and
calling that a query names something that did not happen. The `refused=` counter
is the sum of the two units, and this is what tells an operator which of them a
line is about.
*/
@(private)
refused_unit :: proc(proto: Protocol) -> string {
	return "query" if proto == .UDP else "connection"
}

/*
Say which client `server.allow_from` turned away, once, and then quietly.

A refused source is told nothing: over UDP because a REFUSED is a reflection of
its own, and over the stream transports because the connection is closed before
anything can be written on it. That is the right behaviour toward the client and
it leaves the operator with a resolver that has silently stopped serving
somebody - a default that denies has to be able to say who it denied, or the
first symptom of a network nobody added is a client that "just stopped working"
with nothing to grep for.

So the first refusal since start is a `warn` naming the source and the setting,
and every one after it is `debug`. The counter in the stats line carries the
rest: this is here to point at the setting once, not to log a flood.
*/
@(private)
refusal_reported: bool

@(private)
report_refusal :: proc(client: net.Endpoint, proto: Protocol) {
	say, first := report_once(&refusal_reported, logx.enabled(.Debug))
	if !say {
		return
	}
	/*
	The line itself is what has to be paid for, and it is paid for here.

	`logx` formats through `fmt.tprintf`, so a line costs a few hundred bytes of
	the calling thread's temp arena - and the two callers are the UDP read loop
	and the accept loops, neither of which resets one. The read loop's arena is
	not the one a query is answered from; that belongs to the worker the job is
	handed to. The accept loop's is untouched from start to shutdown. At `debug`,
	where every refusal is logged, that would be an arena a refused source grows
	for as long as it keeps sending - which is the level an operator turns on to
	find out why their clients are being refused, so it is the level this must
	not misbehave at.

	Released where the garbage is made rather than at the call sites, and safe
	because both of them hold nothing in the temp allocator across this: the
	check runs before a datagram is parsed and before a connection is queued.
	*/
	defer free_all(context.temp_allocator)

	// The stack rather than that arena: an address is a fixed few dozen bytes,
	// and the less of a refused packet's cost goes through an allocator the
	// better.
	buf: [64]u8
	builder := strings.builder_from_bytes(buf[:])
	who := net.endpoint_to_string(client, &builder)

	transport := proto_name(proto)
	unit := refused_unit(proto)
	if !first {
		logx.debugf("%s: refused a %s from %s, which is not in server.allow_from", transport, unit, who)
		return
	}
	logx.warnf(
		"%s: refused a %s from %s: it is not in server.allow_from, so nothing was sent back",
		transport,
		unit,
		who,
	)
	logx.warnf(
		"add its network to server.allow_from if that client should be served; refusals are counted as refused= in the stats line, and further ones are logged at debug level",
	)
}

/*
Say which client a full backlog turned away.

Debug only, and not through `report_once`: unlike a refusal, a shed is already
counted as dropped= in the stats line, so an operator watching for it has a
figure that a flood cannot make them miss. This is for the question that figure
raises next - which clients are being turned away - and it is asked by turning
debug on.

The line is formatted out of the read loop's temp arena, which that loop resets
only where it has something to reset, so it is released here as `report_refusal`
does. Safe for the same reason: both call sites are about to `continue`, and
neither holds anything in the temp allocator across this.
*/
@(private)
report_shed :: proc(client: net.Endpoint, limit: int) {
	// Before the address is formatted, not after: this is reached once per
	// datagram of exactly the flood that fills the backlog, so with debug off it
	// has to cost the load and nothing else.
	if !logx.enabled(.Debug) {
		return
	}
	defer free_all(context.temp_allocator)

	// The stack rather than that arena, as in `report_refusal`.
	buf: [64]u8
	builder := strings.builder_from_bytes(buf[:])
	who := net.endpoint_to_string(client, &builder)

	logx.debugf("udp: shedding a query from %s, server.max_pending (%d) is reached", who, limit)
}

/*
Say which client the response budget turned away, and on which transport.

Debug only and not through `report_once`, for the reason `report_shed` is not:
these are already counted as limited= in the stats line, so an operator watching
for them has a figure a flood cannot make them miss, and this is for the question
that figure raises next - which clients, and where.

Unlike the two above, `client` arrives formatted: the stream handlers build it
once per connection and hold it for the connection's life, so there is no address
to render here and nothing to release afterwards. `logx.debugf` returns without
formatting anything when debug is off.

`closing` is what the caller did with the connection, and the transports no longer
agree: the length-prefixed ones end it, DoH answers 429 and keeps it - see
`serve_doh_request`. An operator reading "closing the connection" for a refusal
that closed nothing would go looking for a disconnection that never happened, so
the caller says which it was rather than the line assuming.
*/
@(private)
report_rate_limited :: proc(client: string, proto: Protocol, closing: bool) {
	logx.debugf(
		"%s: %s from %s, its prefix is over server.rate_limit.responses_per_second",
		proto_name(proto),
		"closing the connection" if closing else "refusing a query",
		client,
	)
}

/*
What the connection table allows, said once at startup.

Neither figure is in anybody's file by default - `max_connections` ships with one
and the per-prefix share is derived from it at load - so an operator working out
why a client cannot connect has nowhere else to read them. Returned rather than
printed so a test can hold the two forms side by side, and so `--check` can say
the same thing in the same words - an operator reads that before restarting, and
two wordings of one fact drift apart.

The no-cap form is not a shorter version of the other: it says the thing worth
knowing about that configuration, which is that one client may take the table.
That is where this server was before the setting existed, and it is still
reachable on purpose, by setting the share to `max_connections` or above.
*/
connection_limits_line :: proc(limit, prefix_limit: int) -> string {
	if prefix_limit <= 0 || prefix_limit >= limit {
		return fmt.tprintf(
			"connections: at most %d at once across TCP, DoT and DoH, and any one client prefix (/24, /64) may hold all of them",
			limit,
		)
	}
	return fmt.tprintf(
		"connections: at most %d at once across TCP, DoT and DoH, of which one client prefix (/24, /64) may hold %d; connections past a prefix's share are refused and counted as conn_refused=",
		limit,
		prefix_limit,
	)
}

/*
Say why a connection could not be given a thread, once, and then quietly.

The same reasoning as `report_refusal`, and reached the same way: a peer opening
connections past the limit wrote one line per attempt otherwise, at `warn`, so it
was on at the default level. The setting is named because it is the one thing
that would change the outcome, and because a connection refused for want of a
slot and one refused for want of an allow-list entry look identical from the
client's side.

The three causes are told apart because they ask for different things. Naming
`max_connections` at a host that ran out of threads sends an operator to raise a
limit that was never the bound, and the raise makes it worse; naming it at a
client that has filled its own share sends them to raise the table, which hands
that same client more of it and still refuses the next connection from it. Each
keeps its own flag, so one of them going quiet does not silence the others.
*/
@(private)
conn_limit_reported: bool

@(private)
conn_prefix_limit_reported: bool

@(private)
conn_failed_reported: bool

/*
Everything that differs between the three causes, chosen in one place.

Split out of the reporter because the choosing is the part that can be wrong and
the printing is not: a branch inverted here says "raising max_connections will
not help" to the operator whose only problem is `max_connections`, and tells the
host that ran out of pids to raise it. Every line still appears in the log, and
every one still counts something, so nothing downstream of the mistake looks
wrong. Returned as data so a test can hold them side by side - the same reason
`refused_unit` is its own procedure.

`brief` and `line` take the transport and the limit, in that order, and which
limit that is comes from `spawn_failure_limit`: a share refused against the
table's own size would read as a table that is full when it is not.
*/
@(private)
Spawn_Failure_Words :: struct {
	reported: ^bool,
	// The `debug` line, for every occurrence after the first.
	brief:    string,
	// The `warn`, said once, and the line under it saying what to do.
	line:     string,
	hint:     string,
}

@(private)
spawn_failure_words :: proc(why: Spawn_Result) -> Spawn_Failure_Words {
	switch why {
	case .Limit_Reached:
		return Spawn_Failure_Words {
			reported = &conn_limit_reported,
			brief = "%s: refusing a connection, the limit of %d is reached",
			line = "%s: refusing a connection, server.max_connections (%d) is reached",
			hint = "raise server.max_connections if this server should hold more clients at once; these are counted as conn_refused= in the stats line, and further ones are logged at debug level",
		}
	case .Prefix_Limit_Reached:
		return Spawn_Failure_Words {
			reported = &conn_prefix_limit_reported,
			brief = "%s: refusing a connection, this client's prefix already holds the %d it may",
			line = "%s: refusing a connection, this client's /24 or /64 already holds server.max_connections_per_prefix (%d) of them",
			hint = "raise server.max_connections_per_prefix if one client network should be able to hold more of server.max_connections at once, or set it to max_connections to let any one of them hold the table; these are counted as conn_refused= in the stats line, and further ones are logged at debug level",
		}
	case .Started, .Thread_Failed:
	}
	return Spawn_Failure_Words {
		reported = &conn_failed_reported,
		brief = "%s: refusing a connection, the OS would not start a thread for it, below the limit of %d",
		line = "%s: refusing a connection, the OS would not start a thread for it - this is below server.max_connections (%d), so raising that will not help",
		hint = "check the process thread and memory limits (RLIMIT_NPROC, cgroup pids.max); these are counted as conn_failed= in the stats line, and further ones are logged at debug level",
	}
}

/*
The limit a refusal is about, which is not the same number for all three.

A prefix's share is the figure that refused the connection, so it is the figure
the line has to name: printing `max_connections` there would tell an operator
their table is full at a moment when half of it is free, and send them to raise
the setting that was not the bound. Paired with the words in a procedure of its
own for the same reason they are - the pairing is what can be wrong.
*/
@(private)
spawn_failure_limit :: proc(why: Spawn_Result, cm: ^Conn_Manager) -> int {
	// Set once by `conn_manager_init` and never written again, so read without
	// the manager's lock - which the accept loop is not holding here anyway.
	return cm.prefix_limit if why == .Prefix_Limit_Reached else cm.limit
}

@(private)
report_spawn_failure :: proc(proto: Protocol, why: Spawn_Result, cm: ^Conn_Manager) {
	limit := spawn_failure_limit(why, cm)
	words := spawn_failure_words(why)
	say, first := report_once(words.reported, logx.enabled(.Debug))
	if !say {
		return
	}
	// As in `report_refusal`: the accept loop is the one place that never resets
	// its own temp arena, and the line was formatted out of it.
	defer free_all(context.temp_allocator)

	transport := proto_name(proto)
	if !first {
		logx.debugf(words.brief, transport, limit)
		return
	}
	logx.warnf(words.line, transport, limit)
	logx.warnf(words.hint)
}

/*
Whether a datagram's source could be a client waiting for an answer.

Two things it cannot be, both free to check and both well established:

Port 0 is not a port anything receives on. A query that says it came from one is
either a probe or a packet built by hand, and answering it sends a datagram to a
port the kernel will not deliver.

Our own listening endpoint is the other. A datagram spoofed as coming from the
address and port this server is answering on makes it talk to itself - every
answer arriving as a new query, forever, at whatever rate the loop sustains. A
source port equal to ours from a loopback address is the same thing under a
wildcard bind, where our own datagrams come from whichever local address the
route picked rather than the 0.0.0.0 we asked for.

The same shape aimed at *another* resolver is what a loop between two servers
would be, and this is not what stops that: a client's source port is essentially
never 53, but "essentially never" has counted some real forwarders, so refusing
every datagram from port 53 would refuse them too. What stops it is that neither
end answers an answer - `handle_query` drops anything with QR set before it
looks at the question - so the exchange is one datagram each way rather than a
loop, and the rate limiter bounds even that.
*/
@(private)
plausible_source :: proc(l: ^Listeners, client: net.Endpoint) -> bool {
	if client.port == 0 {
		return false
	}
	bound := l.udp_bound
	if bound.port == 0 || client.port != bound.port {
		return true
	}
	// Bound to a concrete address, and the source claims to be it.
	if addresses_equal(client.address, bound.address) {
		return false
	}
	// Bound to the wildcard, where the source of our own datagrams is whichever
	// local address the route picked rather than the address we bound.
	return !is_loopback(client.address)
}

/*
The IPv4 address inside `::ffff:a.b.c.d`, when that is what an address holds.

An IPv4 client reaching a socket bound to `::` arrives mapped, and so do our own
datagrams to an IPv4 destination under such a bind. `core:net` reports the
sixteen bytes as they arrived and nothing between the socket and here normalises
them, so a judgement that needs the address a client actually has asks for it
through this. A deployment `config.source_allowed` goes out of its way to support
(see `config.address_bytes`, and the `allow_from` section of the README) is one
every other judgement about a source has to be able to make too: whether it is
loopback, and which prefix's budget it spends.

Exactly the mapped prefix, which is `config.unmap_bytes`'s rule and has to stay
the same rule: ten zero bytes, then `ff ff`. The deprecated compat form
`::a.b.c.d` and the translated form `::ffff:0:a.b.c.d` are IPv6 addresses that
happen to carry four familiar octets, no stack sources a datagram from them, and
reading them as IPv4 here would judge a source by an address the ACL compares as
IPv6 - which is the way round that gives a v6 sender the choice.
*/
@(private)
unmap_v4 :: proc(a: net.Address) -> net.Address {
	x, is6 := a.(net.IP6_Address)
	if !is6 {
		return a
	}
	for i in 0 ..< 5 {
		if x[i] != 0 {
			return a
		}
	}
	if u16(x[5]) != 0xffff {
		return a
	}
	hi, lo := u16(x[6]), u16(x[7])
	return net.IP4_Address{u8(hi >> 8), u8(hi), u8(lo >> 8), u8(lo)}
}

// Mapped or not is not a difference between two addresses: `::ffff:10.0.0.1` is
// 10.0.0.1, and a source claiming one of the two forms of an address we bound is
// claiming that address.
@(private)
addresses_equal :: proc(a, b: net.Address) -> bool {
	switch x in unmap_v4(a) {
	case net.IP4_Address:
		y, ok := unmap_v4(b).(net.IP4_Address)
		return ok && x == y
	case net.IP6_Address:
		y, ok := unmap_v4(b).(net.IP6_Address)
		return ok && x == y
	}
	return false
}

/*
Whether an address is one of this host's own.

Read as a statement about who is at the other end: `plausible_source` refuses a
datagram from one on our own listening port, since under a wildcard bind that is
this server talking to itself, and `start_metrics` warns when the endpoint it
bound is not one, since anything else serves the numbers to whatever can reach
them. Both questions are asked of addresses that may arrive mapped, so the
mapping is undone before 127/8 is looked for - `::ffff:127.0.0.1` is the address
our own datagrams to a v4 destination carry under a `::` bind.
*/
@(private)
is_loopback :: proc(a: net.Address) -> bool {
	switch x in unmap_v4(a) {
	case net.IP4_Address:
		return x[0] == 127
	case net.IP6_Address:
		return x == net.IP6_Loopback
	}
	return false
}

@(private)
udp_job :: proc(data: rawptr) {
	job := cast(^Udp_Job)data
	defer {
		delete(job.data)
		free(job)
		free_all(context.temp_allocator)
	}

	s := job.ctx.server
	client := net.endpoint_to_string(job.client, context.temp_allocator)
	response, _, ok := handle_query(s, job.data, .UDP, client, context.temp_allocator)
	if !ok || len(response) == 0 {
		return
	}
	_, _ = net.send_udp(job.socket, response, job.client)
}

// --- TCP and DoT ----------------------------------------------------------

@(private)
Stream_Context :: struct {
	server:    ^Server,
	listeners: ^Listeners,
	proto:     Protocol,
}

@(private)
Stream_Job :: struct {
	ctx:    ^Stream_Context,
	socket: net.TCP_Socket,
	client: net.Endpoint,
}

@(private)
start_stream_listener :: proc(
	s: ^Server,
	l: ^Listeners,
	cfg: config.Listener,
	proto: Protocol,
	socket: ^net.TCP_Socket,
	open: ^bool,
) -> bool {
	name := proto_name(proto)
	endpoint, ok := parse_bind(cfg.address, cfg.port)
	if !ok {
		logx.errorf("listeners.%s: %q is not a valid bind address", name, cfg.address)
		return false
	}
	sock, err := net.listen_tcp(endpoint)
	if err != nil {
		report_bind_failure(fmt.tprintf("listeners.%s", name), cfg.address, cfg.port, err)
		return false
	}
	// So the accept loop below wakes up now and then and can see `stop`.
	_ = net.set_option(sock, .Receive_Timeout, LISTENER_POLL)
	socket^ = sock
	open^ = true

	ctx := new(Stream_Context)
	ctx.server = s
	ctx.listeners = l
	ctx.proto = proto
	if conn_spawn(&l.conns, ctx, accept_loop, counted = false) != .Started {
		logx.errorf("listeners.%s: cannot start the accept loop", name)
		// Nothing was ever handed it, so it is ours to release.
		free(ctx)
		return false
	}
	append(&l.stream_loop_ctx, ctx)
	return true
}

@(private)
start_tcp :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.tcp
	if !start_stream_listener(s, l, cfg, .TCP, &l.tcp_socket, &l.tcp_open) {
		return false
	}
	logx.infof("listening for DNS on %s:%d/tcp", cfg.address, cfg.port)
	return true
}

@(private)
DOT_ALPN := []string{"dot"}

// h2 first: browsers will only use a DoH resolver over HTTP/2, and ALPN picks
// by server preference. A client that offers neither gets a clean handshake
// failure rather than a connection that then talks past us.
@(private)
DOH_ALPN := []string{"h2", "http/1.1"}

@(private)
start_dot :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.dot
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, DOT_ALPN)
	if err != .None {
		logx.errorf("listeners.dot: %s", tlsx.describe_error(err, context.temp_allocator))
		return false
	}
	l.dot_ctx = ctx
	if !start_stream_listener(s, l, cfg, .DoT, &l.dot_socket, &l.dot_open) {
		return false
	}
	logx.infof("listening for DNS-over-TLS on %s:%d", cfg.address, cfg.port)
	return true
}

@(private)
start_doh :: proc(s: ^Server, l: ^Listeners) -> bool {
	cfg := s.cfg.listeners.doh
	ctx, err := tlsx.server_context(cfg.cert_file, cfg.key_file, DOH_ALPN)
	if err != .None {
		logx.errorf("listeners.doh: %s", tlsx.describe_error(err, context.temp_allocator))
		return false
	}
	l.doh_ctx = ctx
	if !start_stream_listener(s, l, cfg, .DoH, &l.doh_socket, &l.doh_open) {
		return false
	}
	logx.infof("listening for DNS-over-HTTPS on %s:%d%s", cfg.address, cfg.port, cfg.path)
	if cfg.mobileconfig_path != "" {
		logx.infof(
			"serving the Apple .mobileconfig profile on %s:%d%s",
			cfg.address,
			cfg.port,
			cfg.mobileconfig_path,
		)
	}
	return true
}

/*
Re-read the certificate and key files and switch the DoT/DoH listeners over to
what they now contain, without touching the sockets or any connection already
accepted.

A new `SSL_CTX` is built first and swapped in only once it is known good, so a
certificate that fails to load - the wrong key, a typo'd path - leaves the
listener serving what it already had rather than falling over. The context an
open connection's `SSL` holds stays valid after the swap: OpenSSL reference
counts an `SSL_CTX` from `SSL_new` on, so freeing the displaced one here only
releases it once the last connection still using it closes.

Called from the maintenance loop on SIGHUP, one listener at a time; nothing
else running concurrently writes `dot_ctx` or `doh_ctx`, but `accept_loop`'s
connection threads read them for every new connection, hence `l.tls_mu`.
*/
reload_tls :: proc(s: ^Server, l: ^Listeners) -> bool {
	ok := true
	if l.dot_open {
		if !reload_tls_ctx(l, &l.dot_ctx, s.cfg.listeners.dot, DOT_ALPN, "dot") {
			ok = false
		}
	}
	if l.doh_open {
		if !reload_tls_ctx(l, &l.doh_ctx, s.cfg.listeners.doh, DOH_ALPN, "doh") {
			ok = false
		}
	}
	return ok
}

@(private)
reload_tls_ctx :: proc(
	l: ^Listeners,
	slot: ^^tlsx.Context,
	cfg: config.Listener,
	alpn: []string,
	name: string,
) -> bool {
	fresh, err := tlsx.server_context(cfg.cert_file, cfg.key_file, alpn)
	if err != .None {
		logx.errorf(
			"listeners.%s: keeping the certificate already in use, %s and %s did not load: %s",
			name,
			cfg.cert_file,
			cfg.key_file,
			tlsx.describe_error(err, context.temp_allocator),
		)
		return false
	}
	/*
	Swapped and released inside the exclusive lock rather than around it.

	Holding it is what says no connection thread is between reading the pointer
	and taking its reference on the `SSL_CTX` - see `accept_tls` - so the
	displaced context can be freed knowing nobody is about to dereference it.
	Released here and not later because there is nothing to wait for: an open
	connection holds the `SSL_CTX` through its own reference, and this only
	drops ours.

	Loading the replacement happens above, outside the lock, because it reads
	two files.
	*/
	sync.rw_mutex_lock(&l.tls_mu)
	old := slot^
	slot^ = fresh
	tlsx.context_destroy(old)
	sync.rw_mutex_unlock(&l.tls_mu)
	logx.infof("listeners.%s: reloaded the certificate from %s", name, cfg.cert_file)
	return true
}

/*
Accept a TLS connection on `proto`, taking the certificate context under the
lock the reload replaces it under.

The shared lock spans reading the pointer and `tlsx.server_session`, which is
the whole of the window that matters: the session takes a reference on the
`SSL_CTX`, so once it has one the reload may swap the context out and free it
without this connection noticing. Everything before that - the pointer still in
the slot, the `Context` behind it - is memory `reload_tls` is about to release,
and reading it afterwards is a use-after-free that ends the process.

The handshake is outside the lock on purpose. It waits on the peer, and a peer
that dawdles over one would otherwise hold off a certificate reload for as long
as it liked; with `server.max_connections` of them, indefinitely. Nothing it
touches is shared with the reload.
*/
@(private)
accept_tls :: proc(l: ^Listeners, proto: Protocol, socket: net.TCP_Socket) -> (^tlsx.Conn, tlsx.Error) {
	session: tlsx.Server_Session
	err: tlsx.Error
	{
		sync.rw_mutex_shared_lock(&l.tls_mu)
		defer sync.rw_mutex_shared_unlock(&l.tls_mu)
		session, err = tlsx.server_session(proto == .DoT ? l.dot_ctx : l.doh_ctx, socket)
	}
	if err != .None {
		return nil, err
	}
	return tlsx.server_handshake(session)
}

@(private)
listening_socket :: proc(l: ^Listeners, proto: Protocol) -> net.TCP_Socket {
	switch proto {
	case .TCP:
		return l.tcp_socket
	case .DoT:
		return l.dot_socket
	case .DoH:
		return l.doh_socket
	case .UDP:
	}
	return l.tcp_socket
}

@(private)
accept_loop :: proc(data: rawptr) {
	ctx := cast(^Stream_Context)data
	l := ctx.listeners
	listener := listening_socket(l, ctx.proto)

	for !sync.atomic_load(&l.stop) {
		client_socket, client, err := net.accept_tcp(listener)
		if err != nil {
			if sync.atomic_load(&l.stop) {
				break
			}
			continue
		}

		/*
		Closed here rather than handed a thread that would answer REFUSED.

		A refusal a client can read is the friendlier of the two, and it is what
		BIND and Unbound send - but it has to be written on a connection, and a
		connection is a thread out of `max_connections` plus, for DoT and DoH, a
		TLS handshake. That would make the allow list a way to exhaust the
		connection limit rather than a defence: a source we have already decided
		not to serve would cost more than one we do. Closing on accept costs a
		prefix compare and a close, and a client whose network is not in the
		list sees the connection go rather than a reason, which is why the log
		has to carry one - see `report_refusal`.
		*/
		if !config.source_allowed(ctx.server.cfg.server.allow_from, client.address) {
			sync.atomic_add(&ctx.server.stats.refused, 1)
			report_refusal(client, ctx.proto)
			net.close(client_socket)
			continue
		}

		job := new(Stream_Job)
		job.ctx = ctx
		job.socket = client_socket
		job.client = client

		/*
		The client's prefix goes with the job, so the connection is counted
		against its own share of the table as well as against the total. It is
		read here, from the address the accept returned, rather than anywhere
		further in: this is the only place that sees a connection before it costs
		a thread, and a share checked after the thread exists would be a limit on
		nothing.
		*/
		if spawned := conn_spawn(&l.conns, job, stream_job, client_prefix(client.address));
		   spawned != .Started {
			/*
			Counted first, and logged only once.

			Bounded the same way `report_refusal` is: this is a refusal a peer
			reaches by opening connections, so a line per attempt is a line rate
			whoever is opening them decides. The counter is what makes that
			demotion safe - a server sitting at its limit still shows a rising
			`conn_refused=` in the stats line long after the one `warn` scrolled
			away.

			Which refusal it was decides the line, and the counter follows what
			the refusal says about this server. Both limits are this server
			deciding it has no room for a client it would otherwise serve, so both
			are `conn_refused=` and an operator watching the counter sees a client
			being turned away either way; the `warn` under it says which figure
			did it, because raising the wrong one of the two makes the other
			worse. A host that cannot give this process another thread is not a
			limit doing its job at all - it happens below both, and it is counted
			apart as `conn_failed=` so that raising nothing is the advice.

			`report_spawn_failure` releases the temp arena the line was formatted
			out of: this loop is the one place that never resets it, and nothing
			here outlives the iteration.
			*/
			if spawned == .Thread_Failed {
				sync.atomic_add(&ctx.server.stats.conn_failed, 1)
			} else {
				sync.atomic_add(&ctx.server.stats.conn_refused, 1)
			}
			report_spawn_failure(ctx.proto, spawned, &l.conns)
			net.close(client_socket)
			free(job)
		}
	}
	// `ctx` is not released here: every connection thread started above holds
	// it for as long as its client keeps the connection open, and this loop
	// exits first. `destroy_listeners` has it.
}

@(private)
stream_job :: proc(data: rawptr) {
	job := cast(^Stream_Job)data
	defer {
		free(job)
		free_all(context.temp_allocator)
	}

	s := job.ctx.server
	timeout := s.cfg.server.client_timeout
	_ = net.set_option(job.socket, .Receive_Timeout, timeout)
	_ = net.set_option(job.socket, .Send_Timeout, timeout)
	_ = net.set_option(job.socket, .TCP_Nodelay, true)

	// The connection handlers below reset the temp allocator after every query,
	// so the client label must not live there: it is used for the lifetime of
	// the connection. A stack buffer owned by this frame outlives all of them.
	client_buf: [64]u8
	client_builder := strings.builder_from_bytes(client_buf[:])
	client := net.endpoint_to_string(job.client, &client_builder)

	switch job.ctx.proto {
	case .TCP:
		defer net.close(job.socket)
		serve_dns_stream(s, {socket = job.socket, peer = job.client}, .TCP, client)
	case .DoT:
		conn, err := accept_tls(job.ctx.listeners, .DoT, job.socket)
		if err != .None {
			logx.debugf("dot: handshake with %s failed: %v", client, err)
			net.close(job.socket)
			return
		}
		defer tlsx.close(conn)
		serve_dns_stream(s, {socket = job.socket, tls = conn, peer = job.client}, .DoT, client)
	case .DoH:
		conn, err := accept_tls(job.ctx.listeners, .DoH, job.socket)
		if err != .None {
			logx.debugf("doh: handshake with %s failed: %v", client, err)
			net.close(job.socket)
			return
		}
		defer tlsx.close(conn)
		if tlsx.alpn_protocol(conn) == "h2" {
			serve_doh2(s, conn, client, job.client)
		} else {
			serve_doh(s, {socket = job.socket, tls = conn, peer = job.client}, client)
		}
	case .UDP:
	// not reachable: UDP has no accept loop
	}
}

/*
Serve DNS messages on a stream, framed with the two-byte length prefix.

Queries on one connection are answered in order. Pipelining clients are rare
enough that the extra machinery to answer out of order is not worth the
complexity here.
*/
@(private)
serve_dns_stream :: proc(s: ^Server, conn: Conn, proto: Protocol, client: string) {
	// Whether this connection has anything the close could take back, which is
	// what decides whether the refusal below drains first - see `stream_linger`.
	answered := false
	for {
		length_buf: [2]u8
		if !conn_read_full(conn, length_buf[:]) {
			return
		}
		length := int(length_buf[0]) << 8 | int(length_buf[1])
		if length < dns.HEADER_SIZE || length > dns.MAX_MESSAGE {
			return
		}

		query := make([]u8, length, context.temp_allocator)
		if !conn_read_full(conn, query) {
			return
		}

		/*
		Charged before the answer is built, as the UDP loop charges before it
		queues, and against the prefix's stream budget rather than the one its
		datagrams spend - see the head of `ratelimit.odin` for why a connection is
		metered at all when nothing on it can be reflected, and why it is not
		metered out of the same pool.

		Charged on a message of a plausible length rather than on one that parses,
		which is where the DoH endpoints charge too, and worth writing down because
		it reads like the place they do not. What `serve_doh_request` and
		`h2_charged` keep out of the budget is a request that was never a question
		put to this service - a scanner's 404, a .mobileconfig download, a POST
		naming the wrong content type, a `dns` parameter that is not base64 - and
		none of that has a spelling here, where a length prefix and a socket are the
		whole envelope. Neither of them looks inside the message either: the floor
		all three share is `dns.HEADER_SIZE`, and the length check above turns
		anything under it away without charging, so the three are already charging
		for the same thing.

		Not moved behind the parse, then. A message this long that does not decode
		is answered - `handle_query` builds it a FORMERR out of its own header - so
		it spends the budget on a response, like everything else the budget counts.
		The one length-legal message that goes unanswered is a response arriving
		where queries are read, and the DoH paths charge for that one too before
		turning it into a 500. Which leaves the parse buying nothing but a rule that
		differed from the UDP loop's, and that loop charges a datagram before it has
		looked at it at all.

		The connection ends rather than this query being skipped. Skipping it
		leaves a client that framed a correct query waiting for an answer that is
		never coming, until `client_timeout` closes the connection anyway, and
		leaves this thread reading the rest of the flood in the meantime; closing
		says so now and hands the slot back to `max_connections`. RFC 7766 6.2.3
		has a server free to hold connections open for no time at all when it is
		under heavy load or attack, which is the case this is, and a client that
		wants another answer is free to open one - which costs it a handshake, and
		over DoT and DoH that is the expensive end of the exchange.

		What the client has already sent is drained before the close, because the
		client this is reached by is the one that pipelined: the queries it sent and
		this server never read are still in the receive queue, and closing a socket
		in that state takes the answers already written down with it. See
		`stream_linger`.

		Only when there is something to take, though: a connection whose very first
		query is over the budget - which under a flood of short connections is all
		of them - has written nothing for the reset to discard, so the drain would
		buy nothing and cost up to `STREAM_LINGER_TIMEOUT` of one of
		`max_connections`, which is the slot this close exists to hand back.
		*/
		if !stream_rate_check(s.limiter, conn.peer, time.tick_now()) {
			report_rate_limited(client, proto, true)
			if answered {
				stream_linger(conn)
			}
			return
		}

		response, _, ok := handle_query(s, query, proto, client, context.temp_allocator)
		if !ok || len(response) == 0 {
			free_all(context.temp_allocator)
			continue
		}

		framed := make([]u8, 2 + len(response), context.temp_allocator)
		framed[0] = u8(len(response) >> 8)
		framed[1] = u8(len(response))
		copy(framed[2:], response)
		if !conn_write_all(conn, framed) {
			return
		}
		answered = true
		free_all(context.temp_allocator)
	}
}

/*
How much of a refused connection `stream_linger` reads and throws away, how long
it waits for any one read, and how long the whole of it may take.

The size is one message at its largest, which is what this connection would have
read next anyway, and it covers the case that gets here with room to spare: a
client pipelining hundreds of questions has sent hundreds of question-sized
messages, which is a few kilobytes between them and not a few megabytes.

The idle wait is short because of what these bytes are: a client that pipelined
wrote them before it could have known the budget had run out, so they are in this
server's receive queue already and a read of a queue with something in it returns
without waiting at all. Once it is empty there is nothing more coming that this
drain is for, and a client is not obliged to shut its sending half down to say so
- so a per-read wait as long as the whole deadline would have every refused
connection hold one of `max_connections` for the full deadline whether or not it
had anything left to give. `http_linger` is bounded the same way, for the same
reason.

The deadline bounds the drain as a whole, which the idle wait alone does not: a
client sending a byte inside every wait stays inside all of them for as long as it
likes, so a drain counted only in bytes and idle time would be somewhere for the
client that has just proved it sends faster than it is answered to sit. Past
either bound the close goes ahead.
*/
@(private)
STREAM_LINGER_BYTES :: 2 + dns.MAX_MESSAGE
@(private)
STREAM_LINGER_TIMEOUT :: 250 * time.Millisecond
@(private)
STREAM_LINGER_IDLE :: 50 * time.Millisecond

/*
Read and throw away what the client had already sent, so that the answers already
written to it are not lost to the close that follows.

`serve_dns_stream` closes on a client that is over its budget, and a client that
pipelines - which RFC 7766 6.2.1.1 allows - has queries in this server's receive
queue that were never read, because the budget ran out before they were reached.
Closing a socket in that state does not send a FIN but an RST (RFC 1122
4.2.2.13), and an RST arriving at a client that has not read yet has its kernel
discard what is already in its receive buffer: the answers this connection did
write, before the budget ran out, are thrown away along with the queries it
declined to read, and the client's `recv` fails where it would have returned
those answers and then the end of the stream. Cutting a flood short is the point
of the close; taking back what was already answered is not. The DoH endpoint
drains before the refusals that close for the same reason - see `http_linger`,
where what would be lost is the 400 or 505 `read_http_request` hands back.

Discarded rather than framed and answered: the budget is spent, and what these
bytes ask is the thing being refused. Past either bound the close goes ahead and
takes the RST with it, which is no worse than not draining at all.

Reached only from a connection that has answered something, for the same reason:
with nothing written there is nothing for the RST to take back, and the drain
would be time out of one of `max_connections` spent protecting nothing.
*/
@(private)
stream_linger :: proc(conn: Conn) {
	conn_set_read_timeout(conn, STREAM_LINGER_IDLE)
	start := time.tick_now()
	chunk: [4096]u8
	discarded := 0
	for discarded < STREAM_LINGER_BYTES && time.tick_since(start) < STREAM_LINGER_TIMEOUT {
		n, ok := conn_read(conn, chunk[:])
		if !ok {
			return
		}
		discarded += n
	}
}

// A stream that may or may not be wrapped in TLS.
Conn :: struct {
	socket: net.TCP_Socket,
	tls:    ^tlsx.Conn,
	/*
	Who is on the other end, for the rate limiter.

	Carried on the connection because that is what it is a property of, and
	because the `client` the handlers already have is the endpoint formatted for
	a log line - which is not something `prefix_key` can hash a prefix back out
	of. Asking the kernel again per query would be a syscall for an answer that
	cannot change.
	*/
	peer:   net.Endpoint,
}

/*
Bound how long one read on this connection waits.

`net.set_option` is not enough on its own, which is the whole reason this exists.
`tlsx` picks SO_RCVTIMEO up at the handshake and then puts the socket into
non-blocking mode, so a TLS read waits on the deadline the connection carries
rather than on the socket option - and a `set_option` afterwards reaches nothing.
Both drains that shorten their reads - `stream_linger` and `http_linger` - are
reached over DoT and DoH as often as over TCP, where the option alone would have
left them waiting out the whole of `client_timeout` for bytes that are not coming,
holding one of `max_connections` while it did. That is the cost the short wait was
written to avoid.

Read only: the write deadline is the connection's, not this moment's.
*/
@(private)
conn_set_read_timeout :: proc(c: Conn, wait: time.Duration) {
	if c.tls != nil {
		tlsx.set_read_timeout(c.tls, wait)
		return
	}
	_ = net.set_option(c.socket, .Receive_Timeout, wait)
}

@(private)
conn_read :: proc(c: Conn, buf: []u8) -> (n: int, ok: bool) {
	if c.tls != nil {
		got, err := tlsx.read(c.tls, buf)
		return got, err == .None && got > 0
	}
	got, err := net.recv_tcp(c.socket, buf)
	return got, err == nil && got > 0
}

@(private)
conn_read_full :: proc(c: Conn, buf: []u8) -> bool {
	got := 0
	for got < len(buf) {
		n, ok := conn_read(c, buf[got:])
		if !ok {
			return false
		}
		got += n
	}
	return true
}

@(private)
conn_write_all :: proc(c: Conn, buf: []u8) -> bool {
	if c.tls != nil {
		_, err := tlsx.write(c.tls, buf)
		return err == .None
	}
	sent := 0
	for sent < len(buf) {
		n, err := net.send_tcp(c.socket, buf[sent:])
		if err != nil || n <= 0 {
			return false
		}
		sent += n
	}
	return true
}

@(private)
now_http_date :: proc(allocator := context.allocator) -> string {
	return http_date(time.now(), allocator)
}

/*
Split from `now_http_date` so a test can hand it a known instant - such as the
Unix epoch - and check the result against a known-correct literal, rather than
every caller trusting the same clock and weekday table this function itself
uses.

A `now: time.Time = {}` default on `now_http_date` itself would not work for
that: `time.Time{}` and the Unix epoch are the same value, so passing the
epoch explicitly would be indistinguishable from passing nothing.
*/
@(private)
http_date :: proc(clock: time.Time, allocator := context.allocator) -> string {
	// RFC 1123 date for the Date header. Callers only need something valid.
	y, m, d := time.date(clock)
	h, mi, sec := time.clock_from_time(clock)
	return fmt.aprintf(
		"%s, %02d %s %04d %02d:%02d:%02d GMT",
		weekday_name(time.weekday(clock)),
		d,
		month_name(int(m)),
		y,
		h,
		mi,
		sec,
		allocator = allocator,
	)
}

@(private)
month_name :: proc(m: int) -> string {
	names := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	if m >= 1 && m <= 12 {
		return names[m - 1]
	}
	return "Jan"
}

// Shared with listeners_test.odin so the two cannot drift apart and still
// agree with each other by accident.
@(private)
WEEKDAY_NAMES := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

@(private)
weekday_name :: proc(wd: time.Weekday) -> string {
	return WEEKDAY_NAMES[int(wd)]
}
