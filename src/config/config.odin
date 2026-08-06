package config

import "core:time"

Log_Level :: enum u8 {
	Debug,
	Info,
	Warn,
	Error,
}

Log_Config :: struct {
	level:   Log_Level,
	queries: bool,
	file:    string,
}

Listener :: struct {
	enabled:   bool,
	address:   string,
	port:      int,
	cert_file: string,
	key_file:  string,
	// DoH only.
	path:      string,
}

Listeners :: struct {
	udp: Listener,
	tcp: Listener,
	dot: Listener,
	doh: Listener,
}

Upstream_Kind :: enum u8 {
	UDP,
	TCP,
	TLS,
	HTTPS,
}

Upstream_Spec :: struct {
	name:      string,
	kind:      Upstream_Kind,
	// Dial target. For HTTPS this is the resolved host of `url`.
	address:   string,
	port:      int,
	// SNI and certificate name. Defaults to `address` when it is a hostname.
	hostname:  string,
	// HTTPS only.
	url:       string,
	path:      string,
	// Addresses used to resolve `hostname` when it is not an IP literal.
	bootstrap: []string,
	verify:    bool,
}

Strategy :: enum u8 {
	// Try servers in configured order, moving on when one fails.
	Failover,
	// Same, but the starting point advances on every query.
	Round_Robin,
	// Query every server at once and take the first usable answer.
	Race,
}

Upstream_Config :: struct {
	strategy:     Strategy,
	timeout:      time.Duration,
	attempts:     int,
	servers:      []Upstream_Spec,
	bootstrap:    []string,
	max_idle:     int,
	idle_timeout: time.Duration,
}

/*
The smallest byte budget worth starting with.

A cache that cannot hold one maximal answer - 64 KiB of wire and about twice
that again in the offsets and TTLs beside it - would refuse every large response
while still answering, which is a cache that has quietly stopped working on the
records that most want caching. Anything under this is a misconfiguration rather
than a small cache, so it is refused at load rather than discovered in
production.
*/
MIN_CACHE_BYTES :: 1024 * 1024

/*
The bounds on `server.max_udp_response`, and where it sits by default.

512 is what a client that sent no OPT record gets and the smallest response any
resolver has to be able to send, so there is nothing below it to choose. 4096 is
the largest buffer this server will believe a client's OPT record about, and so
the largest ceiling there is any point setting.
*/
MIN_UDP_RESPONSE :: 512
MAX_UDP_RESPONSE :: 4096
DEFAULT_MAX_UDP_RESPONSE :: 1232

Cache_Config :: struct {
	enabled:      bool,
	max_entries:  int,
	max_bytes:    int,
	min_ttl:      u32,
	max_ttl:      u32,
	negative_ttl: u32,
	serve_stale:  bool,
}

Block_Response :: enum u8 {
	NX_Domain,
	No_Data,
	Zero_IP,
	Custom_IP,
	Refused,
}

List_Format :: enum u8 {
	Auto,
	Hosts,
	Domains,
	Adblock,
}

Block_List :: struct {
	name:    string,
	url:     string,
	file:    string,
	format:  List_Format,
	enabled: bool,
}

Blocking_Config :: struct {
	enabled:     bool,
	response:    Block_Response,
	custom_ipv4: [4]u8,
	custom_ipv6: [16]u8,
	block_ttl:   u32,
	lists:       []Block_List,
	allow_lists: []Block_List,
	rules:       []string,
	allow_rules: []string,
	refresh:     time.Duration,
	cache_dir:   string,
}

Dnssec_Config :: struct {
	/*
	Whether answers are validated before they are served.

	On, because a resolver that forwards signatures without checking them gives
	the answers an authority they have not earned. The cost is that an upstream
	which cannot return DNSSEC records makes every signed zone unresolvable
	rather than merely unverified, so anything talking to such an upstream has
	to turn this off deliberately.
	*/
	enabled:              bool,
	/*
	Anchors to start from, in DS presentation form. Empty uses the root keys
	IANA publishes, which are compiled in.
	*/
	trust_anchors:        []string,
	// NSEC3 records asking for more iterations than this are treated as
	// unusable, which makes the zone insecure rather than letting it set the
	// validator an arbitrary amount of work (RFC 9276).
	max_nsec3_iterations: int,
}

Cookie_Config :: struct {
	/*
	Whether clients that send a DNS cookie get one back (RFC 7873).

	On, because it costs one hash per query and takes the client-facing path
	from "guess the transaction ID and the source port" to "guess a 64-bit
	value you were never shown". Clients that do not use cookies are unaffected;
	nothing is added to an answer whose query did not ask for it.
	*/
	enabled: bool,
	/*
	Whether a UDP query carrying a cookie must show a valid server cookie
	before it is answered.

	Off, because turning it on costs every new client an extra round trip: the
	first query is answered with BADCOOKIE and a cookie to come back with. Worth
	it while a spoofing attempt is actually under way, which is the case RFC
	7873 section 5.2.3 has it for. Queries with no cookie at all, and queries
	over TCP, DoT or DoH, are unaffected either way.

	Needs `enabled`: what it demands is a cookie this server issued, and with
	that off there are none. The pair is refused rather than quietly ignored,
	since it is turned on while an attack is under way and that is the wrong
	moment to find out it was never in force.
	*/
	require:  bool,
	/*
	Whether elodin presents a cookie of its own to plain UDP and TCP upstreams.

	On, and independent of `enabled`: one setting is about the clients asking us,
	this one is about the servers we ask. It is the same protection in the other
	direction — an off-path attacker forging an answer to one of our queries has
	to guess 64 bits it has never seen, on top of the transaction ID and the
	source port. A forged datagram that fails the check is ignored rather than
	answered, so the genuine reply is still waited for. Once a server has issued
	a cookie it owes one on every reply after it; a server that has never sent
	one does not implement them, and the exchange carries on without.

	Independent of `enabled` in the other respect too: the client's own cookie is
	taken off the query before it is forwarded whichever of the two is set, since
	it is the client's secret rather than something to spend on an upstream.

	Only queries that already carry an OPT record get a cookie, because adding
	one would mean an EDNS negotiation the client never asked for. With DNSSEC
	validation on — the default — every query this server forwards carries one.

	DoT and DoH upstreams are left out: the transport already authenticates the
	server, which is more than a cookie establishes.
	*/
	upstream: bool,
	/*
	The secret cookies are keyed by, as 32 hex characters. Empty draws a random
	one at startup, which is right for a single instance and wrong for several
	behind one address: each would reject the cookies the others handed out.

	Applies to the cookies handed to clients. The client cookies sent upstream
	are drawn at random per upstream and are not derived from this.
	*/
	secret:   string,
}

COOKIE_SECRET_LEN :: 16

/*
Read `cookies.secret` into the bytes it stands for.

Lives here rather than beside the server that uses it so that `--check` and
startup agree by construction. Two parsers written to the same rule are two
parsers that can drift, and the shape of that bug is a configuration `--check`
passes and the resolver then refuses to start on.
*/
parse_cookie_secret :: proc(text: string, out: ^[COOKIE_SECRET_LEN]u8) -> bool {
	if len(text) != COOKIE_SECRET_LEN * 2 {
		return false
	}
	for i in 0 ..< COOKIE_SECRET_LEN {
		hi, hi_ok := cookie_hex_value(text[i * 2])
		lo, lo_ok := cookie_hex_value(text[i * 2 + 1])
		if !hi_ok || !lo_ok {
			return false
		}
		out[i] = hi << 4 | lo
	}
	return true
}

@(private)
cookie_hex_value :: proc(c: u8) -> (v: u8, ok: bool) {
	switch c {
	case '0' ..= '9':
		return c - '0', true
	case 'a' ..= 'f':
		return c - 'a' + 10, true
	case 'A' ..= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

Rewrite_Kind :: enum u8 {
	A,
	AAAA,
	CNAME,
	// Answer the query as if the name were blocked.
	Block,
}

Rewrite_Answer :: struct {
	kind: Rewrite_Kind,
	v4:   [4]u8,
	v6:   [16]u8,
	name: string,
}

Rewrite :: struct {
	// Canonical, lowercase, trailing dot. Wildcards are stored as the suffix
	// they match, so "*.lan." is held as "lan." with wildcard set.
	domain:   string,
	wildcard: bool,
	answers:  []Rewrite_Answer,
	ttl:      u32,
}

Server_Config :: struct {
	/*
	Worker threads that run query handling.

	A worker is occupied for the whole of an upstream round trip, so sustained
	throughput on cache misses is roughly `workers / upstream_rtt`. With a
	typical 20 ms upstream that is about 50 queries per second per worker, and
	because every query shares this pool, a shortage delays answers that were
	going to come from the cache just as much as ones that were not.

	Size it as `target_qps * upstream_rtt`, with headroom: 5000 qps against a
	20 ms upstream wants at least 100.

	Zero derives it from the machine at startup - see `sizing.odin` - because
	every worker costs memory permanently and a number that suits a rack-mounted
	resolver is one a home router pays for and never uses.
	*/
	workers:          int,
	/*
	Worker threads dedicated to racing upstreams, kept separate so a burst of
	races cannot starve the handlers that submitted them.

	Zero derives it as half of `workers`, whether that came from the file or
	from the machine.
	*/
	upstream_workers: int,
	// Per-connection read timeout for TCP, DoT and DoH clients.
	client_timeout:   time.Duration,
	max_connections:  int,
	/*
	Queries allowed to be queued or in flight before new ones are dropped.

	Past this point the server is behind and queueing only adds latency to
	answers whose clients have already given up. DNS clients retry, so shedding
	is the better failure: it keeps latency bounded for the queries that are
	still being served instead of making every one of them slow.

	Zero derives it as `workers * 8`, which is about eight upstream round trips
	of backlog whatever the worker count, so the queue stays a bounded delay
	rather than a growing one.
	*/
	max_pending:      int,
	/*
	Account the process switches to once the listeners have bound.

	Binding a port below 1024 is the only privileged thing elodin does, and it
	is over within a second of starting. Everything after it parses data that
	came off the network, so an operator who started the process as root has
	every reason to want it to be somebody else by the time that begins. A name
	or a numeric uid; empty leaves the process as it started.
	*/
	user:             string,
	// Group to go with `user`. Empty takes the user's primary group.
	group:            string,
	/*
	Networks a query is accepted from, in CIDR form. See `acl.odin`.

	Defaults to the local networks, so an installation nobody has configured
	serves the machine and the network it is on rather than the internet. An
	empty list is no restriction, for a resolver that is meant to be public.
	*/
	allow_from:       []Prefix,
	/*
	The largest UDP response this server will send, whatever the client asked
	for.

	A client advertises a buffer size in its OPT record, and an attacker
	spoofing a victim's address advertises the largest one it can get away with:
	that number is the amplification factor. A 40-byte query claiming 4096 buys
	roughly a hundredfold, and the rate limiter's per-/24 budget is denominated
	in it - 500 responses a second at 4096 is about 2 MB/s aimed at one network,
	and at 1232 about 600 KB/s.

	1232 is the DNS Flag Day 2020 figure and what most resolvers advertise now.
	It costs a TC bit, and a retry over TCP, on any answer between it and what
	the client asked for. Measured against the survey in `bench/results/`, that
	is no A or AAAA answer at all and five DNSKEY answers out of 129, so the
	cost against real traffic is close to nothing and the ceiling it removes is
	one only a zone built to fill it ever reached.

	Raise it, up to 4096, on a network whose path MTU is known to carry large
	datagrams and where the resolver is not reachable by anyone who would abuse
	it. Below 512 there is nothing sensible to send, so that is the floor.
	*/
	max_udp_response: int,
	rate_limit:       Rate_Limit_Config,
	// What the two worker counts were derived from, when they were. Not a
	// setting: filled in at load so startup and `--check` can report it.
	sizing:           Sizing,
}

/*
Response rate limiting for the UDP listener.

`responses_per_second` is per client prefix - /24 for IPv4, /64 for IPv6 -
because an attacker spoofing a victim's address picks freely within their range,
so a per-address budget would only be spread across it. `slip` answers every Nth
query over the budget with a truncated response rather than dropping it, which
tells a real client to come back over TCP where the handshake proves the address
an answer would go to; 0 drops them all.
*/
Rate_Limit_Config :: struct {
	enabled:              bool,
	responses_per_second: int,
	slip:                 int,
}

Config :: struct {
	log:       Log_Config,
	server:    Server_Config,
	listeners: Listeners,
	upstream:  Upstream_Config,
	cache:     Cache_Config,
	blocking:  Blocking_Config,
	dnssec:    Dnssec_Config,
	cookies:   Cookie_Config,
	rewrites:  []Rewrite,
}

default_config :: proc() -> Config {
	c: Config
	c.log = Log_Config {
		level   = .Info,
		queries = false,
	}
	c.server = Server_Config {
		// Both zero: worked out at load from the CPUs and memory this machine
		// actually has. A fixed 128 and 64 sized every installation for five
		// thousand cache misses a second, and the threads that pays for keep
		// their scratch arenas resident whether or not the load ever arrives.
		workers          = 0,
		upstream_workers = 0,
		client_timeout   = 10 * time.Second,
		max_connections  = 512,
		max_pending      = 0,
		// The local networks, and nothing else: a resolver that has not been
		// configured must not be an open one. See `DEFAULT_ALLOW_FROM`.
		allow_from       = DEFAULT_ALLOW_FROM,
		// The DNS Flag Day 2020 figure. See the field, and the measurement in
		// bench/results/2026-08-06-edns-response-sizes.md.
		max_udp_response = DEFAULT_MAX_UDP_RESPONSE,
		/*
		On by default, and generous.

		A resolver that answers anything from anywhere is an amplifier, and the
		default has to be a bound rather than an invitation to configure one.
		Five hundred responses a second to one /24 is far past what a household
		or an office behind one NAT asks for - the busiest of those is a few
		dozen - and far under what makes reflection worth an attacker's
		bandwidth. Every second query past it comes back truncated rather than
		dropped, so a client that really is that busy keeps resolving, over TCP.
		*/
		rate_limit       = Rate_Limit_Config{enabled = true, responses_per_second = 500, slip = 2},
	}
	c.listeners.udp = Listener {
		enabled = true,
		address = "0.0.0.0",
		port    = 53,
	}
	c.listeners.tcp = Listener {
		enabled = true,
		address = "0.0.0.0",
		port    = 53,
	}
	c.listeners.dot = Listener {
		enabled = false,
		address = "0.0.0.0",
		port    = 853,
	}
	c.listeners.doh = Listener {
		enabled = false,
		address = "0.0.0.0",
		port    = 443,
		path    = "/dns-query",
	}
	c.upstream = Upstream_Config {
		strategy     = .Failover,
		timeout      = 5 * time.Second,
		attempts     = 2,
		max_idle     = 8,
		idle_timeout = 30 * time.Second,
	}
	c.cache = Cache_Config {
		enabled      = true,
		max_entries  = 10000,
		max_bytes    = 64 * 1024 * 1024,
		min_ttl      = 0,
		max_ttl      = 86400,
		negative_ttl = 300,
		serve_stale  = false,
	}
	c.blocking = Blocking_Config {
		enabled     = true,
		response    = .NX_Domain,
		custom_ipv4 = {0, 0, 0, 0},
		block_ttl   = 60,
		refresh     = 24 * time.Hour,
		cache_dir   = "/var/cache/elodin",
	}
	c.dnssec = Dnssec_Config {
		enabled              = true,
		max_nsec3_iterations = 100,
	}
	c.cookies = Cookie_Config {
		enabled  = true,
		require  = false,
		upstream = true,
	}
	return c
}
