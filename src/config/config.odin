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
	enabled:           bool,
	address:           string,
	port:              int,
	cert_file:         string,
	key_file:          string,
	// DoH only.
	path:              string,
	// DoH only: the path an iPhone, iPad or Mac downloads its encrypted-DNS
	// configuration profile (.mobileconfig) from. Empty turns it off; when it is
	// set, the profile is served on the DoH listener alongside `path`.
	mobileconfig_path: string,
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

	It bounds the two transports that queue: UDP, whose read loop drops the
	datagram, and DoH over HTTP/2, whose stream is answered 503 rather than
	dropped - there is a client on an open connection there to tell. TCP, DoT
	and HTTP/1.1 DoH answer on their own connection thread and are bounded by
	`max_connections` instead.
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
Response rate limiting.

`responses_per_second` is per client prefix - /24 for IPv4, /64 for IPv6 -
because an attacker spoofing a victim's address picks freely within their range,
so a per-address budget would only be spread across it. `slip` answers every Nth
query over the budget with a truncated response rather than dropping it, which
tells a real client to come back over TCP where the handshake proves the address
an answer would go to; 0 drops them all.

The figure is charged twice over, not once: each prefix gets it for datagrams and
again for queries read off a connection, and neither budget can be spent from the
other's side. Deliberately, and not to be quietly consolidated - a UDP source
address is written by whoever sent the datagram, so one shared budget let a spoofed
flood naming a prefix close the TCP, DoT and DoH connections of the clients who
live in it. `ratelimit.odin` is where that is argued out. The cost is that a client
asking both ways can draw twice the figure.

`slip` applies to UDP alone: a truncated answer is an instruction to ask again over
TCP, so it has nothing to say to a client that is already on a connection.
Over-budget queries there end the connection instead, DoH saying so with a 429
first.
*/
Rate_Limit_Config :: struct {
	enabled:              bool,
	responses_per_second: int,
	slip:                 int,
}

/*
Refusing an upstream answer that points a public name into private address space.

The reasoning for the whole feature is in `src/server/rebind.odin`; what is
decided here is the default, and it is the part of this that can go wrong for
somebody who never read either file.

Off, which is where dnsmasq (`--stop-dns-rebind`), AdGuard Home and Unbound
(`private-address`) all put their version of it too. The reason to follow them
is not deference - it is that the deployment this program is written for is the
one most likely to do the exact thing the guard refuses, and to do it on
purpose. A box on a LAN that every device points at is commonly the same box
running split horizon: a public zone whose names answer with a LAN address, an
upstream that is the operator's own internal server, a homelab whose
`nas.example.com` is `192.168.1.50` by design. On by default, every one of those
names becomes NODATA the moment the operator upgrades - not degraded, gone, and
looking exactly like a name that does not exist - for a configuration that was
never wrong. A security default that breaks working resolution for a large share
of the people it ships to is one they will turn off in a hurry and with a bad
taste, rather than one they will leave on.

So the guard ships off and is turned on by the operator who wants it, which is
the same shape dnsmasq and the others chose. `dnssec.enabled` defaults the other
way in this tree, and the difference is real: an upstream that cannot return
DNSSEC records is a misconfiguration to fix, whereas a public name answering with
a private address is, for this program's audience, a supported and ordinary
thing to be doing. The two are not the same trade.

None of that lowers what the guard is worth to the operator who is not running
split horizon: it is one line to enable, the failure it prevents is silent and
the refusal it produces is loud - a `warn` naming the address and both settings
that would allow it, a `rebind=` counter, a query-log line - and `allow_domains`
exists so that even an operator who does run split horizon can turn it on and
name the zones that are allowed to answer privately. The README recommends
enabling it, in exactly those terms.
*/
Rebind_Config :: struct {
	enabled:        bool,
	/*
	Names whose answers may carry private addresses, each covering itself and
	everything below it - dnsmasq's `--rebind-domain-ok`.

	Matched against the question, not against the owner name of the offending
	record. A CNAME into an exempt zone therefore exempts nothing: the browser's
	origin is the name it asked for, and that is the name whose answer is being
	trusted. The other way round is what an operator means - `home.example`
	listed here covers `nas.home.example` however many CNAMEs the answer takes
	to reach an address.
	*/
	allow_domains:  []string,
	/*
	Whether 127.0.0.0/8 and ::1 are allowed through - dnsmasq's
	`--rebind-localhost-ok`.

	Off, because loopback is the address a rebinding attack most wants: a
	service bound to 127.0.0.1 is one its author believed only local processes
	could reach, and is therefore the one least likely to authenticate. The
	names that legitimately resolve there are few and usually the operator's
	own, which `allow_domains` covers by name rather than by opening the range
	for everything.
	*/
	allow_loopback: bool,
}

/*
The Prometheus endpoint.

Off, because a resolver that opens a second port nobody asked for is a resolver
that has widened its own attack surface on an operator's behalf. Everything it
would serve is already in the `msg=stats` log line, so nothing is lost by
leaving it off, and turning it on costs the process one thread and whatever a
scrape reads.

`address` defaults to loopback rather than to the `0.0.0.0` the DNS listeners
use. These numbers are not secret in the way an answer is, but they do describe
a network - query rates, block rates, which upstreams are up - and there is no
authentication in front of them, so the default is the interface a local scraper
or a sidecar reaches and nothing else. Binding it wider is a deliberate act and
is said so in the log.

9153 is the port CoreDNS uses for the same thing, which is what a scrape config
in an existing cluster already expects.
*/
Metrics_Config :: struct {
	enabled: bool,
	address: string,
	port:    int,
	path:    string,
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
	rebind:    Rebind_Config,
	metrics:   Metrics_Config,
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
		enabled           = false,
		address           = "0.0.0.0",
		port              = 443,
		path              = "/dns-query",
		// On by default once DoH itself is: an iOS or macOS device points at this
		// resolver by installing the profile served here, and the file gives away
		// nothing the DoH URL does not already. Set it to "" to withhold it.
		mobileconfig_path = "/apple-doh.mobileconfig",
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
	c.rebind = Rebind_Config {
		// Off, and with nothing exempt. See the type: the deployment this is
		// written for routinely and legitimately points a public name at a
		// private address - split horizon, a homelab whose public zone answers
		// with a LAN address - so on by default would break resolution for a
		// large share of its own operators on upgrade. It is one line to turn on.
		enabled        = false,
		allow_loopback = false,
	}
	c.metrics = Metrics_Config {
		enabled = false,
		address = "127.0.0.1",
		port    = 9153,
		path    = "/metrics",
	}
	return c
}
