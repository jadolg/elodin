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

Cache_Config :: struct {
	enabled:      bool,
	max_entries:  int,
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
	*/
	workers:          int,
	// Worker threads dedicated to racing upstreams, kept separate so a burst of
	// races cannot starve the handlers that submitted them.
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
}

Config :: struct {
	log:       Log_Config,
	server:    Server_Config,
	listeners: Listeners,
	upstream:  Upstream_Config,
	cache:     Cache_Config,
	blocking:  Blocking_Config,
	dnssec:    Dnssec_Config,
	rewrites:  []Rewrite,
}

default_config :: proc() -> Config {
	c: Config
	c.log = Log_Config {
		level   = .Info,
		queries = false,
	}
	c.server = Server_Config {
		// 128 workers carries roughly 5000 cache misses per second against a
		// 20 ms upstream. Idle threads cost almost nothing, so this is a far
		// better default than a number that only suits a household.
		workers          = 128,
		upstream_workers = 64,
		client_timeout   = 10 * time.Second,
		max_connections  = 512,
		max_pending      = 0,
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
	return c
}
