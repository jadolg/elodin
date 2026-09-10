package itest

import "core:fmt"
import "core:strings"
import "core:time"

/*
Parity: does elodin hand the client what its upstream handed elodin?

The rest of this suite asks whether particular answers are right. This asks a
different question, and one no fixed case can: whether anything at all is lost
between the two sides of the resolver. A generator makes queries nobody wrote
down - types this codec has no structure for, options it does not recognise,
names holding bytes a hostname never holds - and every answer is held against
the upstream's, field by field, with every difference either matched to a
written-down reason or failed.

Two modes, and they ask subtly different things:

  mock  the reference is the very bytes a synthetic upstream put on the wire, so
        any difference is elodin's doing and nothing else's. Hermetic and
        deterministic; this is the one that gates a change.
  live  the reference is a second, byte-identical query put straight to a real
        resolver. Weaker, because a real resolver may answer twice in two ways,
        and everything it reports has to survive that. What it buys is answers
        no mock would think to serve.

Neither runs as part of `mise run itest`: the mock mode takes a minute and the
live mode needs the network. `mise run parity` runs the mock mode; the live one
is asked for by name, since a task that reaches a public resolver is not one to
put behind a bare `mise run`:

    ./bin/itest --parity --parity-upstream 1.1.1.1:53
*/

// The datagram ceiling the parity configuration pins, kept next to the
// comparison that depends on it rather than only in the yaml that sets it.
PARITY_MAX_UDP_RESPONSE :: 1232

Parity_Options :: struct {
	// Queries to send. One is enough to reproduce a known failure; a nightly
	// run sends tens of thousands.
	runs:      int,
	seed:      u64,
	// A resolver to compare against, `host:port`. Empty runs the mock mode.
	upstream:  string,
	// Print every difference, allowed ones included. How the allowance table
	// in parity_compare.odin gets written in the first place.
	explain:   bool,
	verbose:   bool,
}

Parity_Stats :: struct {
	sent:       int,
	compared:   int,
	identical:  int,
	// Answered by elodin itself, so there was no upstream answer to compare.
	local:      int,
	// Elodin did not answer at all.
	unanswered: int,
	// The reference was unusable: the mock never saw the query, or the live
	// resolver disagreed with itself.
	skipped:    int,
	failures:   int,
	/*
	Queries sent over each transport.

	Reported because a run that believed it was covering four and covered one
	is a run whose result means less than it says, and that is not a
	hypothetical: the generator's transport list was once allocated in the
	arena the loop resets per query, so every query after the first went out
	over UDP while the summary said nothing was wrong. A count nobody reads is
	still a count somebody can check.
	*/
	transports: [Parity_Transport]int,
	// How many times each written-down reason was the explanation for a
	// difference, keyed by the reason itself.
	allowances: map[string]int,
}

/*
The tally outlives the per-query arena, so it owns its own memory.

Each reason is cloned in on first sight (`parity_tally`) and freed here. Without
the free the run leaks one string per distinct reason - a handful, not a leak
that matters in a test binary, but `mise run leakcheck` is the one place a
number like that is supposed to be zero.
*/
@(private = "file")
parity_stats_make :: proc() -> Parity_Stats {
	return Parity_Stats{allowances = make(map[string]int, 16, context.allocator)}
}

@(private = "file")
parity_stats_destroy :: proc(stats: ^Parity_Stats) {
	for reason in stats.allowances {
		delete(reason, context.allocator)
	}
	delete(stats.allowances)
}

@(private = "file")
PARITY_POOL := []string {
	"parity.test.",
	"www.parity.test.",
	"deep.nested.parity.test.",
	"a.parity.test.",
	"_dns.resolver.parity.test.",
	"xn--bcher-kva.parity.test.",
	"one.two.three.four.five.parity.test.",
}

run_parity_cases :: proc(r: ^Runner, opts: Parity_Options) {
	if opts.upstream != "" {
		run_parity_live(r, opts)
		return
	}
	run_parity_mock(r, opts)
}

// --- mock mode -------------------------------------------------------------

run_parity_mock :: proc(r: ^Runner, opts: Parity_Options) {
	// Heap, not the arena: `start_case` keeps the pointer and `fail` reads it
	// back on every divergence, by which time the loop below has reset the temp
	// allocator many times over. `harness.odin` clones its log path for the
	// same reason. Freed after `end_case`, which defers run in reverse order.
	title := fmt.aprintf("parity against a synthetic upstream (seed %d)", opts.seed)
	defer delete(title)
	start_case(r, title)
	defer end_case(r)

	udp_port := next_port(r)
	tcp_port := udp_port
	dot_port := next_port(r)
	doh_port := next_port(r)
	mock_port := next_port(r)

	mock := mock_make("parity", mock_port)
	mock_parity_all(mock)
	if !mock_start(mock) {
		fail(r, "the parity mock did not start on port %d", mock_port)
		return
	}
	defer mock_stop(mock)

	tls := r.cert_file != ""
	cfg := parity_config(r, udp_port, dot_port, doh_port, mock_port, tls)
	srv, ok := start_server(
		r,
		Server_Options {
			config = cfg,
			udp_port = udp_port,
			tcp_port = tcp_port,
			dot_port = tls ? dot_port : 0,
			doh_port = tls ? doh_port : 0,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	/*
	The generator holds this for the whole run, so it cannot come from the
	temp allocator: the loop below resets that arena after every query, and a
	slice into it reads reclaimed memory from the second query on. What that
	looked like was every query going out over UDP while the run reported
	itself as covering four transports.
	*/
	transports := make([dynamic]Parity_Transport, 0, 4, context.allocator)
	defer delete(transports)
	append(&transports, Parity_Transport.UDP, Parity_Transport.TCP)
	if tls {
		append(&transports, Parity_Transport.DoT, Parity_Transport.DoH)
	}

	g := pg_make(opts.seed, PARITY_POOL, transports[:])
	stats := parity_stats_make()
	defer parity_stats_destroy(&stats)

	for i in 0 ..< opts.runs {
		parity_one_mock(r, &srv, mock, &g, opts, &stats, i)
		// The generator allocates a query and the comparator a page of strings
		// per iteration; without this a long run grows without bound.
		free_all(context.temp_allocator)
	}

	parity_report(r, opts, stats)
}

@(private = "file")
parity_one_mock :: proc(
	r: ^Runner,
	srv: ^Server,
	mock: ^Mock,
	g: ^Parity_Gen,
	opts: Parity_Options,
	stats: ^Parity_Stats,
	index: int,
) {
	q := pg_query(g)
	mock_reset_replies(mock)
	stats.sent += 1
	stats.transports[q.transport] += 1

	answer, answered := parity_ask_elodin(srv, q)
	if !answered {
		// Not every query has an answer coming: this server drops a message it
		// cannot make a response out of rather than replying to it.
		stats.unanswered += 1
		return
	}

	reference, count := mock_last_reply(mock)
	if count == 0 {
		// Nothing reached the upstream, so the server answered out of its own
		// mouth. Correct for some questions and a finding for others.
		stats.local += 1
		parity_check_local(r, q, answer, opts, stats)
		return
	}
	if reference == nil {
		stats.skipped += 1
		return
	}

	policy := Parity_Policy {
		mode             = .Mock,
		dnssec_validation = false,
		ttl_exact        = true,
		transport        = q.transport,
		client_udp_limit = parity_client_limit(q),
	}
	parity_judge(r, q, reference, answer, policy, opts, stats, index)
}

/*
The configuration a parity run needs.

Everything that would make elodin answer as anything other than a pipe is off,
and each for its own reason:

  cache      a cached answer's ttl counts down, and then the only honest rule
             for a ttl is a range wide enough to hide the bug this is looking
             for. Off, the rule is equality.
  blocking   a blocked name is answered without an upstream, which is the one
             divergence the whole check is defined to exclude.
  rewrites   the same.
  dnssec     the mock serves a zone with no chain to the root, so validation
             would turn every answer into servfail. What validation does to an
             answer is checked in the live mode, which has a real chain.
  rate limit the generator is one address asking as fast as it can, which is
             exactly the shape the limiter exists to stop.

`attempts: 1` so one client query means one upstream exchange, which is what
lets the mock's last reply be read as this query's reference.
*/
@(private = "file")
parity_config :: proc(
	r: ^Runner,
	udp_port, dot_port, doh_port, mock_port: int,
	tls: bool,
) -> string {
	sb := strings.builder_make(context.temp_allocator)
	fmt.sbprintf(
		&sb,
		`log:
  level: warn

server:
  workers: 8
  upstream_workers: 4
  client_timeout: 10s
  # Pinned rather than left at the shipped default, because the comparison has
  # to know it: an answer larger than this is cut down and marked whatever the
  # client advertised, and a check that did not know the number would read that
  # as data being lost. See PARITY_MAX_UDP_RESPONSE.
  max_udp_response: 1232
  rate_limit:
    enabled: false

listeners:
  udp:
    enabled: true
    address: "127.0.0.1"
    port: %d
  tcp:
    enabled: true
    address: "127.0.0.1"
    port: %d
`,
		udp_port,
		udp_port,
	)
	if tls {
		fmt.sbprintf(
			&sb,
			`  dot:
    enabled: true
    address: "127.0.0.1"
    port: %d
    cert_file: %s
    key_file: %s
  doh:
    enabled: true
    address: "127.0.0.1"
    port: %d
    path: /dns-query
    cert_file: %s
    key_file: %s
`,
			dot_port,
			r.cert_file,
			r.key_file,
			doh_port,
			r.cert_file,
			r.key_file,
		)
	}
	fmt.sbprintf(
		&sb,
		`
upstream:
  strategy: failover
  timeout: 5s
  attempts: 1
  servers:
    - name: parity
      type: udp
      address: 127.0.0.1
      port: %d

cache:
  enabled: false

blocking:
  enabled: false

dnssec:
  enabled: false
`,
		mock_port,
	)
	return strings.to_string(sb)
}

// --- live mode -------------------------------------------------------------

run_parity_live :: proc(r: ^Runner, opts: Parity_Options) {
	// Heap rather than the arena; see `run_parity_mock`.
	title := fmt.aprintf("parity against %s (seed %d)", opts.upstream, opts.seed)
	defer delete(title)
	start_case(r, title)
	defer end_case(r)

	host, port, split_ok := parity_split_host_port(opts.upstream)
	if !split_ok {
		fail(r, "cannot read %q as host:port", opts.upstream)
		return
	}

	udp_port := next_port(r)
	dot_port := next_port(r)
	doh_port := next_port(r)

	tls := r.cert_file != ""
	cfg := parity_live_config(r, udp_port, dot_port, doh_port, host, port, tls)
	srv, ok := start_server(
		r,
		Server_Options {
			config = cfg,
			udp_port = udp_port,
			tcp_port = udp_port,
			dot_port = tls ? dot_port : 0,
			doh_port = tls ? doh_port : 0,
			warmup = 5 * time.Second,
		},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	/*
	The generator holds this for the whole run, so it cannot come from the
	temp allocator: the loop below resets that arena after every query, and a
	slice into it reads reclaimed memory from the second query on. What that
	looked like was every query going out over UDP while the run reported
	itself as covering four transports.
	*/
	transports := make([dynamic]Parity_Transport, 0, 4, context.allocator)
	defer delete(transports)
	append(&transports, Parity_Transport.UDP, Parity_Transport.TCP)
	if tls {
		append(&transports, Parity_Transport.DoT, Parity_Transport.DoH)
	}

	g := pg_make(opts.seed, PARITY_LIVE_POOL, transports[:])
	// Nothing here may generate a question the resolver would answer locally:
	// live mode has no way to tell that apart from a divergence.
	g.include_local = false

	stats := parity_stats_make()
	defer parity_stats_destroy(&stats)

	for i in 0 ..< opts.runs {
		parity_one_live(r, &srv, host, port, &g, opts, &stats, i)
		free_all(context.temp_allocator)
	}

	parity_report(r, opts, stats)
}

@(private = "file")
PARITY_LIVE_POOL := []string {
	"example.com.",
	"example.org.",
	"iana.org.",
	"cloudflare.com.",
	"www.cloudflare.com.",
	"isc.org.",
	"nlnetlabs.nl.",
	"ietf.org.",
	"kernel.org.",
	"debian.org.",
	"wikipedia.org.",
	"mozilla.org.",
	"github.com.",
	"_25._tcp.mail.ietf.org.",
	"gmail.com.",
	"nist.gov.",
}

@(private = "file")
parity_one_live :: proc(
	r: ^Runner,
	srv: ^Server,
	host: string,
	port: int,
	g: ^Parity_Gen,
	opts: Parity_Options,
	stats: ^Parity_Stats,
	index: int,
) {
	q := pg_query(g)
	stats.sent += 1
	stats.transports[q.transport] += 1

	policy := Parity_Policy {
		mode             = .Live,
		dnssec_validation = true,
		ttl_exact        = false,
		transport        = q.transport,
		client_udp_limit = parity_client_limit(q),
	}

	/*
	Twice, and only a difference that survives both times is reported.

	The stability check below establishes that the resolver answers this name
	the same way twice, which is most of the problem but not all of it: the
	reference queries and elodin's own go to an anycast address, and two of them
	can land on nodes holding different copies. That produces a difference that
	is real, reproducible in the sense that the bytes really did differ, and
	nothing whatever to do with this server. Asking the whole question again is
	what tells the two apart, and it costs one extra exchange per divergence
	rather than one per query.
	*/
	for attempt in 0 ..< 2 {
		outcome, c := parity_live_attempt(srv, host, port, q, policy, stats, attempt == 0)
		switch outcome {
		case .Skipped, .Unanswered:
			return
		case .Compared:
			if !parity_failed(c.diffs[:]) {
				parity_tally(opts, stats, c, attempt == 0)
				return
			}
		}
		if attempt == 1 {
			parity_report_diffs(r, q, c, opts, stats, index)
		}
	}
}

@(private = "file")
Parity_Outcome :: enum u8 {
	Compared,
	Skipped,
	Unanswered,
}

@(private = "file")
parity_live_attempt :: proc(
	srv: ^Server,
	host: string,
	port: int,
	q: Parity_Query,
	policy: Parity_Policy,
	stats: ^Parity_Stats,
	count_it: bool,
) -> (
	outcome: Parity_Outcome,
	c: Parity_Compare,
) {
	/*
	The reference has to be shown to be a fact about the name rather than about
	the moment. A real resolver rotates rrsets, expires ttls between two
	datagrams and answers from whichever of its anycast nodes took the query, so
	one answer is not a reference - two identical ones are. A name that cannot
	produce them is skipped, and the count of skips is reported, because a mode
	that quietly skipped most of its work would look like a mode that passed.
	*/
	first, first_ok := parity_ask_reference(host, port, q.wire)
	if !first_ok {
		if count_it {
			stats.skipped += 1
		}
		return .Skipped, c
	}
	second, second_ok := parity_ask_reference(host, port, q.wire)
	if !second_ok || !parity_stable_twice(first, second) {
		if count_it {
			stats.skipped += 1
		}
		return .Skipped, c
	}

	answer, answered := parity_ask_elodin(srv, q)
	if !answered {
		if count_it {
			stats.unanswered += 1
		}
		return .Unanswered, c
	}

	c = parity_compare(q, first, answer, policy)
	if count_it {
		stats.compared += 1
		if c.identical {
			stats.identical += 1
		}
	}
	return .Compared, c
}

/*
Whether a resolver gave the same answer twice.

Compared on the canonical form rather than on the bytes: two answers that list
the same records in a different order are the same answer, and holding a live
resolver to byte equality with itself would skip nearly everything.
*/
@(private = "file")
parity_stable_twice :: proc(a, b: []u8) -> bool {
	x := pw_parse(a, context.temp_allocator)
	y := pw_parse(b, context.temp_allocator)
	if !x.ok || !y.ok {
		return false
	}
	if x.rcode != y.rcode || x.ad != y.ad || x.tc != y.tc || x.aa != y.aa {
		return false
	}
	if !parity_same_options(x, y) {
		return false
	}
	return parity_same_records(x.answer, y.answer) &&
		parity_same_records(x.authority, y.authority) &&
		parity_same_records(x.additional, y.additional)
}

/*
Whether two answers carried the same EDNS options.

Part of the stability check for the same reason the records are, and learned the
hard way: an anycast resolver's nodes do not agree to the letter on the text of
an Extended DNS Error - one says "RRSIG queries not supported here" and another
capitalises it - so an options list taken from one node is not a reference for an
answer that came from the other. Checking only the records let that through as a
stable name and then reported the capital letter as elodin changing the option.
*/
@(private = "file")
parity_same_options :: proc(x, y: Pw_Msg) -> bool {
	if len(x.opt.options) != len(y.opt.options) {
		return false
	}
	taken := make([]bool, len(y.opt.options), context.temp_allocator)
	for a in x.opt.options {
		matched := false
		for b, i in y.opt.options {
			if taken[i] || b.code != a.code {
				continue
			}
			// An extended DNS error is judged on its info-code, for the reason
			// `pc_option_text_allowance` gives: the text is the responder's own
			// wording and two nodes of one service word it differently, so
			// holding the reference to its own text would skip every name that
			// carries one.
			ad, bd := a.data, b.data
			if a.code == 15 && len(ad) >= 2 && len(bd) >= 2 {
				ad, bd = ad[:2], bd[:2]
			}
			if len(ad) != len(bd) {
				continue
			}
			same := true
			for k in 0 ..< len(ad) {
				if ad[k] != bd[k] {
					same = false
					break
				}
			}
			if same {
				taken[i], matched = true, true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

@(private = "file")
parity_same_records :: proc(a, b: []Pw_RR) -> bool {
	if len(a) != len(b) {
		return false
	}
	x := pw_section_keys(a, context.temp_allocator)
	y := pw_section_keys(b, context.temp_allocator)
	for key, i in x {
		if key != y[i] {
			return false
		}
	}
	return true
}

@(private = "file")
parity_live_config :: proc(
	r: ^Runner,
	udp_port, dot_port, doh_port: int,
	host: string,
	port: int,
	tls: bool,
) -> string {
	base := parity_config(r, udp_port, dot_port, doh_port, port, tls)
	// The mock's address is the loopback; a live run's is wherever the resolver
	// is.
	replaced, _ := strings.replace(
		base,
		"      address: 127.0.0.1\n",
		fmt.tprintf("      address: %s\n", host),
		1,
		context.temp_allocator,
	)
	/*
	Validation goes back on, because a real resolver has a chain to the root and
	carrying validation through is one of the things that must not be lost.

	And the cache goes on with it, which the mock mode does not want. A zone's
	keys are cached with everything else, so with the cache off every name
	re-walks the chain from the root - enough traffic for a public resolver to
	start dropping it, and then the run measures the dropping rather than the
	resolving. `bench/cmd/bench/survey.go` turns it on for the same reason.

	The price is that a ttl may have counted down by the time it reaches the
	client, so `Parity_Policy.ttl_exact` is false here and the ttl rule is a
	named difference rather than equality. That is a real loss of strictness and it is why the mock mode, which
	does not need the cache, does not pay it.
	*/
	with_dnssec, _ := strings.replace(
		replaced,
		"dnssec:\n  enabled: false\n",
		"dnssec:\n  enabled: true\n",
		1,
		context.temp_allocator,
	)
	with_cache, _ := strings.replace(
		with_dnssec,
		"cache:\n  enabled: false\n",
		"cache:\n  enabled: true\n  max_entries: 20000\n",
		1,
		context.temp_allocator,
	)
	return with_cache
}

// --- fixed cases -----------------------------------------------------------

/*
A divergence a generated run turned up, asked for by name.

A seed is no use for this one. `parity-regression` replays four hundred queries
per seed, and the shape below occurs about once in a hundred thousand - it was
query 2774 of one run and query 12467 of another, so the seeds that found it
would replay four hundred ordinary queries and pass. The query is written down
instead, and this runs in the ordinary suite where it gates a pull request
rather than behind `--parity`, which nothing gates.
*/
run_parity_fixed_cases :: proc(r: ^Runner) {
	parity_additional_dropped_case(r)
}

/*
The name the run that found it asked about.

Verbatim, because the mock synthesises its zone from a hash of the name and the
type (`parity_synth_reply`): a name somebody typed would be answered with some
other shape, and the shape is the whole of what this case needs. Lower case
where the run's was mixed, which is the same name - the mock folds the question
before it hashes it.

Three labels of sixty, which is what makes the reply overflow the client's
datagram by one record rather than by ten.
*/
@(private = "file")
PARITY_286_NAME ::
	"pe3ejfjex8s2vf5cvcgt9dzueqrilmudabo8rtn6yewyef0n4vlnpkihf2pr." +
	"1-ru_xmfmm0qnxytsoewoac2hxp0a-2fp23jqg28t0xnlvhp2s1xwx_1stc7." +
	"qmbcprg7q7aszhfzwprbgzauaexahf6z7a0yvaib2cqigzgej7jdd5hfdhkd." +
	"_dns.resolver.parity.test."

// The datagram this client can be sent, and the ceiling the answer is fitted
// into: the bare 512 of RFC 1035 section 4.2.1, which is also what the query
// below advertises.
@(private = "file")
PARITY_286_CEILING :: 512

/*
A glue record left out to fit the client's datagram is not a divergence (#286).

RFC 2181 section 9: a responder that could not fit additional data leaves the
whole RRSet out and sends the reply as it is, with TC clear. The client asked a
question and has its answer; the address it did not get is ordinary additional
data it can go and ask for. `encode_message` in src/dns/encode.odin does exactly
that, and the comparison had no allowance for it - the record fell through to a
bare "a record missing from the additional section" with no reason beside it,
and a run of the length worth running failed on something nobody did wrong.

The shape is the one the run found: a DNSKEY question the mock answers with
three keys, one NS in the authority section and its A and AAAA glue in the
additional one. That comes to 626 bytes against a client that can take 512, and
elodin writes 511 of them - the answer whole, the authority whole, the A glue,
the OPT record, and no AAAA.

Every part of that shape is checked before the comparison is asked about it. A
case whose fixture stopped holding a record to drop would otherwise agree with
an answer that never dropped one, which is a case that passes and tests nothing.
*/
@(private = "file")
parity_additional_dropped_case :: proc(r: ^Runner) {
	start_case(
		r,
		"parity: a glue record dropped to fit the client's datagram is not a divergence",
	)
	defer end_case(r)

	udp_port := next_port(r)
	mock_port := next_port(r)

	mock := mock_make("parity-fixed", mock_port)
	mock_parity_all(mock)
	if !mock_start(mock) {
		fail(r, "the parity mock did not start on port %d", mock_port)
		return
	}
	defer mock_stop(mock)

	// The same configuration a generated run uses, so the answer is fitted the
	// same way: no cache, no blocking, no rewrites, one attempt per query.
	cfg := parity_config(r, udp_port, 0, 0, mock_port, false)
	srv, ok := start_server(
		r,
		Server_Options{config = cfg, udp_port = udp_port, tcp_port = udp_port},
	)
	if !ok {
		return
	}
	defer stop_server(&srv)

	q := parity_fixed_query(PARITY_286_NAME, 48, PARITY_286_CEILING)
	mock_reset_replies(mock)
	res := query_udp(srv.udp_port, q.wire, context.temp_allocator)
	if !check(r, res.ok, "no answer came back over udp") {
		return
	}
	/*
	The last reply, not the only one.

	This client advertised 512 and the forwarded query carries the client's OPT
	record as it is, so the mock cuts its own reply to 512 and sets TC, and
	src/upstream/plain.odin asks again over TCP. Two replies for one client
	query, and the second is the whole answer and the one to hold elodin's
	against. `parity_one_mock` reads the last reply for the same reason.
	*/
	reference, _ := mock_last_reply(mock)
	if !check(r, reference != nil, "the mock sent no reply") {
		return
	}

	up := pw_parse(reference, context.temp_allocator)
	el := pw_parse(res.wire, context.temp_allocator)
	if !parity_286_shape(r, up, el) {
		return
	}

	policy := Parity_Policy {
		mode              = .Mock,
		dnssec_validation = false,
		ttl_exact         = true,
		transport         = .UDP,
		client_udp_limit  = PARITY_286_CEILING,
	}
	c := parity_compare(q, reference, res.wire, policy)
	for d in c.diffs {
		if d.reason == "" {
			fail(r, "%s: upstream %s, elodin %s", d.what, d.upstream, d.elodin)
		}
	}
}

/*
The shape the case needs, checked before the comparison is asked about it.

None of this is the point of the case; all of it has to hold for the case to
have a point at all. The mock synthesises its zone from a hash of the name, so
a change there could leave this name answered with something that fits a
datagram whole - and a case that compared two identical messages would agree
with them and report a pass. Each check says what stopped holding, and the way
to fix one is to find a name the mock still answers this way and put it in
`PARITY_286_NAME`.
*/
@(private = "file")
parity_286_shape :: proc(r: ^Runner, up, el: Pw_Msg) -> bool {
	if !check(r, up.ok, "the upstream's reply does not parse: %s", up.err) {
		return false
	}
	if !check(r, el.ok, "elodin's answer does not parse: %s", el.err) {
		return false
	}
	if !check(
		r,
		up.size > PARITY_286_CEILING,
		"the upstream's reply is %d bytes, which fits a %d-byte datagram whole, so nothing had to be left out of it",
		up.size,
		PARITY_286_CEILING,
	) {
		return false
	}
	if !check(
		r,
		el.size <= PARITY_286_CEILING,
		"elodin wrote %d bytes to a client that can take %d",
		el.size,
		PARITY_286_CEILING,
	) {
		return false
	}
	if !check(
		r,
		len(el.answer) == len(up.answer) && len(el.authority) == len(up.authority),
		"the cut reached past the additional section: answer %d of %d, authority %d of %d",
		len(el.answer),
		len(up.answer),
		len(el.authority),
		len(up.authority),
	) {
		return false
	}
	if !check(
		r,
		len(el.additional) == len(up.additional) - 1,
		"elodin kept %d of the upstream's %d additional records, and this case is about exactly one of them going missing",
		len(el.additional),
		len(up.additional),
	) {
		return false
	}
	// The bit the whole case turns on: TC clear, so nothing tells the client to
	// come back over TCP and nothing in the comparison can read the drop off a
	// flag.
	return check(
		r,
		!el.tc,
		"elodin set tc, which RFC 2181 section 9 says not to do for additional data that would not fit",
	)
}

/*
A query written down rather than generated.

`pg_query` builds one out of a seed, which is what a run wants and what a fixed
case cannot have. The fields have to say what the bytes say, because the
comparison reads both: the question that comes back is held against `name`,
`qtype` and `qclass`, and the header bits against `rd`, `cd` and `do_bit`.
*/
@(private = "file")
parity_fixed_query :: proc(name: string, qtype: u16, udp_size: u16) -> Parity_Query {
	q := Parity_Query {
		id        = 0x286a,
		qtype     = qtype,
		qclass    = 1,
		rd        = true,
		edns      = true,
		udp_size  = udp_size,
		transport = .UDP,
		desc      = name,
	}
	q.wire = build_query(name, qtype, q.id, q.qclass, udp_size)
	// The question as sent, which is what the echo is compared against. Read
	// back out of the bytes rather than encoded a second time here.
	m := pw_parse(q.wire, context.temp_allocator)
	if m.ok && len(m.question) == 1 {
		q.name = m.question[0].name
	}
	return q
}
