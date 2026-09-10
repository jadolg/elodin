package server

import "core:mem"
import "core:strconv"
import "core:sync"
import "elodin:logx"
import "elodin:tlsx"

/*
The signing side of the Apple configuration profile endpoint.

`mobileconfig.odin` builds the profile; this decides whether it may be signed,
signs it at most once per authority, and keeps what it signed. The endpoint is
the only place in this server where an unauthenticated request asks for a
public-key operation, so most of what is here is about bounding that.

Four things stand between a request and a signature, in this order:

  - the certificate must be valid at this instant, or nothing is served at all;
  - the host must be one the certificate covers, which a header cannot invent;
  - the authority must not already be in the cache, which is what a repeat costs;
  - and the signing budget must have a token, which is what a stream of new
    authorities runs out of.

The first is also the answer to holding signed bytes in memory: an entry signed
while the certificate was good is checked again on the way out, so a certificate
that expires between signing and serving takes its cached profiles with it.
*/

/*
How many signed profiles to keep.

An operator's certificate names a handful of hosts, and each is asked about on
one or two authorities - with the port and without. Sixteen holds every real
deployment's whole working set, and the ceiling is there for the case that is not
real: the port is part of the URL and so part of the key, and a client picks it.
*/
PROFILE_CACHE_ENTRIES :: 16

/*
The signing budget: how many may be signed at once, and how fast that comes back.

These are not a throughput figure. A device downloads its profile once, so a
server that signs four a second sustained is already doing it far faster than
anything real asks for, and four ECDSA signatures a second is a rounding error
against answering DNS. What they bound is the other case - a client that keeps
asking about authorities the cache has never seen - which without them is a way
to buy a public-key operation with a request that costs nothing to send.

The burst is the cache size deliberately: a certificate renewal empties the cache,
and the working set has to be able to refill in one go rather than a name at a
time.
*/
PROFILE_SIGN_BURST :: 16
PROFILE_SIGN_RATE :: 4

Profile_Status :: enum u8 {
	// A signed profile, in the caller's allocator.
	OK,
	// Not an authority this listener could have been reached at - a host the
	// certificate does not cover, or a port it does not answer on. Either way
	// not a profile that could work on the device. The endpoint answers 400.
	Unknown_Host,
	// There is nothing valid to sign with, or the budget to sign is spent. The
	// endpoint answers 503.
	Unavailable,
}

@(private)
Profile_Entry :: struct {
	// Empty for a free slot. Owned, like the profile beside it.
	authority: string,
	profile:   []u8,
	// When this entry was last handed out, on `Profile_Signer.clock`. The lowest
	// is what an insertion into a full cache displaces.
	used:      u64,
}

Profile_Signer :: struct {
	/*
	Held across the signing, not only across the cache.

	Serialising the signatures is the point: it means this endpoint can occupy
	one core with public-key work however many connections ask at once, so a
	flood here cannot take the cores that are answering DNS. The work it guards
	is bounded by the budget below and short - a signature over a couple of
	kilobytes - and every request that is not the first for its authority takes
	the lock only long enough to copy.
	*/
	mu:            sync.Mutex,
	// Our own references, so this survives the reload that replaces the context
	// they came from. See `profile_signer_adopt`.
	signer:        tlsx.Signer,
	// `listeners.doh.path`, which the profile has the device query. Borrowed
	// from the configuration, which outlives this.
	doh_path:      string,
	// `listeners.doh.port`, one of the ports an authority may name. See
	// `profile_servable_port`.
	doh_port:      int,
	entries:       [PROFILE_CACHE_ENTRIES]Profile_Entry,
	clock:         u64,
	tokens:        f64,
	tokens_at:     i64,
	// False until the first request defines the budget's epoch, so a server that
	// has been up for a week does not start with a week of accumulated tokens.
	budget_started: bool,
	// What the metrics and the tests read; written under `mu`, so atomic only
	// for the reading.
	signed_total:  u64,
	refused_total: u64,
	// Counted apart from `refused_total` because the two say different things
	// to an operator: this one is a name mismatch between the request and the
	// certificate, which is a configuration answer, while a refusal is the
	// endpoint declining to work at all.
	unknown_total: u64,
	allocator:     mem.Allocator,
}

// Take the identity `ctx` serves and start with an empty cache. `doh_path` is
// the DoH endpoint's path, which the profiles will point devices at.
make_profile_signer :: proc(
	ctx: ^tlsx.Context,
	doh_path: string,
	doh_port: int,
	allocator := context.allocator,
) -> ^Profile_Signer {
	p := new(Profile_Signer, allocator)
	p.allocator = allocator
	p.doh_path = doh_path
	p.doh_port = doh_port
	p.signer = tlsx.signer_retain(ctx.signer)
	return p
}

/*
Switch to the certificate `ctx` now serves and forget everything signed with the
one before it.

Every cached entry is signed by a key the listener has stopped presenting, so a
renewal is exactly the moment they all have to go. The budget is refilled with
them: the working set has just been emptied through no fault of any client, and
making them wait for it to trickle back would turn a renewal into an outage.
*/
profile_signer_adopt :: proc(p: ^Profile_Signer, ctx: ^tlsx.Context) {
	if p == nil {
		return
	}
	held := tlsx.signer_retain(ctx.signer)
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	tlsx.signer_release(&p.signer)
	p.signer = held
	profile_cache_clear(p)
	p.budget_started = false
	// A renewal can arrive with a key that signs nothing, and from here on the
	// endpoint would answer 503 to everything with no line anywhere saying why.
	warn_unsigned_profiles(p)
}

destroy_profile_signer :: proc(p: ^Profile_Signer) {
	if p == nil {
		return
	}
	sync.mutex_lock(&p.mu)
	profile_cache_clear(p)
	tlsx.signer_release(&p.signer)
	sync.mutex_unlock(&p.mu)
	free(p, p.allocator)
}

@(private)
profile_cache_clear :: proc(p: ^Profile_Signer) {
	for &entry in p.entries {
		profile_entry_release(p, &entry)
	}
}

@(private)
profile_entry_release :: proc(p: ^Profile_Signer, entry: ^Profile_Entry) {
	if len(entry.authority) > 0 {
		delete(entry.authority, p.allocator)
	}
	if len(entry.profile) > 0 {
		delete(entry.profile, p.allocator)
	}
	entry^ = Profile_Entry{}
}

/*
The signed profile for `authority`, or why there is not one.

`now_unix` is the caller's clock reading rather than one taken here, so that the
one decision that must not be made from a stale answer - whether the certificate
is valid - is made against the same instant the rest of the request is.

The returned bytes are the caller's, copied out of the cache under the lock.
*/
profile_for_host :: proc(
	p: ^Profile_Signer,
	authority: string,
	now_unix: i64,
	allocator := context.allocator,
) -> (
	profile: []u8,
	status: Profile_Status,
) {
	if p == nil {
		return nil, .Unavailable
	}
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)

	// Before the cache, not after it: a cached entry is bytes signed by this
	// certificate, and once the certificate is out of its validity window they
	// are no more servable than a fresh signature would be.
	if !tlsx.signer_valid_at(p.signer, now_unix) {
		sync.atomic_add(&p.refused_total, 1)
		return nil, .Unavailable
	}
	// Lowercased before anything else looks at it. The certificate check below
	// is case-insensitive, as DNS names are, but everything after it - the cache
	// key, the URL in the profile - is a byte comparison, so without this a
	// client can spell one covered name a thousand ways and get a cache miss and
	// a signature for each. See `profile_normalise_authority`.
	key := profile_normalise_authority(authority)
	host, port := tlsx.split_host_port(key)
	if !profile_dialable_authority(key, host) ||
	   !tlsx.signer_covers_host(p.signer, host) ||
	   !profile_servable_port(p, port) {
		sync.atomic_add(&p.unknown_total, 1)
		return nil, .Unknown_Host
	}

	if entry := profile_cache_find(p, key); entry != nil {
		p.clock += 1
		entry.used = p.clock
		return profile_served(p, entry.profile, allocator)
	}
	if !profile_take_token(p, now_unix) {
		sync.atomic_add(&p.refused_total, 1)
		return nil, .Unavailable
	}

	plist := build_doh_mobileconfig(key, p.doh_path, context.temp_allocator)
	signed, ok := tlsx.sign_cms(p.signer, transmute([]u8)plist, p.allocator)
	if !ok {
		sync.atomic_add(&p.refused_total, 1)
		return nil, .Unavailable
	}
	sync.atomic_add(&p.signed_total, 1)
	profile_cache_put(p, key, signed)
	return profile_served(p, signed, allocator)
}

/*
Copy a profile out for the caller, or say it could not be.

The copy is the last thing that can fail, and failing it quietly would be the
worst of the three answers: the endpoint would report success and send a body of
nothing, which a device reads as a malformed profile rather than as a server that
could not answer.
*/
@(private)
profile_served :: proc(
	p: ^Profile_Signer,
	src: []u8,
	allocator: mem.Allocator,
) -> (
	[]u8,
	Profile_Status,
) {
	out, err := mem.make_aligned([]u8, len(src), 1, allocator)
	if err != nil {
		sync.atomic_add(&p.refused_total, 1)
		return nil, .Unavailable
	}
	copy(out, src)
	return out, .OK
}

/*
An authority in the one spelling this server will cache and sign for.

A hostname is case-insensitive, and `X509_check_host` compares it that way, so
`dns.example`, `DNS.EXAMPLE` and `dNs.eXaMpLe` are one name as far as the
certificate is concerned. Everything downstream of that check compares bytes: the
cache key, and the URL written into the profile. Left as they arrive, a client
with one covered name has 2^n spellings of it, every one a cache miss and so a
signature of its own - which is the signing budget drained by a client that never
needed a profile, and a 503 for the device that did.

Lowercasing the whole authority rather than the host alone is deliberate and
safe: what follows the host is a port, which is digits, or the brackets and hex
of an address literal, where lower case is the canonical spelling anyway.

The input comes back unchanged when there is nothing to fold, which is every
request a device makes, and also when the scratch allocation fails - a request
served the way it would have been before is a better answer there than none.
*/
@(private)
profile_normalise_authority :: proc(authority: string, allocator := context.temp_allocator) -> string {
	folds := false
	for i in 0 ..< len(authority) {
		if authority[i] >= 'A' && authority[i] <= 'Z' {
			folds = true
			break
		}
	}
	if !folds {
		return authority
	}
	out, err := mem.make_aligned([]u8, len(authority), 1, allocator)
	if err != nil {
		return authority
	}
	for i in 0 ..< len(authority) {
		c := authority[i]
		out[i] = c + ('a' - 'A') if c >= 'A' && c <= 'Z' else c
	}
	return string(out)
}

/*
Whether the authority is one a device could dial back.

`split_host_port` leaves an unbracketed IPv6 literal whole - none of the colons
in `::1` is a port separator, so it is a host with no port - and a certificate
carrying that address as an IP SAN answers for it quite happily. The URL built
from it would not: a URL spells an IPv6 address in brackets, so `https://::1/`
is not an authority any client can dial, and a device handed that profile would
resolve through nothing. The bracketed spelling of the same address goes
through, which makes this a bound on how an address may be written rather than
on which addresses are servable - the same shape as the port rule below, and the
other half of `split_host_port` refusing to unwrap `[elodin.local]`.
*/
@(private)
profile_dialable_authority :: proc(key: string, host: string) -> bool {
	if len(key) > 0 && key[0] == '[' {
		return true
	}
	// The only way a colon survives into the host is an authority whose colons
	// were all part of an address literal.
	for i in 0 ..< len(host) {
		if host[i] == ':' {
			return false
		}
	}
	return true
}

/*
Whether `port` is one this listener could have been reached on.

Empty is the ordinary case - a device on 443 sends no port - and the listener's
own port is the other. 443 is allowed explicitly as well, both because a client
may spell out the default and because that is the port a deployment forwarding
into a different internal one is reached at.

Only the canonical decimal spelling of either, which is what the digits below are
for: `strconv.parse_int` infers a base from an `0x`, `0o`, `0b` or `0z` prefix and
is happy to read leading zeros, so left to it `:08443`, `:008443` and `:0x1bb` are
all the port the listener is on - each one a distinct cache key and a distinct
signature, carrying a URL into the profile that no device can dial.

This is the host check's other half, and it is here for the same two reasons: a
profile naming a port nothing answers on could not work on the device, and the
port is part of the URL and so part of the cache key, so without a bound on it a
client can mint distinct profiles to sign for as long as it likes.
*/
@(private)
profile_servable_port :: proc(p: ^Profile_Signer, port: string) -> bool {
	if port == "" {
		return true
	}
	// A port is at most five digits, and a leading zero is a second spelling of
	// a number that already has one.
	if len(port) > 5 || port[0] == '0' {
		return false
	}
	for i in 0 ..< len(port) {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, ok := strconv.parse_int(port, 10)
	return ok && (n == 443 || n == p.doh_port)
}

@(private)
profile_cache_find :: proc(p: ^Profile_Signer, authority: string) -> ^Profile_Entry {
	for &entry in p.entries {
		if len(entry.authority) > 0 && entry.authority == authority {
			return &entry
		}
	}
	return nil
}

// Store `signed`, which becomes the cache's, displacing the entry handed out
// longest ago when there is no free slot.
@(private)
profile_cache_put :: proc(p: ^Profile_Signer, authority: string, signed: []u8) {
	victim := profile_cache_victim(p)
	profile_entry_release(p, victim)
	p.clock += 1
	victim.authority = profile_clone_string(authority, p.allocator)
	victim.profile = signed
	victim.used = p.clock
}

/*
The slot a new entry takes: a free one, else the one handed out longest ago.

Plainly least-recently-used, and not more than that. What was here before
preferred entries nothing had come back for, on the theory that a flood of
invented authorities is made of those and a real device's is not - but which
entries get asked for twice is the client's to decide, so a flood that repeats
itself marked every slot and the preference evaporated exactly when it was
wanted. A rule that holds only against an attacker who has not read it is worse
than none: it reads as a defence in the code and is not one.

What actually bounds this endpoint is upstream of the cache - the certificate
decides which hosts may be asked about, the port rule and the two normalisations
decide how many ways each may be spelled, and the budget decides how fast. On an
ordinary certificate those leave a working set of a handful, which fits here many
times over. On a wildcard or address SAN they do not, and a sustained flood can
push a device's entry out and refuse the re-signing; see the README, which says
so.
*/
@(private)
profile_cache_victim :: proc(p: ^Profile_Signer) -> ^Profile_Entry {
	oldest: ^Profile_Entry
	for &entry in p.entries {
		if len(entry.authority) == 0 {
			return &entry
		}
		if oldest == nil || entry.used < oldest.used {
			oldest = &entry
		}
	}
	return oldest
}

@(private)
profile_clone_string :: proc(s: string, allocator: mem.Allocator) -> string {
	out, err := mem.make_aligned([]u8, len(s), 1, allocator)
	if err != nil {
		return ""
	}
	copy(out, transmute([]u8)s)
	return string(out)
}

/*
Spend one signature from the budget, refilling it for the time that has passed.

A clock that has stepped backwards only moves the epoch: the alternative is to
treat the step as elapsed time and hand out a refill for it, which is the one
outcome a budget exists to prevent.
*/
@(private)
profile_take_token :: proc(p: ^Profile_Signer, now_unix: i64) -> bool {
	if !p.budget_started {
		p.budget_started = true
		p.tokens = PROFILE_SIGN_BURST
		p.tokens_at = now_unix
	} else if now_unix > p.tokens_at {
		p.tokens = min(f64(PROFILE_SIGN_BURST), p.tokens + f64(now_unix - p.tokens_at) * PROFILE_SIGN_RATE)
		p.tokens_at = now_unix
	} else if now_unix < p.tokens_at {
		p.tokens_at = now_unix
	}
	if p.tokens < 1 {
		return false
	}
	p.tokens -= 1
	return true
}

// What the metrics endpoint reports. Read without the lock: these are counters
// whose readers want a recent value rather than one consistent with each other.
profile_signer_stats :: proc(p: ^Profile_Signer) -> (signed, refused, unknown: u64) {
	if p == nil {
		return 0, 0, 0
	}
	return sync.atomic_load(&p.signed_total),
		sync.atomic_load(&p.refused_total),
		sync.atomic_load(&p.unknown_total)
}

// The counterpart to what `start_doh` builds, in the shape the rest of the
// server's owned things are released in. Safe on a server that never had one.
stop_profile_signer :: proc(s: ^Server) {
	destroy_profile_signer(s.profiles)
	s.profiles = nil
}

// A payload with no meaning beyond being something to sign: what the probe below
// asks is whether the key can produce a CMS structure at all, not what is in it.
@(private)
PROFILE_SIGN_PROBE :: "elodin"

/*
Said where an operator can still do something about it, at startup and again
whenever the identity is replaced.

Two ways this endpoint can be dead on arrival, and neither announces itself: a
context that yielded no certificate and key, and a key CMS cannot sign with at
all - an Ed25519 certificate, say, which TLS is perfectly happy to serve and
which `CMS_sign` refuses for want of a default digest. Both answer every request
503, which is the same 503 an expired certificate and a spent budget give, so
`elodin_mobileconfig_refused_total` climbing says nothing about which.

The second is only learnable by trying, and trying once answers it for every
request that follows: whether `CMS_sign` works is a property of the key rather
than of the request.
*/
@(private)
warn_unsigned_profiles :: proc(p: ^Profile_Signer) {
	if p == nil {
		return
	}
	if !tlsx.signer_present(p.signer) {
		logx.errorf(
			"listeners.doh: the certificate did not yield a signing identity, the .mobileconfig endpoint will not answer",
		)
		return
	}
	probe, ok := tlsx.sign_cms(p.signer, transmute([]u8)string(PROFILE_SIGN_PROBE), context.temp_allocator)
	if !ok {
		logx.errorf(
			"listeners.doh: the certificate's key cannot sign a CMS structure (an Ed25519 key cannot), the .mobileconfig endpoint will answer 503 to everything",
		)
		return
	}
	delete(probe, context.temp_allocator)
}
