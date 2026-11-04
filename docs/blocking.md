# Sink lists

```yaml
blocking:
  enabled: true
  response: nxdomain     # nxdomain | nodata | zeroip | custom | refused
  custom_ipv4: 0.0.0.0
  custom_ipv6: "::"
  block_ttl: 60
  refresh: 24h
  cache_dir: /var/cache/elodin

  lists:
    - name: steven-black
      url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      format: hosts      # auto | hosts | domains | adblock
    - name: personal
      file: /etc/elodin/blocklist.txt

  allowlists: []
  rules: ["||doubleclick.net^"]
  # allow: ["||googleadservices.com^"]   # an exception outranks every list
```

Downloaded lists are cached under `cache_dir`, every `refresh`. A download
that fails falls back to the cached copy if there is one, so a network outage
does not turn blocking off once a list has been fetched.

A list is logged under its `name`, and cached under it; without one the name is
the `url` up to its query, or the `file` when there is no url, so a key in the
query is not logged. A list whose url has a query keeps a fingerprint of the url
beside its copy (`<file>.src`), so changing the query in the file downloads the
list again rather than reading the old query's copy as fresh, and the old copy
does not stand in if that download fails: it is another list.
Two downloaded lists with different urls that would share a cache file are
refused at load; give one a different `name:`. Characters other than letters,
digits, `-`, `_` and `.` become `_` in the file name, so `a/b` and `a_b` share one.

- A download follows up to 4 redirects (301, 302, 303, 307, 308), resolving a
  relative `Location` against the url that answered it (RFC 3986 5.2). An
  `https` list is never followed to `http`, and a list on a public address is
  never followed to one that is not globally reachable: loopback, private,
  link-local, site-local, carrier-grade NAT, multicast, the documentation and benchmarking
  ranges, and the other special-purpose ranges (RFC 6890) no list host can be
  at. An IPv4 address written inside an
  IPv6 one (`::ffff:a.b.c.d`, `::a.b.c.d`,
  `::ffff:0:a.b.c.d`, the NAT64 prefixes `64:ff9b::/96` and `64:ff9b:1::/96`,
  and 6to4 `2002:aabb:ccdd::/48`) is judged as the IPv4 address. Any other
  address under the local-use NAT64 prefix `64:ff9b:1::/48` is never followed
  to, and a list at one is held to the public rule. A list url is requested with its
  query (`?format=hosts`).
- A download counts as failed when it is a web page (its first non-blank byte
  is `<`: a captive portal, an error page sent as a 200) or holds no rules,
  and it does not replace the cached copy (`the download is a web page, not a
  list`, `the download holds no rules, so it is not cached`). A list the
  publisher empties on purpose therefore keeps its last copy; with no copy it
  adds nothing. A cached copy that is a web page, is empty or cannot be read
  is not used, and is downloaded over even inside the refresh window.
- The cached copy is replaced by writing a temporary file beside it, syncing
  it, then renaming it over the old one. A power cut mid-write leaves the old
  copy or the new one, never a truncated list.
- If a list that loaded before has neither a download nor a cached copy at a
  refresh, the refresh is dropped and every rule already in effect is kept
  (`list NAME: loaded before and unavailable now; keeping the rules already in
  effect`). This happens with an unwritable or cleared `cache_dir`. A list that
  has never loaded does not hold the other lists back, and neither does a
  `file:` list: delete one and its rules go at the next refresh.
- A refresh where some downloaded list is unavailable, or was served from its
  cached copy because the download failed or held no rules, is retried after 1
  minute, then 2, 4 and so on, up to 1 hour or `refresh`, whichever is shorter
  (`blocklists: not every list is current; trying again in 1m0s`). A start that
  could not load every list is retried the same way. A missing `file:` list is
  not retried.
- A rule costs about 35 bytes resident: its name, a flags byte and an 8-byte
  slot in a table kept at most 80% full. A load or refresh builds the new rule
  sets beside the ones in use and frees the old ones once they are swapped out,
  so for its length the lists cost about twice that. A table grows by doubling
  while it is built and is trimmed to 80% as it is swapped in, briefly holding
  its slots twice over each time; the four lists in `examples/lan.yaml` peaked
  6% over their final size.
- On glibc, the memory a refresh frees stays resident unless
  `MALLOC_MMAP_THRESHOLD_` is set. Freeing tables that large raises glibc's
  mmap threshold, so the next refresh builds on the heap, which keeps what it
  frees, and resident memory settles at a refresh's peak. The shipped unit sets
  `Environment=MALLOC_MMAP_THRESHOLD_=131072`. Started any other way (by hand,
  another init system, a container), set it in elodin's environment. musl
  returns the memory without it.

## Rule syntax

| syntax                     | matches                          |
|----------------------------|----------------------------------|
| `0.0.0.0 ads.foo.com`      | `ads.foo.com` exactly            |
| `ads.foo.com`              | `ads.foo.com` and its subdomains |
| `\|\|ads.foo.com^`         | `ads.foo.com` and its subdomains |
| `\|ads.foo.com`            | `ads.foo.com` exactly            |
| `*.foo.com`                | subdomains of `foo.com` only     |
| `\|\|*.foo.com^`           | subdomains of `foo.com` only     |
| `address=/foo.com/0.0.0.0` | `foo.com` and its subdomains     |
| `@@\|\|safe.foo.com^`      | never blocked                    |
| `/^ads[0-9]+\.foo\.com$/`  | names the regex matches          |

- Allow rules always win.
- In `blocking.rules` and `blocking.allow`, quote each rule: a leading `*`,
  `@`, `|` or `!` is YAML syntax, and the file is refused with it unquoted.
- `format: auto`, the default, reads the list's first 50 lines that are
  neither blank nor a `#` comment. A `[Adblock` header, a `!` comment, a `@@`,
  `address=/` or `server=/` prefix, or a `||` ahead of any `#` or `!` makes
  the list adblock; otherwise it is hosts when most of those lines start with
  an IP address, and domains when not. A `#` comment, or a `#` or `!` comment
  after an entry, never changes the format.
- Hosts entries are exact, since hosts lists spell out every subdomain; bare
  domains and `||` rules cover subtrees, as in AdGuard Home. A hosts line
  whose first field is not an IPv4 or IPv6 address adds nothing.
- A name holding a byte outside ASCII, such as an international name written
  in UTF-8 (`bücher.example`), is skipped: a client asks for the punycode
  form (`xn--bcher-kva.example`), so write it that way. The list's load says
  how many of those it skipped (`list NAME: N names skipped as not ASCII; an
  international name matches only when written in punycode (xn--...)`),
  leaving out a name refused for something punycode cannot carry: a no-break
  or zero-width space, a symbol, a byte that is not UTF-8, or ASCII no label
  holds, such as `*` or `:`.
- A name with an empty label (`*..com`, `||.com^`, `a..com`, `a。。com`), a
  label past 63 bytes, a name past 255 bytes on the wire, or a broken `\`
  escape is skipped and not counted: no query name holds one, so it could
  never match.
- A UTF-8 byte order mark at the start of a line is ignored, so a list saved
  with one, or joined from files saved with one, keeps each piece's first rule.
- `address=/…/` (dnsmasq syntax) is accepted. A `server=/…/` line that names a
  server is skipped, since dnsmasq forwards it rather than blocking.
- `$important` is dropped and the rest of the rule kept, so an `@@` exception
  beats a `$important` block (AdGuard Home does the opposite).
- A rule with `$third-party` or `$~third-party` (`$~first-party`,
  `$first-party`, `$3p`, `$1p`) is skipped, as AdGuard Home's DNS engine skips
  it, so its `$badfilter` cancels nothing either.
- `$badfilter` cancels what the named rule covers in any list, whichever rule
  gave it: `||*.x^$badfilter` narrows a `||x^` to blocking only `x`. A list's
  `$badfilter` cannot cancel `blocking.rules` or `blocking.allow`.
- `$dnstype` narrows a rule to query types, as in AdGuard Home:
  `||x^$dnstype=AAAA` blocks only AAAA queries for `x` and below,
  `$dnstype=A|AAAA` either, and `$dnstype=~A` every type but A. A type is a
  mnemonic in any case or `TYPEnnn` (RFC 3597). The type checked is the one the
  client asked for, for the question and for every name a CNAME in the answer
  leads to. A block only `$dnstype` rules make, or one a `$dnstype` allow rule
  narrows (`||x^` with `@@||x^$dnstype=A`), is answered NODATA where
  `response` is `nxdomain`: NXDOMAIN would say the name has no other types
  either (RFC 8020), and a client caching it would lose them. Every rule for a
  name applies, so `||x^$dnstype=A` and `||x^$dnstype=AAAA` block both, rules
  that add up to every type (`$dnstype=~A` and `$dnstype=~AAAA`) block the name
  as one without `$dnstype` does, and a rule without `$dnstype` blocks every
  type. A rule naming an unknown type, nothing, or more than 64 types (with the
  name's other `$dnstype` rules), is skipped; so is one that excludes every
  type it names (`$dnstype=A|~A`), and one that would need a 4097th distinct
  set of types in its block or allow set, which lists in use never come near.
  `$badfilter` cancels a rule whatever either one's `$dnstype`.
- Skipped, without failing the list: any other modifier (`$client`, `$ctag`,
  `$denyallow`, `$dnsrewrite`, `$domain`, `$elemhide`, `$removeparam`, ...),
  cosmetic rules (`##`, `$$`), and
  any rule that is not expressible as a domain or a regex. A modifier is read
  as written, as urlfilter reads it: `$ important`, `$important, badfilter` and
  `$IMPORTANT` are unknown, so the rule is skipped.

## Regex rules

`/…/` is matched as AdGuard Home matches it: against the query name, lowercased
and without the trailing dot, case-insensitively, anywhere in the name unless
anchored with `^` and `$`. `@@/…/` is an allow rule, and modifiers work as
for any other rule.

As in AdGuard Home, a rule is only tried on a name holding its longest literal
run, the text left once everything from the first `{`, `(` or `[` to the last of
its kind is dropped and the rest is split at every regex metacharacter. So
`/ads|tracker/` matches only names holding `tracker`, and `/\bads/` none, since
`\b` leaves a `b` in front of `ads`. A pattern holding a `?`, or whose longest
run is one character, has no such run and is tried on every name.

Regex rules are tried after the domain rules: an allow regex when no allow rule
matched, a block regex when no domain rule did. A match runs in time linear in
the name, so no pattern can make a query backtrack. What a list
can make one query cost is bounded instead:

| limit | value |
| --- | --- |
| pattern length | 1024 bytes |
| a `{N}` or `{N,M}` count | 1000, as in RE2 |
| one compiled pattern | 1024 bytes |
| compiled patterns per set, block and allow each | 8 KiB, each character or range a `[…]` lists counting as a byte |
| name matched | 253 characters, spelled as AdGuard Home spells it (below); a longer one, which only a name spelling bytes out reaches, is not matched against regex rules |

The AdGuard DNS filter's 22 usable regex rules come to about 2.1 KiB of that. Each
name a query checks - the question and every CNAME hop - is matched against
both sets.

- Read as RE2 reads it, the syntax urlfilter compiles, in this subset:
  literals and `\` before punctuation; `.`, `^`, `$`; `\d \D \w \W \s \S`,
  and `\b \B` outside a class; classes of literals, ranges and those six,
  folded to both cases before a `^` negates them; `(…)`, `(?:…)` and `|`; and
  `* + ?`, `{n}`, `{n,}`, `{n,m}`, each optionally lazy. A `{` that is no
  count, such as `{,3}` or `{02}`, is the character, as in RE2.
- Refused, as RE2 refuses them: a `)` with no `(`, an unclosed `(` or `[`, a
  class range running backwards (`[a-Z]`), a repeat of a repeat (`a**`,
  `a{2}{3}`) or of nothing (`*a`), a count over 1000, or counts nested in one
  another multiplying to more than 1000 (`(?:a{2}){501}`).
- Refused, as RE2 outside the subset: lookaround (`(?=`), inline flags
  (`(?i)`), named groups, escaped letters or digits other than
  `\d \D \w \W \s \S \b \B` (so `\1`, `\x41`, `\A`, `\z`, `\n`, `\pL`,
  `\Q`), POSIX classes (`[[:alpha:]]`), more than 254 different classes in
  one pattern, and any byte outside printable ASCII (write an international
  name as punycode).
- Refused too: an empty `//` or any pattern that matches the empty string
  (`/ads|/`, `/x*/`), which would block every name the rule is tried on
  (every name at all when it has no shortcut).
- A rule is a cosmetic one, and skipped, when the first `#` or the first `$`
  in the line opens a cosmetic or HTML marker (`##`, `#?#`, `#%#`, `$$`, …)
  with no space before it, as urlfilter reads it: `/ads#?#x/` is skipped and
  `/ads#x/` is a regex.
- The name is matched as AdGuard Home spells it: a label's `.`, `\`, space,
  `'`, `@`, `;`, `(`, `)` and `"` each behind a `\` (`/a\\\(b/` matches the
  label `a(b`), and any other byte outside printable ASCII as `\DDD`.
- Once a set's budget refuses a pattern, every later one is dropped too. The
  count is logged once at load: `filter: N regex rules skipped: a set holds 8192
  of regex cost (compiled bytes, plus one for each character or range a class
  lists), and the lists loaded first used it up`.
  `blocking.rules` load after the lists, so a rule there that is dropped also
  gets its own `adds nothing` warning.
- Regex rules are counted in `elodin_filter_rules` and in the startup line
  `filter: N block rules (N regex), N allow rules (N regex)`.

## CNAME chains

Every hop of a CNAME chain is matched too (Pi-hole's deep CNAME inspection), up
to sixteen names. That catches `metrics.brand.example` CNAME
`tracker.evil.example`, a first-party name no list can carry.

- The query log shows `outcome=blocked detail=cname` for a blocked hop, against
  `detail=list` for a listed question.
- An allow rule on the *question* exempts the whole answer, for a first-party
  name that resolves through a listed CDN. One matching a hop clears that hop
  only.

## Details to search for when a site breaks

These name a withheld or failed answer that no list explains:

| detail | rcode | what happened |
| --- | --- | --- |
| `cname-deep` | the `blocking.response` | the chain ran past the sixteenth name, so where it ends was never checked |
| `cname-unreadable` | SERVFAIL | a CNAME's target could not be parsed, or did not end where its RDLENGTH says; beside NS and no SOA it is a [referral](upstreams.md#rcodes-and-the-rest-of-the-group) instead, `detail=referral` |
| `answer-unreadable` | SERVFAIL | the upstream's reply could not be parsed at all |
| `cache-unreadable` | SERVFAIL | a stored answer could not be parsed on the way back out |

The `-unreadable` ones answer SERVFAIL, not `blocking.response`, because an
unparseable record is as likely a faulty upstream as an attack, and SERVFAIL is
the answer a stub retries or fails over from.

**Watch `answer-unreadable`**: it only appears with blocking on, since with
blocking off nothing parses the answer.
