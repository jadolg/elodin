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

- A download counts as failed when it is a web page (its first non-blank byte
  is `<`: a captive portal, an error page sent as a 200) or holds no rules,
  and it does not replace the cached copy (`the download is a web page, not a
  list`, `the download holds no rules; keeping the cached copy`).
- The cached copy is replaced by writing a temporary file beside it, syncing
  it, then renaming it over the old one. A power cut mid-write leaves the old
  copy or the new one, never a truncated list.
- If a list that loaded before has neither a download nor a cached copy at a
  refresh, the refresh is dropped and every rule already in effect is kept
  (`list NAME: loaded before and unavailable now; keeping the rules already in
  effect`). This happens with an unwritable or cleared `cache_dir`. A list that
  has never loaded does not hold the other lists back.
- A refresh where some list is unavailable, or was served from its cached copy
  because the download failed, is retried after 1 minute, then 2, 4 and so on,
  up to `refresh` (`blocklists: not every list is current; trying again in
  1m0s`). A start that could not load every list is retried the same way.

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
- Hosts entries are exact, since hosts lists spell out every subdomain; bare
  domains and `||` rules cover subtrees, as in AdGuard Home.
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
- Skipped, without failing the list: any other modifier (`$dnstype`, `$client`,
  `$domain`, `$elemhide`, `$removeparam`, ...), cosmetic rules (`##`, `$$`), and
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
| `cname-unreadable` | SERVFAIL | a CNAME's target could not be parsed |
| `answer-unreadable` | SERVFAIL | the upstream's reply could not be parsed at all |
| `cache-unreadable` | SERVFAIL | a stored answer could not be parsed on the way back out |

The `-unreadable` ones answer SERVFAIL, not `blocking.response`, because an
unparseable record is as likely a faulty upstream as an attack, and SERVFAIL is
the answer a stub retries or fails over from.

**Watch `answer-unreadable`**: it only appears with blocking on, since with
blocking off nothing parses the answer.
