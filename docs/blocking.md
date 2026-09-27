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

Hosts entries are exact because hosts-format lists spell out every subdomain they
mean; bare domains and `||` rules cover subtrees, which is how AdGuard Home reads
the same files. Allow rules always win. The `address=/…/` and `server=/…/` forms
are dnsmasq's, accepted because they turn up in lists that are otherwise adblock
syntax; a `server=/…/` line that names a server forwards rather than blocks in
dnsmasq, so it is skipped. `$important` and `$third-party` (`$3p`) are dropped and the rest of the
rule kept, so an `@@` exception beats a `$important` block here, where in
AdGuard Home the `$important` block would win. `$badfilter` cancels what the rule it names covers in any list, whichever rule
gave it - so `||*.x^$badfilter` narrows a `||x^` to blocking only `x` itself - though a list's
cannot cancel `blocking.rules` or `blocking.allow`. A rule with any other
modifier (`$dnstype`, `$client`, `$domain`, `$elemhide`, `$removeparam`, ...) is
skipped rather than widened to every query. So are cosmetic rules (`##`, `$$`)
and any rule that cannot be expressed as a domain; none of them fails its list.
Downloaded lists are cached under `cache_dir`, and a refresh that fails falls
back to the cached copy, so a network outage cannot silently turn blocking off.

**CNAME chains are matched too** — Pi-hole calls it deep CNAME inspection. The
arrangement to catch is a tracker given a subdomain inside the site's own zone,
`metrics.brand.example` CNAME `tracker.evil.example`, where the question is a
first-party name no list can usefully carry. Every hop is matched, up to sixteen,
logged as `outcome=blocked detail=cname` against `detail=list` for a question
that was listed itself; an answer whose chain runs past the sixteenth name is
withheld rather than served. An allow rule on the *question* exempts the whole
answer — the escape hatch when a first-party name resolves through a listed CDN —
while one matching a hop clears that hop and no other.

Four details name a withheld or failed answer that no list explains, and they are
what to search the query log for when a site breaks and the lists do not account
for it:

| detail | rcode | what happened |
| --- | --- | --- |
| `cname-deep` | the `blocking.response` | the chain ran past the sixteenth name, so where it ends was never checked |
| `cname-unreadable` | SERVFAIL | a CNAME's target could not be parsed |
| `answer-unreadable` | SERVFAIL | the upstream's reply could not be parsed at all |
| `cache-unreadable` | SERVFAIL | a stored answer could not be parsed on the way back out |

The `-unreadable` ones answer SERVFAIL rather than `blocking.response`, since a
record that will not parse is as likely an upstream having a bad day as an
attack, and SERVFAIL is the only answer a stub will retry or fail over from.
`answer-unreadable` is the one worth watching: it is a way for a name to stop
resolving that appears only once blocking is on, since with blocking off nothing
walks the answer and nothing needs to parse it.
