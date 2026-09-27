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

Downloaded lists are cached under `cache_dir`. A refresh that fails falls back
to the cached copy if there is one, so a network outage does not turn blocking
off once a list has been fetched.

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

- Allow rules always win.
- Hosts entries are exact, since hosts lists spell out every subdomain; bare
  domains and `||` rules cover subtrees, as in AdGuard Home.
- `address=/…/` (dnsmasq syntax) is accepted. A `server=/…/` line that names a
  server is skipped, since dnsmasq forwards it rather than blocking.
- `$important` and `$third-party` (`$3p`) are dropped and the rest of the rule
  kept, so an `@@` exception beats a `$important` block (AdGuard Home does the
  opposite).
- `$badfilter` cancels what the named rule covers in any list, whichever rule
  gave it: `||*.x^$badfilter` narrows a `||x^` to blocking only `x`. A list's
  `$badfilter` cannot cancel `blocking.rules` or `blocking.allow`.
- Skipped, without failing the list: any other modifier (`$dnstype`, `$client`,
  `$domain`, `$elemhide`, `$removeparam`, ...), cosmetic rules (`##`, `$$`), and
  any rule that is not expressible as a domain.

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
