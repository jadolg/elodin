package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// A competitor is a server the compare section runs beside elodin and
// Unbound. Each is given what elodin is given wherever it has a setting for
// it: the same listeners, certificate, upstream, thread count, cache size,
// bound on queries in flight, idle timeout and list of names to block, with
// rate limiting, query logging and statistics off. Where a server has no
// setting the row says so rather than measuring something else.
type competitor struct {
	// bin is the executable, found in -competitors or on PATH.
	bin string
	// version is the argument that makes it print its version.
	version string
	// transports it serves; the compare rows skip the others.
	transports []string
	// blocks says it can load a list of names and answer them NXDOMAIN.
	blocks bool
	config func(h *harness, o serverOpts, p ports, bin string) ([]string, error)
}

var competitors = map[string]competitor{
	"adguardhome": {"adguardhome", "--version", []string{"udp", "tcp", "dot", "doh1", "doh2"}, true, aghConfig},
	"blocky":      {"blocky", "version", []string{"udp", "tcp", "dot", "doh1"}, true, blockyConfig},
	"coredns":     {"coredns", "-version", []string{"udp", "tcp", "dot", "doh1", "doh2"}, false, corednsConfig},
	"dnsmasq":     {"dnsmasq", "--version", []string{"udp"}, true, dnsmasqConfig},
	"pdns":        {"pdns_recursor", "--version", []string{"udp", "tcp"}, true, pdnsConfig},
	"dnsdist":     {"dnsdist", "--version", []string{"udp", "tcp", "dot", "doh2"}, true, dnsdistConfig},
	"bind":        {"named", "-v", []string{"udp", "tcp", "dot", "doh2"}, true, bindConfig},
	"pihole":      {"pihole-FTL", "-v", []string{"udp", "tcp"}, true, piholeConfig},
	"knot":        {"kresd", "--version", []string{"udp", "tcp", "dot", "doh2"}, true, knotConfig},
}

// supports says whether kind serves transport, and whether it can block.
func supports(kind, transport string) bool {
	switch kind {
	case "elodin":
		return true
	case "unbound":
		return transport != "doh1"
	}
	if transport == "block" {
		return competitors[kind].blocks
	}
	for _, t := range competitors[kind].transports {
		if t == transport {
			return true
		}
	}
	return false
}

// findCompetitor resolves a competitor's binary in dir, then dir's
// usr/{s,}bin (a .deb extracted there), then PATH.
func findCompetitor(dir, bin string) (string, error) {
	if dir != "" {
		for _, sub := range []string{"bin", "root/usr/sbin", "root/usr/bin", "."} {
			p := filepath.Join(dir, sub, bin)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, nil
			}
		}
	}
	return exec.LookPath(bin)
}

// libPath is where an extracted .deb's libraries are, for the servers that
// were unpacked rather than installed.
func (h *harness) libPath() string {
	if h.competitorDir == "" {
		return ""
	}
	r := filepath.Join(h.competitorDir, "root")
	return filepath.Join(r, "usr/lib/aarch64-linux-gnu") + ":" + filepath.Join(r, "usr/lib/x86_64-linux-gnu") + ":" + filepath.Join(r, "usr/lib")
}

func (h *harness) competitorConfig(o serverOpts, p ports) ([]string, error) {
	c, ok := competitors[o.kind]
	if !ok {
		return nil, fmt.Errorf("unknown server kind %q", o.kind)
	}
	if o.dnssec || o.noUpstream {
		return nil, fmt.Errorf("%s: validation and a dead upstream are elodin-only rows", o.name)
	}
	if o.blockRules > 0 && !c.blocks {
		return nil, fmt.Errorf("%s: %s loads no blocklist", o.name, o.kind)
	}
	argv, err := c.config(h, o, p, h.bins[o.kind])
	if err != nil {
		return nil, err
	}
	// env execs the server in its own place, so the pid is still the server's.
	return append([]string{"env", "LD_LIBRARY_PATH=" + h.libPath()}, argv...), nil
}

// competitorLabel names a competitor by the version it reports.
func (h *harness) competitorLabel(kind string) string {
	c := competitors[kind]
	cmd := exec.Command(h.bins[kind], c.version)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+h.libPath())
	outb, _ := cmd.CombinedOutput()
	v := regexp.MustCompile(`v?\d+\.\d+(\.\d+)?`).FindString(string(outb))
	names := map[string]string{
		"adguardhome": "AdGuard Home", "blocky": "Blocky", "coredns": "CoreDNS", "dnsmasq": "dnsmasq",
		"pdns": "PowerDNS Recursor", "dnsdist": "dnsdist", "bind": "BIND", "knot": "Knot Resolver", "pihole": "Pi-hole FTL",
	}
	return strings.TrimSpace(names[kind] + " " + strings.TrimPrefix(v, "v"))
}

// blockNames are the names every server's list holds, the ones elodin's
// synthesised list holds.
func blockNames(n int) []string {
	names := make([]string, 0, n+1)
	names = append(names, "blocked.bench.test")
	for i := range n {
		names = append(names, fmt.Sprintf("sink-%d.bench.invalid", i))
	}
	return names
}

// writeList writes the block list in one line per name, each through line.
func (h *harness) writeList(o serverOpts, ext string, header string, line func(string) string) (string, error) {
	var sb strings.Builder
	sb.WriteString(header)
	for _, n := range blockNames(o.blockRules) {
		sb.WriteString(line(n))
		sb.WriteByte('\n')
	}
	path := filepath.Join(h.dir, o.name+"-"+o.kind+"-block."+ext)
	return path, os.WriteFile(path, []byte(sb.String()), 0o644)
}

// writeRPZ is the list as a response policy zone, the form BIND, Knot and
// PowerDNS load: CNAME to the root is NXDOMAIN.
func (h *harness) writeRPZ(o serverOpts) (string, error) {
	return h.writeList(o, "rpz",
		"$TTL 60\n@ SOA localhost. root.localhost. 1 3600 600 86400 60\n@ NS localhost.\n",
		func(n string) string { return n + " CNAME ." })
}

func (h *harness) writeConf(o serverOpts, ext, cfg string) (string, error) {
	path := filepath.Join(h.dir, o.name+"-"+o.kind+"."+ext)
	return path, os.WriteFile(path, []byte(cfg), 0o644)
}

func (h *harness) certs(o serverOpts) (cert, key string) {
	return filepath.Join(h.dir, o.certKind+"-cert.pem"), filepath.Join(h.dir, o.certKind+"-key.pem")
}

// cacheBytes sizes a byte-sized cache to hold o.cacheEntries answers of per
// bytes, for the servers that size theirs in bytes: per is generous, so the
// larger per-entry row never evicts, and the smaller one does. The default
// row keeps a floor, so the cache is never what separates two servers.
func cacheBytes(o serverOpts, per int) int {
	b := o.cacheEntries * per
	if o.cacheEntries >= 10000 {
		b = max(b, 32<<20)
	}
	return b
}

// inflightBound is the counterpart of max_pending, raised past anything a
// row puts in flight, as Unbound's is.
func inflightBound(o serverOpts) int {
	return max(4096, o.maxPending)
}

func secs(d time.Duration) int { return int(d.Seconds()) }

// aghTemplate is the configuration aghConfig fills in; see there.
const aghTemplate = `schema_version: 34
http:
  address: 127.0.0.1:%d
users: []
dns:
  bind_hosts: [127.0.0.1]
  port: %d
  # The generator is one address; AdGuard's default is 20 a second per client.
  ratelimit: 0
  upstream_dns: ["127.0.0.1:%s"]
  bootstrap_dns: ["127.0.0.1:%s"]
  fallback_dns: []
  upstream_mode: load_balance
  upstream_timeout: 5s
  # AdGuard's bound on queries being handled at once, default 300: the
  # counterpart of max_pending.
  max_goroutines: %d
  cache_enabled: %s
  cache_size: %d
  cache_optimistic: false
  enable_dnssec: false
  aaaa_disabled: false
  use_private_ptr_resolvers: false
  serve_plain_dns: true
tls:
  enabled: true
  server_name: localhost
  port_https: %d
  port_dns_over_tls: %d
  port_dns_over_quic: 0
  allow_unencrypted_doh: false
  certificate_path: %s
  private_key_path: %s
querylog:
  enabled: false
statistics:
  enabled: false
filtering:
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  # 0 would also skip reading the list at start.
  filters_update_interval: 24
  safe_fs_patterns: ["%s/*"]
%slog:
  verbose: false
`

// blockyTemplate is the configuration blockyConfig fills in; see there.
const blockyTemplate = `blocking:
  denylists:
    bench: [%s]
  clientGroupsBlock:
    default: [bench]
  blockType: nxDomain
  loading:
    strategy: blocking
    refreshPeriod: 0
`

// pdnsTemplate is the configuration pdnsConfig fills in; see there.
const pdnsTemplate = `local-address=127.0.0.1
local-port=%d
forward-zones-recurse=.=127.0.0.1:%s
# The mock is on loopback, which the recursor will not query by default.
dont-query=
threads=%d
dnssec=off
max-cache-entries=%d
max-packetcache-entries=%d
# Its bound on queries being resolved at once, per thread.
max-mthreads=%d
max-tcp-clients=%d
max-tcp-per-client=0
client-tcp-timeout=%d
network-timeout=5000
# A UNIX socket path is at most 108 bytes, which the run directory can pass.
socket-dir=%s
disable-syslog=yes
daemon=no
loglevel=3
security-poll-suffix=
`

// bindTemplate is the configuration bindConfig fills in; see there.
const bindTemplate = `tls benchtls { cert-file %q; key-file %q; };
http benchhttp { endpoints { "/dns-query"; }; };
options {
  directory %q;
  pid-file none;
  session-keyfile none;
  listen-on port %d { 127.0.0.1; };
  listen-on port %d tls benchtls { 127.0.0.1; };
  listen-on port %d tls benchtls http benchhttp { 127.0.0.1; };
  listen-on-v6 { none; };
  recursion yes;
  allow-query { any; };
  allow-recursion { 127.0.0.0/8; };
  forwarders { 127.0.0.1 port %s; };
  forward only;
  dnssec-validation no;
  max-cache-size %s;
%s  recursive-clients %d;
  tcp-clients %d;
  http-listener-clients %d;
  tcp-initial-timeout %d;
  tcp-idle-timeout %d;
  minimal-responses no-auth;
%s};
logging { category default { null; }; category lame-servers { null; }; };
%s`

// piholeTemplate is the configuration piholeConfig fills in; see there.
const piholeTemplate = `[dns]
upstreams = ["127.0.0.1#%s"]
port = %d
listeningMode = "BIND"
interface = "lo"
queryLogging = false
dnssec = false
[dns.cache]
size = %d
[dns.blocking]
mode = "NX"
[dns.rateLimit]
count = 0
[resolver]
resolveIPv4 = false
resolveIPv6 = false
[database]
maxDBdays = 0
[webserver]
port = "127.0.0.1:%d"
[files]
database = "%s/ftl.db"
[files.log]
ftl = "%s/FTL.log"
dnsmasq = "%s/dnsmasq.log"
webserver = "%s/web.log"
[ntp.ipv4]
active = false
[ntp.ipv6]
active = false
[ntp.sync]
active = false
[misc]
# dnsmasq's bound on queries forwarded at once, default 150: the
# counterpart of max_pending. FTL answers all of test. itself (RFC 6761);
# the mock's zone is under it, so the more specific server= forwards it,
# and a blocked name under it is answered from the list or not at all.
dnsmasq_lines = ["dns-forward-max=%d", "server=/bench.test/127.0.0.1#%s"]
`
