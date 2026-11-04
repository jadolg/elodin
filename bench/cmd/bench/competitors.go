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

func aghConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	web, err := freePort()
	if err != nil {
		return nil, err
	}
	work := filepath.Join(h.dir, o.name+"-agh")
	_ = os.RemoveAll(work)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	filters := "filters: []\n"
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return "||" + n + "^" })
		if err != nil {
			return nil, err
		}
		filters = fmt.Sprintf("filters:\n  - enabled: true\n    url: %s\n    name: bench\n    id: 1\n", list)
	}
	cache := "true"
	if !o.cache {
		cache = "false"
	}
	// The schema 0.107.80 writes; without it the file is migrated as a
	// version-0 one and the migration refuses it.
	cfg := fmt.Sprintf(aghTemplate, web, p.dns, p.upPort, p.upPort, inflightBound(o), cache, cacheBytes(o, 4096), p.doh, p.dot, cert, key, h.dir, filters)
	path, err := h.writeConf(o, "yaml", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-c", path, "-w", work, "--no-check-update", "--no-permcheck"}, nil
}

func blockyConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	blocking := ""
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return n })
		if err != nil {
			return nil, err
		}
		blocking = fmt.Sprintf(blockyTemplate, list)
	}
	caching := fmt.Sprintf("caching:\n  maxItemsCount: %d\n  prefetching: false\n", o.cacheEntries)
	if !o.cache {
		caching = "caching:\n  maxTime: -1m\n"
	}
	cfg := fmt.Sprintf(`upstreams:
  groups:
    default: [127.0.0.1:%s]
  timeout: 5s
  init:
    strategy: fast
ports:
  dns: 127.0.0.1:%d
  tls: 127.0.0.1:%d
  https: 127.0.0.1:%d
certFile: %s
keyFile: %s
# Blocky answers RFC 6761 names itself, NXDOMAIN for all of test.; the
# mock's zone is under it, so it has to be forwarded instead.
specialUseDomains:
  enable: false
%s%squeryLog:
  type: none
log:
  level: warn
`, p.upPort, p.dns, p.dot, p.doh, cert, key, caching, blocking)
	path, err := h.writeConf(o, "yaml", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "--config", path}, nil
}

func corednsConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	cache := fmt.Sprintf("cache 3600 {\n    success %d\n    denial %d\n  }", o.cacheEntries, o.cacheEntries)
	if !o.cache {
		cache = ""
	}
	// CoreDNS keeps one cache per server block, so the three blocks each
	// fill their own.
	block := func(scheme string, port int, tls string) string {
		return fmt.Sprintf(`%s.:%d {
  bind 127.0.0.1
  %s
  forward . 127.0.0.1:%s {
    max_concurrent %d
  }
  %s
  timeouts {
    idle %ds
  }
}
`, scheme, port, tls, p.upPort, inflightBound(o), cache, secs(o.clientTimeout))
	}
	tls := fmt.Sprintf("tls %s %s", cert, key)
	cfg := block("", p.dns, "") + block("tls://", p.dot, tls) + block("https://", p.doh, tls)
	path, err := h.writeConf(o, "Corefile", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-conf", path, "-quiet"}, nil
}

func dnsmasqConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cache := o.cacheEntries
	if !o.cache {
		cache = 0
	}
	cfg := fmt.Sprintf(`port=%d
listen-address=127.0.0.1
bind-interfaces
no-resolv
no-hosts
no-poll
server=127.0.0.1#%s
cache-size=%d
dns-forward-max=%d
pid-file=
`, p.dns, p.upPort, cache, inflightBound(o))
	if o.blockRules > 0 {
		// Pi-hole's own form before it moved the list into gravity.db.
		list, err := h.writeList(o, "conf", "", func(n string) string { return "address=/" + n + "/" })
		if err != nil {
			return nil, err
		}
		cfg += "conf-file=" + list + "\n"
	}
	path, err := h.writeConf(o, "conf", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "--keep-in-foreground", "--conf-file=" + path}, nil
}

func pdnsConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-pdns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sock, err := os.MkdirTemp("", "pdns")
	if err != nil {
		return nil, err
	}
	threads := unboundThreads(o.loops)
	entries := o.cacheEntries
	if !o.cache {
		entries = 0
	}
	cfg := fmt.Sprintf(pdnsTemplate, p.dns, p.upPort, threads, entries, entries, inflightBound(o), o.maxConnections, secs(o.clientTimeout), sock)
	if o.blockRules > 0 {
		rpz, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		lua := filepath.Join(dir, "rpz.lua")
		if err := os.WriteFile(lua, []byte(fmt.Sprintf("rpzFile(%q, {policyName=\"bench\"})\n", rpz)), 0o644); err != nil {
			return nil, err
		}
		cfg += "lua-config-file=" + lua + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "recursor.conf"), []byte(cfg), 0o644); err != nil {
		return nil, err
	}
	return []string{bin, "--config-dir=" + dir, "--enable-old-settings"}, nil
}

func dnsdistConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	cert, key := h.certs(o)
	threads := unboundThreads(o.loops)
	var sb strings.Builder
	sb.WriteString("setSecurityPollSuffix('')\nsetACL({'127.0.0.0/8'})\n")
	// One UDP listener is one thread; SO_REUSEPORT listeners are how dnsdist
	// spreads UDP over more.
	fmt.Fprintf(&sb, "setLocal('127.0.0.1:%d', {reusePort=true})\n", p.dns)
	for range threads - 1 {
		fmt.Fprintf(&sb, "addLocal('127.0.0.1:%d', {reusePort=true})\n", p.dns)
	}
	fmt.Fprintf(&sb, "addTLSLocal('127.0.0.1:%d', %q, %q)\n", p.dot, cert, key)
	fmt.Fprintf(&sb, "addDOHLocal('127.0.0.1:%d', %q, %q, '/dns-query')\n", p.doh, cert, key)
	fmt.Fprintf(&sb, "newServer({address='127.0.0.1:%s', healthCheckMode='up'})\n", p.upPort)
	fmt.Fprintf(&sb, "setUDPTimeout(5)\nsetTCPRecvTimeout(%d)\nsetMaxTCPClientThreads(%d)\n", secs(o.clientTimeout), threads)
	if o.cache {
		fmt.Fprintf(&sb, "getPool(''):setCache(newPacketCache(%d))\n", o.cacheEntries)
	}
	if o.blockRules > 0 {
		list, err := h.writeList(o, "txt", "", func(n string) string { return n })
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&sb, `local s = newDNSNameSet()
for l in io.lines(%q) do s:add(newDNSName(l)) end
addAction(QNameSetRule(s), RCodeAction(DNSRCode.NXDOMAIN))
`, list)
	}
	path, err := h.writeConf(o, "lua", sb.String())
	if err != nil {
		return nil, err
	}
	return []string{bin, "--supervised", "--disable-syslog", "-C", path}, nil
}

func bindConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-bind")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	cacheSize := fmt.Sprint(cacheBytes(o, 4096))
	// BIND's idle timeouts are tenths of a second, at most two minutes.
	idle := min(1200, secs(o.clientTimeout)*10)
	rpz, zone := "", ""
	if o.blockRules > 0 {
		path, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		rpz = `  response-policy { zone "rpz.bench"; };` + "\n"
		zone = fmt.Sprintf("zone \"rpz.bench\" { type primary; file %q; };\n", path)
	}
	nocache := ""
	if !o.cache {
		nocache = "  max-cache-ttl 0;\n  max-ncache-ttl 0;\n"
	}
	cfg := fmt.Sprintf(bindTemplate, cert, key, dir, p.dns, p.dot, p.doh, p.upPort, cacheSize, nocache, inflightBound(o),
		o.maxConnections, o.maxConnections, idle, idle, rpz, zone)
	path, err := h.writeConf(o, "conf", cfg)
	if err != nil {
		return nil, err
	}
	return []string{bin, "-g", "-c", path, "-n", fmt.Sprint(unboundThreads(o.loops))}, nil
}

func knotConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-knot")
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cert, key := h.certs(o)
	var sb strings.Builder
	fmt.Fprintf(&sb, `net.listen('127.0.0.1', %d, {kind='dns'})
net.listen('127.0.0.1', %d, {kind='tls'})
net.listen('127.0.0.1', %d, {kind='doh2'})
net.tls(%q, %q)
net.tcp_in_idle(%d)
trust_anchors.remove('.')
cache.open(%d, 'lmdb://%s')
`, p.dns, p.dot, p.doh, cert, key, o.clientTimeout.Milliseconds(), max(10<<20, cacheBytes(o, 4096)), filepath.Join(dir, "cache"))

	if o.blockRules > 0 {
		rpz, err := h.writeRPZ(o)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&sb, "policy.add(policy.rpz(policy.DENY, %q))\n", rpz)
	}
	// Knot answers RFC 6761 names itself, NXDOMAIN for all of test.; the
	// rule for the mock's zone is more specific than its own and forwards it.
	for _, zone := range []string{".", "bench.test."} {
		fmt.Fprintf(&sb, "policy.rule_forward_add(%q, {dnssec=false}, {{'127.0.0.1@%s'}})\n", zone, p.upPort)
	}
	path, err := h.writeConf(o, "lua", sb.String())
	if err != nil {
		return nil, err
	}
	// One kresd is one thread; Knot scales across cores by running one
	// process per core behind SO_REUSEPORT, which this harness, sampling one
	// pid, does not do. Its rows are one process.
	return []string{bin, "-n", "-q", "-c", path, dir}, nil
}

// piholeConfig runs Pi-hole's FTL, which reads its configuration and its
// list from /etc/pihole and nowhere else. It runs as root in a mount namespace
// of its own with the run's directory bound over /etc/pihole (which has to
// exist as an empty mount point), and the list is a gravity.db built from
// Pi-hole's own schema, -competitors/pihole/gravity.db.sql.
func piholeConfig(h *harness, o serverOpts, p ports, bin string) ([]string, error) {
	dir := filepath.Join(h.dir, o.name+"-pihole")
	etc := filepath.Join(dir, "etc")
	_ = exec.Command("sudo", "rm", "-rf", dir).Run()
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return nil, err
	}
	web, err := freePort()
	if err != nil {
		return nil, err
	}
	schema, err := os.ReadFile(filepath.Join(h.competitorDir, "pihole", "gravity.db.sql"))
	if err != nil {
		return nil, err
	}
	var sql strings.Builder
	sql.Write(schema)
	sql.WriteString("\nBEGIN;\nINSERT INTO adlist (id,address,enabled) VALUES (1,'file:///bench',1);\n")
	if o.blockRules > 0 {
		for _, n := range blockNames(o.blockRules) {
			fmt.Fprintf(&sql, "INSERT INTO gravity (domain,adlist_id) VALUES ('%s',1);\n", n)
		}
	}
	fmt.Fprintf(&sql, "INSERT OR REPLACE INTO info VALUES ('updated', %d);\n", time.Now().Unix())
	fmt.Fprintf(&sql, "INSERT OR REPLACE INTO info VALUES ('gravity_count', %d);\nCOMMIT;\n", o.blockRules)
	db := exec.Command(bin, "sqlite3", filepath.Join(etc, "gravity.db"))
	db.Stdin = strings.NewReader(sql.String())
	if outb, err := db.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("building gravity.db: %w: %s", err, outb)
	}
	cache := o.cacheEntries
	if !o.cache {
		cache = 0
	}
	cfg := fmt.Sprintf(piholeTemplate, p.upPort, p.dns, cache, web, dir, dir, dir, dir, inflightBound(o), p.upPort)
	if err := os.WriteFile(filepath.Join(etc, "pihole.toml"), []byte(cfg), 0o644); err != nil {
		return nil, err
	}
	return []string{"sudo", "unshare", "-m", "sh", "-c",
		fmt.Sprintf("mount --bind %s /etc/pihole && exec %s -f", etc, bin)}, nil
}

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
