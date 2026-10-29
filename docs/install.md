# Installing and running

## From the apt repository

Packages for amd64 and arm64 are published to <https://deb.akiel.dev/> with
every release, so `apt upgrade` keeps elodin current:

```sh
sudo install -d -m755 /etc/apt/keyrings
curl -fsSL https://deb.akiel.dev/gpg.pub.key | gpg --dearmor | sudo tee /etc/apt/keyrings/akiel.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/keyrings/akiel.gpg] https://deb.akiel.dev/ all main' | sudo tee /etc/apt/sources.list.d/akiel.list
sudo apt update
sudo apt install elodin
```

`signed-by` trusts the key for this repository only, rather than for every
source apt reads. What the package installs, and the question it asks, are
below.

## From a .deb

Each GitHub release also carries the `.deb` for each architecture:

```sh
sudo apt install ./elodin_*_amd64.deb
```

The binary lands at `/usr/bin/elodin`, the unit at
`/usr/lib/systemd/system/elodin.service`, and the example configuration at
`/etc/elodin/elodin.yaml` as a conffile, so dpkg keeps your edits across
upgrades. `apt purge` removes the configuration, the blocklist cache and the
state directory.

The install asks one question, defaulting to yes:

> **Make elodin the system resolver?**

Yes stops, disables and **masks** systemd-resolved (masked so a later systemd
upgrade cannot switch it back on and take port 53), replaces `/etc/resolv.conf`
with a real file naming `127.0.0.1`, carrying over any `search` domains, and
starts elodin. elodin reaches its blocklists and upstreams through
`upstream.bootstrap`, so it does not depend on the resolver it replaces.

Nothing is disabled until `elodin --check` has passed. If elodin then fails to
stay up, the package puts systemd-resolved and the old `/etc/resolv.conf` back
and fails the install; `apt remove` restores them the same way.
`sudo dpkg-reconfigure elodin` asks again. For unattended installs, preseed it:

```sh
echo 'elodin elodin/takeover-dns boolean true' | sudo debconf-set-selections
```

## From source, as a service

Build it as in the [README](../README.md#building-from-source), then install
`packaging/elodin.service`, which expects the binary at `/usr/local/bin/elodin`
and the configuration at `/etc/elodin/elodin.yaml`:

```sh
sudo install -m755 bin/elodin /usr/local/bin/elodin
sudo install -Dm644 examples/elodin.yaml /etc/elodin/elodin.yaml
sudo install -m644 packaging/elodin.service /etc/systemd/system/
sudo systemctl enable --now elodin
```

The unit binds :53 through `AmbientCapabilities=CAP_NET_BIND_SERVICE` rather
than as root, and runs under `DynamicUser=yes` with `ProtectSystem=strict`.
`Restart=on-failure` with `StartLimitBurst=5` retries a start that fails for a
passing reason and gives up in `failed` on one that does not — a port it cannot
have, a certificate it cannot read. `systemctl reset-failed elodin` clears that.
The unit also sets `MALLOC_MMAP_THRESHOLD_=131072`, without which glibc keeps the
memory each blocklist refresh frees (see [Sink lists](blocking.md));
`UnsetEnvironment=MALLOC_MMAP_THRESHOLD_` in a drop-in takes glibc's default
instead.

GitHub releases also carry `linux-amd64` and `linux-arm64` tarballs of the
binary, the unit and the example configuration.

## Privileges

Binding a port below 1024 is the only thing elodin needs root for. Either of two
arrangements keeps it from being root while it parses what comes off the
network.

**Never become root.** Grant the capability, as the systemd unit does, or
`setcap` as the [README](../README.md#building-from-source) shows, and start as an ordinary
user. Leave `server.user` empty.

**Start as root and put it down.** Name an account and elodin switches to it the
moment the listeners have their ports:

```yaml
server:
  user: elodin        # a name or a numeric uid
  group: elodin       # optional; defaults to the user's primary group
```

Supplementary groups go first, then the gid, then the uid — real, effective and
saved — and the real and effective ids are read back from the kernel before the
drop is reported. A drop that was configured and did not happen ends the
process. A misspelt account name fails `--check`; running as root with no
`server.user` logs a warning. `blocking.cache_dir` changes owner along with the
process, since a refresh hours later has to reopen it. Started this way, elodin
downloads and parses the blocklists before it binds, so that much happens as
root; the first arrangement avoids it.

## Signals

`SIGTERM` and `SIGINT` stop the listeners and let the queries in flight finish. An idle
client connection is only noticed when its read times out, so stopping can take
up to `server.client_timeout` (ten seconds by default). A second signal
terminates immediately. Blocklists are downloaded and the rule sets built on a
thread of their own, so a signal is acted on at once whatever a download is
waiting for; a stop does not wait for a rebuild in progress (`blocklists: not
waiting for the rebuild in progress`), and one during the downloads at startup
exits before anything is listening.

`SIGHUP` (`systemctl reload elodin`) reloads without dropping a connection or a
cached answer it has no reason to, in this order:

1. The log file is opened again by name, which is what logrotate's `create`
   expects.
2. The configuration file is read again. It goes through the checks `--check`
   runs, and every upstream group, trust anchor and cookie secret a change needs
   is built before anything is swapped in. A file that fails any of that is
   logged (`reload: ... is not usable; keeping the configuration already in
   effect`) and changes nothing. A query already being answered finishes under
   the configuration it started with. A change to the rule sets rebuilds them
   afterwards on the blocklists' own thread, once any rebuild in progress is
   over (`reload: the rules are rebuilt once the rebuild in progress is over`).
3. The DoT/DoH certificate and key are read again from the paths the process
   started with, whether or not the file loaded. A session in progress keeps the
   certificate it handshook with; one that fails to load is logged and the
   listener keeps serving what it had.

A reload that applies something logs one line, then the warnings startup logs
about the configuration:

```
ts=2026-10-19T19:35:57Z level=info msg=reloaded changed=upstream,rewrites rebuilt=upstreams cache=flushed
```

`changed` is the sections that differ; `rebuilt` the parts built afresh
(`upstreams`, `validator`, `cookies`, `limiter`, `answers`, or `none`); rule
sets rebuilt after it log their own `filter:` line (`filter: blocking is off; no
rules in effect` when turned off), or keep the rules in effect;
`cache` is `kept`, `flushed`, `new` or `off`.

| section | on reload |
|---|---|
| `log`, `rewrites`, `special_use`, `rebind` | applied from the next query |
| `server.allow_from`, `max_pending`, `max_udp_response`, `client_timeout` | applied from the next query or read |
| `server.rate_limit` | a change rebuilds the limiter, so every prefix starts again from a full budget |
| `upstream`, `cookies.upstream` | a change rebuilds every group and route: new connections, new upstream cookies |
| `cache` | resized in place; turned off or on, dropped or started empty |
| `dnssec` | a change rebuilds the validator, which fetches its zone keys again |
| `cookies` | applied; the secret is kept unless `cookies.secret` changes |
| `blocking` | a change to `enabled`, the lists or the rules rebuilds the rule sets, and a list whose cached copy is within `refresh` is not downloaded again; `response`, `custom_ipv4`, `custom_ipv6`, `block_ttl` and `refresh` apply from the next query or tick. Lists read from a `file:` are read again on every SIGHUP, changed configuration or not. If a list that loaded before cannot be had, the rules in effect are kept, as on a refresh, and the change applies at the retry |
| `listeners` (including `udp.readers`, the loop count), `metrics`, `max_connections`, `max_connections_per_prefix`, `user`, `group`, `blocking.cache_dir` | need a restart; each one changed is named in a warning and keeps the value it started with |

A change to which upstreams are asked (`upstream.servers`, `upstream.bootstrap`,
`upstream.zones` and their servers), to `dnssec.enabled`, `trust_anchors` or
`max_nsec3_iterations`, to `rebind`, or to `cache.min_ttl`,
`max_ttl` or `negative_ttl` empties the answer cache, since each decides what was
stored and how it was checked first. An answer a query already in flight stores afterwards is not served
either. Unchanged sections keep what they built: the upstream connections and
cookies, the cache, the client cookie secret and the rate-limit budgets survive a
reload of anything else.

`blocking.cache_dir` is handed to `server.user` at startup only if blocking is
on then. Turning blocking on with a reload after that needs the directory to be
writable by that user already (the packaged unit's `CacheDirectory=` is);
otherwise the lists still load, are not cached, and the log says so.

A listener cannot move without a restart: below port 1024 it could not be bound
again once privileges are dropped, and the event loops it runs on are started once.
