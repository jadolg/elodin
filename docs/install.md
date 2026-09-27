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

`SIGTERM` and `SIGINT` stop the listeners and let the worker pools drain. An idle
client connection is only noticed when its read times out, so stopping can take
up to `server.client_timeout` (ten seconds by default). A second signal
terminates immediately.

`SIGHUP` re-reads the DoT/DoH certificate and key from the configured paths and
switches the listeners over without dropping connections; a session in progress
keeps the certificate it handshook with. One that fails to load is logged and the
listener keeps serving what it had. Nothing else is reloaded — listener
addresses, the upstream set and blocking need a restart.
