#!/usr/bin/env bash
#
# Run the container image the way examples/compose.yaml runs it, and check that
# it is usable: it resolves over UDP and TCP, validates DNSSEC, blocks, serves
# metrics, keeps its blocklist cache in a volume it can write, reloads on
# SIGHUP and stops cleanly on SIGTERM - as an unprivileged user, on a read-only
# root filesystem, with every capability dropped and no shell to fall back on.
#
#   scripts/image-smoke.sh [image]
#
# The image defaults to $ELODIN_IMAGE, then elodin:dev (`mise run image`). Needs
# docker, dig and curl, and egress to the DoT upstreams and the blocklists in
# examples/docker.yaml, which the image uses as it ships.

set -euo pipefail
cd "$(dirname "$0")/.."

image=${1:-${ELODIN_IMAGE:-elodin:dev}}
for tool in docker dig curl; do
	command -v "$tool" >/dev/null || { echo "image-smoke: needs $tool" >&2; exit 1; }
done

name=elodin-smoke-$$
volume=elodin-smoke-cache-$$
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
	docker volume rm -f "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

failed=0
fail() {
	echo "FAIL: $*" >&2
	failed=1
}
pass() {
	echo "ok:   $*"
}

# Wait up to `$1` seconds for a log line matching `$2`, which may already be
# there. Lists download before `ready`, hence the minute.
wait_log() {
	local deadline=$((SECONDS + $1))
	until docker logs "$name" 2>&1 | grep -qE "$2"; do
		if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
			return 1
		fi
		[ $SECONDS -lt $deadline ] || return 1
		sleep 0.5
	done
}

wait_ready_count() {
	local deadline=$((SECONDS + 90))
	until [ "$(docker logs "$name" 2>&1 | grep -c 'msg=ready')" -ge "$1" ]; do
		if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
			return 1
		fi
		[ $SECONDS -lt $deadline ] || return 1
		sleep 0.5
	done
}

# The hardening examples/compose.yaml sets, so a release that needs a writable
# root, a capability or more than its cache volume fails here rather than for a
# user. The ports go to 127.0.0.1 on whatever the host has free: port 53 on a
# CI runner belongs to systemd-resolved.
start() {
	docker run -d --name "$name" \
		--read-only --cap-drop ALL --security-opt no-new-privileges:true \
		--ulimit nofile=65536:65536 \
		-v "$volume:/var/cache/elodin" \
		-p 127.0.0.1::53/udp -p 127.0.0.1::53/tcp -p 127.0.0.1::9153/tcp \
		"$image" >/dev/null
	if ! wait_log 90 'msg=ready'; then
		docker logs "$name" >&2 || true
		echo "image-smoke: $image did not become ready" >&2
		exit 1
	fi
	dns_port=$(docker port "$name" 53/udp | head -1 | sed 's/.*://')
	tcp_port=$(docker port "$name" 53/tcp | head -1 | sed 's/.*://')
	metrics_port=$(docker port "$name" 9153/tcp | head -1 | sed 's/.*://')
}

start
q() { dig +time=5 +tries=2 @127.0.0.1 "$@"; }

uid=$(docker top "$name" -o pid,uid,comm | awk '$3 == "elodin" { print $2 }')
if [ "$uid" = 65532 ]; then
	pass "runs as uid 65532"
else
	fail "runs as uid ${uid:-?}, want 65532"
fi

if q -p "$dns_port" +short example.com A | grep -qE '^[0-9]+\.'; then
	pass "UDP answers"
else
	fail "no A for example.com over UDP"
fi
if q -p "$tcp_port" +tcp +short example.org A | grep -qE '^[0-9]+\.'; then
	pass "TCP answers"
else
	fail "no A for example.org over TCP"
fi
# The AD bit needs both upstream TLS checked against the image's CA bundle and
# DNSSEC validated with the image's libcrypto.
if q -p "$dns_port" +dnssec cloudflare.com A | grep -q 'flags:.* ad;'; then
	pass "DNSSEC validates"
else
	fail "no AD bit for cloudflare.com"
fi
if q -p "$dns_port" doubleclick.net A | grep -q 'status: NXDOMAIN'; then
	pass "blocks"
else
	fail "doubleclick.net was not blocked"
fi

# Every list downloaded over HTTPS, and was written into the volume as the
# image's account.
docker logs "$name" 2>&1 | grep -q 'download failed' && fail "a blocklist download failed: $(docker logs "$name" 2>&1 | grep 'download failed' | head -1)"
cached=$(docker cp "$name:/var/cache/elodin" - | tar -tv --numeric-owner | awk '$NF ~ /\.list$/ && $2 == "65532/65532"' | wc -l)
if [ "$cached" -ge 1 ]; then
	pass "$cached blocklists cached in the volume"
else
	fail "no blocklist was cached in /var/cache/elodin"
fi

if curl -fsS "http://127.0.0.1:$metrics_port/metrics" | grep -q '^elodin_'; then
	pass "metrics served"
else
	fail "no elodin_ metrics on 9153"
fi

# Nothing but elodin to run: no shell for an exec, or for anything that got in.
# Only the runtime's "no such file" counts; an exec refused for any other
# reason, a container that stopped say, proves nothing.
if out=$(docker exec "$name" /bin/sh -c true 2>&1); then
	fail "the image has a shell"
elif grep -q 'stat /bin/sh: no such file or directory' <<<"$out"; then
	pass "no shell"
else
	fail "could not tell whether the image has a shell: $out"
fi

# The configuration is the one it started with and its lists are all URLs, so a
# reload that read and accepted the file says exactly this. A refused one
# (`reload: ... is not usable`) starts with `reload: ` too.
docker kill -s HUP "$name" >/dev/null
if wait_log 20 'msg="reload: nothing a reload puts into effect has changed"'; then
	pass "reloads on SIGHUP"
else
	fail "no reload after SIGHUP"
fi

# A restart keeps the volume, so the lists come from it rather than the network.
docker restart -t 15 "$name" >/dev/null
# The log carries both runs, so this waits for the second `ready`.
if wait_log 90 'using the cached copy' && wait_ready_count 2; then
	pass "restart reuses the cached lists"
else
	fail "after a restart the lists were not read from the volume"
fi

# SIGTERM, as `docker stop` sends it: a clean exit, well inside the grace period.
started=$SECONDS
docker stop -t 15 "$name" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
took=$((SECONDS - started))
if [ "$code" = 0 ]; then
	pass "stops cleanly on SIGTERM (${took}s)"
else
	fail "exit code $code after SIGTERM"
fi

# The compose sample parses. Only its syntax: it names the published image,
# not the one under test, whose settings the run above has already exercised.
if docker compose version >/dev/null 2>&1; then
	if docker compose -f examples/compose.yaml config -q; then
		pass "examples/compose.yaml is valid"
	else
		fail "examples/compose.yaml does not parse"
	fi
fi

if [ "$failed" != 0 ]; then
	echo "--- logs" >&2
	docker logs "$name" >&2 || true
	exit 1
fi
echo "image-smoke: $image is usable"
