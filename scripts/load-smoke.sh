#!/usr/bin/env bash
#
# Put the optimised binary under sustained load on every transport and fail if
# it stops answering, answers wrongly, dies, keeps memory it should give back,
# spins once the load is gone, or cannot shut down.
#
# Not a benchmark: `mise run bench` measures, this only asks whether the server
# survives being leaned on, and it runs on every architecture CI builds for. The
# thresholds are deliberately loose - a shared CI runner is noisy, and a gate
# that flakes is a gate that gets ignored - so what trips them is a server that
# broke, not one that was slow. Each phase prints its figures, so a run that
# passes is still a record of what it did.
#
# The generator and the upstream are the benchmark's own (`bench/cmd/loadgen`,
# `bench/cmd/mockdns`): neither shares elodin's codec, so a bug in it cannot
# agree with itself here.

set -euo pipefail

BIN=${BIN:-bin/elodin}
# Seconds per phase; the mixed phase runs twice as long.
SECS=${LOAD_SECONDS:-15}
BASE=${LOAD_PORT_BASE:-39000}
DNS=$((BASE + 53)) DOT=$((BASE + 853)) DOH=$((BASE + 443)) METRICS=$((BASE + 153)) UP=$((BASE + 99))

# LOAD_WORK keeps the logs somewhere CI can upload them from.
work=${LOAD_WORK:-$(mktemp -d)}
mkdir -p "$work"
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	echo "logs kept in $work"
}
trap cleanup EXIT

echo "==> building the load generator and the mock upstream"
(cd bench && go build -o "$work/loadgen" ./cmd/loadgen && go build -o "$work/mockdns" ./cmd/mockdns)

# Newer generators check the certificate the server presents and take it with
# -ca; older ones skip the check and have no such flag.
ca=()
"$work/loadgen" -h 2>&1 | grep -q -- '-ca ' && ca=(-ca "$work/cert.pem")

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$work/key.pem" -out "$work/cert.pem" -days 2 -subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

# Rate limiting off and the whole table to one prefix: every client here is
# 127.0.0.1, which is exactly the source those limits exist to hold back, and
# this run is about the server's machinery rather than its limits.
cat >"$work/elodin.yaml" <<EOF
log:
  level: warn
  file: $work/elodin.log
server:
  max_connections: 2048
  max_connections_per_prefix: 2048
  rate_limit:
    enabled: false
listeners:
  udp: {enabled: true, address: "127.0.0.1", port: $DNS}
  tcp: {enabled: true, address: "127.0.0.1", port: $DNS}
  dot: {enabled: true, address: "127.0.0.1", port: $DOT, cert_file: $work/cert.pem, key_file: $work/key.pem}
  doh: {enabled: true, address: "127.0.0.1", port: $DOH, path: /dns-query, cert_file: $work/cert.pem, key_file: $work/key.pem}
upstream:
  timeout: 2s
  bootstrap: [127.0.0.1]
  servers:
    - {name: mock, type: udp, address: 127.0.0.1, port: $UP}
cache:
  enabled: true
  max_entries: 100000
blocking:
  enabled: false
dnssec:
  enabled: false
metrics:
  enabled: true
  address: 127.0.0.1
  port: $METRICS
EOF

"$work/mockdns" -addr "127.0.0.1:$UP" -delay 20ms >"$work/mockdns.log" 2>&1 &
pids+=($!)
"$BIN" --config "$work/elodin.yaml" --no-fetch >"$work/stdout" 2>&1 &
server=$!
pids+=("$server")

for _ in $(seq 1 100); do
	curl -sf -o /dev/null "http://127.0.0.1:$METRICS/metrics" && break
	sleep 0.1
done
curl -sf -o /dev/null "http://127.0.0.1:$METRICS/metrics" || {
	echo "elodin did not come up"; cat "$work/stdout"; exit 1
}

alive() {
	kill -0 "$server" 2>/dev/null || {
		echo "FAIL: elodin exited during $1"; tail -n 40 "$work/stdout" "$work/elodin.log"; exit 1
	}
}

rss_mb() { echo $(($(awk '/VmRSS/{print $2}' "/proc/$server/status") / 1024)); }

# phase <name> <min qps> <loadgen flags...>: run one load and hold it to the bar.
# Errors are timeouts, resets and malformed replies; rcodes other than NOERROR
# are counted with them, since the mock answers every name.
phase() {
	local name=$1 min=$2
	shift 2
	"$work/loadgen" -duration "${SECS}s" -warmup 1s "${ca[@]}" "$@" >"$work/$name.json"
	alive "$name"
	local answered errors noerror qps
	answered=$(jq '.answered' "$work/$name.json")
	errors=$(jq '.errors' "$work/$name.json")
	# The handshake phase counts connections and reports no rcodes.
	noerror=$(jq 'if .rcodes == null then .answered else (.rcodes.noerror // 0) end' "$work/$name.json")
	qps=$(jq '.qps | floor' "$work/$name.json")
	printf '%-14s %7s qps  answered=%-8s errors=%-6s p99=%sms  rss=%sMB\n' \
		"$name" "$qps" "$answered" "$errors" "$(jq '.p99_ms' "$work/$name.json")" "$(rss_mb)"
	if [ "$qps" -lt "$min" ]; then
		echo "FAIL: $name answered $qps qps, under the floor of $min"; exit 1
	fi
	if [ $((errors * 100)) -gt "$answered" ] || [ $(((answered - noerror) * 100)) -gt "$answered" ]; then
		echo "FAIL: $name: more than 1% of queries failed or were not NOERROR"; jq . "$work/$name.json"; exit 1
	fi
}

echo "==> load, ${SECS}s a phase"
phase udp-hits     500 -transport udp  -server "127.0.0.1:$DNS" -clients 64
phase udp-misses   300 -transport udp  -server "127.0.0.1:$DNS" -clients 64 -qmode unique -rate 3000
phase tcp-hits     500 -transport tcp  -server "127.0.0.1:$DNS" -clients 64
phase tcp-misses   300 -transport tcp  -server "127.0.0.1:$DNS" -clients 64 -qmode unique -rate 3000
phase dot-hits     500 -transport dot  -server "127.0.0.1:$DOT" -clients 64
phase doh1-hits    500 -transport doh1 -server "127.0.0.1:$DOH" -clients 64
phase doh2-hits    500 -transport doh2 -server "127.0.0.1:$DOH" -clients 16 -concurrency 16
phase doh2-misses  300 -transport doh2 -server "127.0.0.1:$DOH" -clients 16 -concurrency 16 -qmode unique -rate 3000
phase handshakes    50 -transport handshake -server "127.0.0.1:$DOT" -clients 16

echo "==> every transport at once, $((SECS * 2))s"
SECS=$((SECS * 2))
mixed=()
for t in udp tcp dot doh1 doh2; do
	case $t in udp | tcp) at=$DNS ;; dot) at=$DOT ;; *) at=$DOH ;; esac
	"$work/loadgen" -duration "${SECS}s" -warmup 1s "${ca[@]}" -transport $t \
		-server "127.0.0.1:$at" -clients 32 -qmode unique -rate 1000 >"$work/mixed-$t.json" &
	mixed+=($!)
done
for p in "${mixed[@]}"; do wait "$p"; done
alive "the mixed phase"
for t in udp tcp dot doh1 doh2; do
	answered=$(jq '.answered' "$work/mixed-$t.json")
	errors=$(jq '.errors' "$work/mixed-$t.json")
	echo "mixed-$t       answered=$answered errors=$errors"
	if [ "$answered" -lt $((SECS * 200)) ] || [ $((errors * 100)) -gt "$answered" ]; then
		echo "FAIL: mixed-$t"; jq . "$work/mixed-$t.json"; exit 1
	fi
done

echo "==> after the load"
# Quiet for longer than the loops' one-second idle trim, so the stacks the burst
# kept warm have been given back.
sleep 5
rss=$(rss_mb)
echo "resident: ${rss}MB"
if [ "$rss" -gt 512 ]; then
	echo "FAIL: ${rss}MB resident once the load is gone"; exit 1
fi

# An idle server sleeps in epoll_wait. More than a twentieth of a core over ten
# seconds of nothing is a loop that spins.
read -r u0 s0 < <(awk '{print $14, $15}' "/proc/$server/stat")
sleep 10
read -r u1 s1 < <(awk '{print $14, $15}' "/proc/$server/stat")
ticks=$((u1 + s1 - u0 - s0))
echo "idle CPU: $ticks ticks in 10s"
if [ "$ticks" -gt 50 ]; then
	echo "FAIL: $ticks clock ticks of CPU over ten idle seconds"; exit 1
fi

curl -sf -o /dev/null "http://127.0.0.1:$METRICS/metrics" || { echo "FAIL: /metrics stopped answering"; exit 1; }

kill -TERM "$server"
for _ in $(seq 1 300); do
	kill -0 "$server" 2>/dev/null || break
	sleep 0.1
done
if kill -0 "$server" 2>/dev/null; then
	echo "FAIL: still running 30s after SIGTERM"; exit 1
fi
status=0
wait "$server" || status=$?
if [ "$status" -ne 0 ]; then
	echo "FAIL: exited with status $status"; tail -n 40 "$work/stdout"; exit 1
fi
echo "==> survived the load and shut down cleanly"
