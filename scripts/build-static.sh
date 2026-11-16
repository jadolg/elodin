#!/usr/bin/env bash
#
# Build elodin as one static binary carrying musl and OpenSSL, which runs on any
# Linux of its architecture: glibc distributions, Alpine and OpenWrt alike.
#
#   scripts/build-static.sh [--itest]
#
# Writes bin/static/elodin; --itest also writes bin/static/itest, the suite
# linked the same way, so it can run where the binary does. Needs the mise
# toolchain and docker.
#
# Odin compiles on the host, as for every other build, into an object rather than
# an executable. The object links inside an Alpine container, which is where a
# static OpenSSL built against musl comes from (`openssl-libs-static`): no
# glibc distribution ships one. `-static-pie` keeps the binary position
# independent, so ASLR still places it. The debug information the static
# libraries bring is dropped (22.8 MB to 8.5 MB on amd64); the symbols stay, as
# in the dynamic build, so a backtrace still names its frames.
#
# ELODIN_STATIC makes tlsx leave the host's openssl.cnf alone (see `tlsx.STATIC`).

set -euo pipefail
cd "$(dirname "$0")/.."

itest=0
while [ $# -gt 0 ]; do
	case "$1" in
	--itest) itest=1 ;;
	*) echo "build-static: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

: "${ELODIN_DEFINES:?run through mise, which sets ELODIN_DEFINES}"
: "${ELODIN_ALPINE:?run through mise, which sets ELODIN_ALPINE}"
for tool in docker readelf file; do
	command -v "$tool" >/dev/null || { echo "build-static: needs $tool" >&2; exit 1; }
done

out=bin/static
rm -rf "$out"
mkdir -p "$out/elodin-obj" "$out/itest-obj"

# The fiber switch, which `prepare` assembles and fiber.odin's foreign import
# names; an object build links nothing, so it is passed to the linker below.
[ -f bin/elodin_switch.o ] || { echo "build-static: bin/elodin_switch.o is missing; run mise run prepare" >&2; exit 1; }

# Each build gets a directory of its own: an unoptimised one writes an object per
# package, all of which the link takes.
# shellcheck disable=SC2086 # ELODIN_DEFINES is a list of flags
odin build src/main -collection:elodin=src -o:speed -build-mode:obj \
	-define:ELODIN_STATIC=true $ELODIN_DEFINES -out:"$out/elodin-obj/elodin.o"
objects=elodin
if [ "$itest" = 1 ]; then
	# shellcheck disable=SC2086
	odin build src/itest -collection:elodin=src -build-mode:obj \
		-define:ELODIN_STATIC=true $ELODIN_DEFINES -out:"$out/itest-obj/itest.o"
	objects="elodin itest"
fi

# The container runs as root to install packages; what it writes is handed back
# to whoever ran this. The checkout is mounted at its own path, so a path the
# container names is one on the host too.
docker run --rm -v "$PWD:$PWD" -w "$PWD" \
	-e OBJECTS="$objects" -e OWNER="$(id -u):$(id -g)" -e OUT="$out" \
	"$ELODIN_ALPINE" sh -euc '
		apk add --no-cache -q gcc musl-dev openssl-dev openssl-libs-static >/dev/null
		for o in $OBJECTS; do
			gcc -static-pie -Wl,--strip-debug "$OUT/$o-obj/"*.o bin/elodin_switch.o -o "$OUT/$o" -lssl -lcrypto -lm -lpthread
		done
		rm -r "$OUT/elodin-obj" "$OUT/itest-obj"
		echo "linked against $(apk info -e -v openssl-libs-static musl | tr "\n" " ")"
		chown -R "$OWNER" "$OUT"
	'

# Static means no program interpreter and nothing to load: a binary that asks
# for either would fail on the hosts this build exists for.
for o in $objects; do
	# Captured before they are searched: a readelf that fails stops the script
	# here (set -e) rather than leaving the search nothing to find.
	headers=$(readelf -lW "$out/$o")
	dynamic=$(readelf -dW "$out/$o")
	if grep -q 'INTERP' <<<"$headers" || grep -q '(NEEDED)' <<<"$dynamic"; then
		echo "build-static: $out/$o is not static:" >&2
		grep -A1 INTERP <<<"$headers" >&2 || true
		grep NEEDED <<<"$dynamic" >&2 || true
		exit 1
	fi
	file -b "$out/$o"
done
