# The container image: elodin, the musl loader and the OpenSSL it links, the CA
# bundle, and nothing else - no shell, no package manager, no busybox.
#
# Not buildable from the checkout alone: Odin compiles on the host, as for every
# other build, and scripts/build-image.sh hands this file a context holding the
# objects (obj/), the default configuration and nothing else. Run it as
# `mise run image`.
#
# The link stage is the one scripts/build-static.sh uses, with `-pie` in place
# of `-static-pie`: OpenSSL stays a pair of shared libraries beside the binary
# rather than being linked into it, so an image rebuilt after Alpine ships an
# OpenSSL fix carries the fix without elodin being compiled again, and the
# library's version is a file anyone can look at.

ARG ALPINE=alpine:3.24

FROM ${ALPINE} AS link
RUN apk add --no-cache -q gcc musl-dev openssl-dev ca-certificates
COPY obj/ /obj/
# The binary, then every library its dynamic section names, each at the path
# the loader will look for it, found by asking the loader. Each line of musl's
# ldd is either `name => path (addr)` or, for the loader itself, `path (addr)`.
# No list of file names is kept here, so an OpenSSL soname change or a new
# dependency is picked up rather than missed.
#
# The CA bundle goes to /etc/ssl/cert.pem, the file Alpine's OpenSSL reads by
# default. The Debian path (/etc/ssl/certs/ca-certificates.crt) would be
# ignored, and every verified upstream would fail its handshake.
#
# The account exists so `docker exec`, `ps` and a log line name it; elodin
# itself never looks it up, since it starts as that uid rather than dropping to
# it. /var/cache/elodin is where `blocking.cache_dir` points by default, and
# belongs to the account so a named volume mounted there inherits that.
RUN set -eu; \
	gcc -pie -Wl,--strip-debug /obj/elodin/*.o /obj/elodin_switch.o -o /elodin -lssl -lcrypto -lm -lpthread; \
	install -D -m 0755 /elodin /rootfs/usr/bin/elodin; \
	ldd /elodin | awk '$2 == "=>" { print $3; next } { print $1 }' | sort -u | while read -r lib; do \
		install -D -m 0755 "$(readlink -f "$lib")" "/rootfs$lib"; \
	done; \
	install -D -m 0644 "$(readlink -f /etc/ssl/cert.pem)" /rootfs/etc/ssl/cert.pem; \
	printf 'elodin:x:65532:65532:elodin:/var/cache/elodin:/sbin/nologin\n' > /rootfs/etc/passwd; \
	printf 'elodin:x:65532:\n' > /rootfs/etc/group; \
	install -d -m 0755 -o 65532 -g 65532 /rootfs/var/cache/elodin; \
	echo "linked against $(apk info -e -v musl libssl3 libcrypto3 | tr '\n' ' ')"
COPY elodin.yaml /rootfs/etc/elodin/elodin.yaml

# The integration suite, linked the same way and run against the binary above,
# on the same libraries: this stage is the link stage, whose libssl and
# libcrypto are the files the image carries. The suite needs the openssl CLI
# and strace, which the image itself never will. scripts/build-image.sh builds
# it only when asked (--itest).
FROM link AS itest
RUN set -eu; \
	apk add --no-cache -q openssl strace; \
	gcc -pie /obj/itest/*.o /obj/elodin_switch.o -o /usr/local/bin/itest -lssl -lcrypto -lm -lpthread; \
	cp /elodin /usr/bin/elodin

FROM scratch AS image
ARG VERSION=dev
ARG REVISION=unknown
# --chown keeps the cache directory the account's; COPY otherwise gives every
# file to root.
COPY --from=link /rootfs/ /
COPY --from=link --chown=65532:65532 /rootfs/var/cache/elodin/ /var/cache/elodin/
USER 65532:65532
# Documentation only; publishing is `-p`. 9153 is the metrics endpoint the
# default configuration serves.
EXPOSE 53/udp 53/tcp 9153/tcp
ENTRYPOINT ["/usr/bin/elodin"]
LABEL org.opencontainers.image.title="elodin" \
	org.opencontainers.image.description="A filtering DNS forwarder in Odin, in the spirit of Pi-hole and AdGuard Home" \
	org.opencontainers.image.source="https://github.com/jadolg/elodin" \
	org.opencontainers.image.licenses="MIT" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}"
