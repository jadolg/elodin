# The container image: elodin on Google's distroless Debian base, which carries
# glibc, OpenSSL, the CA bundle and an unprivileged account, and no shell,
# package manager or any other program.
#
# Not buildable from the checkout alone: Odin compiles on the host, as for every
# other build, and scripts/build-image.sh hands this file a context holding the
# objects (obj/), the default configuration, an empty cache/ and nothing else.
# Run it as `mise run image`.
#
# The objects link in a Debian container of the release the base is built from,
# against the same glibc and libssl-dev the base's libraries come from. Linking
# on the runner instead would tie the binary to the runner's glibc, which is
# newer than Debian's and would leave it asking for symbol versions the image
# does not have.
#
# Both images are pinned by digest, so a commit builds the same image whenever
# it is built; Dependabot moves the pins (.github/dependabot.yml), and each move
# goes through CI's image job like any other change. The base's digest is also
# written into the image's labels (scripts/build-image.sh), which is what
# .github/workflows/image-refresh.yml compares to decide a published release
# needs rebuilding on a newer base.

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS link
RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends gcc libc6-dev libssl-dev >/dev/null \
	&& rm -rf /var/lib/apt/lists/*
COPY obj/ /obj/
RUN gcc -pie -Wl,--strip-debug /obj/elodin/*.o /obj/elodin_switch.o -o /elodin -lssl -lcrypto -lm -lpthread \
	&& echo "linked against $(dpkg-query -W -f '${Package} ${Version}  ' libc6 libssl3t64)"

# The integration suite, linked the same way and run against the binary above,
# on the same Debian release. It needs the openssl CLI and strace, which the
# image itself never will. scripts/build-image.sh builds it only when asked
# (--itest).
FROM link AS itest
RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends openssl strace ca-certificates >/dev/null \
	&& rm -rf /var/lib/apt/lists/* \
	&& gcc -pie /obj/itest/*.o /obj/elodin_switch.o -o /usr/local/bin/itest -lssl -lcrypto -lm -lpthread \
	&& cp /elodin /usr/bin/elodin

# The `nonroot` variant runs as uid and gid 65532 (`nonroot`), and sets
# SSL_CERT_FILE to its CA bundle, which is where upstream TLS and list downloads
# are checked: Debian's OpenSSL would otherwise look under /usr/lib/ssl, which
# the base does not have.
FROM gcr.io/distroless/base-debian13:nonroot@sha256:a08d9054afbaf1af9b90fd02cdc7b32236319b5376d374505a41548d42b0c5db AS image
ARG VERSION=dev
ARG REVISION=unknown
ARG BASE_NAME=unknown
ARG BASE_DIGEST=unknown
COPY --from=link /elodin /usr/bin/elodin
COPY elodin.yaml /etc/elodin/elodin.yaml
# The blocklist cache (`blocking.cache_dir`), the account's, so a named volume
# mounted there takes that ownership. --chown because COPY otherwise gives what
# it creates to root.
COPY --chown=65532:65532 cache/ /var/cache/elodin/
# glibc keeps the memory a blocklist refresh frees unless its mmap threshold is
# pinned; packaging/elodin.service sets the same, and docs/blocking.md says why.
ENV MALLOC_MMAP_THRESHOLD_=131072
WORKDIR /
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
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.base.name="${BASE_NAME}" \
	org.opencontainers.image.base.digest="${BASE_DIGEST}"
