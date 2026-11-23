# The container image: elodin on Google's distroless Debian base, which carries
# glibc, OpenSSL, the CA bundle and an unprivileged account, and no shell,
# package manager or any other program.
#
#   docker build -t elodin .
#   docker build --build-arg ELODIN_VERSION=0.29.0 -t elodin .
#
# Everything happens in here: elodin compiles in a Debian container with the
# Odin release mise.toml pins and `mise run release`, the task every other build
# uses, so the toolchain and the flags have one source. It builds for the
# platform the builder runs on; CI builds each architecture on a runner of that
# architecture, since Odin under emulation would take an age.
#
# Compiling in the Debian release the base is built from links the binary
# against the very glibc and libssl the image carries; the `verify` stage runs it
# against them to prove it.
#
# Every image is pinned by digest, so a commit builds the same image whenever it
# is built. Dependabot moves the pins (.github/dependabot.yml), each move goes
# through CI's image job, and .github/workflows/image-refresh.yml rebuilds the
# newest release on a moved base.
#
# Targets: `image` (the default, last), `verify` (checks the image's files and
# that the binary runs on them; CI builds it), `itest` (the integration suite
# beside the same binary; `mise run itest-image` runs it).

FROM jdxcode/mise:2026.11.10@sha256:80aa2afb17ba760cabe74ac90771ca2d1470773d514cc2bb79c69c8d3f92f150 AS mise

# The compiler and the libraries elodin links against: what `build` and
# `itest` share, and nothing a commit's source changes.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS toolchain
# Unversioned on purpose (DL3008). The release is fixed by the digest above,
# and within it Debian keeps only the current version of a package: a version
# pinned here would vanish from the archive with the next security update and
# fail every build of this commit from then on. What has to hold - the binary
# runs on the base's glibc and OpenSSL - is what the `verify` stage checks.
#
# clang is Debian's rather than the one mise.toml pins: Odin uses it only to
# assemble the fiber switch and to drive the linker, and mise.toml's is a
# 1.2 GB conda build.
# hadolint ignore=DL3008
RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends ca-certificates clang libc6-dev libssl-dev >/dev/null \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=mise /usr/local/bin/mise /usr/local/bin/mise
WORKDIR /src
ENV MISE_TRUSTED_CONFIG_PATHS=/src \
	MISE_DISABLE_TOOLS=clang,go \
	MISE_YES=1
# The toolchain, in a layer of its own that only a change to mise.toml rebuilds.
COPY mise.toml ./
RUN mise install odin

FROM toolchain AS build
COPY src/ src/
# The checkout's git history is not in the build, so the version comes in as an
# argument; mise.toml's own derivation defers to it.
ARG ELODIN_VERSION=dev
ENV ELODIN_VERSION=${ELODIN_VERSION}
RUN mise run release \
	&& install -d -m 0755 /cache \
	&& echo "linked against $(dpkg-query -W -f '${Package} ${Version}  ' libc6 libssl3t64)"

# The integration suite, compiled the same way, beside the binary above, with
# the openssl CLI and strace it needs and the image never will. It reads its
# fixtures from a checkout mounted at run time. The tools go in before the
# source, so a commit reuses their layer rather than installing them again.
FROM toolchain AS itest
# hadolint ignore=DL3008
RUN apt-get update -qq \
	&& apt-get install -y -qq --no-install-recommends openssl strace >/dev/null \
	&& rm -rf /var/lib/apt/lists/*
COPY src/ src/
ARG ELODIN_VERSION=dev
ENV ELODIN_VERSION=${ELODIN_VERSION}
COPY --from=build /src/bin/ bin/
# The variables are lists of flags, split on purpose, and expanded by the
# inner shell mise starts with them set, hence the single quotes.
# hadolint ignore=SC2016,SC2086
RUN mise exec -- sh -c 'odin build src/itest -out:bin/itest -collection:elodin=src -extra-linker-flags:"$ELODIN_LDFLAGS" $ELODIN_DEFINES'

# The `nonroot` variant runs as uid and gid 65532 (`nonroot`), and sets
# SSL_CERT_FILE to its CA bundle, where upstream TLS and list downloads are
# checked: Debian's OpenSSL would otherwise look under /usr/lib/ssl, which the
# base does not have.
FROM gcr.io/distroless/base-debian13:nonroot@sha256:83e67481ae9fc8c7a6d211113431fb8085619bed49672e583261111bac184f0d AS image
COPY --from=build /src/bin/elodin /usr/bin/elodin
COPY examples/docker.yaml /etc/elodin/elodin.yaml
# The blocklist cache (`blocking.cache_dir`), the account's, so a named volume
# mounted there takes that ownership. --chown because COPY otherwise gives what
# it creates to root.
COPY --from=build --chown=65532:65532 /cache/ /var/cache/elodin/
# glibc keeps the memory a blocklist refresh frees unless its mmap threshold is
# pinned; packaging/elodin.service sets the same, and docs/blocking.md says why.
ENV MALLOC_MMAP_THRESHOLD_=131072
USER 65532:65532
# Documentation only; publishing is `-p`. 9153 is the metrics endpoint the
# default configuration serves.
EXPOSE 53/udp 53/tcp 9153/tcp
ENTRYPOINT ["/usr/bin/elodin"]
LABEL org.opencontainers.image.title="elodin" \
	org.opencontainers.image.description="A filtering DNS forwarder in Odin, in the spirit of Pi-hole and AdGuard Home" \
	org.opencontainers.image.source="https://github.com/jadolg/elodin" \
	org.opencontainers.image.licenses="MIT"

# The image's filesystem, checked from outside it, since it has no shell to
# check itself with:
#   - no program but elodin: every program - an ELF file or a `#!` script, read
#     from the files, since the base marks some data executable - is elodin or
#     a shared library under usr/lib. Two of those run as well, as in every
#     dynamically linked image: libc.so.6 prints its version, and the dynamic
#     loader starts an ELF file it is given. The base's update-motd script is
#     the other exception, and with no shell nothing can run it. A shell,
#     busybox or a package manager arriving with a base update fails here. The
#     scan has to find elodin itself, so a scan that broke fails rather than
#     finding nothing.
#   - the cache directory is the account's.
#   - the binary starts on the image's own libraries, chrooted into it. Only
#     `--version`: a build step has no /proc to give the chroot, which reading
#     a configuration needs. scripts/image-smoke.sh runs the image itself on
#     its default configuration.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS verify
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY --from=image / /rootfs/
WORKDIR /rootfs
RUN set -eu; \
	programs=$(find . -type f -exec sh -c 'for f; do \
		case "$(head -c 4 "$f" | od -An -c | tr -d " ")" in \
		"177ELF"|"#!"*) printf "%s\n" "${f#./}" ;; \
		esac; done' sh {} +); \
	grep -qx usr/bin/elodin <<<"$programs" || { echo "the scan did not find usr/bin/elodin; it is broken"; exit 1; }; \
	found=$(grep -Ev '^(usr/bin/elodin|etc/update-motd\.d/10-uname)$|^usr/lib(64)?/.*\.so(\.[0-9.]+)?$' <<<"$programs" || true); \
	if [ -n "$found" ]; then echo "the image holds programs other than elodin:"; echo "$found"; exit 1; fi; \
	owner=$(stat -c %u:%g var/cache/elodin); \
	[ "$owner" = 65532:65532 ] || { echo "var/cache/elodin is owned by $owner, want 65532:65532"; exit 1; }; \
	chroot --userspec=65532:65532 /rootfs /usr/bin/elodin --version; \
	echo "verify: the image holds no program but elodin"

# The default target is the image, not the check above.
FROM image
