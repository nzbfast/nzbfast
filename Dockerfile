# nzbfast - multi-stage build → slim runtime image.
# Ships the daemon (`nzbfast serve`) with unrar available for the
# compressed-post fallback paths.

# Base images are pinned by digest (Scorecard Pinned-Dependencies): a tag
# is mutable, so `rust:1-bookworm` is not a reproducible input. The digest
# is the multi-arch manifest LIST, not a per-platform manifest, so the
# arm64 and amd64 builds both still resolve. Dependabot's `docker`
# ecosystem moves these forward weekly - if you unpin one, drop its
# ecosystem entry too, or the pin silently rots.
FROM rust:1-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7 AS build
WORKDIR /src
# Issue #38: a wedged daemon in the official image could not be given a
# usable backtrace - the release profile strips symbols and the strip
# below strips again, so `gdb -p` resolved 1010 frames of `?? ()`.
# Build with symbols + line tables instead (env overrides the profile's
# `strip = "symbols"`), then split them into a debuglink sidecar the
# runtime stage ships at gdb's standard search path. The binary on PATH
# stays stripped. Set BEFORE the cache-warming stub build too, or the
# profile hash changes and the dependency cache is thrown away.
ENV CARGO_PROFILE_RELEASE_STRIP=none \
    CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
# Cache dependency compilation: copy manifests, build a stub, then the source.
COPY Cargo.toml Cargo.lock ./
COPY crates/nzbkit/Cargo.toml crates/nzbkit/
COPY crates/nzbfast/Cargo.toml crates/nzbfast/
RUN mkdir -p crates/nzbkit/src crates/nzbfast/src \
    && echo 'fn main(){}' > crates/nzbfast/src/main.rs \
    && echo '' > crates/nzbkit/src/lib.rs \
    && cargo build --release -p nzbfast 2>/dev/null || true
# Real sources (vendor/ carries the rapidyenc C for the build.rs FFI;
# web/ + docs/MANUAL.html are include_str!-embedded by serve.rs).
COPY vendor/ vendor/
COPY web/ web/
# The whole docs tree: MANUAL.html plus docs/i18n/MANUAL.<lang>.html -
# all include_str!-embedded by serve.rs (the i18n manuals broke the
# image build when only MANUAL.html was copied).
COPY docs/ docs/
COPY crates/ crates/
RUN touch crates/nzbkit/src/lib.rs crates/nzbfast/src/main.rs \
    && cargo build --release -p nzbfast \
    && objcopy --only-keep-debug target/release/nzbfast target/release/nzbfast.debug \
    && objcopy --strip-all --add-gnu-debuglink=target/release/nzbfast.debug \
         target/release/nzbfast

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
# unrar (non-free) matches the real unrar the desktop bundles embed -
# unrar-free chokes on too many real-world RAR sets.
RUN sed -i 's/Components: main/Components: main non-free non-free-firmware/' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        unrar p7zip-full ca-certificates tini curl gosu \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/nzbfast /usr/local/bin/nzbfast
# The symbol sidecar, where gdb's debuglink search looks for it
# (/usr/lib/debug + the binary's directory). `apt-get install gdb` in a
# wedged container then gives named, line-numbered frames from
# `gdb -p $(pidof nzbfast) -batch -ex 'thread apply all bt'`.
COPY --from=build /src/target/release/nzbfast.debug /usr/lib/debug/usr/local/bin/nzbfast.debug

LABEL org.opencontainers.image.title="nzbfast" \
      org.opencontainers.image.source="https://github.com/nzbfast/nzbfast" \
      org.opencontainers.image.url="https://nzbfast.com" \
      org.opencontainers.image.vendor="nzbfast"

# Config + data mount points (compose/NAS bind them). WORKDIR /config so
# relative state (index.db) lands on the persisted config volume.
ENV NZBFAST_CONFIG=/config/config.json \
    NZBFAST_PORT=6789 \
    NZBFAST_OUT=/downloads \
    NZBFAST_WATCH=/watch
RUN mkdir -p /config /downloads /watch /incomplete
WORKDIR /config
VOLUME ["/config", "/downloads", "/watch"]
EXPOSE 6789

COPY packaging/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS "http://127.0.0.1:${NZBFAST_PORT:-6789}/api?mode=version&output=json" >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
