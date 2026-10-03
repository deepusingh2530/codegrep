# syntax=docker/dockerfile:1
#
# scanward — single-binary SAST scanner (release image)
#
# Two stages must share a distro line: the runtime image's glibc must be >= the
# one the binary linked against (rust:slim alone tracks newer Debian releases
# than debian:bookworm-slim).
#
#   docker run --rm -v "$PWD:/src" ghcr.io/deepusingh2530/scanward
#
# The rule corpus is baked in at /rules and is the default, so a first run needs
# no flags beyond the mount. Pass args to override, e.g.
#   docker run --rm -v "$PWD:/src" ghcr.io/deepusingh2530/scanward scan /src --min-severity error --error

FROM rust:slim-bookworm AS build
WORKDIR /src

# Dependencies first: this layer is cached until a manifest actually changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/cg-ir/Cargo.toml crates/cg-ir/
COPY crates/cg-parser/Cargo.toml crates/cg-parser/
COPY crates/cg-matcher/Cargo.toml crates/cg-matcher/
COPY crates/cg-taint/Cargo.toml crates/cg-taint/
COPY crates/cg-rules/Cargo.toml crates/cg-rules/
COPY crates/scanward/Cargo.toml crates/scanward/
RUN mkdir -p crates/cg-{ir,parser,matcher,taint,rules}/src crates/scanward/src \
 && echo "" > crates/cg-parser/src/lib.rs \
 && echo "" > crates/cg-ir/src/lib.rs \
 && echo "" > crates/cg-matcher/src/lib.rs \
 && echo "" > crates/cg-taint/src/lib.rs \
 && echo "" > crates/cg-rules/src/lib.rs \
 && echo "" > crates/scanward/src/lib.rs \
 && echo "fn main() {}" > crates/scanward/src/main.rs \
 && cargo build --release -p scanward 2>/dev/null || true

COPY crates/ crates/
# Touch so cargo rebuilds the real sources over the placeholder layer.
RUN touch crates/*/src/lib.rs crates/scanward/src/main.rs \
 && cargo build --release -p scanward \
 && strip target/release/scanward

FROM debian:bookworm-slim AS runtime

ARG VERSION="dev"
LABEL org.opencontainers.image.title="scanward" \
      org.opencontainers.image.description="Fast, fully-offline multi-language SAST scanner" \
      org.opencontainers.image.source="https://github.com/deepusingh2530/scanward" \
      org.opencontainers.image.url="https://github.com/deepusingh2530/scanward" \
      org.opencontainers.image.documentation="https://github.com/deepusingh2530/scanward#readme" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="scanward contributors"

# Non-root by default: a scanner reads untrusted code, so it should not run as
# root. UID is fixed so bind-mounted volumes line up predictably.
RUN useradd --create-home --uid 10001 scanward

COPY --from=build /src/target/release/scanward /usr/local/bin/scanward
COPY --chown=root:root rules /rules

USER scanward
WORKDIR /src
ENV SCANWARD_RULES=/rules

ENTRYPOINT ["scanward"]
# Corpus is baked in, so the common case is a bare run against the mount.
CMD ["scan", "/src", "--rules", "/rules"]