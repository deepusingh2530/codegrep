# scanward — single-binary SAST scanner (release image)
# Both stages must share the same distro line: the runtime image's glibc
# must be >= the one the binary linked against (rust:slim alone tracks
# newer Debian releases than debian:bookworm-slim).
FROM rust:slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p scanward

FROM debian:bookworm-slim
COPY --from=build /src/target/release/scanward /usr/local/bin/scanward
COPY rules /rules
ENTRYPOINT ["scanward"]
CMD ["scan", "--help"]
