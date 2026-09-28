# codegrep — single-binary SAST scanner (release image)
FROM rust:1.75-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p codegrep

FROM debian:bookworm-slim
COPY --from=build /src/target/release/codegrep /usr/local/bin/codegrep
COPY rules /rules
ENTRYPOINT ["codegrep"]
CMD ["scan", "--help"]
