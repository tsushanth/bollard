# Builds all bollard binaries; each compose service runs the one it needs.
# Build context is the repo root (see docker-compose.yml).
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release

FROM debian:stable-slim
RUN useradd -r -u 10001 bollard
COPY --from=build /src/target/release/bollard-proxy /usr/local/bin/
COPY --from=build /src/target/release/bollard-broker /usr/local/bin/
COPY --from=build /src/target/release/bollard-mcp /usr/local/bin/
COPY --from=build /src/target/release/bollard-infer /usr/local/bin/
USER bollard
