# EdgeAuth edge identity verifier — multi-stage production image.
#
# Builds the `edgeauth-node` binary (the native GraphQL server) and ships it on
# a slim, non-root Debian base. The verification core additionally compiles to
# `wasm32-unknown-unknown` for edge/serverless deployment — see the README.

FROM rust:1.89-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p edgeauth-node \
    && strip target/release/edgeauth-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --home-dir /nonexistent --no-create-home edgeauth
COPY --from=build /app/target/release/edgeauth-node /usr/local/bin/edgeauth-node
USER 10001
EXPOSE 8080
ENV EA_BIND_ADDR=0.0.0.0:8080 RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/edgeauth-node"]
CMD ["serve"]
