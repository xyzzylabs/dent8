# dent8 CLI/MCP image — the full operational build (Postgres + SQLite backends, signed
# identity, witness). Used by examples/witness-operated/ to run the witness signer and
# monitor on infrastructure separate from the writer; equally usable as an agent's MCP
# server container.
#
#   docker build -t dent8 .
#   docker run --rm dent8 --help

FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
# Build deps for the bundled SQLite C sources.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p dent8 --features postgres,sqlite \
    && strip target/release/dent8

FROM debian:bookworm-slim
# ca-certificates for TLS Postgres connections.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /home/dent8 dent8 \
    # Volume mount points for the operated-witness split, owned by the runtime user (a fresh
    # named volume inherits the image's ownership for its mount path). The private key, local
    # witness logs, and copied public key live on separate volumes so publisher/monitor services
    # do not need the signing-key volume.
    && mkdir -p /witness/private /witness/log /witness/public /published \
    && chown -R dent8 /witness /published
COPY --from=build /src/target/release/dent8 /usr/local/bin/dent8
USER dent8
WORKDIR /home/dent8
ENTRYPOINT ["dent8"]
CMD ["--help"]
