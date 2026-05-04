# ─── Build stage ─────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build without TLS feature so the server runs plain HTTP (no self-signed cert
# browser warnings in local/dev environments).
RUN cargo build --release --no-default-features \
    -p mcpcondor-standard --bin mcpcondor

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/mcpcondor /usr/local/bin/mcpcondor

COPY docker/mcpcondor.toml /etc/mcpcondor.toml

RUN useradd -r -s /bin/false mcpcondor \
    && mkdir -p /data \
    && chown mcpcondor:mcpcondor /data

USER mcpcondor
VOLUME ["/data"]
EXPOSE 3000

ENV RUST_LOG=info
ENV MCPSHIELD_CONFIG=/etc/mcpcondor.toml

ENTRYPOINT ["/usr/local/bin/mcpcondor"]
