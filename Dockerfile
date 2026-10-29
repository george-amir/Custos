# Multi-stage production Dockerfile for Custos (`custos`)
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/custos
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nftables \
    ipset \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/lib/custos
COPY --from=builder /usr/src/custos/target/release/custos /usr/local/bin/custos
COPY config.example.toml /etc/custos/config.toml

EXPOSE 8085 50051

ENTRYPOINT ["/usr/local/bin/custos"]
CMD ["--config", "/etc/custos/config.toml", "run"]
