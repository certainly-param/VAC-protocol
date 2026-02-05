FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY sidecar/ .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vac-sidecar /usr/local/bin/vac-sidecar
EXPOSE 3000
ENTRYPOINT ["vac-sidecar"]
