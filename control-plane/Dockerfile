FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY control-plane/ .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vac-control-plane /usr/local/bin/vac-control-plane
EXPOSE 8081
ENTRYPOINT ["vac-control-plane"]
