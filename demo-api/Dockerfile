FROM rust:1.83-bookworm as builder
WORKDIR /app
COPY demo-api/ .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vac-demo-api /usr/local/bin/vac-demo-api
EXPOSE 8080
ENTRYPOINT ["vac-demo-api"]
