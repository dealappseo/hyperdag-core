FROM rustlang/rust:nightly-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/zkp-postcard/Cargo.toml services/zkp-postcard/Cargo.lock* ./
COPY services/zkp-postcard/src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zkp-postcard /usr/local/bin/
ENV PORT=8080
EXPOSE 8080
CMD ["zkp-postcard"]
