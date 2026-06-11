FROM rustlang/rust:nightly-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
# Vendored Poseidon2/BabyBear leaf crate (path dep) — MUST be copied into the build context.
# Railway Root Directory is services/zkp-postcard, so a sibling ../babybear-leaf is unreachable
# (caused the 2026-06-11 "failed to read /babybear-leaf/Cargo.toml" build failure).
COPY babybear-leaf/ babybear-leaf/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zkp-postcard /usr/local/bin/
ENV PORT=8080
EXPOSE 8080
CMD ["zkp-postcard"]
