FROM rust:1.90-trixie AS builder
WORKDIR /usr/src
COPY . .
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM gcr.io/distroless/cc-debian13
WORKDIR /app
COPY --from=builder /usr/src/target/release/mtls-sidecar /app
ENTRYPOINT ["./mtls-sidecar"]
