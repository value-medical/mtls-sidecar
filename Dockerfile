FROM rust:1.90-trixie AS builder
WORKDIR /usr/src
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian13
WORKDIR /app
COPY --from=builder /usr/src/target/release/mtls-sidecar /app
ENTRYPOINT ["./mtls-sidecar"]
