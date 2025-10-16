FROM rust:1.90 AS builder
WORKDIR /usr/src
COPY . .
RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 app
WORKDIR /root
COPY --from=builder /usr/src/target/release/mtls-sidecar /usr/local/bin/
USER app
ENTRYPOINT ["/usr/local/bin/mtls-sidecar"]
