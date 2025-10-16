# mtls-sidecar

A minimal Rust-based sidecar proxy for enforcing inbound mTLS in Kubernetes pods. It terminates mTLS connections,
verifies client certificates against trusted CAs, and forwards validated HTTP requests to an upstream application in the
same pod. The sidecar monitors mounted certificate files for updates (e.g., from Vault Secrets Operator) and reloads TLS
configuration without restarts.

## Purpose

This component provides a lightweight layer for securing HTTP services with mutual TLS, integrating seamlessly with
Kubernetes Secret mounts. It focuses on inbound termination and proxying, avoiding broader features like routing or
outbound connections.

## Key Features

- Enforces mTLS with client certificate verification against a CA bundle.
- Hot-reloads TLS configuration on file changes.
- Simple reverse proxy to a single upstream endpoint.
- Optional injection of client certificate details into upstream headers.
- Dedicated monitoring port for health probes and optional Prometheus metrics.
- Supports both `kubernetes.io/tls` and VSO Opaque Secret formats via file auto-detection.

## Non-Features

- No multi-port or advanced routing support.
- No outbound mTLS or service discovery.
- No rate limiting, caching, or additional authentication.
- Minimal logging and metrics for simplicity (upstream is expected to provide these).

## Configuration

Configuration is via environment variables only, with sensible defaults for common setups. All vars are optional strings
unless noted.

| Variable                 | Default Value                 | Description                                                     |
|--------------------------|-------------------------------|-----------------------------------------------------------------|
| `TLS_LISTEN_PORT`        | `8443`                        | TCP port for inbound mTLS listener.                             |
| `UPSTREAM_URL`           | `http://localhost:8080`       | Full URL for the proxy target.                                  |
| `UPSTREAM_READINESS_URL` | `http://localhost:8080/ready` | URL for upstream readiness check.                               |
| `CERT_DIR`               | `/etc/certs`                  | Directory containing server cert/key files.                     |
| `CA_DIR`                 | `/etc/ca`                     | Directory containing the CA bundle file.                        |
| `INJECT_CLIENT_HEADERS`  | `false`                       | If `true`, inject `X-Client-CN` and `X-Client-Subject` headers. |
| `MONITOR_PORT`           | `8081`                        | Port for health probes and metrics.                             |
| `ENABLE_METRICS`         | `false`                       | If `true`, expose Prometheus `/metrics` on the monitor port.    |

## Deployment Assumptions

- Deployed as a Kubernetes sidecar container alongside the main application.
- Secrets are mounted as read-only volumes to `CERT_DIR` and `CA_DIR`.
- Upstream is HTTP-only, accessible via localhost.
- Runs as non-root user (UID 1000).
- Supports HTTP/1.1 and HTTP/2; TLS 1.2+ with secure ciphers.
- Certificates are PEM-encoded PKCS#1, PKCS#8, or SEC1 formats.

## Secret Handling

Mount entire Secrets to directories; the sidecar auto-detects files:

- Server cert: Prefers `tls.crt` + `tls.key`  in `CERT_DIR`; falls back to `certificate` + `private_key`.
- CA bundle: Prefers `ca-bundle.pem` or `ca.crt` in `CA_DIR`; merges `ca.crt` or `issuing_ca` if found in `CERT_DIR`.
- Ignores unused keys (e.g., `_raw`, `expiration`).

On load/reload failure, logs an error and retains the previous configuration.

## Performance and Security

- Low overhead: <50MB RAM, <5% CPU at 1k req/s.
- Graceful shutdown with 30s timeout.
- Structured JSON logging for requests, reloads, and errors.
- License: MIT.


## Building and Running

Build: `cargo build --release`.

Dockerfile (multi-stage):

```
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
```

To use in Kubernetes, mount VSO-managed Secrets and set env vars in the Deployment spec:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mtls-sidecar-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mtls-sidecar-demo
  template:
    metadata:
      labels:
        app: mtls-sidecar-demo
    spec:
      containers:
        - name: app
          image: traefik/whoami
          ports:
            - containerPort: 80
              name: http
          livenessProbe:
            httpGet:
              path: /health
              port: 80
            initialDelaySeconds: 15
            periodSeconds: 20
        - name: mtls-sidecar
          image: mtls-sidecar
          imagePullPolicy: Always
          ports:
            - containerPort: 8443
              name: https
            - containerPort: 8081
              name: mtls-monitor
          env:
            - name: RUST_LOG
              value: debug
            - name: UPSTREAM_URL
              value: "http://localhost"
            - name: UPSTREAM_READINESS_URL
              value: "http://localhost/health"
          volumeMounts:
            - name: server-tls-volume
              mountPath: /etc/certs
              readOnly: true
          readinessProbe:
            httpGet:
              path: /ready
              port: 8081
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /live
              port: 8081
            initialDelaySeconds: 15
            periodSeconds: 20
      volumes:
        - name: server-tls-volume
          secret:
            secretName: sidecar-demo-mtls
```

Test with:

```
curl --cert client.crt --key client.key https://<pod-ip>:8443/
```

## Contributing

### Development Setup

- **Rust Version**: Rust 1.90+ and Cargo are required.
- **Dependencies**: The project uses the following key dependencies (see `Cargo.toml` for full list):
  - `tokio` for async runtime.
  - `rustls` and related crates for TLS handling.
  - `hyper` and `hyper-util` for HTTP server and client.
  - `tracing` for structured logging.
  - `anyhow` for error handling.
  - `axum` for the monitoring server.
  - `notify` for file watching.
- **Development Dependencies**: For testing and development:
  - `tempfile`, `rcgen`, `time` for test certificate generation.
  - `reqwest` for integration tests (with rustls features).
  - `portpicker` for dynamic port allocation in tests.
- **Build Optimization**: Use `lto = true` and `codegen-units = 1` in `[profile.release]` for optimized builds.

### Code Style and Guidelines

- **Rust Idioms**: Follow standard Rust practices. Use `Arc<RwLock<T>>` or channels for shared state; prefer `?` for error propagation.
- **Imports**:
  - Group stdlib imports first (`use std::{...};`), then external crates, then local modules.
  - Qualify ambiguous imports (e.g., `tokio::fs`).
- **Style**:
  - Run `cargo fmt` and `cargo clippy --fix` on all code.
  - No `unsafe` code allowed.
  - Aim for high test coverage on core logic.
- **Modules**: Organize code into `src/{config, tls_manager, proxy, monitoring, watcher, http_client_like}.rs`; import with `mod name;`.

### Error Handling

- Use `anyhow::Result<T>` throughout the codebase; chain errors with `.context("Descriptive message")`.
- For non-fatal errors (e.g., reload failures), log at `tracing::warn!` or `error!` and continue with previous state.
- Fatal errors (e.g., initial config load) should exit gracefully with code 1.

### Project Structure

- `src/main.rs`: Application entry point with async runtime and signal handling.
- `src/config.rs`: Environment variable parsing and configuration struct.
- `src/tls_manager.rs`: TLS configuration loading, reloading, and server setup.
- `src/proxy.rs`: HTTP request handling and upstream forwarding.
- `src/watcher.rs`: Filesystem event monitoring for certificate updates.
- `src/monitoring.rs`: Axum-based server for health probes and metrics.
- `src/http_client_like.rs`: Trait for HTTP client abstraction.
- `tests/integration.rs`: Integration tests using reqwest and dynamic ports.
- Tests: Inline unit tests in each module with `#[cfg(test)]`.

### Testing

- **Unit Tests**: Write comprehensive unit tests for core functions, mocking external dependencies where needed.
- **Integration Tests**: Use `#[tokio::test]` in `tests/` with `reqwest` for end-to-end testing. Ensure tests use dynamic ports to avoid conflicts.
- **Running Tests**: Execute `cargo test` to run all tests. Ensure 100% coverage on critical paths.
- **CI**: Tests should pass on all supported Rust versions.

## License

MIT License. See `LICENSE` file.
