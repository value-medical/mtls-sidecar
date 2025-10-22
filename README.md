# mtls-sidecar

[![Tests](https://img.shields.io/github/actions/workflow/status/value-medical/mtls-sidecar/ci.yml?branch=main&label=Tests&logo=rust)](https://github.com/value-medical/mtls-sidecar/actions/workflows/ci.yml)
[![Docker Build](https://img.shields.io/github/actions/workflow/status/value-medical/mtls-sidecar/docker.yml?branch=main&label=Docker%20Build&logo=docker)](https://github.com/value-medical/mtls-sidecar/actions/workflows/docker.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/sebcvm/mtls-sidecar)](https://hub.docker.com/r/sebcvm/mtls-sidecar)
[![Docker Image Size](https://img.shields.io/docker/image-size/sebcvm/mtls-sidecar/latest?logo=docker)](https://hub.docker.com/r/sebcvm/mtls-sidecar)

A minimal Rust-based sidecar proxy for enforcing mutual TLS in Kubernetes pods. It terminates inbound mTLS connections,
verifies client certificates against trusted CAs, forwards validated HTTP requests to an upstream application in the
same pod, and provides an outbound mTLS forward proxy for secure external connections. The sidecar monitors mounted
certificate files for updates (e.g., from Vault Secrets Operator) and reloads TLS configuration without restarts.

## Purpose

This component provides a lightweight layer for securing HTTP services with mutual TLS, integrating seamlessly with
Kubernetes Secret mounts. It focuses on inbound mTLS termination and proxying, and also provides an outbound mTLS forward
proxy for secure outbound connections.

## Key Features

- Inbound mTLS reverse proxy
  - Accepts HTTPS requests on a dedicated port, performs client certificate verification against a CA bundle, and forwards valid requests to an upstream HTTP service.
  - Optional injection of client certificate details into upstream headers.
  - **Important**: The upstream service should listen on `localhost` only to prevent host network exposure.
- Outbound mTLS forward proxy:
  - Accepts HTTP connections on a separate port (bound to `localhost`).
  - Forwards requests for HTTPS addresses, authenticating with client certificates and verifying server identity against the CA bundle.
- Hot-reloads TLS configuration on file changes.
  - Supports both `kubernetes.io/tls` and VSO Opaque Secret formats via file auto-detection.
- Supports HTTP/1.1 and HTTP/2 proxying, enabling mTLS termination for gRPC services.
- Low overhead: <19MB RAM, <16.0% CPU at 1k req/s (avg 17.0MB RAM, peak 18.6MB RAM, avg 12.6% CPU, peak 15.3% CPU)
- Dedicated monitoring port for health probes (including server certificate expiry validation) and optional Prometheus metrics.
- Structured JSON logging for requests, reloads, and errors.
- Graceful shutdown.

## Non-Features

- No multi-port or advanced routing support.
- No service discovery.
- No rate limiting, caching, or additional authentication.
- Minimal logging and metrics for simplicity (upstream is expected to provide these).

## Configuration

Configuration is via environment variables only, with sensible defaults for common setups. All vars are optional strings
unless noted.

| `UPSTREAM_URL`           | `http://localhost:8080`       | Full URL for the proxy target.                               |
| Variable                 | Default Value           | Description                                                  |
|--------------------------|-------------------------|--------------------------------------------------------------|
| `CA_DIR`                 | `/etc/ca`               | Directory containing the CA bundle file.                     |
| `TLS_LISTEN_PORT`        | `8443`                  | TCP port for inbound mTLS listener.                          |
| `SERVER_CERT_DIR`        | `/etc/certs`            | Directory containing server certificate files.               |
| `INJECT_CLIENT_HEADERS`  | `false`                 | If `true`, inject `X-Client-TLS-Info` header.                |
| `CLIENT_CERT_DIR`        | `/etc/client-certs`     | Directory containing client certificate files.               |
| `OUTBOUND_PROXY_PORT`    | ``                      | TCP port for outbound mTLS proxy listener (empty disables).  |
| `MONITOR_PORT`           | `8081`                  | Port for health probes and metrics.                          |
| `ENABLE_METRICS`         | `false`                 | If `true`, expose Prometheus `/metrics` on the monitor port. |

## Deployment Assumptions

- Deployed as a Kubernetes sidecar container alongside the main application.
- Secrets are mounted as read-only volumes to `SERVER_CERT_DIR` and `CA_DIR`.
- Upstream is HTTP-only, accessible via localhost.
- Runs as non-root user (UID 1000).
- Supports HTTP/1.1 and HTTP/2; TLS 1.2+ with secure ciphers.
- Certificates are PEM-encoded PKCS#1, PKCS#8, or SEC1 formats.

## Secret Handling

Mount entire Secrets to directories; the sidecar auto-detects files:

- Server cert: Prefers `tls.crt` + `tls.key`  in `SERVER_CERT_DIR`; falls back to `certificate` + `private_key`.
- Client cert: Prefers `tls.crt` + `tls.key` in `CLIENT_CERT_DIR`; falls back to `certificate` + `private_key`.
- CA bundle: Prefers `ca-bundle.pem` or `ca.crt` in `CA_DIR`; merges `ca.crt` or `issuing_ca` if found in `SERVER_CERT_DIR` or `CLIENT_CERT_DIR`.
- Ignores unused keys (e.g., `_raw`, `expiration`).

On load/reload failure, logs an error and retains the previous configuration.

## Client Certificate Header Injection

When `INJECT_CLIENT_HEADERS` is set to `true`, the sidecar extracts key details from the validated client certificate during mTLS termination and injects them into the forwarded HTTP request via a single custom header: `X-Client-TLS-Info`. This provides the upstream application with lightweight, pre-parsed x509 information (e.g., subject, SANs, hash) without requiring it to handle TLS or certificate parsing. All extraction occurs in the sidecar using Rust's `rustls` and `x509-parser` crates, ensuring containment of TLS concerns.

The header value is a base64-encoded JSON object (for single-hop scenarios, which is the default in this minimal sidecar). This format avoids parsing complexities like quoting or delimiters in traditional schemes, relying only on universal base64 decoding followed by JSON parsing. The payload is compact (~200-500 bytes pre-encoding) and includes only authentication-relevant fields.

### Header Format

- **Header Name**: `X-Client-TLS-Info` (case-insensitive; value is opaque to intermediaries).
- **Value**: Base64 (standard RFC 4648) of a compact JSON string. No line breaks or extra whitespace.
- **Structure**: JSON object with string keys and values/arrays as shown below. Fields are derived directly from the client certificate's leaf (end-entity) after validation.

#### Extracted Fields

| Field        | Type          | Description                                                                 | Example Value                               |
|--------------|---------------|-----------------------------------------------------------------------------|---------------------------------------------|
| `subject`    | string        | Full distinguished name (DN) as RFC 2253 string, normalized by sidecar.     | `"CN=client.example.com,O=Acme"`            |
| `uri_sans`   | array<string> | URI subject alternative names (SANs), e.g., for SPIFFE identities.          | `["spiffe://cluster/ns/default/sa/client"]` |
| `dns_sans`   | array<string> | DNS subject alternative names (SANs).                                       | `["client.example.com"]`                    |
| `hash`       | string        | SHA-256 hex digest of the certificate DER, prefixed with `"sha256:"`.       | `"sha256:abc123def456..."`                  |
| `not_before` | string        | Issuance timestamp in ISO 8601 format.                                      | `"2025-01-01T00:00:00Z"`                    |
| `not_after`  | string        | Expiry timestamp in ISO 8601 format.                                        | `"2026-01-01T00:00:00Z"`                    |
| `serial`     | string        | Certificate serial number as hex string.                                    | `"0x1234567890abcdef"`                      |

### Upstream Examples

The format is designed for easy integration in common web service languages.
Upstream code should validate the header presence and decode/parse safely (e.g., handle missing/invalid values gracefully).
For minimal upstream examples, refer to the `examples/` directory.

- **Java** (using Spring or similar):
  ```java
  import java.util.Base64;
  import com.fasterxml.jackson.databind.ObjectMapper;
  String header = request.getHeader("X-Client-TLS-Info");
  if (header != null) {
      String jsonStr = new String(Base64.getDecoder().decode(header));
      Map<String, Object> info = new ObjectMapper().readValue(jsonStr, Map.class);
      String clientSubject = (String) info.get("subject");
      log.info("Client Subject: " + clientSubject);
  }
  ```

### Security Considerations

- **Trust Model**: Upstream should listen on `localhost` only to prevent host
 should treat the header as trusted (sidecar validates the cert), verifying `hash` against a known trust store if required.
- **Chain of Custody**: Suitable for single-hop scenarios; avoid forwarding to untrusted parties.
- **Spoofing Prevention**: The sidecar strips this header on inbound requests to prevent client tampering.

This feature unburdens upstream services while exposing just enough cert info for auth/audit.

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

## Testing

This example setup uses cert-manager and trust-manager to create test certificates and a trust bundle for mTLS testing.
A ClusterIssuer named `ca-issuer` is assumed to already exist.

1. Create a CA for server and client certs (could be separate CAs, but using one for simplicity):
   ```sh
   kubectl create -f examples/kubernetes/cert-ca.yaml
   ```
2. Create a ClusterIssuer that uses this CA:
   ```sh
   kubectl create -f examples/kubernetes/clusterissuer.yaml
   ```
3. Create a trust-manager Bundle to build a ConfigMap with the testing CA cert:
   ```sh
   kubectl create -f examples/kubernetes/bundle.yaml
   ```
4. Create a deployment that uses the sidecar:
   ```sh
   kubectl create -f examples/kubernetes/deploy.yaml
   ```
5. Create a service to expose the sidecar:
   ```sh
   kubectl create -f examples/kubernetes/svc.yaml
   ```
6. Create a test pod that uses curl to connect to the sidecar with mTLS:
   ```sh
   kubectl create -f examples/kubernetes/pod.yaml
   ```

The pod should complete successfully, indicating that the sidecar accepted the mTLS connection and forwarded the request to the upstream.

Cleanup:
```sh
kubectl delete -f examples/kubernetes/pod.yaml
kubectl delete -f examples/kubernetes/svc.yaml
kubectl delete -f examples/kubernetes/deploy.yaml
kubectl delete -f examples/kubernetes/bundle.yaml
kubectl delete -f examples/kubernetes/clusterissuer.yaml
kubectl delete -f examples/kubernetes/cert-ca.yaml
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
- Use `crate::error::DomainError` for domain-specific errors.
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