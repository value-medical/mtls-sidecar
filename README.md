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

## Overall Guidelines

### Project Dependencies

Use Rust 1.90+ and Cargo. The `Cargo.toml` should define a binary crate with these dependencies:

- `tokio = { version = "1.48", features = ["full"] }` for async runtime.
- `rustls = "0.23"` and `rustls-pemfile = "2.1"` for TLS and PEM parsing.
- `tokio-rustls = "0.26"` for TLS stream handling.
- `hyper = { version = "1.7", features = ["full"] }`, `hyper-rustls = "0.27"`, and `hyper-util = { version = "0.1", features = ["tokio"] }` for HTTP and TLS integration.
- `http-body-util = "0.1"` for HTTP body utilities.
- `tracing = "0.1"` and `tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }` for structured
  logging.
- `anyhow = "1.0"` for error chaining.

For dev: `tokio-test = "0.4"`, `tempfile = "3.23"`, `rcgen = "0.13"` for test certificate generation, `time = "0.3"` for certificate validity periods, `bytes = "1.0"` for byte buffers, and `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }` for integration tests.
Excluding default features for reqwest is necessary to avoid native-tls dependencies, which conflict with rustls.

Set `[profile.release] lto = true` and `codegen-units = 1` for optimization.

### Coding Style and Imports

- Follow Rust idioms: Use `Arc<Mutex<T>>` or channels for shared state; prefer `?` for error propagation.
- Imports:
    - Group stdlib first (`use std::{...};`), then external crates, then local modules.
    - Qualify where ambiguous (e.g., `tokio::fs`).
- Style:
    - Run `cargo fmt` and `cargo clippy --fix` after each step.
    - No `unsafe`.
    - Aim for 100% test coverage on core logic.
- Modules: Organize into `src/{config, tls_manager, proxy, monitoring, watcher}.rs`; import as `mod config;`.

### Error Handling

- Use `anyhow::Result<T>` everywhere; chain with `.context("Descriptive message")`.
- On non-fatal errors (e.g., reload fail), log at `tracing::warn!` or `error!` and fallback to prior state.
- Fatal errors (e.g., initial load) panic or exit with code 1.

### Source Files

- `src/main.rs`: Entry point with async runtime.
- `src/tls_manager.rs`: TLS config loading, reloading, and server setup.
- `src/proxy.rs`: Request handling and upstream forwarding.
- `src/config.rs`: Env parsing struct and loader.
- `src/watcher.rs`: Filesystem event loop.
- `src/monitoring.rs`: Axum app for probes and metrics.
- Tests: Inline in each module with `#[cfg(test)]`.

## Step-by-Step Implementation Guide

Implement in order, building incrementally.
After each step:

- Add logging via `tracing`. Use `tracing::info!` for milestones, `error!` for failures.
- Write unit tests (e.g., mock files with `tempfile`), run `cargo test`, and verify with a local binary.
- Write integration tests in `tests/` using `#[tokio::test]` and `reqwest`.

### Step 1: mTLS Termination

Implement basic TLS server setup in `tls_manager.rs` and `main.rs`.

- Use hard-code defaults:
    - Listen on port `8443`
    - Read certs from `/etc/certs/tls.crt` + `/etc/certs/tls.key`
    - Read CA bundle from `/etc/ca/ca-bundle.pem`.
- Define a `TlsManager` struct with an `Arc<rustls::ServerConfig>` field.
- In `TlsManager::new(cert_dir: &str, ca_dir: &str)`, read and parse PEM files using `rustls-pemfile`; build a `rustls::ServerConfig` with safe
  defaults, client auth requiring verification, and a custom CA pool from the bundle.
- In `main.rs`, call `TlsManager::new("/etc/certs", "/etc/ca")`; spawn a Hyper server with `tokio_rustls::TlsAcceptor` on the hardcoded port; serve a simple echo handler that
  returns 200 OK if client cert verified.
- Add tracing: Log "TLS loaded" on init, "Client connected" on handshake (do not log cert details).
- Tests:
    - Mock dir with `tempfile`, assert config parses certs and rejects invalid PEM.
    - Integration test: Use `tokio-test` to connect with valid/invalid certs, assert 200/401.

### Step 2: Proxy to Upstream

Extend the TLS handler to forward requests. Hard-code upstream as `http://localhost:8080`.

- In `proxy.rs`, define a handler function taking a `hyper::Request` and `TlsManager` ref.
- Use a custom `TlsAcceptor` in `tls_manager.rs` that captures client certificates during the TLS handshake and stores
  them in `hyper::Request::extensions()`; extract and verify client cert from extensions; if absent or unverified,
  return 401.
- Use `hyper::Client` with a plain HTTP connector to forward the request (copy headers/body, set host from upstream).
- In `tls_manager.rs`, update the service_fn to call the proxy handler.
- Update `main.rs` to use this in the Hyper builder.
- Add tracing: Log "Proxied request" with method/path, and any 5xx errors.
- Tests:
    - Use `hyper::service::service_fn` mock client; assert forward preserves headers, injects no extras yet.
    - Integration test: Start a mock upstream server, assert requests reach it with valid certs.
    - Assert 401 on missing/invalid certs.

### Step 3: Configurability

Introduce env-based config for the core features (TLS port, upstream URL, cert/CA dirs).

- In `config.rs`, define `struct Config` with fields:
    - `tls_listen_port: u16`
    - `upstream_url: String`
    - `cert_dir: String`
    - `ca_dir: String`
- Implement `Config::from_env()` parsing vars with `std::env::var` fallbacks.
- In `main.rs`, load `Config` early; pass to `TlsManager::new()` and proxy setup; bind server to config port, parse
  upstream for client.
- Load CA pool from `CA_DIR`:
    - Look for `ca-bundle.pem` or `ca.crt`; if missing, use an empty pool.
- Auto-detect files in `CERT_DIR`:
    - Scan for preferred names (`tls.crt` + `tls.key`), fallback names (`certificate` + `private_key`).
    - Error if neither pair found.
    - If present, merge `ca.crt` or `issuing_ca` from `CERT_DIR` into CA pool.
- Fail if the CA pool is empty after loading.
- Update `TlsManager::new()` to accept `&Config` and use its fields.
- Update `main.rs` to handle errors gracefully: log and exit if config or TLS load fails.
- Update tracing: Include config values in init log.
- Tests:
    - Unit tests for `Config::from_env()` with various env setups.
    - Mock dirs for cert/CA loading, assert correct files chosen and errors on missing.
    - Integration test: Start server with different configs, assert correct port and upstream behavior.

### Step 4: Client Header Injection

- In `config.rs`, add `inject_client_headers: bool` field.
- Parse `INJECT_CLIENT_HEADERS` as bool in `Config::from_env()`.
- Pass this flag to the proxy handler.
- In proxy handler, if `inject_client_headers`, extract cert subject/CN and insert headers (`X-Client-CN`,
  `X-Client-Subject`).
- Add tracing: Log when headers are injected (do not log cert details).
- Tests:
    - Mock requests with verified certs, assert headers present/absent based on config
    - Set env vars in `#[tokio::test]`, assert parsed values and header injection.
    - Integration test: Start server with injection enabled, assert upstream receives headers.

### Step 5: File Watching

Add hot-reload capability for TLS files.

- Extend `Cargo.toml` with `notify = "8.2"` for filesystem watching.
- In `watcher.rs`, define an async `start_watcher` function taking paths and `Arc<TlsManager>`.
- Use `notify::Watcher` to monitor `cert_dir` and `ca_dir` non-recursively.
- In a loop, receive events; on write/create for relevant files (e.g., ends with `.crt`, `.key`, `.pem`), call
  `TlsManager::reload()` (re-run load logic, update `self.config` Arc).
- In `tls_manager.rs`, add `async fn reload(&self, ...)` mirroring `new()` but swapping the Arc atomically.
- In `main.rs`, spawn the watcher task after server start.
- Add tracing: Log "File changed, reloading" per event, "Reload success/fail".
- Tests:
    - Use `tempfile` dir, simulate writes with `fs::write`, assert config updates without panic.
    - Mock watcher events, assert reload called appropriately.
    - Integration test: Start server, modify cert files, assert new connections use updated certs.
    - Ensure existing connections remain unaffected during reload.

### Step 6: Health Probes

Implement liveness and readiness endpoints on a dedicated port.

- Extend `Cargo.toml` with `axum = { version = "0.8", features = ["tokio"] }` for the monitoring server routing.
- In `config.rs`, add `upstream_readiness_url: String` and `monitor_port: u16`; parse `MONITOR_PORT` with default `8081` (env var not defined or empty).
- In `monitoring.rs`, define an Axum `Router` with:
    - GET `/live` (always 200 if TLS loaded)
    - GET `/ready` (200 if TLS valid AND upstream GET to `UPSTREAM_READINESS_URL` succeeds within 1s timeout, passing
      all request headers).
- Use `hyper::Client` for the ping in `/ready`.
- In `main.rs`, after config load, spawn an async task to bind `TcpListener` on `monitor_port` and serve the Axum app;
  skip if `monitor_port` is 0.
- Ensure graceful shutdown: On main exit, signal the monitor server to stop.
- Add tracing: Log probe calls with outcome.
- Tests:
    - Spawn test server, use `reqwest` to hit endpoints, assert statuses (mock upstream for readiness).
    - Integration test: Start full server, hit probes, assert correct behavior under various states (e.g., invalid TLS).
    - Ensure probe server shuts down gracefully on main exit.

### Step 7: Metrics

Add optional Prometheus metrics on the monitoring port.

- Extend `Cargo.toml` with `prometheus = "0.14"` for metrics.
- In `config.rs`, add `enable_metrics: bool`; parse `ENABLE_METRICS` as bool (default false).
- In `main.rs`, pass this flag to the monitoring server setup.
- In `monitoring.rs`, if `config.enable_metrics`, register counters via `prometheus::register`:
    - `tls_reloads_total`
    - `mtls_failures_total`
    - `requests_total`
- Add route `/metrics` encoding to text.
- Increment counters in relevant spots:
    - Reload success (+1 to reloads)
    - Client auth fail (+1 to failures)
    - Request proxy (+1 to total)
- Add tracing: Log metric enables in init.
- Tests: Enable via config, hit `/metrics`, parse response for incremented values.
- Integration test: Start server with metrics enabled, assert `/metrics` endpoint works and shows increments.

### Step 8: Fix TLS Handshake Panic

Address the critical issue where TLS handshake failures cause the service to panic.

- Problem: In `main.rs`, `acceptor.accept(stream).await.unwrap()` panics on TLS handshake failure, crashing the service.
- Fix: Replace `unwrap()` with proper error handling. Use `match` or `if let Err(e)` to log the error at `tracing::error!` and continue the accept loop.
- Ensure the loop continues accepting new connections even after a handshake failure.
- Add tracing: Log "TLS handshake failed" with error details (avoid logging sensitive cert data).
- Tests:
    - Unit test: Mock TLS acceptor failure, assert error logged and loop continues.
    - Integration test: Attempt connection with invalid certificate, verify server remains running and accepts subsequent valid connections.

### Step 9: Implement Streaming Response Handling

Prevent memory exhaustion from large upstream responses.

- Problem: In `proxy.rs`, `resp.into_body().collect().await?.to_bytes()` loads entire response into memory, risking OOM on large responses.
- Fix: Implement streaming by forwarding the response body directly without collecting. Use `hyper::Response` with the upstream body's stream, avoiding full buffering.
- Update the return type to handle streaming bodies properly.
- Add tracing: Log response status without body content.
- Tests:
    - Unit test: Mock large response body, assert memory usage remains bounded.
    - Integration test: Send request resulting in large upstream response, verify successful proxying without excessive memory use.

### Step 10: Improve Error Handling and Validation

Enhance robustness of configuration and error propagation.

- Problem: Environment variable parsing silently defaults invalid values; missing validation for URLs/paths.
- Fix: In `config.rs`, add validation functions that return `Result` for invalid env vars, logging warnings. Validate upstream URLs are valid HTTP URLs, ports are valid, paths exist (or log warnings).
- Update `Config::from_env()` to return `Result<Config>`, propagating errors.
- In `main.rs`, handle config load failures by logging and exiting gracefully.
- Add tracing: Log validation warnings for invalid config values.
- Tests:
    - Unit tests for `Config::from_env()` with invalid env vars, assert errors returned.
    - Integration test: Start with invalid config, assert clean exit with error logs.

### Step 11: Optimize HTTP Client Usage

Improve performance by reusing HTTP connections.

- Problem: New `hyper::Client` created per request in `proxy.rs`, preventing connection reuse.
- Fix: Create a single `hyper::Client` instance in `main.rs` or `proxy.rs`, store in `Arc` if needed, and reuse across requests.
- Use `hyper_util::client::legacy::Client` with appropriate connector for connection pooling.
- Add tracing: Log client creation once.
- Tests:
    - Unit test: Assert client reused across multiple handler calls.
    - Integration test: Send multiple requests, verify connection reuse via logs or metrics.

### Step 12: Refactor Certificate Loading Logic

Eliminate code duplication in TLS manager.

- Problem: Duplicate certificate loading code between `TlsManager::new()` and `reload()`.
- Fix: Extract common logic into private helper functions like `load_certificates()`, `load_ca_bundle()`, `build_server_config()`.
- Update both `new()` and `reload()` to call these helpers.
- Ensure atomic updates in `reload()` using `Arc::new()` and `RwLock`.
- Tests:
    - Unit tests for helper functions with mock files.
    - Integration test: Trigger reload, assert config updated without duplication issues.

### Step 13: Secure Host Header Handling

Prevent host header injection vulnerabilities.

- Problem: Host header set manually in `proxy.rs` without validation, potentially allowing injection if upstream URL parsing fails.
- Fix: Properly parse upstream URL to extract host and port. Validate and construct host header safely. Handle HTTPS upstreams correctly.
- Use `hyper::Uri` parsing for robustness.
- Add tracing: Log upstream host setting.
- Tests:
    - Unit test: Various upstream URLs, assert correct host header.
    - Integration test: Proxy to HTTPS upstream, verify correct host header.

### Step 14: Support Multiple Key Formats

Extend compatibility for different private key formats.

- Problem: Only PKCS#8 keys supported in `tls_manager.rs`.
- Fix: Add support for PKCS#1 (RSA) and other formats by trying multiple parsers: `pkcs8_private_keys()`, `rsa_private_keys()`, etc.
- Update key loading to attempt different formats in order.
- Add tracing: Log key format detected.
- Tests:
    - Unit test: Load PKCS#1 key, assert success.
    - Integration test: Server with PKCS#1 key, verify TLS handshake.

### Step 15: Refine File Watcher Triggers

Reduce unnecessary reloads by being more specific.

- Problem: Watcher triggers on any `.crt/.key/.pem` file, even irrelevant ones.
- Fix: Make watched file patterns configurable or match exactly the files used (e.g., only specific filenames like `tls.crt`).
- Update `is_relevant_event()` to check exact filenames or make it configurable via env var.
- Add tracing: Log which file triggered reload.
- Tests:
    - Unit test: Events on irrelevant files, assert no reload triggered.
    - Integration test: Modify irrelevant file, verify no reload.

### Step 16: Configurable Timeouts

Allow customization of timeouts for better adaptability.

- Problem: Readiness check timeout hardcoded to 1s in `monitoring.rs`.
- Fix: Add `readiness_timeout_secs: u64` to `Config`, parse from env `READINESS_TIMEOUT_SECS` default 1.
- Update ready_handler to use configurable timeout.
- Add tracing: Log timeout value.
- Tests:
    - Unit test: Config with different timeouts, assert used.
    - Integration test: Slow upstream, verify timeout behavior.

### Step 17: Fix Test Port Conflicts

Ensure tests run reliably in parallel.

- Problem: Integration tests bind to fixed ports, causing conflicts.
- Fix: Use `portpicker` crate or find free ports dynamically in tests.
- Update `tests/integration.rs` to allocate random ports.
- Add dependency `portpicker = "0.1"` to dev-dependencies.
- Tests: Run tests in parallel, assert no port conflicts.

### Step 18: Implement Graceful Shutdown

Handle signals for clean termination.

- Problem: No signal handling, abrupt shutdown can lose requests.
- Fix: Use `tokio::signal` to listen for SIGTERM/SIGINT. On signal, stop accepting new connections, wait for in-flight requests, then exit.
- Update `main.rs` to use `tokio::select!` for signal and accept loop.
- Add tracing: Log shutdown initiated.
- Tests:
    - Integration test: Send signal, verify clean shutdown without losing requests.

### Step 19: Expand Metrics

Add more detailed observability.

- Problem: Only basic counters; missing latency, errors by type.
- Fix: Add histograms for request duration, counters for different error types (e.g., TLS errors, upstream errors).
- Update `monitoring.rs` to register additional metrics.
- Increment in relevant places.
- Tests: Assert new metrics appear and increment correctly.

### Step 20: Enhance Logging

Provide better observability.

- Problem: Minimal logging; missing client IPs, response details.
- Fix: Add structured logging for client IP (from stream), response status, request timing.
- Use `tracing` spans for requests.
- Avoid logging sensitive data.
- Tests: Assert logs contain expected fields.

### Step 21: Add Comprehensive Tests

Improve test coverage for error paths.

- Problem: Missing unit tests for error scenarios.
- Fix: Add unit tests for all error paths: invalid certs, upstream failures, config errors.
- Aim for high coverage.
- Tests: Run `cargo tarpaulin` or similar, verify coverage >90%.

### Step 22: Dependency Maintenance

Keep dependencies secure and up-to-date.

- Problem: Potential security vulnerabilities in outdated deps.
- Fix: Regularly run `cargo audit`, update dependencies in `Cargo.toml`.
- Use `cargo update` and test thoroughly.
- Add CI step for audit.
- Tests: Ensure builds pass after updates.

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
  namespace: default
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
            - containerPort: 8080
              name: http
        - name: mtls-sidecar
          image: value-medical/mtls-sidecar:v1
          ports:
            - containerPort: 8443
              name: https
            - containerPort: 8081
              name: mtls-monitor
          env:
            - name: UPSTREAM_URL
              value: "http://localhost:8080"
          volumeMounts:
            - name: server-tls-volume
              mountPath: /etc/certs
              readOnly: true
            - name: ca-volume
              mountPath: /etc/ca
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
            secretName: server-tls-secret
        - name: ca-volume
          secret:
            secretName: ca-secret
```

Test with:

```
curl --cert client.crt --key client.key https://<pod-ip>:8443/
```

## License

MIT License. See `LICENSE` file.
