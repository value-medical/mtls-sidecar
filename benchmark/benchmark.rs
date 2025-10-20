use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use portpicker;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair};
use reqwest::Certificate;
use std::process::{Command};
use std::time::Duration;
use tempfile::TempDir;
use time::Duration as TimeDuration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting mTLS sidecar benchmark...");
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("Failed to install rustls crypto provider");

    // Build sidecar in release mode if not already
    println!("Building sidecar in release mode...");
    let status = Command::new("cargo")
        .args(&["build", "--release"])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to build sidecar");
    }

    let mut results = Vec::new();
    let num_runs = 3;
    for run in 1..=num_runs {
        println!("Running benchmark iteration {}/{}", run, num_runs);
        let result = run_benchmark().await?;
        println!("Iteration {} completed: RAM avg {:.1}MB peak {:.1}MB, CPU avg {:.1}% peak {:.1}%",
                 run, result.avg_ram_mb, result.peak_ram_mb, result.avg_cpu, result.peak_cpu);
        results.push(result);
    }

    // Calculate averages
    let avg_ram = results.iter().map(|r| r.avg_ram_mb).sum::<f64>() / <i32 as Into<f64>>::into(num_runs);
    let peak_ram = results.iter().map(|r| r.peak_ram_mb).max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
    let avg_cpu = results.iter().map(|r| r.avg_cpu).sum::<f64>() / <i32 as Into<f64>>::into(num_runs);
    let peak_cpu = results.iter().map(|r| r.peak_cpu).max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();

    println!("\nBenchmark Results (averaged over {} runs):", num_runs);
    println!("Average RAM: {:.1} MB", avg_ram);
    println!("Peak RAM: {:.1} MB", peak_ram);
    println!("Average CPU: {:.1}%", avg_cpu);
    println!("Peak CPU: {:.1}%", peak_cpu);

    // Update README.md
    update_readme(avg_ram, peak_ram, avg_cpu, peak_cpu)?;

    Ok(())
}

struct BenchmarkResult {
    avg_ram_mb: f64,
    peak_ram_mb: f64,
    avg_cpu: f64,
    peak_cpu: f64,
}

async fn run_benchmark() -> Result<BenchmarkResult> {
    let duration_seconds = 30;

    // Pick ports
    let upstream_port = portpicker::pick_unused_port().expect("No free port");
    let sidecar_port = portpicker::pick_unused_port().expect("No free port");
    let monitor_port = portpicker::pick_unused_port().expect("No free port");

    // Generate certs
    let (ca_cert, issuer) = generate_ca();
    let (server_cert, server_key) = generate_server_cert(&issuer);
    let (client_cert, client_key) = generate_client_cert(&issuer);

    // Write certs to temp dir
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");
    let ca_dir = temp_dir.path().join("ca");
    std::fs::create_dir(&cert_dir)?;
    std::fs::create_dir(&ca_dir)?;

    std::fs::write(cert_dir.join("tls.crt"), server_cert.pem())?;
    std::fs::write(cert_dir.join("tls.key"), server_key.serialize_pem())?;
    std::fs::write(ca_dir.join("ca-bundle.crt"), ca_cert.pem())?;

    // Write client cert for hey
    let client_cert_path = temp_dir.path().join("client.crt");
    let client_key_path = temp_dir.path().join("client.key");
    std::fs::write(&client_cert_path, client_cert.pem())?;
    std::fs::write(&client_key_path, client_key.serialize_pem())?;

    // Start upstream server
    let upstream_handle = tokio::spawn(start_upstream_server(upstream_port));

    // Start sidecar as separate process
    let cert_dir_str = cert_dir.to_str().unwrap().to_string();
    let ca_dir_str = ca_dir.to_str().unwrap().to_string();
    let mut sidecar_cmd = Command::new("./target/release/mtls-sidecar")
        .env("TLS_LISTEN_PORT", sidecar_port.to_string())
        .env("UPSTREAM_URL", format!("http://127.0.0.1:{}", upstream_port))
        .env("UPSTREAM_READINESS_URL", format!("http://127.0.0.1:{}/ready", upstream_port))
        .env("SERVER_CERT_DIR", &cert_dir_str)
        .env("CA_DIR", &ca_dir_str)
        .env("INJECT_CLIENT_HEADERS", "false")
        .env("MONITOR_PORT", &monitor_port.to_string())
        .env("ENABLE_METRICS", "false")
        .spawn()?;
    let sidecar_pid = sidecar_cmd.id();

    // Wait for sidecar to be ready
    let readiness_url = format!("http://127.0.0.1:{}/ready", monitor_port);
    let client = reqwest::Client::new();
    for _ in 0..5 {  // wait up to 5 seconds
        if let Ok(resp) = client.get(&readiness_url).send().await {
            if resp.status() == 200 {
                break;
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    // Start monitoring
    let monitor_handle = tokio::spawn(monitor_process(sidecar_pid, duration_seconds));

    // Run load test for 60 seconds
    println!("Starting load test...");
    let load_test_result = run_load_test(sidecar_port, &client_cert_path, &client_key_path, &ca_dir, duration_seconds).await;
    if let Err(e) = load_test_result {
        eprintln!("Load test failed: {}", e);
    }

    // Stop monitoring
    monitor_handle.abort();

    // Stop sidecar process
    sidecar_cmd.kill()?;
    sidecar_cmd.wait()?;

    // Stop upstream server
    upstream_handle.abort();

    // Get results
    let metrics = monitor_handle.await??;

    Ok(BenchmarkResult {
        avg_ram_mb: metrics.avg_ram,
        peak_ram_mb: metrics.peak_ram,
        avg_cpu: metrics.avg_cpu,
        peak_cpu: metrics.peak_cpu,
    })
}

async fn start_upstream_server(port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let service = service_fn(|_req| async {
                Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("OK"))))
            });
            auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
    }
}

struct Metrics {
    avg_ram: f64,
    peak_ram: f64,
    avg_cpu: f64,
    peak_cpu: f64,
}

async fn monitor_process(pid: u32, duration_seconds: u32) -> Result<Metrics> {

    let mut ram_values = Vec::new();
    let mut cpu_values = Vec::new();

    for _ in 0..duration_seconds {
        let output = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "rss,%cpu"])
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let lines: Vec<&str> = stdout.lines().collect();
        if lines.len() >= 2 {
            let parts: Vec<&str> = lines[1].split_whitespace().collect();
            if parts.len() >= 2 {
                let ram_kb: f64 = parts[0].parse()?;
                let cpu: f64 = parts[1].parse()?;
                ram_values.push(ram_kb / 1024.0); // MB
                cpu_values.push(cpu);
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    let avg_ram = ram_values.iter().sum::<f64>() / ram_values.len() as f64;
    let peak_ram = ram_values.iter().cloned().fold(0.0, f64::max);
    let avg_cpu = cpu_values.iter().sum::<f64>() / cpu_values.len() as f64;
    let peak_cpu = cpu_values.iter().cloned().fold(0.0, f64::max);

    Ok(Metrics {
        avg_ram,
        peak_ram,
        avg_cpu,
        peak_cpu,
    })
}

fn generate_ca() -> (rcgen::Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test CA");
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let issuer = Issuer::new(params, key_pair);
    (cert, issuer)
}

fn generate_server_cert(
    issuer: &Issuer<KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, issuer).unwrap();
    (cert, key_pair)
}

fn generate_client_cert(
    issuer: &Issuer<KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "client");
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let (yesterday, tomorrow) = validity_period();
    params.not_before = yesterday;
    params.not_after = tomorrow;
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, &issuer).unwrap();
    (cert, key_pair)
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = TimeDuration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}

async fn run_load_test(sidecar_port: u16, client_cert_path: &std::path::Path, client_key_path: &std::path::Path, ca_dir: &std::path::Path, duration_seconds: u32) -> Result<()> {
    let ca_cert = std::fs::read(ca_dir.join("ca-bundle.crt"))?;
    let client_cert = std::fs::read(client_cert_path)?;
    let client_key = std::fs::read(client_key_path)?;

    let mut identity_pem = client_cert.clone();
    identity_pem.extend(&client_key);
    let client = reqwest::Client::builder()
        .add_root_certificate(Certificate::from_pem(&ca_cert)?)
        .identity(reqwest::Identity::from_pem(&identity_pem)?)
        .build()?;

    let url = format!("https://localhost:{}/", sidecar_port);

    // Spawn 100 concurrent clients, each sending ~10 req/s
    let num_clients = 100;
    let requests_per_second = 10;
    let mut handles = Vec::new();
    for _ in 0..num_clients {
        let client = client.clone();
        let url = url.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..(requests_per_second * duration_seconds) {
                let _ = client.get(&url).send().await;
                sleep(Duration::from_millis((1000 / requests_per_second).into())).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}

fn update_readme(avg_ram: f64, peak_ram: f64, avg_cpu: f64, peak_cpu: f64) -> Result<()> {
    let readme_path = "README.md";
    let content = std::fs::read_to_string(readme_path)?;
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let target_prefix = "- Low overhead: ";
    if let Some(index) = lines.iter().position(|line| line.starts_with(target_prefix)) {
        lines[index] = format!("- Low overhead: <{:.0}MB RAM, <{:.1}% CPU at 1k req/s (avg {:.1}MB RAM, peak {:.1}MB RAM, avg {:.1}% CPU, peak {:.1}% CPU)",
                               peak_ram.ceil(), peak_cpu.ceil(), avg_ram, peak_ram, avg_cpu, peak_cpu);
    }
    let new_content = lines.join("\n");
    std::fs::write(readme_path, new_content)?;
    println!("Updated README.md with benchmark results");
    Ok(())
}