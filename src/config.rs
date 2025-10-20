use crate::error::DomainError;
use anyhow::{Error, Result};
use hyper::Uri;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub tls_listen_port: Option<u16>,
    pub upstream_url: Option<String>,
    pub ca_dir: Option<PathBuf>,
    pub server_cert_dir: Option<PathBuf>,
    pub client_cert_dir: Option<PathBuf>,
    pub inject_client_headers: bool,
    pub upstream_readiness_url: Option<String>,
    pub outbound_proxy_port: Option<u16>,
    pub monitor_port: u16,
    pub enable_metrics: bool,
}
#[derive(Default)]
struct ConfigBuilder {
    tls_listen_port: Option<u16>,
    upstream_url: Option<String>,
    ca_dir: Option<PathBuf>,
    server_cert_dir: Option<PathBuf>,
    client_cert_dir: Option<PathBuf>,
    inject_client_headers: Option<bool>,
    upstream_readiness_url: Option<String>,
    outbound_proxy_port: Option<u16>,
    monitor_port: Option<u16>,
    enable_metrics: Option<bool>,
}

impl ConfigBuilder {
    fn tls_listen_port(mut self, val: Option<u16>) -> Self {
        self.tls_listen_port = val;
        self
    }

    fn upstream_url(mut self, val: String) -> Self {
        self.upstream_url = Some(val);
        self
    }

    fn ca_dir(mut self, val: Option<PathBuf>) -> Self {
        self.ca_dir = val;
        self
    }

    fn server_cert_dir(mut self, val: Option<PathBuf>) -> Self {
        self.server_cert_dir = val;
        self
    }

    fn client_cert_dir(mut self, val: Option<PathBuf>) -> Self {
        self.client_cert_dir = val;
        self
    }

    fn inject_client_headers(mut self, val: bool) -> Self {
        self.inject_client_headers = Some(val);
        self
    }

    fn upstream_readiness_url(mut self, val: String) -> Self {
        self.upstream_readiness_url = Some(val);
        self
    }

    fn outbound_proxy_port(mut self, val: Option<u16>) -> Self {
        self.outbound_proxy_port = val;
        self
    }

    fn monitor_port(mut self, val: u16) -> Self {
        self.monitor_port = Some(val);
        self
    }

    fn enable_metrics(mut self, val: bool) -> Self {
        self.enable_metrics = Some(val);
        self
    }

    fn build(self) -> Result<Config, Error> {
        Ok(Config {
            tls_listen_port: self.tls_listen_port,
            upstream_url: self.upstream_url,
            ca_dir: self.ca_dir,
            server_cert_dir: self.server_cert_dir,
            client_cert_dir: self.client_cert_dir,
            inject_client_headers: self.inject_client_headers.unwrap_or(false),
            upstream_readiness_url: self.upstream_readiness_url,
            outbound_proxy_port: self.outbound_proxy_port,
            monitor_port: self.monitor_port.unwrap(),
            enable_metrics: self.enable_metrics.unwrap(),
        })
    }
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Self::from_env_map(None)
    }
    fn parse_optional_port(s: &str, name: &str) -> Result<Option<u16>> {
        if s.is_empty() {
            return Ok(None);
        }
        let port: u16 = s
            .parse()
            .map_err(|_| DomainError::Config(format!("Invalid {}: {}", name, s)))?;
        if port == 0 {
            return Err(DomainError::Config(format!("{} cannot be 0", name)).into());
        }
        Ok(Some(port))
    }

    fn parse_monitor_port(s: &str) -> Result<u16> {
        let port: u16 = s
            .parse()
            .map_err(|_| DomainError::Config(format!("Invalid MONITOR_PORT: {}", s)))?;
        if port == 0 {
            tracing::warn!("MONITOR_PORT is 0, monitoring server will be disabled");
        }
        Ok(port)
    }

    fn parse_bool(s: &str, name: &str) -> Result<bool> {
        s.parse()
            .map_err(|_| DomainError::Config(format!("Invalid {}: {}", name, s)).into())
    }

    fn parse_uri(s: &str, name: &str) -> Result<String> {
        let uri: Uri = s
            .parse()
            .map_err(|_| DomainError::Config(format!("Invalid {}: {}", name, s)))?;
        if uri.scheme_str() != Some("http") {
            return Err(DomainError::Config(format!("{} must be HTTP", name)).into());
        }
        Ok(s.to_string())
    }

    fn parse_optional_path(s: &str, name: &str) -> Option<PathBuf> {
        if s.is_empty() {
            return None;
        }
        let path = Path::new(s);
        if !path.exists() {
            tracing::warn!("{} does not exist: {}", name, s);
        }
        Some(path.to_path_buf())
    }

    fn from_env_map(env_map: Option<&HashMap<String, String>>) -> Result<Self, Error> {
        let get_var = |key: &str| -> String {
            if let Some(map) = env_map {
                map.get(key).cloned()
            } else {
                env::var(key).ok()
            }
            .unwrap_or_else(|| match key {
                "TLS_LISTEN_PORT" => "8443".to_string(),
                "UPSTREAM_URL" => "http://localhost:8080".to_string(),
                "SERVER_CERT_DIR" => "/etc/certs".to_string(),
                "CA_DIR" => "/etc/ca".to_string(),
                "INJECT_CLIENT_HEADERS" => "false".to_string(),
                "UPSTREAM_READINESS_URL" => "http://localhost:8080/ready".to_string(),
                "OUTBOUND_PROXY_PORT" => "".to_string(),
                "CLIENT_CERT_DIR" => "/etc/client-certs".to_string(),
                "MONITOR_PORT" => "8081".to_string(),
                "ENABLE_METRICS" => "false".to_string(),
                _ => "".to_string(),
            })
        };

        let builder = ConfigBuilder::default()
            .tls_listen_port(Self::parse_optional_port(
                &get_var("TLS_LISTEN_PORT"),
                "TLS_LISTEN_PORT",
            )?)
            .upstream_url(Self::parse_uri(&get_var("UPSTREAM_URL"), "UPSTREAM_URL")?)
            .ca_dir(Self::parse_optional_path(&get_var("CA_DIR"), "CA_DIR"))
            .server_cert_dir(Self::parse_optional_path(
                &get_var("SERVER_CERT_DIR"),
                "SERVER_CERT_DIR",
            ))
            .client_cert_dir(Self::parse_optional_path(
                &get_var("CLIENT_CERT_DIR"),
                "CLIENT_CERT_DIR",
            ))
            .inject_client_headers(Self::parse_bool(
                &get_var("INJECT_CLIENT_HEADERS"),
                "INJECT_CLIENT_HEADERS",
            )?)
            .upstream_readiness_url(Self::parse_uri(
                &get_var("UPSTREAM_READINESS_URL"),
                "UPSTREAM_READINESS_URL",
            )?)
            .outbound_proxy_port(Self::parse_optional_port(
                &get_var("OUTBOUND_PROXY_PORT"),
                "OUTBOUND_PROXY_PORT",
            )?)
            .monitor_port(Self::parse_monitor_port(&get_var("MONITOR_PORT"))?)
            .enable_metrics(Self::parse_bool(
                &get_var("ENABLE_METRICS"),
                "ENABLE_METRICS",
            )?);

        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_defaults() {
        let env_map = HashMap::new();
        let config = Config::from_env_map(Some(&env_map)).unwrap();
        assert_eq!(config.tls_listen_port, Some(8443));
        assert_eq!(config.upstream_url, Some("http://localhost:8080".to_string()));
        assert_eq!(config.ca_dir.unwrap().to_str().unwrap(), "/etc/ca");
        assert_eq!(
            config.server_cert_dir.unwrap().to_str().unwrap(),
            "/etc/certs"
        );
        assert_eq!(
            config.client_cert_dir.unwrap().to_str().unwrap(),
            "/etc/client-certs"
        );
        assert_eq!(config.inject_client_headers, false);
        assert_eq!(config.upstream_readiness_url, Some("http://localhost:8080/ready".to_string()));
        assert_eq!(config.outbound_proxy_port, None);
        assert_eq!(config.monitor_port, 8081);
        assert_eq!(config.enable_metrics, false);
    }

    #[test]
    fn test_from_env_with_vars() {
        let mut env_map = HashMap::new();
        env_map.insert("TLS_LISTEN_PORT".to_string(), "9443".to_string());
        env_map.insert(
            "UPSTREAM_URL".to_string(),
            "http://example.com:9090".to_string(),
        );
        env_map.insert(
            "UPSTREAM_READINESS_URL".to_string(),
            "http://example.com:9090/health".to_string(),
        );
        env_map.insert("SERVER_CERT_DIR".to_string(), "/custom/certs".to_string());
        env_map.insert("CA_DIR".to_string(), "/custom/ca".to_string());
        env_map.insert("INJECT_CLIENT_HEADERS".to_string(), "true".to_string());

        let config = Config::from_env_map(Some(&env_map)).unwrap();
        assert_eq!(config.tls_listen_port, Some(9443));
        assert_eq!(config.upstream_url, Some("http://example.com:9090".to_string()));
        assert_eq!(config.ca_dir.unwrap().to_str().unwrap(), "/custom/ca");
        assert_eq!(
            config.server_cert_dir.unwrap().to_str().unwrap(),
            "/custom/certs"
        );
        assert_eq!(
            config.client_cert_dir.unwrap().to_str().unwrap(),
            "/etc/client-certs"
        );
        assert_eq!(config.inject_client_headers, true);
        assert_eq!(
            config.upstream_readiness_url,
            Some("http://example.com:9090/health".to_string())
        );
        assert_eq!(config.outbound_proxy_port, None);
        assert_eq!(config.monitor_port, 8081);
        assert_eq!(config.enable_metrics, false);
    }

    #[test]
    fn test_from_env_invalid_port() {
        let mut env_map = HashMap::new();
        env_map.insert("TLS_LISTEN_PORT".to_string(), "invalid".to_string());
        let result = Config::from_env_map(Some(&env_map));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid TLS_LISTEN_PORT"));
    }

    #[test]
    fn test_from_env_port_zero() {
        let mut env_map = HashMap::new();
        env_map.insert("TLS_LISTEN_PORT".to_string(), "0".to_string());
        let result = Config::from_env_map(Some(&env_map));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("TLS_LISTEN_PORT cannot be 0"));
    }

    #[test]
    fn test_from_env_invalid_upstream_url() {
        let mut env_map = HashMap::new();
        env_map.insert("UPSTREAM_URL".to_string(), "not-a-url".to_string());
        let result = Config::from_env_map(Some(&env_map));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UPSTREAM_URL must be HTTP"));
    }

    #[test]
    fn test_from_env_invalid_scheme() {
        let mut env_map = HashMap::new();
        env_map.insert(
            "UPSTREAM_URL".to_string(),
            "https://example.com".to_string(),
        );
        let result = Config::from_env_map(Some(&env_map));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("UPSTREAM_URL must be HTTP"));
    }

    #[test]
    fn test_from_env_invalid_bool() {
        let mut env_map = HashMap::new();
        env_map.insert("INJECT_CLIENT_HEADERS".to_string(), "maybe".to_string());
        let result = Config::from_env_map(Some(&env_map));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid INJECT_CLIENT_HEADERS"));
    }
}
