use anyhow::{anyhow, Result};
use hyper::Uri;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub tls_listen_port: Option<u16>,
    pub upstream_url: String,
    pub ca_dir: Option<PathBuf>,
    pub server_cert_dir: Option<PathBuf>,
    pub client_cert_dir: Option<PathBuf>,
    pub inject_client_headers: bool,
    pub upstream_readiness_url: String,
    pub outbound_proxy_port: Option<u16>,
    pub monitor_port: u16,
    pub enable_metrics: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_env_map(None)
    }

    fn from_env_map(env_map: Option<&HashMap<String, String>>) -> Result<Self> {
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

        // Validate TLS_LISTEN_PORT
        let tls_listen_port_str = get_var("TLS_LISTEN_PORT");
        let tls_listen_port: Option<u16> = if tls_listen_port_str.is_empty() {
            None
        } else {
            let port: u16 = tls_listen_port_str
                .parse()
                .map_err(|_| anyhow!("Invalid TLS_LISTEN_PORT: {}", tls_listen_port_str))?;
            if port == 0 {
                return Err(anyhow!("TLS_LISTEN_PORT cannot be 0"));
            }
            Some(port)
        };

        // Validate UPSTREAM_URL
        let upstream_url_str = get_var("UPSTREAM_URL");
        let upstream_uri: Uri = upstream_url_str
            .parse()
            .map_err(|_| anyhow!("Invalid UPSTREAM_URL: {}", upstream_url_str))?;
        if upstream_uri.scheme_str() != Some("http") {
            return Err(anyhow!("UPSTREAM_URL must be HTTP"));
        }

        // Validate CA_DIR
        let ca_dir_str = get_var("CA_DIR");
        let ca_dir = if ca_dir_str.is_empty() {
            None
        } else {
            let ca_dir_path = Path::new(&ca_dir_str);
            if !ca_dir_path.exists() {
                tracing::warn!("CA_DIR does not exist: {}", ca_dir_str);
            }
            Some(ca_dir_path.to_path_buf())
        };

        // Validate SERVER_CERT_DIR
        let server_cert_dir_str = get_var("SERVER_CERT_DIR");
        let server_cert_dir = if server_cert_dir_str.is_empty() {
            None
        } else {
            let server_cert_dir_path = Path::new(&server_cert_dir_str);
            if !server_cert_dir_path.exists() {
                tracing::warn!("SERVER_CERT_DIR does not exist: {}", server_cert_dir_str);
            }
            Some(server_cert_dir_path.to_path_buf())
        };

        // Validate CLIENT_CERT_DIR
        let client_cert_dir_str = get_var("CLIENT_CERT_DIR");
        let client_cert_dir = if client_cert_dir_str.is_empty() {
            None
        } else {
            let client_cert_dir_path = Path::new(&client_cert_dir_str);
            if !client_cert_dir_path.exists() {
                tracing::warn!("CLIENT_CERT_DIR does not exist: {}", client_cert_dir_str);
            }
            Some(client_cert_dir_path.to_path_buf())
        };

        // Validate INJECT_CLIENT_HEADERS
        let inject_client_headers_str = get_var("INJECT_CLIENT_HEADERS");
        let inject_client_headers: bool = inject_client_headers_str.parse().map_err(|_| {
            anyhow!(
                "Invalid INJECT_CLIENT_HEADERS: {}",
                inject_client_headers_str
            )
        })?;

        // Validate UPSTREAM_READINESS_URL
        let upstream_readiness_url_str = get_var("UPSTREAM_READINESS_URL");
        let upstream_readiness_uri: Uri = upstream_readiness_url_str.parse().map_err(|_| {
            anyhow!(
                "Invalid UPSTREAM_READINESS_URL: {}",
                upstream_readiness_url_str
            )
        })?;
        if upstream_readiness_uri.scheme_str() != Some("http") {
            return Err(anyhow!("UPSTREAM_READINESS_URL must be HTTP"));
        }

        // Validate OUTBOUND_PROXY_PORT
        let outbound_proxy_port_str = get_var("OUTBOUND_PROXY_PORT");
        let outbound_proxy_port: Option<u16> = if outbound_proxy_port_str.is_empty() {
            None
        } else {
            let port: u16 = outbound_proxy_port_str
                .parse()
                .map_err(|_| anyhow!("Invalid OUTBOUND_PROXY_PORT: {}", outbound_proxy_port_str))?;
            if port == 0 {
                return Err(anyhow!("OUTBOUND_PROXY_PORT cannot be 0"));
            }
            Some(port)
        };


        // Validate MONITOR_PORT
        let monitor_port_str = get_var("MONITOR_PORT");
        let monitor_port: u16 = monitor_port_str
            .parse()
            .map_err(|_| anyhow!("Invalid MONITOR_PORT: {}", monitor_port_str))?;
        if monitor_port == 0 {
            tracing::warn!("MONITOR_PORT is 0, monitoring server will be disabled");
        }

        // Validate ENABLE_METRICS
        let enable_metrics_str = get_var("ENABLE_METRICS");
        let enable_metrics: bool = enable_metrics_str
            .parse()
            .map_err(|_| anyhow!("Invalid ENABLE_METRICS: {}", enable_metrics_str))?;

        Ok(Config {
            tls_listen_port,
            ca_dir,
            server_cert_dir,
            client_cert_dir,
            upstream_url: upstream_url_str,
            upstream_readiness_url: upstream_readiness_url_str,
            inject_client_headers,
            outbound_proxy_port,
            monitor_port,
            enable_metrics,
        })
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
        assert_eq!(config.upstream_url, "http://localhost:8080");
        assert_eq!(config.ca_dir.unwrap().to_str().unwrap(), "/etc/ca");
        assert_eq!(config.server_cert_dir.unwrap().to_str().unwrap(), "/etc/certs");
        assert_eq!(config.client_cert_dir.unwrap().to_str().unwrap(), "/etc/client-certs");
        assert_eq!(config.inject_client_headers, false);
        assert_eq!(config.upstream_readiness_url, "http://localhost:8080/ready");
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
        assert_eq!(config.upstream_url, "http://example.com:9090");
        assert_eq!(config.ca_dir.unwrap().to_str().unwrap(), "/custom/ca");
        assert_eq!(config.server_cert_dir.unwrap().to_str().unwrap(), "/custom/certs");
        assert_eq!(config.client_cert_dir.unwrap().to_str().unwrap(), "/etc/client-certs");
        assert_eq!(config.inject_client_headers, true);
        assert_eq!(
            config.upstream_readiness_url,
            "http://example.com:9090/health"
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
