use std::collections::HashMap;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub tls_listen_port: u16,
    pub upstream_url: String,
    pub cert_dir: String,
    pub ca_dir: String,
    pub inject_client_headers: bool,
    pub upstream_readiness_url: String,
    pub monitor_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_env_map(None)
    }

    fn from_env_map(env_map: Option<&HashMap<String, String>>) -> Self {
        let get_var = |key: &str| -> String {
            if let Some(map) = env_map {
                map.get(key).cloned()
            } else {
                env::var(key).ok()
            }
            .unwrap_or_else(|| match key {
                "TLS_LISTEN_PORT" => "8443".to_string(),
                "UPSTREAM_URL" => "http://localhost:8080".to_string(),
                "CERT_DIR" => "/etc/certs".to_string(),
                "CA_DIR" => "/etc/ca".to_string(),
                "INJECT_CLIENT_HEADERS" => "false".to_string(),
                "UPSTREAM_READINESS_URL" => "http://localhost:8080/ready".to_string(),
                "MONITOR_PORT" => "8081".to_string(),
                _ => "".to_string(),
            })
        };

        let tls_listen_port = get_var("TLS_LISTEN_PORT").parse().unwrap_or(8443);
        let upstream_url = get_var("UPSTREAM_URL");
        let upstream_readiness_url = get_var("UPSTREAM_READINESS_URL");
        let cert_dir = get_var("CERT_DIR");
        let ca_dir = get_var("CA_DIR");
        let inject_client_headers = get_var("INJECT_CLIENT_HEADERS").parse().unwrap_or(false);
        let monitor_port = get_var("MONITOR_PORT").parse().unwrap_or(8081);

        Config {
            tls_listen_port,
            upstream_url,
            cert_dir,
            ca_dir,
            inject_client_headers,
            upstream_readiness_url,
            monitor_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_defaults() {
        let env_map = HashMap::new();
        let config = Config::from_env_map(Some(&env_map));
        assert_eq!(config.tls_listen_port, 8443);
        assert_eq!(config.upstream_url, "http://localhost:8080");
        assert_eq!(config.cert_dir, "/etc/certs");
        assert_eq!(config.ca_dir, "/etc/ca");
        assert_eq!(config.inject_client_headers, false);
        assert_eq!(config.upstream_readiness_url, "http://localhost:8080/ready");
        assert_eq!(config.monitor_port, 8081);
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
        env_map.insert("CERT_DIR".to_string(), "/custom/certs".to_string());
        env_map.insert("CA_DIR".to_string(), "/custom/ca".to_string());
        env_map.insert("INJECT_CLIENT_HEADERS".to_string(), "true".to_string());

        let config = Config::from_env_map(Some(&env_map));
        assert_eq!(config.tls_listen_port, 9443);
        assert_eq!(config.upstream_url, "http://example.com:9090");
        assert_eq!(config.cert_dir, "/custom/certs");
        assert_eq!(config.ca_dir, "/custom/ca");
        assert_eq!(config.inject_client_headers, true);
        assert_eq!(
            config.upstream_readiness_url,
            "http://example.com:9090/health"
        );
        assert_eq!(config.monitor_port, 8081);
    }
}
