use base64;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, SubjectAlternativeName};
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use x509_parser::prelude::*;

pub struct HeaderInjector {
    valid: bool,
    headers: Vec<(&'static str, String)>,
}

impl HeaderInjector {
    pub fn new() -> Self {
        HeaderInjector {
            valid: false,
            headers: Vec::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn inject(&self, mut builder: http::request::Builder) -> http::request::Builder {
        for (key, value) in &self.headers {
            builder = builder.header(*key, value.as_str());
        }
        builder
    }

    pub fn parse_client_cert(&mut self, cert_der: &rustls::pki_types::CertificateDer<'static>) {
        if let Ok((_, cert)) = X509Certificate::from_der(cert_der.as_ref()) {
            let subject = cert.subject().to_string();

            let mut uri_sans = Vec::new();
            let mut dns_sans = Vec::new();
            if let Some(san_ext) = cert
                .extensions()
                .iter()
                .find(|e| e.oid == OID_X509_EXT_SUBJECT_ALT_NAME)
            {
                if let Ok((_, san)) = SubjectAlternativeName::from_der(san_ext.value) {
                    for gn in &san.general_names {
                        match gn {
                            GeneralName::URI(uri) => uri_sans.push(uri.to_string()),
                            GeneralName::DNSName(dns) => dns_sans.push(dns.to_string()),
                            _ => {}
                        }
                    }
                }
            }

            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(cert_der.as_ref());
                format!("sha256:{:x}", hasher.finalize())
            };

            let not_before = cert.validity().not_before.to_string();
            let not_after = cert.validity().not_after.to_string();

            let serial = format!("0x{:x}", cert.serial);

            let json_obj = json!({
                "subject": subject,
                "uri_sans": uri_sans,
                "dns_sans": dns_sans,
                "hash": hash,
                "not_before": not_before,
                "not_after": not_after,
                "serial": serial,
            });

            let json_str = json_obj.to_string();
            let b64 = base64::engine::general_purpose::STANDARD.encode(json_str.as_bytes());

            self.valid = true;
            self.headers.push(("X-Client-TLS-Info", b64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use serde_json::Value;

    #[test]
    fn test_inject_client_headers_with_sans() {
        // Create a test certificate with DNS SANs
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&cert_der);

        assert!(inj.valid);
        let header_value = inj
            .headers
            .iter()
            .filter(|(k, _)| *k == "X-Client-TLS-Info")
            .next()
            .unwrap()
            .1
            .as_str();

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header_value)
            .unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let info: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(info["subject"], "CN=test-client, O=Test Org");
        assert!(info["dns_sans"]
            .as_array()
            .unwrap()
            .contains(&Value::String("example.com".to_string())));
        assert!(info["uri_sans"].as_array().unwrap().is_empty());
        assert!(info["hash"].as_str().unwrap().starts_with("sha256:"));
        assert!(info["serial"].as_str().unwrap().starts_with("0x"));
        assert!(info["not_before"].is_string());
        assert!(info["not_after"].is_string());
    }

    #[test]
    fn test_inject_client_headers_no_sans() {
        // Create a test certificate without SANs
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "simple-client");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&cert_der);

        assert!(inj.valid);
        let header_value = inj
            .headers
            .iter()
            .filter(|(k, _)| *k == "X-Client-TLS-Info")
            .next()
            .unwrap()
            .1
            .as_str();

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header_value)
            .unwrap();
        let json_str = String::from_utf8(decoded).unwrap();
        let info: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(info["subject"], "CN=simple-client");
        assert!(info["dns_sans"].as_array().unwrap().is_empty());
        assert!(info["uri_sans"].as_array().unwrap().is_empty());
        assert!(info["hash"].as_str().unwrap().starts_with("sha256:"));
        assert!(info["serial"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn test_inject_client_headers_invalid_cert() {
        // Test with invalid certificate data
        let invalid_der = rustls::pki_types::CertificateDer::from(vec![0, 1, 2, 3]);

        let mut inj = HeaderInjector::new();
        inj.parse_client_cert(&invalid_der);

        // Should not have the header since parsing failed
        assert!(!inj.valid);
        assert!(inj
            .headers
            .iter()
            .filter(|(k, _)| *k == "X-Client-TLS-Info")
            .next()
            .is_none());
    }

}
