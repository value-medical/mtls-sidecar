use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::tls_manager::TlsManager;

fn should_watch_ca_dir(cert_dir: &str, ca_dir: &str) -> bool {
    Path::new(ca_dir).exists() && ca_dir != cert_dir
}

pub async fn start_watcher(
    cert_dir: &str,
    ca_dir: &str,
    tls_manager: Arc<TlsManager>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(100);

    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;

    watcher.watch(Path::new(cert_dir), RecursiveMode::NonRecursive)?;
    if should_watch_ca_dir(cert_dir, ca_dir) {
        watcher.watch(Path::new(ca_dir), RecursiveMode::NonRecursive)?;
    }

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => {
                if is_relevant_event(&event) {
                    tracing::info!("File changed, reloading TLS config");
                    match tls_manager.reload(cert_dir, ca_dir).await {
                        Ok(_) => {
                            tracing::info!("Reload success");
                            crate::monitoring::TLS_RELOADS_TOTAL.inc();
                        }
                        Err(e) => tracing::error!("Reload fail: {:?}", e),
                    }
                }
            }
            Err(e) => tracing::error!("Watch error: {:?}", e),
        }
    }

    Ok(())
}

fn is_relevant_event(event: &Event) -> bool {
    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
        && event.paths.iter().any(|path| {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            matches!(ext, "crt" | "key" | "pem")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_is_relevant_event() {
        let temp_dir = TempDir::new().unwrap();
        let cert_file = temp_dir.path().join("tls.crt");
        let key_file = temp_dir.path().join("tls.key");
        let pem_file = temp_dir.path().join("ca.pem");
        let irrelevant_file = temp_dir.path().join("readme.txt");

        // Create files
        fs::write(&cert_file, b"cert").unwrap();
        fs::write(&key_file, b"key").unwrap();
        fs::write(&pem_file, b"pem").unwrap();
        fs::write(&irrelevant_file, b"text").unwrap();

        // Test relevant events
        let create_cert = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![cert_file.clone()],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&create_cert));

        let modify_key = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![key_file],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&modify_key));

        let modify_pem = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![pem_file],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&modify_pem));

        // Test irrelevant event
        let modify_irrelevant = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![irrelevant_file],
            attrs: Default::default(),
        };
        assert!(!is_relevant_event(&modify_irrelevant));

        // Test non-modify event
        let remove_cert = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![cert_file],
            attrs: Default::default(),
        };
        assert!(!is_relevant_event(&remove_cert));
    }

    #[test]
    fn test_should_watch_ca_dir() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path().join("cert");
        let ca_dir_existing = temp_dir.path().join("ca");
        let ca_dir_nonexistent = temp_dir.path().join("nonexistent");

        // Create directories
        fs::create_dir(&cert_dir).unwrap();
        fs::create_dir(&ca_dir_existing).unwrap();

        // Test: ca_dir exists and is different from cert_dir
        assert!(should_watch_ca_dir(
            cert_dir.to_str().unwrap(),
            ca_dir_existing.to_str().unwrap()
        ));

        // Test: ca_dir does not exist
        assert!(!should_watch_ca_dir(
            cert_dir.to_str().unwrap(),
            ca_dir_nonexistent.to_str().unwrap()
        ));

        // Test: ca_dir is the same as cert_dir
        assert!(!should_watch_ca_dir(
            cert_dir.to_str().unwrap(),
            cert_dir.to_str().unwrap()
        ));
    }
}
