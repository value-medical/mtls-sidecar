use std::path::{PathBuf};
use std::sync::Arc;

use crate::config::Config;
use crate::tls_manager::TlsManager;
use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

fn should_watch_dir(dir: &PathBuf) -> bool {
    dir.try_exists().unwrap_or(false)
}

pub async fn start_watcher(config: Arc<Config>, tls_manager: Arc<TlsManager>) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(100);

    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;

    let mut watched_dirs: Vec<PathBuf> = vec![];
    if let Some(ca_dir) = &config.ca_dir {
        if should_watch_dir(ca_dir) {
            watcher.watch(ca_dir, RecursiveMode::NonRecursive)?;
            watched_dirs.push(ca_dir.clone());
        }
    }
    if let Some(server_cert_dir) = &config.server_cert_dir {
        if !watched_dirs.contains(server_cert_dir) && should_watch_dir(server_cert_dir) {
            watcher.watch(server_cert_dir, RecursiveMode::NonRecursive)?;
            watched_dirs.push(server_cert_dir.clone());
        }
    }
    if let Some(client_cert_dir) = &config.client_cert_dir {
        if !watched_dirs.contains(client_cert_dir) && should_watch_dir(client_cert_dir) {
            watcher.watch(client_cert_dir, RecursiveMode::NonRecursive)?;
            watched_dirs.push(client_cert_dir.clone());
        }
    }

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => {
                if is_relevant_event(&event) {
                    tracing::info!("File changed, reloading TLS config");
                    match tls_manager.reload(&config).await {
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
    fn test_should_watch_dir() {
        let temp_dir = TempDir::new().unwrap();
        let dir_existing = temp_dir.path().join("existing");
        let dir_nonexistent = temp_dir.path().join("nonexistent");

        // Create directory
        fs::create_dir(&dir_existing).unwrap();

        // Test: dir exists
        assert!(should_watch_dir(&dir_existing));

        // Test: dir does not exist
        assert!(!should_watch_dir(&dir_nonexistent));
    }
}
