use crate::crypto;
use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{debug, warn};
use walkdir::WalkDir;

const MAGIC: &[u8] = b"CNRV1";

#[derive(Clone)]
pub struct StorageManager {
    root: PathBuf,
    key: Vec<u8>,
    pub last_error: Arc<RwLock<Option<String>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SegmentEntry {
    pub name: String,
    pub bytes: u64,
    pub modified_unix: u64,
}

impl StorageManager {
    pub fn new(root: PathBuf, key_hex: &str) -> Result<Self> {
        let key = crypto::parse_hex_exact(key_hex, 32)?;
        Ok(Self {
            root,
            key,
            last_error: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn ensure_dirs(&self) -> Result<()> {
        tokio::fs::create_dir_all(self.root.join("segments")).await?;
        Ok(())
    }

    pub fn start_encryptor(&self, interval_secs: u64) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs.max(2)));
            loop {
                tick.tick().await;
                if let Err(err) = this.encrypt_pending_once().await {
                    warn!(error = %err, "segment encryption pass failed");
                    *this.last_error.write().await = Some(err.to_string());
                }
            }
        });
    }

    pub async fn encrypt_pending_once(&self) -> Result<()> {
        let root = self.root.join("segments");
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || encrypt_pass(&root, &key))
            .await
            .context("join encrypt pass")??;
        Ok(())
    }

    pub async fn list_sources(&self) -> Result<Vec<String>> {
        let dir = self.root.join("segments");
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("read_dir {}", dir.display()))?;
        while let Some(entry) = rd.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                out.push(entry.file_name().to_string_lossy().to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    pub async fn list_segments(&self, source_id: &str, limit: usize) -> Result<Vec<SegmentEntry>> {
        let dir = self.root.join("segments").join(source_id);
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(err) => return Err(err.into()),
        };

        while let Some(entry) = rd.next_entry().await? {
            let file_type = entry.file_type().await?;
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !(name.ends_with(".cnv") || name.ends_with(".mp4")) {
                continue;
            }

            let md = entry.metadata().await?;
            let modified = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            out.push(SegmentEntry {
                name,
                bytes: md.len(),
                modified_unix: modified,
            });
        }

        out.sort_by(|a, b| b.modified_unix.cmp(&a.modified_unix));
        out.truncate(limit.max(1));
        Ok(out)
    }

    pub async fn read_segment(&self, source_id: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.root.join("segments").join(source_id).join(name);
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("read segment {}", path.display()))?;

        if name.ends_with(".cnv") {
            decrypt_blob(&self.key, &bytes)
        } else {
            Ok(bytes)
        }
    }
}

fn encrypt_pass(root: &Path, key: &[u8]) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("mp4") {
            continue;
        }

        let enc_path = path.with_extension("cnv");
        if enc_path.exists() {
            continue;
        }

        let raw = std::fs::read(path)
            .with_context(|| format!("read plain segment {}", path.display()))?;
        if raw.is_empty() {
            continue;
        }

        let nonce = crypto::random_nonce_24();
        let cipher = crypto::encrypt_payload(key, &nonce, &raw)?;

        let mut out = Vec::with_capacity(MAGIC.len() + nonce.len() + cipher.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&cipher);

        std::fs::write(&enc_path, out)
            .with_context(|| format!("write encrypted segment {}", enc_path.display()))?;
        std::fs::remove_file(path)
            .with_context(|| format!("remove plain segment {}", path.display()))?;
        debug!(path = %enc_path.display(), "encrypted segment");
    }

    Ok(())
}

fn decrypt_blob(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MAGIC.len() + 24 {
        return Err(anyhow!("encrypted blob too short"));
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("invalid encrypted blob magic"));
    }
    let nonce: [u8; 24] = blob[MAGIC.len()..MAGIC.len() + 24]
        .try_into()
        .map_err(|_| anyhow!("nonce decode"))?;
    let cipher = &blob[MAGIC.len() + 24..];
    crypto::decrypt_payload(key, &nonce, cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_blob_roundtrip() {
        let key = vec![42u8; 32];
        let plain = b"abc123";
        let nonce = crypto::random_nonce_24();
        let enc = crypto::encrypt_payload(&key, &nonce, plain).unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&enc);

        let dec = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(dec, plain);
    }
}
