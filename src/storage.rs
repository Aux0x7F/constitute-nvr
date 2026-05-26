use crate::crypto;
use anyhow::{Context, Result, anyhow};
use constitute_protocol::{StoragePinIntent, validate_storage_pin_intent};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
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

pub fn storage_pin_intent_for_segment(
    service_pk: &str,
    source_id: &str,
    segment: &SegmentEntry,
    desired_replicas: u32,
    retention: &str,
    issued_at: u64,
) -> Result<StoragePinIntent> {
    let metadata = segment_metadata(source_id, segment);
    let manifest_hash = metadata_manifest_hash(&metadata);
    let intent = StoragePinIntent {
        intent_id: format!(
            "pin-nvr-segment-{}-{}-{issued_at}",
            record_token(source_id),
            record_token(&segment.name)
        ),
        object_refs: vec![storage_object_ref_for_manifest_hash(&manifest_hash)],
        manifest_hash,
        desired_replicas: desired_replicas.max(1),
        retention: retention_class(retention),
        authority_refs: vec![authority_ref(service_pk)],
        expires_at: None,
    };
    validate_storage_pin_intent(&intent)?;
    Ok(intent)
}

pub fn storage_pin_intent_for_history(
    service_pk: &str,
    source_id: &str,
    segments: &[SegmentEntry],
    desired_replicas: u32,
    retention: &str,
    issued_at: u64,
) -> Result<StoragePinIntent> {
    let mut object_refs = segments
        .iter()
        .map(|segment| {
            let metadata = segment_metadata(source_id, segment);
            storage_object_ref_for_manifest_hash(&metadata_manifest_hash(&metadata))
        })
        .collect::<Vec<_>>();
    let metadata = json!({
        "kind": "nvr.media.history",
        "sourceId": source_id,
        "segments": segments,
    });
    let manifest_hash = metadata_manifest_hash(&metadata);
    if object_refs.is_empty() {
        object_refs.push(storage_object_ref_for_manifest_hash(&manifest_hash));
    }
    let intent = StoragePinIntent {
        intent_id: format!("pin-nvr-history-{}-{issued_at}", record_token(source_id)),
        object_refs,
        manifest_hash,
        desired_replicas: desired_replicas.max(1),
        retention: retention_class(retention),
        authority_refs: vec![authority_ref(service_pk)],
        expires_at: None,
    };
    validate_storage_pin_intent(&intent)?;
    Ok(intent)
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

fn segment_metadata(source_id: &str, segment: &SegmentEntry) -> serde_json::Value {
    json!({
        "kind": "nvr.media.segment",
        "sourceId": source_id,
        "name": segment.name,
        "bytes": segment.bytes,
        "modifiedUnix": segment.modified_unix,
    })
}

fn storage_object_ref_for_manifest_hash(hash: &str) -> String {
    let digest = hash.trim().strip_prefix("sha256:").unwrap_or(hash.trim());
    format!("storage:object:{digest}")
}

fn metadata_manifest_hash(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn record_token(value: &str) -> String {
    let token = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let token = token.trim_matches('-');
    if token.is_empty() {
        "unknown".to_string()
    } else {
        token.to_string()
    }
}

fn authority_ref(service_pk: &str) -> String {
    let service_pk = service_pk.trim();
    if service_pk.is_empty() {
        "service:nvr".to_string()
    } else {
        format!("service:{service_pk}")
    }
}

fn retention_class(retention: &str) -> String {
    let retention = retention.trim();
    if retention.is_empty() {
        "nvr-history".to_string()
    } else {
        retention.to_string()
    }
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

    #[test]
    fn segment_and_history_outputs_create_valid_storage_pin_intents_without_media_bytes() {
        let segment = SegmentEntry {
            name: "20260508T010203.cnv".to_string(),
            bytes: 4096,
            modified_unix: 1_767_316_923,
        };

        let segment_intent = storage_pin_intent_for_segment(
            "service-pk",
            "cam-1",
            &segment,
            2,
            "nvr-retained-media",
            1_767_316_924,
        )
        .expect("segment intent");
        validate_storage_pin_intent(&segment_intent).expect("valid segment intent");
        assert_eq!(segment_intent.desired_replicas, 2);
        assert_eq!(segment_intent.object_refs.len(), 1);

        let history_intent = storage_pin_intent_for_history(
            "service-pk",
            "cam-1",
            &[segment],
            1,
            "nvr-history",
            1_767_316_925,
        )
        .expect("history intent");
        validate_storage_pin_intent(&history_intent).expect("valid history intent");

        let rendered = serde_json::to_string(&history_intent).expect("json");
        assert!(!rendered.contains("mediaBytes"));
        assert!(!rendered.contains("payloadBytes"));
        assert!(!rendered.contains("data:"));
    }
}
