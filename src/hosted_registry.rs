use crate::config::Config;
use crate::util;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_NVR_HOSTED_SERVICE_MANIFEST: &str = "/data/constitute-nvr/hosted-service.json";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedServiceManifest {
    pub service: String,
    pub service_pk: String,
    pub device_label: String,
    pub service_version: String,
    pub host_gateway_pk: String,
    pub api_bind: String,
    pub api_base_url: String,
    pub health_url: String,
    pub camera_devices: Vec<Value>,
    pub updated_at: u64,
}

pub fn hosted_service_manifest_path() -> PathBuf {
    if let Ok(raw) = env::var("CONSTITUTE_NVR_HOSTED_SERVICE_MANIFEST") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(DEFAULT_NVR_HOSTED_SERVICE_MANIFEST)
}

pub fn persist_hosted_service_manifest(cfg: &Config) -> Result<PathBuf> {
    let path = hosted_service_manifest_path();
    let manifest = HostedServiceManifest::from_config(cfg);
    write_manifest(&path, &manifest)?;
    Ok(path)
}

fn write_manifest(path: &Path, manifest: &HostedServiceManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating hosted-service manifest dir: {}",
                parent.display()
            )
        })?;
    }
    let tmp = path.with_extension("json.tmp");
    let payload = serde_json::to_vec_pretty(manifest)
        .context("failed serializing hosted-service manifest")?;
    fs::write(&tmp, payload).with_context(|| {
        format!(
            "failed writing hosted-service manifest temp file: {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed moving hosted-service manifest into place: {}",
            path.display()
        )
    })?;
    Ok(())
}

impl HostedServiceManifest {
    pub fn from_config(cfg: &Config) -> Self {
        let api_base_url = local_base_url(&cfg.api.bind).unwrap_or_default();
        let health_url = if api_base_url.is_empty() {
            String::new()
        } else {
            format!("{api_base_url}/health")
        };
        Self {
            service: "nvr".to_string(),
            service_pk: cfg.nostr_pubkey.trim().to_string(),
            device_label: if cfg.device_label.trim().is_empty() {
                "Constitute NVR".to_string()
            } else {
                cfg.device_label.trim().to_string()
            },
            service_version: cfg.service_version.trim().to_string(),
            host_gateway_pk: cfg.gateway.host_gateway_pk.trim().to_string(),
            api_bind: cfg.api.bind.trim().to_string(),
            api_base_url,
            health_url,
            camera_devices: cfg
                .camera_devices
                .iter()
                .map(|camera| {
                    json!({
                        "sourceId": camera.source_id,
                        "name": camera.name,
                        "ptzCapable": camera.ptz_capable,
                        "enabled": camera.enabled,
                    })
                })
                .collect(),
            updated_at: util::now_unix_seconds() * 1000,
        }
    }
}

fn local_base_url(bind: &str) -> Option<String> {
    let mut raw = bind.trim().to_string();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains(':') {
        raw = format!("127.0.0.1:{raw}");
    }
    let addr: SocketAddr = raw.parse().ok()?;
    Some(format!("http://127.0.0.1:{}", addr.port()))
}
