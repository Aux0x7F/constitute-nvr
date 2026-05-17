use crate::config::Config;
use crate::util;
use anyhow::{Context, Result};
use constitute_protocol::{
    CAPABILITY_MEDIA_STREAM_PREVIEW, CAPABILITY_PROJECTION_DELTA_APPLY,
    CAPABILITY_PROJECTION_OBSERVE, CAPABILITY_STORAGE_PIN, CAPABILITY_STREAM_SESSION_CONTROL,
    CAPABILITY_STREAM_SESSION_OFFER,
};
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
    pub aliases: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub surface_channel: String,
    pub summary: String,
    pub nodes: Vec<Value>,
    pub retired: Value,
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
            aliases: vec!["NVR".to_string(), "Security Cameras".to_string()],
            capabilities: vec![
                CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
                CAPABILITY_STREAM_SESSION_OFFER.to_string(),
                CAPABILITY_STREAM_SESSION_CONTROL.to_string(),
                CAPABILITY_PROJECTION_OBSERVE.to_string(),
                CAPABILITY_PROJECTION_DELTA_APPLY.to_string(),
                CAPABILITY_STORAGE_PIN.to_string(),
            ],
            surface_channel: "nvr.surface".to_string(),
            summary: "Security camera inventory, live stream attach descriptors, recording state, and camera network policy.".to_string(),
            nodes: vec![
                json!({
                    "path": "cameras",
                    "nodeId": "nvr.cameras",
                    "label": "Cameras",
                    "description": "Camera inventory and source readiness.",
                    "backingChannel": "nvr.surface",
                    "capabilities": [
                        CAPABILITY_PROJECTION_OBSERVE
                    ]
                }),
                json!({
                    "path": "streams",
                    "nodeId": "nvr.streams",
                    "label": "Streams",
                    "description": "Live preview stream activation and stream status.",
                    "backingChannel": "nvr.streams",
                    "capabilities": [
                        CAPABILITY_MEDIA_STREAM_PREVIEW,
                        CAPABILITY_STREAM_SESSION_OFFER,
                        CAPABILITY_STREAM_SESSION_CONTROL,
                        CAPABILITY_PROJECTION_OBSERVE,
                        CAPABILITY_PROJECTION_DELTA_APPLY
                    ]
                }),
                json!({
                    "path": "recordings",
                    "nodeId": "nvr.recordings",
                    "label": "Recordings",
                    "description": "Recording retention and archive pin intents.",
                    "backingChannel": "nvr.surface",
                    "capabilities": [
                        CAPABILITY_STORAGE_PIN,
                        CAPABILITY_PROJECTION_OBSERVE
                    ]
                }),
                json!({
                    "path": "cameraNetwork",
                    "nodeId": "nvr.cameraNetwork",
                    "label": "Camera Network",
                    "description": "Camera subnet health and repair state.",
                    "backingChannel": "nvr.surface",
                    "capabilities": [
                        CAPABILITY_PROJECTION_OBSERVE
                    ]
                }),
                json!({
                    "path": "health",
                    "nodeId": "nvr.health",
                    "label": "Health",
                    "description": "NVR health and configured source count.",
                    "backingChannel": "nvr.surface",
                    "capabilities": [
                        CAPABILITY_PROJECTION_OBSERVE
                    ]
                }),
            ],
            retired: json!({}),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_service_manifest_omits_retired_product_routes() {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-hosted-registry-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (cfg, _) = Config::load_or_create(&path).expect("config");
        let _ = std::fs::remove_file(&path);

        let manifest = HostedServiceManifest::from_config(&cfg);
        let rendered = serde_json::to_string(&manifest).expect("manifest json");

        assert!(
            manifest
                .capabilities
                .contains(&CAPABILITY_MEDIA_STREAM_PREVIEW.to_string())
        );
        assert!(
            manifest
                .capabilities
                .contains(&CAPABILITY_STORAGE_PIN.to_string())
        );
        assert!(!rendered.contains(&format!("/{}-{}", "service", "access")));
        assert!(!rendered.contains(&format!("/{}-{}", "service", "exchange")));
        assert!(!rendered.contains(&format!("/sess{}", "ion")));
        assert!(!rendered.contains(&format!("/{}{}", "swarm", "/edge")));
    }
}
