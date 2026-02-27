use crate::nostr;
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::StaticSecret;

pub const DEFAULT_STORAGE_PLACEHOLDER: &str = "/mnt/REPLACE_WITH_STORAGE_MOUNT/constitute-nvr";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub key: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmConfig {
    pub bind: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_announce_interval_secs")]
    pub announce_interval_secs: u64,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default)]
    pub endpoint_hint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiConfig {
    pub bind: String,
    #[serde(default)]
    pub public_ws_url: String,
    pub identity_id: String,
    #[serde(default)]
    pub authorized_device_pks: Vec<String>,
    pub identity_secret_hex: String,
    pub server_secret_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    pub root: String,
    pub encryption_key_hex: String,
    #[serde(default = "default_segment_encrypt_interval_secs")]
    pub encrypt_interval_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateConfig {
    #[serde(default = "default_update_enabled")]
    pub enabled: bool,
    #[serde(default = "default_update_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_update_source_dir")]
    pub source_dir: String,
    #[serde(default = "default_update_branch")]
    pub branch: String,
    #[serde(default = "default_update_script")]
    pub script_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CameraConfig {
    pub source_id: String,
    pub name: String,
    pub onvif_host: String,
    #[serde(default = "default_onvif_port")]
    pub onvif_port: u16,
    pub rtsp_url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_camera_enabled")]
    pub enabled: bool,
    #[serde(default = "default_segment_secs")]
    pub segment_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiModuleConfig {
    #[serde(default = "default_ui_repo")]
    pub repo: String,
    #[serde(rename = "ref", default = "default_ui_ref")]
    pub repo_ref: String,
    #[serde(default)]
    pub manifest_url: String,
    #[serde(default = "default_ui_entry")]
    pub entry: String,
}

impl Default for UiModuleConfig {
    fn default() -> Self {
        Self {
            repo: default_ui_repo(),
            repo_ref: default_ui_ref(),
            manifest_url: String::new(),
            entry: default_ui_entry(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub node_id: String,
    #[serde(default = "default_node_role")]
    pub node_role: String,
    #[serde(default = "default_device_label")]
    pub device_label: String,
    pub service_version: String,
    pub nostr_pubkey: String,
    pub nostr_sk_hex: String,
    pub swarm: SwarmConfig,
    pub api: ApiConfig,
    pub storage: StorageConfig,
    pub update: UpdateConfig,
    #[serde(default)]
    pub ui: UiModuleConfig,
    #[serde(default)]
    pub cameras: Vec<CameraConfig>,
}

impl Config {
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed reading config: {}", path.display()))?;
            let mut cfg: Self = serde_json::from_str(&raw).context("failed parsing config.json")?;
            let changed = cfg.apply_defaults();
            if changed {
                cfg.persist(path)?;
            }
            Ok((cfg, false))
        } else {
            let mut cfg = Self::default_generated();
            cfg.apply_defaults();
            cfg.persist(path)?;
            Ok((cfg, true))
        }
    }

    pub fn persist(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating config dir: {}", parent.display()))?;
        }
        let content = serde_json::to_string_pretty(self).context("failed serializing config")?;
        fs::write(path, content)
            .with_context(|| format!("failed writing config: {}", path.display()))?;
        Ok(())
    }

    pub fn apply_defaults(&mut self) -> bool {
        let mut changed = false;

        if self.node_id.trim().is_empty() {
            self.node_id = format!("nvr-{}", short_hex(4));
            changed = true;
        }

        if self.node_role.trim().is_empty() {
            self.node_role = default_node_role();
            changed = true;
        }

        if self.device_label.trim().is_empty() {
            self.device_label = default_device_label();
            changed = true;
        }

        if self.nostr_sk_hex.trim().is_empty() {
            let (pk, sk) = nostr::generate_keypair();
            self.nostr_pubkey = pk;
            self.nostr_sk_hex = sk;
            changed = true;
        } else if self.nostr_pubkey.trim().is_empty() {
            if let Ok(pk) = nostr::pubkey_from_sk_hex(&self.nostr_sk_hex) {
                self.nostr_pubkey = pk;
                changed = true;
            }
        }

        if self.storage.encryption_key_hex.trim().is_empty() {
            self.storage.encryption_key_hex = random_hex(32);
            changed = true;
        }

        if self.storage.root.trim().is_empty() {
            self.storage.root = DEFAULT_STORAGE_PLACEHOLDER.to_string();
            changed = true;
        }

        if self.api.identity_secret_hex.trim().is_empty() {
            self.api.identity_secret_hex = random_hex(32);
            changed = true;
        }

        if self.api.server_secret_hex.trim().is_empty() {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let _ = StaticSecret::from(bytes);
            self.api.server_secret_hex = hex::encode(bytes);
            changed = true;
        }

        if self.ui.repo.trim().is_empty() {
            self.ui.repo = default_ui_repo();
            changed = true;
        }

        if self.ui.repo_ref.trim().is_empty() {
            self.ui.repo_ref = default_ui_ref();
            changed = true;
        }

        if self.ui.entry.trim().is_empty() {
            self.ui.entry = default_ui_entry();
            changed = true;
        }

        if self.ui.manifest_url.trim().is_empty() {
            if let Some(url) = derive_manifest_url(&self.ui.repo, &self.ui.repo_ref) {
                self.ui.manifest_url = url;
                changed = true;
            }
        }

        if self.swarm.zones.is_empty() {
            self.swarm.zones.push(ZoneConfig {
                key: short_hex(10),
                name: "Default Zone".to_string(),
            });
            changed = true;
        }

        changed
    }

    pub fn storage_root(&self) -> PathBuf {
        PathBuf::from(self.storage.root.clone())
    }

    fn default_generated() -> Self {
        let (pk, sk) = nostr::generate_keypair();
        Self {
            node_id: format!("nvr-{}", short_hex(4)),
            node_role: default_node_role(),
            device_label: default_device_label(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            nostr_pubkey: pk,
            nostr_sk_hex: sk,
            swarm: SwarmConfig {
                bind: "0.0.0.0:4050".to_string(),
                peers: Vec::new(),
                announce_interval_secs: default_announce_interval_secs(),
                zones: vec![ZoneConfig {
                    key: short_hex(10),
                    name: "Default Zone".to_string(),
                }],
                endpoint_hint: String::new(),
            },
            api: ApiConfig {
                bind: "0.0.0.0:8456".to_string(),
                public_ws_url: String::new(),
                identity_id: "REPLACE_WITH_IDENTITY_ID".to_string(),
                authorized_device_pks: Vec::new(),
                identity_secret_hex: random_hex(32),
                server_secret_hex: random_hex(32),
            },
            storage: StorageConfig {
                root: DEFAULT_STORAGE_PLACEHOLDER.to_string(),
                encryption_key_hex: random_hex(32),
                encrypt_interval_secs: default_segment_encrypt_interval_secs(),
            },
            update: UpdateConfig {
                enabled: default_update_enabled(),
                interval_secs: default_update_interval_secs(),
                source_dir: default_update_source_dir(),
                branch: default_update_branch(),
                script_path: default_update_script(),
            },
            ui: UiModuleConfig::default(),
            cameras: Vec::new(),
        }
    }
}

fn default_node_role() -> String {
    "native".to_string()
}

fn default_device_label() -> String {
    "Constitute NVR".to_string()
}

fn default_announce_interval_secs() -> u64 {
    20
}

fn default_segment_encrypt_interval_secs() -> u64 {
    5
}

fn default_camera_enabled() -> bool {
    true
}

fn default_segment_secs() -> u64 {
    10
}

fn default_onvif_port() -> u16 {
    80
}

fn default_update_enabled() -> bool {
    true
}

fn default_update_interval_secs() -> u64 {
    300
}

fn default_update_source_dir() -> String {
    "/opt/constitute-nvr-src".to_string()
}

fn default_update_branch() -> String {
    "main".to_string()
}

fn default_update_script() -> String {
    "/usr/local/bin/constitute-nvr-self-update".to_string()
}

fn default_ui_repo() -> String {
    "Aux0x7F/constitute-nvr-ui".to_string()
}

fn default_ui_ref() -> String {
    "main".to_string()
}

fn default_ui_entry() -> String {
    "dist/index.html".to_string()
}

fn derive_manifest_url(repo: &str, repo_ref: &str) -> Option<String> {
    let trimmed = repo.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((owner, name)) = trimmed.split_once('/') {
        if owner.trim().is_empty() || name.trim().is_empty() {
            return None;
        }
        let reference = if repo_ref.trim().is_empty() {
            default_ui_ref()
        } else {
            repo_ref.trim().to_string()
        };
        return Some(format!(
            "https://raw.githubusercontent.com/{}/{}/{}/app.manifest.json",
            owner.trim(),
            name.trim(),
            reference
        ));
    }
    None
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn short_hex(len: usize) -> String {
    random_hex(len).chars().take(len * 2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_role() {
        let cfg = Config::default_generated();
        assert_eq!(cfg.node_role, "native");
        assert!(!cfg.nostr_pubkey.is_empty());
        assert!(!cfg.nostr_sk_hex.is_empty());
    }

    #[test]
    fn default_config_has_ui_defaults() {
        let cfg = Config::default_generated();
        assert_eq!(cfg.ui.repo, "Aux0x7F/constitute-nvr-ui");
        assert_eq!(cfg.ui.repo_ref, "main");
        assert_eq!(cfg.ui.entry, "dist/index.html");
    }

    #[test]
    fn apply_defaults_populates_keys() {
        let mut cfg = Config::default_generated();
        cfg.nostr_pubkey.clear();
        cfg.apply_defaults();
        assert!(!cfg.nostr_pubkey.is_empty());
    }

    #[test]
    fn apply_defaults_derives_manifest_url() {
        let mut cfg = Config::default_generated();
        cfg.ui.manifest_url.clear();
        cfg.apply_defaults();
        assert!(cfg.ui.manifest_url.contains("raw.githubusercontent.com"));
        assert!(cfg.ui.manifest_url.ends_with("/app.manifest.json"));
    }
}
