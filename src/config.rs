use crate::nostr;
use crate::util;
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
    #[serde(default)]
    pub allow_unsigned_hello_mvp: bool,
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
    #[serde(default)]
    pub mode: UpdateMode,
    #[serde(default = "default_update_source_dir")]
    pub source_dir: String,
    #[serde(default = "default_update_branch")]
    pub branch: String,
    #[serde(default = "default_update_script")]
    pub script_path: String,
    #[serde(default)]
    pub build_user: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    #[default]
    ReleaseArtifact,
    SourceBuild,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoProvisionConfig {
    #[serde(default)]
    pub reolink_enabled: bool,
    #[serde(default = "default_reolink_username")]
    pub reolink_username: String,
    #[serde(default)]
    pub reolink_password: String,
    #[serde(default)]
    pub reolink_desired_password: String,
    #[serde(default)]
    pub reolink_generate_password: bool,
    #[serde(default = "default_reolink_discover_timeout_secs")]
    pub reolink_discover_timeout_secs: u64,
    #[serde(default)]
    pub reolink_hint_ip: String,
}

impl Default for AutoProvisionConfig {
    fn default() -> Self {
        Self {
            reolink_enabled: false,
            reolink_username: default_reolink_username(),
            reolink_password: String::new(),
            reolink_desired_password: String::new(),
            reolink_generate_password: false,
            reolink_discover_timeout_secs: default_reolink_discover_timeout_secs(),
            reolink_hint_ip: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CameraTimeMode {
    #[default]
    Ntp,
    Manual,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CameraHardeningConfig {
    #[serde(default = "default_camera_hardening_enable_onvif")]
    pub enable_onvif: bool,
    #[serde(default = "default_camera_hardening_enable_rtsp")]
    pub enable_rtsp: bool,
    #[serde(default = "default_camera_hardening_disable_p2p")]
    pub disable_p2p: bool,
    #[serde(default = "default_camera_hardening_disable_http")]
    pub disable_http: bool,
    #[serde(default = "default_camera_hardening_disable_https")]
    pub disable_https: bool,
    #[serde(default = "default_camera_hardening_preserve_proprietary_9000")]
    pub preserve_proprietary_9000: bool,
}

impl Default for CameraHardeningConfig {
    fn default() -> Self {
        Self {
            enable_onvif: default_camera_hardening_enable_onvif(),
            enable_rtsp: default_camera_hardening_enable_rtsp(),
            disable_p2p: default_camera_hardening_disable_p2p(),
            disable_http: default_camera_hardening_disable_http(),
            disable_https: default_camera_hardening_disable_https(),
            preserve_proprietary_9000: default_camera_hardening_preserve_proprietary_9000(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CameraDesiredConfig {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub time_mode: CameraTimeMode,
    #[serde(default)]
    pub ntp_server: String,
    #[serde(default)]
    pub manual_time: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub overlay_text: String,
    #[serde(default = "default_camera_overlay_timestamp")]
    pub overlay_timestamp: bool,
    #[serde(default)]
    pub desired_password: String,
    #[serde(default)]
    pub generate_password: bool,
    #[serde(default)]
    pub hardening: CameraHardeningConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraCredentialHistoryEntry {
    #[serde(default)]
    pub ts: u64,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraCredentialState {
    #[serde(default)]
    pub pending_password: String,
    #[serde(default)]
    pub pending_started_at: u64,
    #[serde(default)]
    pub last_rotation_status: String,
    #[serde(default)]
    pub last_rotation_error: String,
    #[serde(default)]
    pub history: Vec<CameraCredentialHistoryEntry>,
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
    #[serde(default)]
    pub driver_id: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub mac_address: String,
    #[serde(default)]
    pub rtsp_port: u16,
    #[serde(default)]
    pub ptz_capable: bool,
    #[serde(default = "default_camera_enabled")]
    pub enabled: bool,
    #[serde(default = "default_segment_secs")]
    pub segment_secs: u64,
    #[serde(default)]
    pub desired: CameraDesiredConfig,
    #[serde(default)]
    pub credentials: CameraCredentialState,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CameraNetworkConfig {
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub subnet_cidr: String,
    #[serde(default)]
    pub host_ip: String,
    #[serde(default)]
    pub dhcp_enabled: bool,
    #[serde(default)]
    pub dhcp_range_start: String,
    #[serde(default)]
    pub dhcp_range_end: String,
    #[serde(default = "default_camera_network_ntp_enabled")]
    pub ntp_enabled: bool,
    #[serde(default)]
    pub ntp_server: String,
    #[serde(default)]
    pub dns_server: String,
    #[serde(default = "default_camera_network_lease_file")]
    pub lease_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LivePreviewConfig {
    #[serde(default = "default_live_preview_udp_port_min")]
    pub udp_port_min: u16,
    #[serde(default = "default_live_preview_udp_port_max")]
    pub udp_port_max: u16,
}

impl Default for LivePreviewConfig {
    fn default() -> Self {
        Self {
            udp_port_min: default_live_preview_udp_port_min(),
            udp_port_max: default_live_preview_udp_port_max(),
        }
    }
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub host_gateway_pk: String,
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
    pub pair_identity_label: String,
    #[serde(default)]
    pub pair_code: String,
    #[serde(default)]
    pub pair_code_hash: String,
    #[serde(default = "default_pair_request_interval_secs")]
    pub pair_request_interval_secs: u64,
    #[serde(default = "default_pair_request_attempts")]
    pub pair_request_attempts: u32,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub ui: UiModuleConfig,
    #[serde(default)]
    pub autoprovision: AutoProvisionConfig,
    #[serde(default)]
    pub camera_network: CameraNetworkConfig,
    #[serde(default)]
    pub live_preview: LivePreviewConfig,
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

        if self.autoprovision.reolink_username.trim().is_empty() {
            self.autoprovision.reolink_username = default_reolink_username();
            changed = true;
        }

        if self.autoprovision.reolink_discover_timeout_secs == 0 {
            self.autoprovision.reolink_discover_timeout_secs =
                default_reolink_discover_timeout_secs();
            changed = true;
        }

        changed |= apply_camera_network_defaults(&mut self.camera_network);
        changed |= apply_live_preview_defaults(&mut self.live_preview);
        for camera in &mut self.cameras {
            changed |= apply_camera_defaults(camera, &self.camera_network);
        }

        if self.swarm.zones.is_empty() {
            self.swarm.zones.push(ZoneConfig {
                key: short_hex(10),
                name: "Default Zone".to_string(),
            });
            changed = true;
        }

        if self.pair_request_interval_secs == 0 {
            self.pair_request_interval_secs = default_pair_request_interval_secs();
            changed = true;
        }

        if self.pair_request_attempts == 0 {
            self.pair_request_attempts = default_pair_request_attempts();
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
                allow_unsigned_hello_mvp: false,
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
                mode: UpdateMode::default(),
                source_dir: default_update_source_dir(),
                branch: default_update_branch(),
                script_path: default_update_script(),
                build_user: String::new(),
            },
            pair_identity_label: String::new(),
            pair_code: String::new(),
            pair_code_hash: String::new(),
            pair_request_interval_secs: default_pair_request_interval_secs(),
            pair_request_attempts: default_pair_request_attempts(),
            gateway: GatewayConfig::default(),
            ui: UiModuleConfig::default(),
            autoprovision: AutoProvisionConfig::default(),
            camera_network: CameraNetworkConfig::default(),
            live_preview: LivePreviewConfig::default(),
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

fn default_camera_overlay_timestamp() -> bool {
    true
}

fn default_segment_secs() -> u64 {
    10
}

fn default_camera_hardening_enable_onvif() -> bool {
    true
}

fn default_camera_hardening_enable_rtsp() -> bool {
    true
}

fn default_camera_hardening_disable_p2p() -> bool {
    true
}

fn default_camera_hardening_disable_http() -> bool {
    false
}

fn default_camera_hardening_disable_https() -> bool {
    false
}

fn default_camera_hardening_preserve_proprietary_9000() -> bool {
    true
}

fn default_onvif_port() -> u16 {
    80
}

fn default_reolink_username() -> String {
    "admin".to_string()
}

fn default_reolink_discover_timeout_secs() -> u64 {
    3
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

fn default_live_preview_udp_port_min() -> u16 {
    41000
}

fn default_live_preview_udp_port_max() -> u16 {
    41031
}

fn apply_camera_network_defaults(cfg: &mut CameraNetworkConfig) -> bool {
    let mut changed = false;
    if cfg.lease_file.trim().is_empty() {
        cfg.lease_file = default_camera_network_lease_file();
        changed = true;
    }
    if cfg.subnet_cidr.trim().is_empty() {
        return changed;
    }

    let Some(network) = cfg.subnet_cidr.split('/').next().map(str::trim) else {
        return false;
    };
    let octets = network
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if octets.len() != 4 {
        return false;
    }

    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    if cfg.host_ip.trim().is_empty() {
        cfg.host_ip = format!("{prefix}.1");
        changed = true;
    }
    if cfg.dhcp_range_start.trim().is_empty() {
        cfg.dhcp_range_start = format!("{prefix}.50");
        changed = true;
    }
    if cfg.dhcp_range_end.trim().is_empty() {
        cfg.dhcp_range_end = format!("{prefix}.199");
        changed = true;
    }
    if cfg.dns_server.trim().is_empty() {
        cfg.dns_server = cfg.host_ip.clone();
        changed = true;
    }
    if cfg.ntp_server.trim().is_empty() {
        cfg.ntp_server = cfg.host_ip.clone();
        changed = true;
    }
    changed
}

fn default_camera_network_ntp_enabled() -> bool {
    true
}

fn default_camera_network_lease_file() -> String {
    "/var/lib/misc/dnsmasq.leases".to_string()
}

fn apply_live_preview_defaults(cfg: &mut LivePreviewConfig) -> bool {
    let mut changed = false;
    if cfg.udp_port_min == 0 {
        cfg.udp_port_min = default_live_preview_udp_port_min();
        changed = true;
    }
    if cfg.udp_port_max == 0 {
        cfg.udp_port_max = default_live_preview_udp_port_max();
        changed = true;
    }
    if cfg.udp_port_max < cfg.udp_port_min {
        cfg.udp_port_max = cfg.udp_port_min;
        changed = true;
    }
    changed
}

fn apply_camera_defaults(camera: &mut CameraConfig, network: &CameraNetworkConfig) -> bool {
    let mut changed = false;
    if camera.driver_id.trim().is_empty() {
        camera.driver_id = if camera.source_id.trim().starts_with("reolink-") {
            "reolink".to_string()
        } else {
            "generic_onvif_rtsp".to_string()
        };
        changed = true;
    }
    if camera.vendor.trim().is_empty() && camera.driver_id == "reolink" {
        camera.vendor = "Reolink".to_string();
        changed = true;
    }
    if camera.model.trim().is_empty() {
        let inferred_model = infer_camera_model(camera);
        if !inferred_model.is_empty() {
            camera.model = inferred_model;
            changed = true;
        }
    }
    if camera.rtsp_port == 0 {
        camera.rtsp_port = parse_rtsp_port(&camera.rtsp_url).unwrap_or(554);
        changed = true;
    }
    if camera.driver_id == "reolink" && !camera.ptz_capable {
        let model = camera.model.trim();
        let name = camera.name.trim();
        if model_suggests_ptz(model) || model_suggests_ptz(name) {
            camera.ptz_capable = true;
            changed = true;
        }
    }
    if camera.desired.display_name.trim().is_empty() && !camera.name.trim().is_empty() {
        camera.desired.display_name = camera.name.trim().to_string();
        changed = true;
    }
    if camera.desired.ntp_server.trim().is_empty() && !network.ntp_server.trim().is_empty() {
        camera.desired.ntp_server = network.ntp_server.trim().to_string();
        changed = true;
    }
    if camera.desired.timezone.trim().is_empty() {
        camera.desired.timezone = "UTC".to_string();
        changed = true;
    }
    if camera.desired.overlay_text.trim().is_empty() && !camera.name.trim().is_empty() {
        camera.desired.overlay_text = camera.name.trim().to_string();
        changed = true;
    }
    if camera.desired.hardening.disable_http
        && camera.desired.hardening.disable_https
        && !camera.desired.hardening.enable_onvif
    {
        camera.desired.hardening.disable_http = false;
        changed = true;
    }
    changed |= sync_camera_credential_state(camera);
    changed
}

fn infer_camera_model(camera: &CameraConfig) -> String {
    let name = camera.name.trim();
    if name.is_empty() {
        return String::new();
    }
    if camera.driver_id == "reolink" {
        let lowered = name.to_ascii_lowercase();
        if lowered.starts_with("reolink ") {
            return name["Reolink ".len()..].trim().to_string();
        }
    }
    if name == camera.source_id.trim() {
        return String::new();
    }
    name.to_string()
}

const MAX_CAMERA_CREDENTIAL_HISTORY: usize = 8;

pub fn camera_credential_candidates(camera: &CameraConfig) -> Vec<String> {
    let mut candidates = Vec::new();
    push_unique_password(&mut candidates, &camera.password);
    push_unique_password(&mut candidates, &camera.credentials.pending_password);
    for entry in &camera.credentials.history {
        push_unique_password(&mut candidates, &entry.password);
    }
    candidates
}

pub fn mark_camera_rotation_pending(
    camera: &mut CameraConfig,
    pending_password: &str,
    note: &str,
) -> bool {
    let pending_password = pending_password.trim();
    if pending_password.is_empty() {
        return false;
    }

    let mut changed = false;
    if camera.credentials.pending_password != pending_password {
        camera.credentials.pending_password = pending_password.to_string();
        changed = true;
    }
    let now = util::now_unix_seconds();
    if camera.credentials.pending_started_at != now {
        camera.credentials.pending_started_at = now;
        changed = true;
    }
    changed |= set_rotation_status(camera, "pending", "");
    changed |= record_password_history(
        camera,
        pending_password,
        "pending",
        if note.trim().is_empty() {
            "credential rotation requested"
        } else {
            note.trim()
        },
    );
    changed
}

pub fn mark_camera_rotation_failed(camera: &mut CameraConfig, error: &str) -> bool {
    let error = error.trim();
    let mut changed = set_rotation_status(camera, "failed", error);
    if !camera.credentials.pending_password.trim().is_empty() {
        let pending = camera.credentials.pending_password.clone();
        changed |= record_password_history(&mut *camera, &pending, "failed", error);
    }
    if !camera.password.trim().is_empty() {
        let current = camera.password.clone();
        changed |= ensure_password_history(
            &mut *camera,
            &current,
            "known_good",
            "current active credential",
        );
    }
    changed
}

pub fn finalize_camera_password_rotation(
    camera: &mut CameraConfig,
    active_password: &str,
    status: &str,
    note: &str,
) -> bool {
    adopt_camera_active_password(camera, active_password, status, note, true)
}

pub fn adopt_camera_active_password(
    camera: &mut CameraConfig,
    active_password: &str,
    status: &str,
    note: &str,
    clear_pending: bool,
) -> bool {
    let active_password = active_password.trim();
    if active_password.is_empty() {
        return false;
    }

    let final_status = if status.trim().is_empty() {
        "verified"
    } else {
        status.trim()
    };
    let final_note = if note.trim().is_empty() {
        "verified active credential"
    } else {
        note.trim()
    };

    let mut changed = false;
    let previous_password = camera.password.trim().to_string();
    if !previous_password.is_empty() && previous_password != active_password {
        changed |= record_password_history(
            camera,
            &previous_password,
            "previous",
            "previous active credential retained for recovery",
        );
    }
    if camera.password != active_password {
        camera.password = active_password.to_string();
        changed = true;
    }
    changed |= record_password_history(camera, active_password, final_status, final_note);
    if clear_pending {
        if !camera.credentials.pending_password.is_empty() {
            camera.credentials.pending_password.clear();
            changed = true;
        }
        if camera.credentials.pending_started_at != 0 {
            camera.credentials.pending_started_at = 0;
            changed = true;
        }
    }
    changed |= set_rotation_status(camera, final_status, "");
    changed
}

fn sync_camera_credential_state(camera: &mut CameraConfig) -> bool {
    let mut changed = false;
    if !camera.password.trim().is_empty() {
        let current = camera.password.clone();
        changed |=
            ensure_password_history(camera, &current, "known_good", "current active credential");
    }
    if !camera.credentials.pending_password.trim().is_empty() {
        let pending = camera.credentials.pending_password.clone();
        changed |=
            ensure_password_history(camera, &pending, "pending", "pending credential rotation");
    }
    if camera.credentials.pending_password.trim() == camera.password.trim()
        && !camera.credentials.pending_password.trim().is_empty()
    {
        camera.credentials.pending_password.clear();
        camera.credentials.pending_started_at = 0;
        changed = true;
    }
    if camera.credentials.history.len() > MAX_CAMERA_CREDENTIAL_HISTORY {
        camera
            .credentials
            .history
            .truncate(MAX_CAMERA_CREDENTIAL_HISTORY);
        changed = true;
    }
    changed
}

fn ensure_password_history(
    camera: &mut CameraConfig,
    password: &str,
    status: &str,
    note: &str,
) -> bool {
    let password = password.trim();
    if password.is_empty() {
        return false;
    }
    if camera
        .credentials
        .history
        .iter()
        .any(|entry| entry.password.trim() == password)
    {
        return false;
    }
    camera.credentials.history.insert(
        0,
        CameraCredentialHistoryEntry {
            ts: util::now_unix_seconds(),
            password: password.to_string(),
            status: status.trim().to_string(),
            note: note.trim().to_string(),
        },
    );
    if camera.credentials.history.len() > MAX_CAMERA_CREDENTIAL_HISTORY {
        camera
            .credentials
            .history
            .truncate(MAX_CAMERA_CREDENTIAL_HISTORY);
    }
    true
}

fn record_password_history(
    camera: &mut CameraConfig,
    password: &str,
    status: &str,
    note: &str,
) -> bool {
    let password = password.trim();
    if password.is_empty() {
        return false;
    }

    camera
        .credentials
        .history
        .retain(|entry| entry.password.trim() != password);
    camera.credentials.history.insert(
        0,
        CameraCredentialHistoryEntry {
            ts: util::now_unix_seconds(),
            password: password.to_string(),
            status: status.trim().to_string(),
            note: note.trim().to_string(),
        },
    );
    if camera.credentials.history.len() > MAX_CAMERA_CREDENTIAL_HISTORY {
        camera
            .credentials
            .history
            .truncate(MAX_CAMERA_CREDENTIAL_HISTORY);
    }
    true
}

fn set_rotation_status(camera: &mut CameraConfig, status: &str, error: &str) -> bool {
    let mut changed = false;
    let status = status.trim();
    let error = error.trim();
    if camera.credentials.last_rotation_status != status {
        camera.credentials.last_rotation_status = status.to_string();
        changed = true;
    }
    if camera.credentials.last_rotation_error != error {
        camera.credentials.last_rotation_error = error.to_string();
        changed = true;
    }
    changed
}

fn push_unique_password(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() || out.iter().any(|item| item == value) {
        return;
    }
    out.push(value.to_string());
}

fn parse_rtsp_port(rtsp_url: &str) -> Option<u16> {
    let trimmed = rtsp_url.trim();
    let marker = "://";
    let start = trimmed.find(marker)? + marker.len();
    let remainder = &trimmed[start..];
    let host_part = remainder.split('/').next().unwrap_or_default();
    let host_part = host_part.rsplit('@').next().unwrap_or(host_part);
    let port_str = host_part.rsplit_once(':')?.1.trim();
    port_str.parse::<u16>().ok()
}

fn model_suggests_ptz(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("ptz")
        || normalized.contains("track")
        || normalized.contains("e1")
        || normalized.contains("pan")
        || normalized.contains("tilt")
}

fn default_pair_request_interval_secs() -> u64 {
    15
}

fn default_pair_request_attempts() -> u32 {
    24
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

    #[test]
    fn apply_defaults_sets_pair_enrollment_defaults() {
        let mut cfg = Config::default_generated();
        cfg.pair_request_interval_secs = 0;
        cfg.pair_request_attempts = 0;
        cfg.apply_defaults();
        assert_eq!(cfg.pair_request_interval_secs, 15);
        assert_eq!(cfg.pair_request_attempts, 24);
    }

    #[test]
    fn apply_defaults_derives_camera_network_ranges() {
        let mut cfg = Config::default_generated();
        cfg.camera_network.subnet_cidr = "192.168.250.0/24".to_string();
        cfg.camera_network.host_ip.clear();
        cfg.camera_network.dhcp_range_start.clear();
        cfg.camera_network.dhcp_range_end.clear();
        cfg.apply_defaults();
        assert_eq!(cfg.camera_network.host_ip, "192.168.250.1");
        assert_eq!(cfg.camera_network.dhcp_range_start, "192.168.250.50");
        assert_eq!(cfg.camera_network.dhcp_range_end, "192.168.250.199");
    }

    #[test]
    fn apply_defaults_repairs_live_preview_port_range() {
        let mut cfg = Config::default_generated();
        cfg.live_preview.udp_port_min = 0;
        cfg.live_preview.udp_port_max = 0;
        cfg.apply_defaults();
        assert_eq!(cfg.live_preview.udp_port_min, 41000);
        assert_eq!(cfg.live_preview.udp_port_max, 41031);

        cfg.live_preview.udp_port_min = 43000;
        cfg.live_preview.udp_port_max = 42999;
        cfg.apply_defaults();
        assert_eq!(cfg.live_preview.udp_port_min, 43000);
        assert_eq!(cfg.live_preview.udp_port_max, 43000);
    }

    #[test]
    fn credential_rotation_history_retains_previous_and_pending_passwords() {
        let mut camera = CameraConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "old-secret".to_string(),
            driver_id: "reolink".to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig::default(),
            credentials: CameraCredentialState::default(),
        };

        assert!(mark_camera_rotation_pending(
            &mut camera,
            "new-secret",
            "test rotation request",
        ));
        let candidates = camera_credential_candidates(&camera);
        assert_eq!(candidates[0], "old-secret");
        assert_eq!(candidates[1], "new-secret");

        assert!(finalize_camera_password_rotation(
            &mut camera,
            "new-secret",
            "verified",
            "rotation verified",
        ));
        let candidates = camera_credential_candidates(&camera);
        assert_eq!(camera.password, "new-secret");
        assert_eq!(candidates[0], "new-secret");
        assert!(candidates.iter().any(|value| value == "old-secret"));
        assert!(camera.credentials.pending_password.is_empty());
        assert_eq!(camera.credentials.last_rotation_status, "verified");
    }

    #[test]
    fn failed_rotation_keeps_pending_candidate_for_recovery() {
        let mut camera = CameraConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "known-good".to_string(),
            driver_id: "reolink".to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig::default(),
            credentials: CameraCredentialState::default(),
        };

        mark_camera_rotation_pending(&mut camera, "candidate", "attempting rotation");
        assert!(mark_camera_rotation_failed(
            &mut camera,
            "verification failed",
        ));

        let candidates = camera_credential_candidates(&camera);
        assert_eq!(candidates[0], "known-good");
        assert!(candidates.iter().any(|value| value == "candidate"));
        assert_eq!(camera.credentials.last_rotation_status, "failed");
        assert_eq!(
            camera.credentials.last_rotation_error,
            "verification failed"
        );
    }

    #[test]
    fn apply_defaults_repairs_lockout_prone_hardening_defaults() {
        let mut cfg = Config::default_generated();
        cfg.cameras.push(CameraConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            driver_id: "reolink".to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                hardening: CameraHardeningConfig {
                    enable_onvif: false,
                    disable_http: true,
                    disable_https: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            credentials: CameraCredentialState::default(),
        });

        cfg.apply_defaults();
        assert!(!cfg.cameras[0].desired.hardening.disable_http);
        assert!(cfg.cameras[0].desired.hardening.disable_https);
    }

    #[test]
    fn apply_defaults_allows_http_and_https_disabled_when_onvif_recovery_exists() {
        let mut cfg = Config::default_generated();
        cfg.cameras.push(CameraConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            driver_id: "reolink".to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                hardening: CameraHardeningConfig {
                    enable_onvif: true,
                    disable_http: true,
                    disable_https: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            credentials: CameraCredentialState::default(),
        });

        cfg.apply_defaults();
        assert!(cfg.cameras[0].desired.hardening.disable_http);
        assert!(cfg.cameras[0].desired.hardening.disable_https);
    }

    #[test]
    fn apply_defaults_normalizes_legacy_reolink_camera_metadata() {
        let mut cfg = Config::default_generated();
        cfg.camera_network.subnet_cidr = "192.168.250.0/24".to_string();
        cfg.cameras.push(CameraConfig {
            source_id: "reolink-192-168-250-97".to_string(),
            name: "Reolink E1 Outdoor SE".to_string(),
            onvif_host: "192.168.250.97".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@192.168.250.97:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            driver_id: String::new(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 0,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig::default(),
            credentials: CameraCredentialState::default(),
        });

        cfg.apply_defaults();
        let camera = &cfg.cameras[0];
        assert_eq!(camera.driver_id, "reolink");
        assert_eq!(camera.vendor, "Reolink");
        assert_eq!(camera.model, "E1 Outdoor SE");
        assert!(camera.ptz_capable);
        assert_eq!(camera.desired.ntp_server, "192.168.250.1");
        assert_eq!(camera.desired.overlay_text, "Reolink E1 Outdoor SE");
        assert_eq!(camera.desired.display_name, "Reolink E1 Outdoor SE");
    }
}
