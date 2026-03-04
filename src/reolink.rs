use crate::{camera, reolink_cgi, reolink_proto};
use anyhow::{Context, Result, anyhow};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::time::{Duration, Instant, sleep, timeout};

const DISCOVERY_PROBE: [u8; 4] = [0xaa, 0xaa, 0x00, 0x00];
const DHCP_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_END: u8 = 255;
const GENERATED_DEVICE_PASSWORD_LEN: usize = 24;
const DEVICE_PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkDiscovery {
    pub ip: String,
    pub mac: String,
    pub uid: String,
    pub model: String,
    pub from: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkProbe {
    pub ip: String,
    pub proprietary_port_open: bool,
    pub rtsp_port_open: bool,
    pub onvif_port_open: bool,
    pub onvif_xaddr: String,
    pub standards_ready: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkNormalPortConfig {
    pub i_surv_port_enable: i32,
    pub i_surv_port: i32,
    pub i_http_port_enable: i32,
    pub i_http_port: i32,
    pub i_https_port_enable: i32,
    pub i_https_port: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkAdvancedPortConfig {
    pub i_onvif_port_enable: i32,
    pub i_onvif_port: i32,
    pub i_rtsp_port_enable: i32,
    pub i_rtsp_port: i32,
    pub i_rtmp_port_enable: i32,
    pub i_rtmp_port: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkP2PConfig {
    pub i_enable: i32,
    pub i_port: i32,
    #[serde(default)]
    pub server_domain_name: String,
}

impl From<ReolinkNormalPortConfig> for reolink_proto::ReolinkNetNormalPort {
    fn from(value: ReolinkNormalPortConfig) -> Self {
        Self {
            surv_enabled: value.i_surv_port_enable != 0,
            surv_port: value.i_surv_port.max(0) as u32,
            http_enabled: value.i_http_port_enable != 0,
            http_port: value.i_http_port.max(0) as u32,
            https_enabled: value.i_https_port_enable != 0,
            https_port: value.i_https_port.max(0) as u32,
        }
    }
}

impl From<reolink_proto::ReolinkNetNormalPort> for ReolinkNormalPortConfig {
    fn from(value: reolink_proto::ReolinkNetNormalPort) -> Self {
        Self {
            i_surv_port_enable: i32::from(value.surv_enabled),
            i_surv_port: value.surv_port as i32,
            i_http_port_enable: i32::from(value.http_enabled),
            i_http_port: value.http_port as i32,
            i_https_port_enable: i32::from(value.https_enabled),
            i_https_port: value.https_port as i32,
        }
    }
}

impl From<ReolinkAdvancedPortConfig> for reolink_proto::ReolinkNetAdvancedPort {
    fn from(value: ReolinkAdvancedPortConfig) -> Self {
        Self {
            onvif_enabled: value.i_onvif_port_enable != 0,
            onvif_port: value.i_onvif_port.max(0) as u32,
            rtsp_enabled: value.i_rtsp_port_enable != 0,
            rtsp_port: value.i_rtsp_port.max(0) as u32,
            rtmp_enabled: value.i_rtmp_port_enable != 0,
            rtmp_port: value.i_rtmp_port.max(0) as u32,
        }
    }
}

impl From<reolink_proto::ReolinkNetAdvancedPort> for ReolinkAdvancedPortConfig {
    fn from(value: reolink_proto::ReolinkNetAdvancedPort) -> Self {
        Self {
            i_onvif_port_enable: i32::from(value.onvif_enabled),
            i_onvif_port: value.onvif_port as i32,
            i_rtsp_port_enable: i32::from(value.rtsp_enabled),
            i_rtsp_port: value.rtsp_port as i32,
            i_rtmp_port_enable: i32::from(value.rtmp_enabled),
            i_rtmp_port: value.rtmp_port as i32,
        }
    }
}

impl From<ReolinkP2PConfig> for reolink_proto::ReolinkP2PCfg {
    fn from(value: ReolinkP2PConfig) -> Self {
        Self {
            enabled: value.i_enable != 0,
            port: value.i_port.max(0) as u32,
            server_domain: value.server_domain_name,
        }
    }
}

impl From<reolink_proto::ReolinkP2PCfg> for ReolinkP2PConfig {
    fn from(value: reolink_proto::ReolinkP2PCfg) -> Self {
        Self {
            i_enable: i32::from(value.enabled),
            i_port: value.port as i32,
            server_domain_name: value.server_domain,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkSetupRequest {
    pub ip: String,
    #[serde(default = "default_reolink_username")]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub desired_password: String,
    #[serde(default)]
    pub generate_password: bool,
    #[serde(default)]
    pub normal: Option<ReolinkNormalPortConfig>,
    #[serde(default)]
    pub advanced: Option<ReolinkAdvancedPortConfig>,
    #[serde(default)]
    pub p2p: Option<ReolinkP2PConfig>,
}

impl ReolinkSetupRequest {
    pub fn normalized(mut self) -> Result<Self> {
        parse_ipv4(&self.ip).context("invalid ip")?;
        if self.username.trim().is_empty() {
            self.username = default_reolink_username();
        }
        if self.generate_password && self.desired_password.trim().is_empty() {
            self.desired_password = generate_device_password();
        }
        if self.password.trim().is_empty() && self.desired_password.trim().is_empty() {
            return Err(anyhow!(
                "either password or desired_password (or generate_password) is required"
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkConnectRequest {
    pub ip: String,
    #[serde(default = "default_reolink_username")]
    pub username: String,
    #[serde(default = "default_reolink_channel")]
    pub channel: i32,
    pub password: String,
}

impl ReolinkConnectRequest {
    pub fn normalized(mut self) -> Result<Self> {
        parse_ipv4(&self.ip).context("invalid ip")?;
        if self.username.trim().is_empty() {
            self.username = default_reolink_username();
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkStateSnapshot {
    #[serde(default)]
    pub normal: Value,
    #[serde(default)]
    pub advanced: Value,
    #[serde(default)]
    pub p2p: Value,
    #[serde(default)]
    pub auto_reboot: Value,
    #[serde(default)]
    pub ptz: Value,
    #[serde(default)]
    pub ptz_position: Value,
    #[serde(default)]
    pub presets: Value,
    #[serde(default)]
    pub cruises: Value,
    #[serde(default)]
    pub smart_track_task: Value,
    #[serde(default)]
    pub smart_track_limit: Value,
    #[serde(default)]
    pub signature_login: Value,
    #[serde(default)]
    pub user_config: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkStateResult {
    #[serde(default)]
    pub state: ReolinkStateSnapshot,
    #[serde(default)]
    pub active_password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkStateApplyRequest {
    #[serde(flatten)]
    pub connection: ReolinkConnectRequest,
    #[serde(default)]
    pub normal: Option<Value>,
    #[serde(default)]
    pub advanced: Option<Value>,
    #[serde(default)]
    pub p2p: Option<Value>,
    #[serde(default)]
    pub auto_reboot: Option<Value>,
    #[serde(default)]
    pub ptz: Option<Value>,
    #[serde(default)]
    pub ptz_position: Option<Value>,
    #[serde(default)]
    pub smart_track_task: Option<Value>,
    #[serde(default)]
    pub smart_track_limit: Option<Value>,
    #[serde(default)]
    pub signature_login: Option<Value>,
    #[serde(default)]
    pub user_config: Option<Value>,
}

impl ReolinkStateApplyRequest {
    pub fn normalized(self) -> Result<Self> {
        Ok(Self {
            connection: self.connection.normalized()?,
            normal: self.normal,
            advanced: self.advanced,
            p2p: self.p2p,
            auto_reboot: self.auto_reboot,
            ptz: self.ptz,
            ptz_position: self.ptz_position,
            smart_track_task: self.smart_track_task,
            smart_track_limit: self.smart_track_limit,
            signature_login: self.signature_login,
            user_config: self.user_config,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkStateApplyResult {
    #[serde(default)]
    pub before: ReolinkStateSnapshot,
    #[serde(default)]
    pub after: ReolinkStateSnapshot,
    #[serde(default)]
    pub active_password: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkSetupBridgeResult {
    pub ip: String,
    pub username: String,
    pub before_normal: ReolinkNormalPortConfig,
    pub before_advanced: ReolinkAdvancedPortConfig,
    pub before_p2p: ReolinkP2PConfig,
    pub after_normal: ReolinkNormalPortConfig,
    pub after_advanced: ReolinkAdvancedPortConfig,
    pub after_p2p: ReolinkP2PConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkSetupResult {
    pub bridge: ReolinkSetupBridgeResult,
    pub probe: ReolinkProbe,
    #[serde(default)]
    pub generated_password: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReolinkPasswordRecoveryNote {
    ip: String,
    username: String,
    desired_password: String,
    generated: bool,
    note: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkBootstrapRequest {
    pub server_ip: String,
    pub lease_ip: String,
    #[serde(default)]
    pub target_mac: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_subnet_mask")]
    pub subnet_mask: String,
    #[serde(default)]
    pub router_ip: String,
    #[serde(default)]
    pub dns_ip: String,
}

impl ReolinkBootstrapRequest {
    pub fn normalized(mut self) -> Result<Self> {
        parse_ipv4(&self.server_ip).context("invalid server_ip")?;
        parse_ipv4(&self.lease_ip).context("invalid lease_ip")?;
        parse_ipv4(&self.subnet_mask).context("invalid subnet_mask")?;

        if self.router_ip.trim().is_empty() {
            self.router_ip = self.server_ip.clone();
        } else {
            parse_ipv4(&self.router_ip).context("invalid router_ip")?;
        }

        if self.dns_ip.trim().is_empty() {
            self.dns_ip = self.server_ip.clone();
        } else {
            parse_ipv4(&self.dns_ip).context("invalid dns_ip")?;
        }

        if self.timeout_secs == 0 {
            self.timeout_secs = default_timeout_secs();
        }

        if !self.target_mac.trim().is_empty() {
            normalize_mac(&self.target_mac).context("invalid target_mac")?;
        }

        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkBootstrapResult {
    pub lease_acked: bool,
    pub assigned_ip: String,
    pub target_mac: String,
    pub discovered: Vec<ReolinkDiscovery>,
    pub probe: ReolinkProbe,
}

#[derive(Clone, Debug)]
struct DhcpLeaseAck {
    assigned_ip: String,
    target_mac: String,
}

pub async fn discover(timeout_secs: u64) -> Result<Vec<ReolinkDiscovery>> {
    discover_on_targets(
        &[SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 2000)],
        timeout_secs,
    )
    .await
}

pub async fn discover_with_hint(hint_ip: &str, timeout_secs: u64) -> Result<Vec<ReolinkDiscovery>> {
    let mut targets = vec![SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 2000)];
    let hinted = SocketAddrV4::new(broadcast_ip(hint_ip)?, 2000);
    if !targets.contains(&hinted) {
        targets.push(hinted);
    }
    discover_on_targets(&targets, timeout_secs).await
}

async fn discover_on_targets(
    targets: &[SocketAddrV4],
    timeout_secs: u64,
) -> Result<Vec<ReolinkDiscovery>> {
    let socket = UdpSocket::bind("0.0.0.0:3000")
        .await
        .context("failed binding Reolink discovery socket to udp/3000")?;
    socket
        .set_broadcast(true)
        .context("failed enabling UDP broadcast on discovery socket")?;
    for target in targets {
        socket
            .send_to(&DISCOVERY_PROBE, *target)
            .await
            .with_context(|| format!("failed sending Reolink discovery probe to {}", target))?;
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::<ReolinkDiscovery>::new();

    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }

        let recv = timeout(remain, socket.recv_from(&mut buf)).await;
        let Ok(Ok((len, from))) = recv else {
            break;
        };

        if len == 0 {
            continue;
        }

        let device = parse_discovery_payload(&buf[..len], from.to_string());
        if device.ip.is_empty() && device.mac.is_empty() && device.uid.is_empty() {
            continue;
        }

        if !out
            .iter()
            .any(|existing| existing.ip == device.ip && existing.mac == device.mac)
        {
            out.push(device);
        }
    }

    out.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
    Ok(out)
}

pub async fn probe(ip: &str, timeout_secs: u64) -> Result<ReolinkProbe> {
    let target = parse_ipv4(ip).context("invalid probe ip")?;
    let timeout_secs = timeout_secs.max(1);
    let proprietary_port_open = tcp_open(target, 9000, timeout_secs).await;
    let rtsp_port_open = tcp_open(target, 554, timeout_secs).await;
    let onvif_port_open = tcp_open(target, 8000, timeout_secs).await;

    let onvif_xaddr = if onvif_port_open {
        let expected = format!("http://{}:8000/onvif/device_service", target);
        let discovered = camera::discover_onvif(timeout_secs.min(3))
            .await
            .unwrap_or_default();
        discovered
            .into_iter()
            .find(|entry| entry.endpoint.contains(&target.to_string()))
            .map(|entry| entry.endpoint)
            .unwrap_or(expected)
    } else {
        String::new()
    };

    Ok(ReolinkProbe {
        ip: target.to_string(),
        proprietary_port_open,
        rtsp_port_open,
        onvif_port_open,
        standards_ready: rtsp_port_open && onvif_port_open,
        onvif_xaddr,
    })
}

pub async fn setup(request: ReolinkSetupRequest) -> Result<ReolinkSetupResult> {
    let request = request.normalized()?;
    let generated_password = if request.generate_password {
        request.desired_password.clone()
    } else {
        String::new()
    };
    let recovery_path = if should_persist_recovery_note(&request) {
        Some(write_password_recovery_note(&request).await?)
    } else {
        None
    };

    let bridge_result = if sdk_bridge_available() {
        setup_via_sdk_bridge(&request)
            .await
            .context("Reolink proprietary 9000 setup failed")
    } else {
        reolink_cgi::setup(&request).await
    };

    let bridge = match bridge_result {
        Ok(bridge) => {
            if let Some(path) = &recovery_path {
                let _ = fs::remove_file(path).await;
            }
            bridge
        }
        Err(err) => {
            if let Some(path) = &recovery_path {
                return Err(err.context(format!(
                    "camera password may already have changed; recovery note: {}; desired password: {}",
                    path.display(), request.desired_password
                )));
            }
            return Err(err);
        }
    };

    let probe = probe(&request.ip, 3).await?;
    Ok(ReolinkSetupResult {
        bridge,
        probe,
        generated_password,
    })
}

fn sdk_bridge_script_path() -> PathBuf {
    if let Ok(raw) = env::var("CONSTITUTE_REOLINK_BRIDGE") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.ancestors().nth(2) {
        return workspace_root
            .join("reolink-rev-eng")
            .join("reolink-sdk-bridge.cjs");
    }

    manifest_dir
        .join("..")
        .join("..")
        .join("reolink-rev-eng")
        .join("reolink-sdk-bridge.cjs")
}

fn should_persist_recovery_note(request: &ReolinkSetupRequest) -> bool {
    !request.desired_password.trim().is_empty() && request.desired_password != request.password
}

fn password_recovery_note_path(ip: &str) -> PathBuf {
    let safe_ip = ip
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    env::temp_dir().join(format!("constitute-nvr-reolink-recovery-{safe_ip}.json"))
}

async fn write_password_recovery_note(request: &ReolinkSetupRequest) -> Result<PathBuf> {
    let note = ReolinkPasswordRecoveryNote {
        ip: request.ip.clone(),
        username: request.username.clone(),
        desired_password: request.desired_password.clone(),
        generated: request.generate_password,
        note: "Delete this file after you confirm the camera is reachable with the desired password.",
    };
    let path = password_recovery_note_path(&request.ip);
    let bytes =
        serde_json::to_vec_pretty(&note).context("failed encoding password recovery note")?;
    fs::write(&path, bytes)
        .await
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(path)
}

fn sdk_bridge_available() -> bool {
    cfg!(target_os = "windows") && sdk_bridge_script_path().exists()
}

pub async fn read_state(request: ReolinkConnectRequest) -> Result<ReolinkStateResult> {
    let request = request.normalized()?;
    if sdk_bridge_available() {
        let value = run_sdk_bridge_value(json!({
            "action": "state",
            "ip": request.ip,
            "username": request.username,
            "password": request.password,
        }))
        .await?;

        return serde_json::from_value(value).context("failed decoding Reolink runtime state");
    }

    reolink_cgi::read_state(&request).await
}

pub async fn apply_state(request: ReolinkStateApplyRequest) -> Result<ReolinkStateApplyResult> {
    let request = request.normalized()?;
    if sdk_bridge_available() {
        let value = run_sdk_bridge_value(json!({
            "action": "apply",
            "ip": request.connection.ip,
            "username": request.connection.username,
            "channel": request.connection.channel,
            "password": request.connection.password,
            "normal": request.normal,
            "advanced": request.advanced,
            "p2p": request.p2p,
            "autoReboot": request.auto_reboot,
            "ptz": request.ptz,
            "ptzPosition": request.ptz_position,
            "smartTrackTask": request.smart_track_task,
            "smartTrackLimit": request.smart_track_limit,
            "signatureLogin": request.signature_login,
            "userConfig": request.user_config,
        }))
        .await?;

        return serde_json::from_value(value)
            .context("failed decoding Reolink runtime state update");
    }

    reolink_cgi::apply_state(&request).await
}

async fn setup_via_sdk_bridge(request: &ReolinkSetupRequest) -> Result<ReolinkSetupBridgeResult> {
    let value = run_sdk_bridge_value(json!({
        "action": "setup",
        "ip": request.ip,
        "username": request.username,
        "password": request.password,
        "desiredPassword": request.desired_password,
        "normal": request.normal,
        "advanced": request.advanced,
        "p2p": request.p2p,
    }))
    .await?;

    serde_json::from_value(value).context("failed decoding Reolink SDK bridge result")
}

async fn run_sdk_bridge_value(payload: Value) -> Result<Value> {
    let script = sdk_bridge_script_path();
    if !script.exists() {
        return Err(anyhow!(
            "Reolink SDK bridge script not found at {}",
            script.display()
        ));
    }

    let response_path = env::temp_dir().join(format!(
        "constitute-nvr-reolink-bridge-{}.json",
        rand::thread_rng().r#gen::<u64>()
    ));

    let mut child = Command::new("node")
        .arg(&script)
        .arg(&response_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed spawning node for {}", script.display()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(
                &serde_json::to_vec(&payload).context("failed encoding Reolink bridge request")?,
            )
            .await
            .context("failed writing request to Reolink SDK bridge")?;
    } else {
        return Err(anyhow!("failed opening stdin for Reolink SDK bridge"));
    }

    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for Reolink SDK bridge")?;

    let raw = fs::read(&response_path)
        .await
        .with_context(|| format!("failed reading {}", response_path.display()))?;
    let _ = fs::remove_file(&response_path).await;

    let value: Value =
        serde_json::from_slice(&raw).context("failed parsing Reolink SDK bridge response")?;
    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !output.status.success() || !ok {
        let bridge_error = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown Reolink SDK bridge error");
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(anyhow!(bridge_error.to_string()));
        }
        return Err(anyhow!(format!("{bridge_error}; {stderr}")));
    }

    Ok(value)
}

pub async fn bootstrap(request: ReolinkBootstrapRequest) -> Result<ReolinkBootstrapResult> {
    let request = request.normalized()?;
    let ack = run_dhcp_bootstrap(&request).await?;

    sleep(Duration::from_millis(750)).await;

    let discovered = discover_with_hint(&request.lease_ip, 3)
        .await
        .unwrap_or_default();
    let probe = probe(&ack.assigned_ip, 3).await?;

    Ok(ReolinkBootstrapResult {
        lease_acked: true,
        assigned_ip: ack.assigned_ip,
        target_mac: ack.target_mac,
        discovered,
        probe,
    })
}

async fn run_dhcp_bootstrap(request: &ReolinkBootstrapRequest) -> Result<DhcpLeaseAck> {
    let bind = format!("{}:67", request.server_ip);
    let socket = UdpSocket::bind(&bind)
        .await
        .with_context(|| format!("failed binding DHCP responder on {}", bind))?;
    socket
        .set_broadcast(true)
        .context("failed enabling UDP broadcast on DHCP socket")?;

    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(request.timeout_secs.max(1));
    let target_mac = if request.target_mac.trim().is_empty() {
        None
    } else {
        Some(normalize_mac(&request.target_mac)?)
    };
    let lease_ip = parse_ipv4(&request.lease_ip)?;
    let server_ip = parse_ipv4(&request.server_ip)?;
    let subnet_mask = parse_ipv4(&request.subnet_mask)?;
    let router_ip = parse_ipv4(&request.router_ip)?;
    let dns_ip = parse_ipv4(&request.dns_ip)?;
    let broadcast = SocketAddrV4::new(broadcast_ip(&request.lease_ip)?, 68);

    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return Err(anyhow!("timed out waiting for DHCP request"));
        }

        let recv = timeout(remain, socket.recv_from(&mut buf)).await;
        let Ok(Ok((len, _from))) = recv else {
            return Err(anyhow!("timed out waiting for DHCP request"));
        };
        if len < 240 || buf[0] != 1 {
            continue;
        }
        if buf[236..240] != DHCP_COOKIE {
            continue;
        }

        let client_mac = buf[28..34].to_vec();
        if let Some(expected) = &target_mac {
            if &client_mac != expected {
                continue;
            }
        }

        match dhcp_message_type(&buf[..len]) {
            Some(DHCP_DISCOVER) => {
                let offer = build_dhcp_reply(
                    &buf[..len],
                    DHCP_OFFER,
                    &client_mac,
                    lease_ip,
                    server_ip,
                    subnet_mask,
                    router_ip,
                    dns_ip,
                )?;
                socket
                    .send_to(&offer, broadcast)
                    .await
                    .context("failed sending DHCP offer")?;
            }
            Some(DHCP_REQUEST) => {
                let ack = build_dhcp_reply(
                    &buf[..len],
                    DHCP_ACK,
                    &client_mac,
                    lease_ip,
                    server_ip,
                    subnet_mask,
                    router_ip,
                    dns_ip,
                )?;
                socket
                    .send_to(&ack, broadcast)
                    .await
                    .context("failed sending DHCP ack")?;
                return Ok(DhcpLeaseAck {
                    assigned_ip: lease_ip.to_string(),
                    target_mac: format_mac(&client_mac),
                });
            }
            _ => {}
        }
    }
}

fn build_dhcp_reply(
    request: &[u8],
    message_type: u8,
    client_mac: &[u8],
    lease_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    router_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
) -> Result<Vec<u8>> {
    let mut packet = vec![0u8; 300];
    packet[0] = 2;
    packet[1] = 1;
    packet[2] = 6;
    packet[3] = 0;
    packet[4..8].copy_from_slice(&request[4..8]);
    packet[8..10].copy_from_slice(&request[8..10]);
    packet[10..12].copy_from_slice(&request[10..12]);
    packet[16..20].copy_from_slice(&lease_ip.octets());
    packet[20..24].copy_from_slice(&server_ip.octets());
    packet[28..34].copy_from_slice(client_mac);
    packet[236..240].copy_from_slice(&DHCP_COOKIE);

    let mut idx = 240;
    idx = push_dhcp_option(&mut packet, idx, 53, &[message_type]);
    idx = push_dhcp_option(&mut packet, idx, 54, &server_ip.octets());
    idx = push_dhcp_option(&mut packet, idx, 51, &3600u32.to_be_bytes());
    idx = push_dhcp_option(&mut packet, idx, 1, &subnet_mask.octets());
    idx = push_dhcp_option(&mut packet, idx, 3, &router_ip.octets());
    idx = push_dhcp_option(&mut packet, idx, 6, &dns_ip.octets());
    if idx >= packet.len() {
        return Err(anyhow!("DHCP packet overflow"));
    }
    packet[idx] = DHCP_END;
    packet.truncate(idx + 1);
    Ok(packet)
}

fn push_dhcp_option(packet: &mut Vec<u8>, idx: usize, code: u8, value: &[u8]) -> usize {
    let end = idx + 2 + value.len();
    if end > packet.len() {
        packet.resize(end, 0);
    }
    packet[idx] = code;
    packet[idx + 1] = value.len() as u8;
    packet[idx + 2..end].copy_from_slice(value);
    end
}

fn dhcp_message_type(packet: &[u8]) -> Option<u8> {
    let mut idx = 240;
    while idx < packet.len() {
        let code = packet[idx];
        idx += 1;
        if code == DHCP_END {
            return None;
        }
        if code == 0 {
            continue;
        }
        if idx >= packet.len() {
            return None;
        }
        let len = packet[idx] as usize;
        idx += 1;
        if idx + len > packet.len() {
            return None;
        }
        if code == 53 && len == 1 {
            return Some(packet[idx]);
        }
        idx += len;
    }
    None
}

fn parse_discovery_payload(payload: &[u8], from: String) -> ReolinkDiscovery {
    let body = if payload.len() > 8 {
        &payload[8..]
    } else {
        payload
    };
    let parts = body
        .split(|byte| *byte == 0)
        .filter_map(parse_printable_token)
        .collect::<Vec<_>>();

    let mut out = ReolinkDiscovery::default();
    out.from = from;

    let mut extras = Vec::new();
    for value in parts {
        if out.ip.is_empty() && parse_ipv4(&value).is_ok() {
            out.ip = value;
            continue;
        }
        if out.mac.is_empty() && looks_like_mac(&value) {
            out.mac = value;
            continue;
        }
        extras.push(value);
    }

    if let Some(model) = extras
        .iter()
        .find(|value| value.contains(' ') && value.chars().any(|ch| ch.is_ascii_alphabetic()))
    {
        out.model = model.clone();
    }
    if out.model.is_empty() {
        if let Some(model) = extras
            .iter()
            .find(|value| value.chars().any(|ch| ch.is_ascii_alphabetic()))
        {
            out.model = model.clone();
        }
    }
    if let Some(uid) = extras
        .iter()
        .find(|value| value != &&out.model && looks_like_uid(value))
    {
        out.uid = uid.clone();
    }
    if out.uid.is_empty() {
        if let Some(uid) = extras.iter().find(|value| value != &&out.model) {
            out.uid = uid.clone();
        }
    }

    out
}

fn looks_like_mac(value: &str) -> bool {
    value.len() == 17
        && value.bytes().enumerate().all(|(idx, byte)| {
            if [2, 5, 8, 11, 14].contains(&idx) {
                byte == b':' || byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn looks_like_uid(value: &str) -> bool {
    value.len() >= 8
        && !value.contains(' ')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn parse_printable_token(chunk: &[u8]) -> Option<String> {
    if chunk.is_empty() {
        return None;
    }
    if chunk
        .iter()
        .any(|byte| !byte.is_ascii_graphic() && *byte != b' ')
    {
        return None;
    }
    let value = String::from_utf8_lossy(chunk).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn default_reolink_username() -> String {
    "admin".to_string()
}

fn default_reolink_channel() -> i32 {
    0
}

fn default_timeout_secs() -> u64 {
    20
}

fn default_subnet_mask() -> String {
    "255.255.255.0".to_string()
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input.trim()).with_context(|| format!("invalid IPv4 address: {input}"))
}

fn broadcast_ip(ip: &str) -> Result<Ipv4Addr> {
    let mut octets = parse_ipv4(ip)?.octets();
    octets[3] = 255;
    Ok(Ipv4Addr::from(octets))
}

fn normalize_mac(input: &str) -> Result<Vec<u8>> {
    let parts = input
        .trim()
        .replace('-', ":")
        .split(':')
        .filter(|part| !part.is_empty())
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing MAC address")?;
    if parts.len() != 6 {
        return Err(anyhow!("MAC address must contain six octets"));
    }
    Ok(parts)
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn generate_device_password() -> String {
    let mut rng = rand::thread_rng();
    (0..GENERATED_DEVICE_PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..DEVICE_PASSWORD_CHARSET.len());
            DEVICE_PASSWORD_CHARSET[idx] as char
        })
        .collect()
}

async fn tcp_open(target: Ipv4Addr, port: u16, timeout_secs: u64) -> bool {
    let addr = SocketAddrV4::new(target, port);
    timeout(
        Duration::from_secs(timeout_secs.max(1)),
        TcpStream::connect(addr),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reolink_discovery_payload() {
        let payload = b"\x00\x00\x00\x00\xaa\xaa\x00\x00192.168.1.20\x00EC:71:DB:32:0A:8F\x00E1 Outdoor SE PoE\x009527000L3X9U13GR\x00";
        let out = parse_discovery_payload(payload, "192.168.1.20:2000".to_string());
        assert_eq!(out.ip, "192.168.1.20");
        assert_eq!(out.mac, "EC:71:DB:32:0A:8F");
        assert_eq!(out.model, "E1 Outdoor SE PoE");
        assert_eq!(out.uid, "9527000L3X9U13GR");
    }

    #[test]
    fn skips_binary_garbage_in_reolink_discovery_payload() {
        let payload = b"\x00\x00\x00\x00\xaa\xaa\x00\x00\x01\x02garbage\x00192.168.1.20\x00EC:71:DB:32:0A:8F\x00E1 Outdoor SE PoE\x009527000L3X9U13GR\x00";
        let out = parse_discovery_payload(payload, "192.168.1.20:2000".to_string());
        assert_eq!(out.ip, "192.168.1.20");
        assert_eq!(out.mac, "EC:71:DB:32:0A:8F");
        assert_eq!(out.model, "E1 Outdoor SE PoE");
        assert_eq!(out.uid, "9527000L3X9U13GR");
    }

    #[test]
    fn parses_dhcp_message_type() {
        let mut packet = vec![0u8; 244];
        packet[236..240].copy_from_slice(&DHCP_COOKIE);
        packet[240] = 53;
        packet[241] = 1;
        packet[242] = DHCP_DISCOVER;
        packet[243] = DHCP_END;
        assert_eq!(dhcp_message_type(&packet), Some(DHCP_DISCOVER));
    }

    #[test]
    fn normalizes_mac() {
        let out = normalize_mac("EC:71:DB:32:0A:8F").expect("mac");
        assert_eq!(out, vec![0xEC, 0x71, 0xDB, 0x32, 0x0A, 0x8F]);
    }

    #[test]
    fn setup_request_defaults_username() {
        let request = ReolinkSetupRequest {
            ip: "192.168.1.20".to_string(),
            username: String::new(),
            password: "secret".to_string(),
            desired_password: String::new(),
            generate_password: false,
            normal: None,
            advanced: None,
            p2p: None,
        }
        .normalized()
        .expect("normalized");
        assert_eq!(request.username, "admin");
    }

    #[test]
    fn converts_bridge_configs_to_core_models() {
        let normal = ReolinkNormalPortConfig {
            i_surv_port_enable: 1,
            i_surv_port: 9000,
            i_http_port_enable: 0,
            i_http_port: 80,
            i_https_port_enable: 1,
            i_https_port: 443,
        };
        let advanced = ReolinkAdvancedPortConfig {
            i_onvif_port_enable: 1,
            i_onvif_port: 8000,
            i_rtsp_port_enable: 1,
            i_rtsp_port: 554,
            i_rtmp_port_enable: 0,
            i_rtmp_port: 1935,
        };
        let p2p = ReolinkP2PConfig {
            i_enable: 0,
            i_port: 0,
            server_domain_name: "p2p.reolink.com".into(),
        };

        let normal_core: reolink_proto::ReolinkNetNormalPort = normal.clone().into();
        let advanced_core: reolink_proto::ReolinkNetAdvancedPort = advanced.clone().into();
        let p2p_core: reolink_proto::ReolinkP2PCfg = p2p.clone().into();

        assert_eq!(ReolinkNormalPortConfig::from(normal_core), normal);
        assert_eq!(ReolinkAdvancedPortConfig::from(advanced_core), advanced);
        assert_eq!(ReolinkP2PConfig::from(p2p_core), p2p);
    }

    #[test]
    fn generates_device_password_with_expected_shape() {
        let out = generate_device_password();
        assert_eq!(out.len(), GENERATED_DEVICE_PASSWORD_LEN);
        assert!(
            out.bytes()
                .all(|byte| DEVICE_PASSWORD_CHARSET.contains(&byte))
        );
    }

    #[test]
    fn setup_request_generates_password_when_requested() {
        let request = ReolinkSetupRequest {
            ip: "192.168.1.20".to_string(),
            username: "admin".to_string(),
            password: String::new(),
            desired_password: String::new(),
            generate_password: true,
            normal: None,
            advanced: None,
            p2p: None,
        }
        .normalized()
        .expect("normalized");
        assert_eq!(
            request.desired_password.len(),
            GENERATED_DEVICE_PASSWORD_LEN
        );
    }
}
