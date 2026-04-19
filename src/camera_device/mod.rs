pub mod apply;
pub mod control;
pub mod discovery;
pub mod drivers;
pub mod identification;
pub mod inventory;
pub mod mount;
pub mod protocol;
pub mod reconcile;
pub mod registry;
pub mod types;

use crate::config::{
    CameraDeviceConfig as CameraConfig, CameraDeviceDesiredConfig as CameraDesiredConfig, Config,
    adopt_camera_active_password,
    camera_device_credential_candidates as camera_credential_candidates,
    finalize_camera_password_rotation,
    mark_camera_device_rotation_failed as mark_camera_rotation_failed,
    mark_camera_rotation_pending,
};
use crate::recording;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, LocalResult, NaiveDateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use futures_util::stream::{self, StreamExt};
use regex::Regex;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio::time::{Duration, Instant, sleep, timeout};

use self::drivers::reolink::{cgi as reolink_cgi, driver as reolink};
use self::drivers::xm_40e::driver as xm;
use self::protocol::onvif;
use self::registry::{
    DRIVER_ID_GENERIC_ONVIF_RTSP, DRIVER_ID_REOLINK, DRIVER_ID_XM_40E, driver_is_xm,
};
const REOLINK_NATIVE_PTZ_SETTLE_TIMEOUT_MS: u64 = 5_000;
const REOLINK_NATIVE_PTZ_POLL_INTERVAL_MS: u64 = 250;
const REOLINK_CGI_FALLBACK_MIN_PULSE_MS: u64 = 180;
const REOLINK_CGI_FALLBACK_MAX_PULSE_MS: u64 = 1_200;
const REOLINK_CGI_FALLBACK_SPEED: i32 = 32;
const REOLINK_OBSERVED_STEP_MAX_ATTEMPTS: usize = 8;
const CAMERA_TIME_MAX_DRIFT_SECS: i64 = 90;

pub trait CameraDriver {
    fn match_candidate(&self, candidate: &DiscoveredCameraCandidate) -> Option<DriverMatch>;
    fn capabilities(&self, camera: &CameraConfig) -> CameraCapabilitySet;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraCapabilitySet {
    pub live_view: bool,
    pub ptz: bool,
    pub time_sync: bool,
    pub manual_time: bool,
    pub timezone: bool,
    pub overlay_text: bool,
    pub overlay_timestamp: bool,
    pub password_rotate: bool,
    pub hardening_profile: bool,
    pub raw_probe: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraNetworkSummary {
    pub managed: bool,
    pub interface: String,
    pub subnet_cidr: String,
    pub host_ip: String,
    pub dhcp_enabled: bool,
    pub dhcp_range_start: String,
    pub dhcp_range_end: String,
    pub ntp_enabled: bool,
    pub ntp_server: String,
    pub timezone: String,
    pub dns_server: String,
    pub lease_file: String,
}

#[derive(Clone, Debug, Default)]
struct SiteTimePolicy {
    ntp_enabled: bool,
    ntp_server: String,
    timezone: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraSignatureSet {
    pub vendor: String,
    pub model: String,
    pub public_title: String,
    pub onvif_xaddrs: Vec<String>,
    pub upnp_model: String,
    pub reolink_uid: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraTransportFacts {
    pub http: bool,
    pub https: bool,
    pub rtsp: bool,
    pub onvif: bool,
    pub proprietary_9000: bool,
    pub onvif_xaddr: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverMatch {
    pub driver_id: String,
    pub kind: String,
    pub confidence: u8,
    pub reason: String,
    pub mountable: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredCameraCandidate {
    pub candidate_id: String,
    pub ip: String,
    pub mac: String,
    pub lease_hostname: String,
    pub discovered_via: Vec<String>,
    pub signatures: CameraSignatureSet,
    pub transports: CameraTransportFacts,
    pub driver_match: DriverMatch,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedCameraState {
    pub display_name: String,
    pub driver_id: String,
    pub vendor: String,
    pub model: String,
    pub ip: String,
    pub mac_address: String,
    pub time_mode: String,
    pub ntp_server: String,
    pub manual_time: String,
    pub timezone: String,
    pub overlay_text: String,
    pub overlay_timestamp: Option<bool>,
    pub ptz_capable: bool,
    pub current_pose: CameraPose,
    pub pose_status: String,
    pub pose_source: String,
    pub services: Value,
    pub raw: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraPose {
    pub pan: Option<f32>,
    pub tilt: Option<f32>,
    pub zoom: Option<f32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraReconcileResult {
    pub status: String,
    pub message: String,
    pub applied_fields: Vec<String>,
    pub failed_fields: Vec<String>,
    pub unsupported_fields: Vec<String>,
    pub drift_fields: Vec<String>,
    pub verified: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraCredentialSafety {
    pub status: String,
    pub pending: bool,
    pub history_depth: usize,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MountedCamera {
    pub source_id: String,
    pub driver_id: String,
    pub display_name: String,
    pub vendor: String,
    pub model: String,
    pub ip: String,
    pub mac_address: String,
    pub enabled: bool,
    pub rtsp_url: String,
    pub capabilities: CameraCapabilitySet,
    pub credential_safety: CameraCredentialSafety,
    pub desired: CameraDesiredConfig,
    pub observed: ObservedCameraState,
    pub current_pose: CameraPose,
    pub desired_pose: CameraPose,
    pub pose_status: String,
    pub verification: CameraReconcileResult,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraPtzControlResult {
    pub current_pose: CameraPose,
    pub desired_pose: CameraPose,
    pub pose_status: String,
    pub management_plane: String,
    #[serde(default)]
    pub ptz_diagnostics: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraInventory {
    pub mounted_devices: Vec<MountedCamera>,
    pub candidate_devices: Vec<DiscoveredCameraCandidate>,
    pub camera_network: CameraNetworkSummary,
}

pub use apply::apply_camera_device_config;
pub use control::control_camera_device;
pub use inventory::{list_camera_device_inventory, read_camera_device};
pub use mount::mount_camera_device;
pub use reconcile::reconcile_camera_device;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MountCameraRequest {
    pub candidate: DiscoveredCameraCandidate,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub desired_password: String,
    #[serde(default)]
    pub generate_password: bool,
    #[serde(default)]
    pub rtsp_url: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraDeviceMountResult {
    #[serde(skip_serializing, skip_deserializing)]
    pub configured: CameraConfig,
    pub mounted: MountedCamera,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyMountedCameraRequest {
    pub source_id: String,
    pub desired: CameraDesiredConfig,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CameraDeviceApplyResult {
    #[serde(skip_serializing, skip_deserializing)]
    pub configured: CameraConfig,
    pub mounted: MountedCamera,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeCameraRequest {
    #[serde(default)]
    pub source_id: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub driver_id: String,
}

struct ReolinkDriver;
struct Xm40eDriver;
struct GenericOnvifRtspDriver;

impl CameraDriver for ReolinkDriver {
    fn match_candidate(&self, candidate: &DiscoveredCameraCandidate) -> Option<DriverMatch> {
        let vendor = candidate.signatures.vendor.to_ascii_lowercase();
        let model = candidate.signatures.model.to_ascii_lowercase();
        let title = candidate.signatures.public_title.to_ascii_lowercase();
        let is_reolink = vendor.contains("reolink")
            || model.contains("reolink")
            || title.contains("reolink")
            || !candidate.signatures.reolink_uid.trim().is_empty()
            || candidate.transports.proprietary_9000;
        if !is_reolink {
            return None;
        }
        Some(DriverMatch {
            driver_id: DRIVER_ID_REOLINK.to_string(),
            kind: "vendor_driver".to_string(),
            confidence: if !candidate.signatures.reolink_uid.trim().is_empty() {
                100
            } else if candidate.transports.proprietary_9000 {
                95
            } else {
                90
            },
            reason: "matched Reolink signatures".to_string(),
            mountable: true,
        })
    }

    fn capabilities(&self, camera: &CameraConfig) -> CameraCapabilitySet {
        CameraCapabilitySet {
            live_view: true,
            ptz: camera.ptz_capable,
            time_sync: true,
            manual_time: false,
            timezone: true,
            overlay_text: true,
            overlay_timestamp: true,
            password_rotate: true,
            hardening_profile: true,
            raw_probe: true,
        }
    }
}

impl CameraDriver for GenericOnvifRtspDriver {
    fn match_candidate(&self, candidate: &DiscoveredCameraCandidate) -> Option<DriverMatch> {
        if !(candidate.transports.onvif || candidate.transports.rtsp) {
            return None;
        }
        Some(DriverMatch {
            driver_id: DRIVER_ID_GENERIC_ONVIF_RTSP.to_string(),
            kind: "generic_driver".to_string(),
            confidence: if candidate.transports.onvif && candidate.transports.rtsp {
                80
            } else {
                65
            },
            reason: "matched ONVIF/RTSP capabilities".to_string(),
            mountable: true,
        })
    }

    fn capabilities(&self, camera: &CameraConfig) -> CameraCapabilitySet {
        CameraCapabilitySet {
            live_view: true,
            ptz: camera.ptz_capable,
            raw_probe: true,
            ..Default::default()
        }
    }
}

impl CameraDriver for Xm40eDriver {
    fn match_candidate(&self, candidate: &DiscoveredCameraCandidate) -> Option<DriverMatch> {
        if !candidate_looks_like_xm(candidate) || !candidate.transports.rtsp {
            return None;
        }
        Some(DriverMatch {
            driver_id: DRIVER_ID_XM_40E.to_string(),
            kind: "vendor_driver".to_string(),
            confidence: if candidate.transports.onvif { 88 } else { 82 },
            reason: "matched XM/NetSurveillance 40E-class footprint".to_string(),
            mountable: true,
        })
    }

    fn capabilities(&self, _camera: &CameraConfig) -> CameraCapabilitySet {
        CameraCapabilitySet {
            live_view: true,
            ptz: false,
            time_sync: true,
            manual_time: false,
            timezone: true,
            overlay_text: false,
            overlay_timestamp: false,
            raw_probe: true,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
struct LeaseEntry {
    ip: String,
    mac: String,
    hostname: String,
}

pub fn camera_network_summary(cfg: &Config) -> CameraNetworkSummary {
    CameraNetworkSummary {
        managed: cfg.camera_network.managed,
        interface: cfg.camera_network.interface.clone(),
        subnet_cidr: cfg.camera_network.subnet_cidr.clone(),
        host_ip: cfg.camera_network.host_ip.clone(),
        dhcp_enabled: cfg.camera_network.dhcp_enabled,
        dhcp_range_start: cfg.camera_network.dhcp_range_start.clone(),
        dhcp_range_end: cfg.camera_network.dhcp_range_end.clone(),
        ntp_enabled: cfg.camera_network.ntp_enabled,
        ntp_server: cfg.camera_network.ntp_server.clone(),
        timezone: cfg.camera_network.timezone.clone(),
        dns_server: cfg.camera_network.dns_server.clone(),
        lease_file: cfg.camera_network.lease_file.clone(),
    }
}

fn site_time_policy(cfg: &Config) -> SiteTimePolicy {
    SiteTimePolicy {
        ntp_enabled: cfg.camera_network.ntp_enabled,
        ntp_server: cfg.camera_network.ntp_server.trim().to_string(),
        timezone: first_nonempty(&cfg.camera_network.timezone, "UTC"),
    }
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(left) & mask) == (u32::from(right) & mask)
}

fn effective_ntp_server_for_camera(cfg: &Config, camera: &CameraConfig) -> Option<String> {
    let host = camera.onvif_host.trim().parse::<Ipv4Addr>().ok()?;
    let iface = cfg.camera_network.interface.trim();
    if iface.is_empty() {
        return None;
    }
    interface_ipv4_cidrs(iface).into_iter().find_map(|(addr, prefix)| {
        same_ipv4_subnet(addr, host, prefix).then(|| addr.to_string())
    })
}

fn effective_site_time_policy(cfg: &Config, camera: &CameraConfig) -> SiteTimePolicy {
    let mut policy = site_time_policy(cfg);
    if let Some(ntp_server) = effective_ntp_server_for_camera(cfg, camera) {
        policy.ntp_server = ntp_server;
    }
    policy
}

fn site_timezone_code(site_timezone: &str, now_utc: DateTime<Utc>) -> Option<i32> {
    let tz: Tz = site_timezone.trim().parse().ok()?;
    let local = now_utc.with_timezone(&tz);
    Some(local.offset().fix().local_minus_utc() / 60 + 720)
}

fn site_local_time_string_for_xm(site_timezone: &str, now_utc: DateTime<Utc>) -> Option<String> {
    let tz: Tz = site_timezone.trim().parse().ok()?;
    Some(
        now_utc
            .with_timezone(&tz)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    )
}

fn observed_site_time_offset_secs(
    site_timezone: &str,
    observed_manual_time: &str,
    now_utc: DateTime<Utc>,
) -> Option<i64> {
    let tz: Tz = site_timezone.trim().parse().ok()?;
    let naive = NaiveDateTime::parse_from_str(observed_manual_time.trim(), "%Y-%m-%dT%H:%M:%S")
        .ok()?;
    let local = match tz.from_local_datetime(&naive) {
        LocalResult::Single(value) => value,
        LocalResult::Ambiguous(first, _) => first,
        LocalResult::None => return None,
    };
    Some((local.with_timezone(&Utc) - now_utc).num_seconds().abs())
}

fn observed_timezone_matches(policy: &SiteTimePolicy, observed: &ObservedCameraState) -> bool {
    if policy.timezone.trim().is_empty() {
        return true;
    }
    if policy.timezone.trim() == observed.timezone.trim() {
        return true;
    }
    observed
        .raw
        .get("time")
        .and_then(|value| value.get("timezoneCode"))
        .and_then(Value::as_i64)
        .and_then(|code| site_timezone_code(&policy.timezone, Utc::now()).map(|expected| code == expected as i64))
        .unwrap_or(false)
}

fn site_local_time_string(site_timezone: &str, now_utc: DateTime<Utc>) -> Option<String> {
    let tz: Tz = site_timezone.trim().parse().ok()?;
    Some(
        now_utc
            .with_timezone(&tz)
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
    )
}

fn to_onvif_site_time_policy(policy: &SiteTimePolicy) -> onvif::OnvifSiteTimePolicy {
    onvif::OnvifSiteTimePolicy {
        ntp_enabled: policy.ntp_enabled,
        ntp_server: policy.ntp_server.clone(),
        timezone: policy.timezone.clone(),
    }
}

fn reolink_observed_time_mode(
    onvif_state: Option<&onvif::OnvifState>,
    presentation: &reolink_cgi::ReolinkPresentationState,
) -> String {
    onvif_state
        .map(|state| state.time_mode.clone())
        .filter(|value: &String| !value.trim().is_empty())
        .unwrap_or_else(|| presentation.time_mode.clone())
}

fn reolink_observed_ntp_server(
    onvif_state: Option<&onvif::OnvifState>,
    presentation: &reolink_cgi::ReolinkPresentationState,
) -> String {
    onvif_state
        .map(|state| state.ntp_server.clone())
        .filter(|value: &String| !value.trim().is_empty())
        .unwrap_or_else(|| presentation.ntp_server.clone())
}

fn reolink_observed_manual_time(
    onvif_state: Option<&onvif::OnvifState>,
    presentation: &reolink_cgi::ReolinkPresentationState,
) -> String {
    if !presentation.manual_time.trim().is_empty() {
        return presentation.manual_time.clone();
    }
    onvif_state
        .map(|state| state.manual_time.clone())
        .filter(|value: &String| !value.trim().is_empty())
        .unwrap_or_default()
}

fn reolink_observed_timezone(
    onvif_state: Option<&onvif::OnvifState>,
    presentation: &reolink_cgi::ReolinkPresentationState,
) -> String {
    if !presentation.timezone.trim().is_empty() {
        return presentation.timezone.clone();
    }
    onvif_state
        .map(|state| state.timezone.clone())
        .filter(|value: &String| !value.trim().is_empty())
        .unwrap_or_default()
}

pub async fn discover_candidates(cfg: &Config) -> Result<Vec<DiscoveredCameraCandidate>> {
    let mut map = HashMap::<String, DiscoveredCameraCandidate>::new();
    for lease in parse_lease_file(&cfg.camera_network.lease_file) {
        if lease.ip.trim().is_empty() {
            continue;
        }
        let candidate = map
            .entry(lease.ip.clone())
            .or_insert_with(|| blank_candidate(&lease.ip));
        candidate.mac = first_nonempty(&candidate.mac, &lease.mac);
        candidate.lease_hostname = first_nonempty(&candidate.lease_hostname, &lease.hostname);
        push_unique_string(&mut candidate.discovered_via, "dhcp_lease");
    }

    for discovered in recording::discover_onvif(2).await.unwrap_or_default() {
        let Some((ip, _)) = host_and_port_from_xaddr(&discovered.endpoint) else {
            continue;
        };
        let candidate = map
            .entry(ip.clone())
            .or_insert_with(|| blank_candidate(&ip));
        push_unique_string(&mut candidate.discovered_via, "onvif_ws_discovery");
        push_unique_string(&mut candidate.signatures.onvif_xaddrs, &discovered.endpoint);
        candidate.transports.onvif = true;
        if candidate.transports.onvif_xaddr.trim().is_empty() {
            candidate.transports.onvif_xaddr = discovered.endpoint.trim().to_string();
        }
    }

    for discovered in reolink::discover(2).await.unwrap_or_default() {
        if discovered.ip.trim().is_empty() {
            continue;
        }
        let candidate = map
            .entry(discovered.ip.clone())
            .or_insert_with(|| blank_candidate(&discovered.ip));
        push_unique_string(&mut candidate.discovered_via, "reolink_lan");
        candidate.mac = first_nonempty(&candidate.mac, &discovered.mac);
        candidate.signatures.vendor = first_nonempty(&candidate.signatures.vendor, "Reolink");
        candidate.signatures.model = first_nonempty(&candidate.signatures.model, &discovered.model);
        candidate.signatures.reolink_uid =
            first_nonempty(&candidate.signatures.reolink_uid, &discovered.uid);
        candidate.transports.proprietary_9000 = true;
    }

    for discovered in discover_interface_scan_candidates(cfg).await {
        let candidate = map
            .entry(discovered.ip.clone())
            .or_insert_with(|| blank_candidate(&discovered.ip));
        candidate.mac = first_nonempty(&candidate.mac, &discovered.mac);
        candidate.lease_hostname =
            first_nonempty(&candidate.lease_hostname, &discovered.lease_hostname);
        for seen in &discovered.discovered_via {
            push_unique_string(&mut candidate.discovered_via, seen);
        }
        candidate.signatures.vendor =
            first_nonempty(&candidate.signatures.vendor, &discovered.signatures.vendor);
        candidate.signatures.model =
            first_nonempty(&candidate.signatures.model, &discovered.signatures.model);
        candidate.signatures.public_title = first_nonempty(
            &candidate.signatures.public_title,
            &discovered.signatures.public_title,
        );
        candidate.transports.http = candidate.transports.http || discovered.transports.http;
        candidate.transports.https = candidate.transports.https || discovered.transports.https;
        candidate.transports.rtsp = candidate.transports.rtsp || discovered.transports.rtsp;
        candidate.transports.onvif = candidate.transports.onvif || discovered.transports.onvif;
        candidate.transports.proprietary_9000 =
            candidate.transports.proprietary_9000 || discovered.transports.proprietary_9000;
    }

    let client = http_client()?;
    for candidate in map.values_mut() {
        hydrate_candidate(candidate, &client).await?;
        candidate.driver_match = match_candidate(candidate);
        candidate.candidate_id = candidate_id(candidate);
    }

    let mut out = map.into_values().collect::<Vec<_>>();
    out.sort_by(|left, right| candidate_sort_key(left).cmp(&candidate_sort_key(right)));
    Ok(out)
}

fn sync_display_name_and_linked_overlay(existing: &CameraConfig, next: &mut CameraConfig) {
    let requested_display_name = next.desired.display_name.trim();
    if requested_display_name.is_empty() {
        return;
    }
    if driver_is_xm(&existing.driver_id) || driver_is_xm(&next.driver_id) {
        next.name = requested_display_name.to_string();
        return;
    }
    let previous_display_name = camera_display_name(existing);
    let requested_overlay_text = next.desired.overlay_text.trim();
    next.name = requested_display_name.to_string();
    // Treat overlay text as linked to the display name unless the operator
    // has explicitly diverged it to a different value.
    if requested_overlay_text.is_empty()
        || (!previous_display_name.trim().is_empty()
            && requested_overlay_text == previous_display_name.trim())
    {
        next.desired.overlay_text = requested_display_name.to_string();
    }
}

pub async fn control_mounted_camera(
    camera: &CameraConfig,
    ptz_payload: &Value,
) -> Result<CameraPtzControlResult> {
    match camera.driver_id.trim() {
        DRIVER_ID_REOLINK => control_reolink_camera(camera, ptz_payload).await,
        DRIVER_ID_GENERIC_ONVIF_RTSP => control_onvif_camera(camera, ptz_payload).await,
        _ => Err(anyhow!(
            "camera driver does not support managed PTZ control"
        )),
    }
}

pub async fn probe_camera_device(cfg: &Config, request: ProbeCameraRequest) -> Result<Value> {
    if !request.source_id.trim().is_empty() {
        let camera = read_camera_device(cfg, &request.source_id).await?;
        return Ok(json!({
            "mode": "mounted",
            "camera": camera,
            "cameraNetwork": camera_network_summary(cfg),
        }));
    }
    if request.ip.trim().is_empty() {
        return Err(anyhow!("probe_camera_device requires source_id or ip"));
    }
    let mut candidate = blank_candidate(&request.ip);
    hydrate_candidate(&mut candidate, &http_client()?).await?;
    candidate.driver_match = match_candidate(&candidate);

    let requested_driver = request.driver_id.trim();
    let effective_driver = if !requested_driver.is_empty() {
        requested_driver
    } else {
        candidate.driver_match.driver_id.trim()
    };

    let diagnostics = if effective_driver == DRIVER_ID_REOLINK
        && !request.username.trim().is_empty()
        && !request.password.trim().is_empty()
    {
        match probe_reolink_candidate(&candidate, &request).await {
            Ok(result) => result,
            Err(error) => json!({
                "driverId": DRIVER_ID_REOLINK,
                "status": "error",
                "message": error.to_string(),
            }),
        }
    } else if driver_is_xm(effective_driver)
        && !request.username.trim().is_empty()
        && !request.password.trim().is_empty()
    {
        match probe_xm_candidate(&candidate, &request).await {
            Ok(result) => result,
            Err(error) => json!({
                "driverId": DRIVER_ID_XM_40E,
                "status": "error",
                "message": error.to_string(),
            }),
        }
    } else {
        json!({
            "driverId": if effective_driver.is_empty() {
                "unmatched"
            } else {
                effective_driver
            },
            "status": "discovered",
            "message": if effective_driver == DRIVER_ID_GENERIC_ONVIF_RTSP {
                "Generic ONVIF/RTSP candidate; mount to apply managed configuration."
            } else {
                "Discovery candidate hydrated from current network signatures."
            },
        })
    };

    Ok(json!({
        "mode": "candidate",
        "candidate": candidate,
        "cameraNetwork": camera_network_summary(cfg),
        "diagnostics": diagnostics,
    }))
}

async fn control_reolink_camera(
    camera: &CameraConfig,
    ptz_payload: &Value,
) -> Result<CameraPtzControlResult> {
    let ports = probe_common_ports(&camera.onvif_host).await;
    let target_pose = parse_requested_pose(ptz_payload);
    let mut native_error = None;

    if let Some(target_pose) = target_pose {
        if ports.proprietary_9000 {
            match control_reolink_native_absolute(camera, target_pose).await {
                Ok(result) => return Ok(result),
                Err(error) => native_error = Some(error),
            }
        } else {
            native_error = Some(anyhow!(
                "native Reolink PTZ is unavailable because {}:9000 is not reachable",
                camera.onvif_host
            ));
        }

        // Interim policy: keep native 9000 absolute PTZ as the preferred path, but when the
        // lab E1 acknowledges SetPtzPos without actuating, steer with directional pulses and use
        // native GetPtzCurPos as the fulfillment sensor until true native absolute set lands.
        if (ports.http || ports.https)
            && let Ok(result) = control_reolink_observed_step_fallback(
                camera,
                target_pose,
                native_error.as_ref().map(|error| error.to_string()),
            )
            .await
        {
            return Ok(result);
        }
    }

    if (ports.http || ports.https) && reolink_fallback_command(ptz_payload).is_some() {
        let native_error_text = native_error.as_ref().map(|error| error.to_string());
        match control_reolink_cgi_fallback(camera, ptz_payload, native_error_text.as_deref()).await
        {
            Ok(result) => return Ok(result),
            Err(fallback_error) => {
                if let Some(native_error) = native_error {
                    return Err(anyhow!(
                        "native Reolink PTZ failed: {} | CGI fallback failed: {}",
                        native_error,
                        fallback_error
                    ));
                }
                return Err(fallback_error);
            }
        }
    }

    if let Some(native_error) = native_error {
        return Err(native_error);
    }

    Err(anyhow!(
        "PTZ control is not available for {} because neither native Reolink 9000 nor CGI PTZ is reachable",
        camera.onvif_host
    ))
}

async fn control_onvif_camera(
    camera: &CameraConfig,
    ptz_payload: &Value,
) -> Result<CameraPtzControlResult> {
    if let Some(target_pose) = parse_requested_pose(ptz_payload) {
        let current = onvif::ptz_set_pose(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
            target_pose.pan,
            target_pose.tilt,
            target_pose.zoom,
        )
        .await?;
        let pose = CameraPose {
            pan: current.pan,
            tilt: current.tilt,
            zoom: current.zoom,
        };
        return Ok(CameraPtzControlResult {
            current_pose: pose.clone(),
            desired_pose: CameraPose {
                pan: target_pose.pan,
                tilt: target_pose.tilt,
                zoom: target_pose.zoom,
            },
            pose_status: "settled".to_string(),
            management_plane: "onvif_absolute".to_string(),
            ptz_diagnostics: Value::Null,
        });
    }

    if let Some(step) = parse_pose_step(ptz_payload) {
        let current = onvif::ptz_step_pose(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
            step.pan.unwrap_or(0.0),
            step.tilt.unwrap_or(0.0),
            step.zoom.unwrap_or(0.0),
        )
        .await?;
        let pose = CameraPose {
            pan: current.pan,
            tilt: current.tilt,
            zoom: current.zoom,
        };
        return Ok(CameraPtzControlResult {
            current_pose: pose.clone(),
            desired_pose: pose,
            pose_status: "settled".to_string(),
            management_plane: "onvif_step".to_string(),
            ptz_diagnostics: Value::Null,
        });
    }

    let direction = ptz_payload
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("stop");
    let active = ptz_payload
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(direction != "stop");
    onvif::ptz_control(
        &camera.onvif_host,
        camera.onvif_port.max(1),
        &camera.username,
        &camera.password,
        direction,
        active,
    )
    .await?;
    Ok(CameraPtzControlResult {
        pose_status: if active { "moving" } else { "stopped" }.to_string(),
        management_plane: "onvif_continuous".to_string(),
        ..Default::default()
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct RequestedPose {
    pan: Option<f32>,
    tilt: Option<f32>,
    zoom: Option<f32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReolinkNativeAxisRange {
    min: i32,
    max: i32,
    tolerance: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReolinkNativePtzProfile {
    label: &'static str,
    pan: ReolinkNativeAxisRange,
    tilt: ReolinkNativeAxisRange,
    zoom: Option<ReolinkNativeAxisRange>,
}

#[derive(Clone, Debug)]
struct ReolinkNativePtzObservation {
    raw: reolink::ReolinkNativePtzPosition,
    normalized: CameraPose,
    profile: &'static str,
}

#[derive(Clone, Debug)]
struct ReolinkFallbackPtzCommand {
    op: &'static str,
    pulse_ms: Option<u64>,
    desired_pose: CameraPose,
    pose_status: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReolinkObservedStepPlan {
    axis: &'static str,
    op: &'static str,
    pulse_ms: u64,
    remaining_raw: i32,
}

fn parse_requested_pose(ptz_payload: &Value) -> Option<RequestedPose> {
    let target = ptz_payload.get("targetPose")?;
    if !target.is_object() {
        return None;
    }
    let pan = target
        .get("pan")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    let tilt = target
        .get("tilt")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    let zoom = target
        .get("zoom")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    if pan.is_none() && tilt.is_none() && zoom.is_none() {
        None
    } else {
        Some(RequestedPose { pan, tilt, zoom })
    }
}

fn parse_pose_step(ptz_payload: &Value) -> Option<RequestedPose> {
    let step = ptz_payload.get("step")?;
    if !step.is_object() {
        return None;
    }
    let pan = step
        .get("pan")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    let tilt = step
        .get("tilt")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    let zoom = step
        .get("zoom")
        .and_then(Value::as_f64)
        .map(|value| value as f32);
    if pan.is_none() && tilt.is_none() && zoom.is_none() {
        None
    } else {
        Some(RequestedPose { pan, tilt, zoom })
    }
}

fn camera_pose_from_requested_pose(value: RequestedPose) -> CameraPose {
    CameraPose {
        pan: value.pan,
        tilt: value.tilt,
        zoom: value.zoom,
    }
}

fn reolink_native_ptz_profile(camera: &CameraConfig) -> Option<ReolinkNativePtzProfile> {
    let label = format!("{} {}", camera.model, camera.name).to_ascii_lowercase();
    if label.contains("e1 outdoor") {
        return Some(ReolinkNativePtzProfile {
            label: "reolink_e1_outdoor_v1",
            pan: ReolinkNativeAxisRange {
                min: 0,
                max: 3550,
                tolerance: 18,
            },
            tilt: ReolinkNativeAxisRange {
                min: 0,
                max: 500,
                tolerance: 12,
            },
            zoom: Some(ReolinkNativeAxisRange {
                min: 0,
                max: 100,
                tolerance: 4,
            }),
        });
    }
    None
}

fn reolink_normalized_to_raw(value: f32, axis: ReolinkNativeAxisRange) -> i32 {
    let clamped = value.clamp(-1.0, 1.0);
    let ratio = (clamped + 1.0) * 0.5;
    axis.min + (((axis.max - axis.min) as f32) * ratio).round() as i32
}

fn reolink_raw_to_normalized(value: i32, axis: ReolinkNativeAxisRange) -> f32 {
    let clamped = value.clamp(axis.min, axis.max);
    let span = (axis.max - axis.min).max(1) as f32;
    (((clamped - axis.min) as f32) / span) * 2.0 - 1.0
}

fn reolink_native_observation(
    profile: ReolinkNativePtzProfile,
    raw: reolink::ReolinkNativePtzPosition,
) -> ReolinkNativePtzObservation {
    ReolinkNativePtzObservation {
        raw,
        normalized: CameraPose {
            pan: Some(reolink_raw_to_normalized(raw.pan, profile.pan)),
            tilt: Some(reolink_raw_to_normalized(raw.tilt, profile.tilt)),
            zoom: profile
                .zoom
                .map(|axis| reolink_raw_to_normalized(raw.zoom, axis)),
        },
        profile: profile.label,
    }
}

fn reolink_native_target_pose(
    profile: ReolinkNativePtzProfile,
    current: reolink::ReolinkNativePtzPosition,
    requested: RequestedPose,
) -> reolink::ReolinkNativePtzPosition {
    reolink::ReolinkNativePtzPosition {
        pan: requested
            .pan
            .map(|value| reolink_normalized_to_raw(value, profile.pan))
            .unwrap_or(current.pan),
        tilt: requested
            .tilt
            .map(|value| reolink_normalized_to_raw(value, profile.tilt))
            .unwrap_or(current.tilt),
        zoom: match (requested.zoom, profile.zoom) {
            (Some(value), Some(axis)) => reolink_normalized_to_raw(value, axis),
            _ => current.zoom,
        },
    }
}

fn reolink_native_target_reached(
    profile: ReolinkNativePtzProfile,
    requested: RequestedPose,
    target: reolink::ReolinkNativePtzPosition,
    observed: reolink::ReolinkNativePtzPosition,
) -> bool {
    let pan_ok =
        requested.pan.is_none() || (observed.pan - target.pan).abs() <= profile.pan.tolerance;
    let tilt_ok =
        requested.tilt.is_none() || (observed.tilt - target.tilt).abs() <= profile.tilt.tolerance;
    let zoom_ok = requested.zoom.is_none()
        || profile
            .zoom
            .map(|axis| (observed.zoom - target.zoom).abs() <= axis.tolerance)
            .unwrap_or(true);
    pan_ok && tilt_ok && zoom_ok
}

fn reolink_native_ptz_json(native: &ReolinkNativePtzObservation) -> Value {
    json!({
        "managementPlane": "reolink_native_absolute",
        "profile": native.profile,
        "rawPose": native.raw,
        "currentPose": native.normalized,
        "poseStatus": "settled",
    })
}

async fn resolve_reolink_native_connection(
    camera: &CameraConfig,
    preferred_passwords: &[String],
) -> Result<reolink::ReolinkConnectRequest> {
    let mut candidates = Vec::new();
    for candidate in preferred_passwords {
        push_unique_string(&mut candidates, candidate);
    }
    for candidate in reolink_password_candidates(camera) {
        push_unique_string(&mut candidates, &candidate);
    }
    if candidates.is_empty() {
        candidates.push(String::new());
    }

    let mut errors = Vec::new();
    for candidate in candidates {
        let connection = reolink::ReolinkConnectRequest {
            ip: camera.onvif_host.clone(),
            username: camera.username.clone(),
            channel: 0,
            password: candidate,
        };
        match reolink::read_native_ptz_position(connection.clone()).await {
            Ok(_) => return Ok(connection),
            Err(error) => errors.push(error.to_string()),
        }
    }

    Err(anyhow!(
        "no working credential candidate could read native Reolink PTZ position: {}",
        errors.join(" | ")
    ))
}

async fn try_reolink_native_ptz_observation(
    camera: &CameraConfig,
    preferred_passwords: &[String],
) -> Option<ReolinkNativePtzObservation> {
    let profile = reolink_native_ptz_profile(camera)?;
    let connection = resolve_reolink_native_connection(camera, preferred_passwords)
        .await
        .ok()?;
    let raw = reolink::read_native_ptz_position(connection).await.ok()?;
    Some(reolink_native_observation(profile, raw))
}

async fn wait_for_reolink_native_target(
    camera: &CameraConfig,
    connection: &reolink::ReolinkConnectRequest,
    profile: ReolinkNativePtzProfile,
    requested: RequestedPose,
    target: reolink::ReolinkNativePtzPosition,
    mut observed: reolink::ReolinkNativePtzPosition,
) -> Result<reolink::ReolinkNativePtzPosition> {
    if reolink_native_target_reached(profile, requested, target, observed) {
        return Ok(observed);
    }

    let deadline = Instant::now() + Duration::from_millis(REOLINK_NATIVE_PTZ_SETTLE_TIMEOUT_MS);
    while Instant::now() < deadline {
        sleep(Duration::from_millis(REOLINK_NATIVE_PTZ_POLL_INTERVAL_MS)).await;
        observed = reolink::read_native_ptz_position(connection.clone()).await?;
        if reolink_native_target_reached(profile, requested, target, observed) {
            return Ok(observed);
        }
    }

    Err(anyhow!(
        "native Reolink PTZ move on {} did not reach the requested target; last observed raw pose was {:?} for target {:?}",
        camera.onvif_host,
        observed,
        target
    ))
}

async fn control_reolink_native_absolute(
    camera: &CameraConfig,
    target_pose: RequestedPose,
) -> Result<CameraPtzControlResult> {
    let profile = reolink_native_ptz_profile(camera).ok_or_else(|| {
        anyhow!(
            "native Reolink PTZ is not calibrated for {} {}",
            camera.vendor,
            first_nonempty(&camera.model, &camera.name)
        )
    })?;
    let connection = resolve_reolink_native_connection(camera, &[]).await?;
    let current_native = reolink::read_native_ptz_position(connection.clone()).await?;
    let target_native = reolink_native_target_pose(profile, current_native, target_pose);
    let set_result = reolink::set_native_ptz_position(connection.clone(), target_native).await?;
    let response_code = set_result
        .ack
        .get("responseCode")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if response_code != 200 && set_result.after == set_result.before {
        return Err(anyhow!(
            "native Reolink PTZ absolute set was acknowledged with response code {} but did not change pose",
            response_code
        ));
    }
    let settled_raw = wait_for_reolink_native_target(
        camera,
        &connection,
        profile,
        target_pose,
        target_native,
        set_result.after,
    )
    .await?;
    let settled = reolink_native_observation(profile, settled_raw);

    Ok(CameraPtzControlResult {
        current_pose: settled.normalized.clone(),
        desired_pose: camera_pose_from_requested_pose(target_pose),
        pose_status: "settled".to_string(),
        management_plane: "reolink_native_absolute".to_string(),
        ptz_diagnostics: json!({
            "profile": settled.profile,
            "native": {
                "before": set_result.before,
                "target": set_result.target,
                "after": set_result.after,
                "observed": settled.raw,
                "cmdIdx": set_result.cmd_idx,
                "ack": set_result.ack,
            }
        }),
    })
}

fn reolink_observed_step_axis_plan(
    axis_name: &'static str,
    delta: i32,
    axis: ReolinkNativeAxisRange,
    negative_op: &'static str,
    positive_op: &'static str,
) -> Option<ReolinkObservedStepPlan> {
    if delta.abs() <= axis.tolerance {
        return None;
    }
    let span = (axis.max - axis.min).max(1) as f32;
    let ratio = (delta.abs() as f32 / span).clamp(0.0, 1.0);
    let pulse_ms = (REOLINK_CGI_FALLBACK_MIN_PULSE_MS as f32
        + ratio * (REOLINK_CGI_FALLBACK_MAX_PULSE_MS - REOLINK_CGI_FALLBACK_MIN_PULSE_MS) as f32)
        .round() as u64;
    Some(ReolinkObservedStepPlan {
        axis: axis_name,
        op: if delta < 0 { negative_op } else { positive_op },
        pulse_ms: pulse_ms.clamp(
            REOLINK_CGI_FALLBACK_MIN_PULSE_MS,
            REOLINK_CGI_FALLBACK_MAX_PULSE_MS,
        ),
        remaining_raw: delta,
    })
}

fn reolink_observed_step_plan(
    profile: ReolinkNativePtzProfile,
    requested: RequestedPose,
    target: reolink::ReolinkNativePtzPosition,
    observed: reolink::ReolinkNativePtzPosition,
) -> Option<ReolinkObservedStepPlan> {
    let pan_plan = requested.pan.and_then(|_| {
        reolink_observed_step_axis_plan(
            "pan",
            target.pan - observed.pan,
            profile.pan,
            "Left",
            "Right",
        )
    });
    let tilt_plan = requested.tilt.and_then(|_| {
        reolink_observed_step_axis_plan(
            "tilt",
            target.tilt - observed.tilt,
            profile.tilt,
            "Down",
            "Up",
        )
    });

    match (pan_plan, tilt_plan) {
        (Some(pan), Some(tilt)) => {
            if pan.remaining_raw.abs() >= tilt.remaining_raw.abs() {
                Some(pan)
            } else {
                Some(tilt)
            }
        }
        (Some(pan), None) => Some(pan),
        (None, Some(tilt)) => Some(tilt),
        (None, None) => None,
    }
}

async fn send_reolink_cgi_pulse(
    connection: &reolink::ReolinkConnectRequest,
    op: &'static str,
    pulse_ms: u64,
) -> Result<()> {
    reolink_cgi::ptz_command(connection, op, REOLINK_CGI_FALLBACK_SPEED).await?;
    sleep(Duration::from_millis(pulse_ms)).await;
    reolink_cgi::ptz_stop(connection).await
}

async fn control_reolink_observed_step_fallback(
    camera: &CameraConfig,
    target_pose: RequestedPose,
    native_error: Option<String>,
) -> Result<CameraPtzControlResult> {
    let profile = reolink_native_ptz_profile(camera).ok_or_else(|| {
        anyhow!(
            "native Reolink PTZ is not calibrated for {} {}",
            camera.vendor,
            first_nonempty(&camera.model, &camera.name)
        )
    })?;
    let native_connection = resolve_reolink_native_connection(camera, &[]).await?;
    let cgi_connection = resolve_reolink_connection_for(
        &camera.onvif_host,
        &camera.username,
        &[native_connection.password.clone()],
    )
    .await?;
    let mut observed_raw = reolink::read_native_ptz_position(native_connection.clone()).await?;
    let target_raw = reolink_native_target_pose(profile, observed_raw, target_pose);
    let mut attempts = Vec::new();

    // This is an interim bridge, not the final control plane: use native 9000 only for readback
    // and fulfill absolute requests by nudging the camera until the observed pose converges.
    for attempt_idx in 0..REOLINK_OBSERVED_STEP_MAX_ATTEMPTS {
        if reolink_native_target_reached(profile, target_pose, target_raw, observed_raw) {
            let settled = reolink_native_observation(profile, observed_raw);
            return Ok(CameraPtzControlResult {
                current_pose: settled.normalized.clone(),
                desired_pose: camera_pose_from_requested_pose(target_pose),
                pose_status: "settled".to_string(),
                management_plane: "reolink_observed_step_fallback".to_string(),
                ptz_diagnostics: json!({
                    "profile": settled.profile,
                    "interim": true,
                    "nativeAbsoluteError": native_error,
                    "native": {
                        "target": target_raw,
                        "observed": settled.raw,
                    },
                    "fallback": {
                        "mode": "observed_step",
                        "attempts": attempts,
                    }
                }),
            });
        }

        let plan = reolink_observed_step_plan(profile, target_pose, target_raw, observed_raw)
            .ok_or_else(|| {
                anyhow!(
                    "Reolink observed-step fallback cannot derive a pan/tilt pulse for the requested target"
                )
            })?;
        let before = observed_raw;
        send_reolink_cgi_pulse(&cgi_connection, plan.op, plan.pulse_ms).await?;
        sleep(Duration::from_millis(REOLINK_NATIVE_PTZ_POLL_INTERVAL_MS)).await;
        observed_raw = reolink::read_native_ptz_position(native_connection.clone()).await?;
        attempts.push(json!({
            "index": attempt_idx + 1,
            "axis": plan.axis,
            "op": plan.op,
            "pulseMs": plan.pulse_ms,
            "remainingRaw": plan.remaining_raw,
            "before": before,
            "after": observed_raw,
            "moved": observed_raw != before,
        }));
    }

    let observed = reolink_native_observation(profile, observed_raw);
    Ok(CameraPtzControlResult {
        current_pose: observed.normalized.clone(),
        desired_pose: camera_pose_from_requested_pose(target_pose),
        pose_status: "directed".to_string(),
        management_plane: "reolink_observed_step_fallback".to_string(),
        ptz_diagnostics: json!({
            "profile": observed.profile,
            "interim": true,
            "nativeAbsoluteError": native_error,
            "native": {
                "target": target_raw,
                "observed": observed.raw,
            },
            "fallback": {
                "mode": "observed_step",
                "attempts": attempts,
                "status": "target_not_reached_within_attempt_budget",
            }
        }),
    })
}

fn reolink_fallback_direction_from_pose(step: RequestedPose) -> Option<&'static str> {
    let pan = step.pan.unwrap_or(0.0);
    let tilt = step.tilt.unwrap_or(0.0);
    if pan.abs() <= f32::EPSILON && tilt.abs() <= f32::EPSILON {
        return None;
    }
    if pan.abs() >= tilt.abs() {
        if pan < 0.0 {
            Some("Left")
        } else {
            Some("Right")
        }
    } else if tilt < 0.0 {
        Some("Down")
    } else {
        Some("Up")
    }
}

fn reolink_fallback_pulse_ms(step: RequestedPose) -> u64 {
    let magnitude = step
        .pan
        .unwrap_or(0.0)
        .abs()
        .max(step.tilt.unwrap_or(0.0).abs())
        .max(step.zoom.unwrap_or(0.0).abs());
    let pulse = (magnitude * 900.0).round() as u64;
    pulse.clamp(
        REOLINK_CGI_FALLBACK_MIN_PULSE_MS,
        REOLINK_CGI_FALLBACK_MAX_PULSE_MS,
    )
}

fn reolink_fallback_command(ptz_payload: &Value) -> Option<ReolinkFallbackPtzCommand> {
    if let Some(step) = parse_pose_step(ptz_payload) {
        if let Some(op) = reolink_fallback_direction_from_pose(step) {
            return Some(ReolinkFallbackPtzCommand {
                op,
                pulse_ms: Some(reolink_fallback_pulse_ms(step)),
                desired_pose: parse_requested_pose(ptz_payload)
                    .map(camera_pose_from_requested_pose)
                    .unwrap_or_default(),
                pose_status: "directed".to_string(),
            });
        }
    }

    let direction = ptz_payload
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("stop")
        .trim()
        .to_ascii_lowercase();
    let active = ptz_payload
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(direction != "stop");
    let op = match direction.as_str() {
        "left" => "Left",
        "right" => "Right",
        "up" => "Up",
        "down" => "Down",
        _ => "Stop",
    };
    Some(ReolinkFallbackPtzCommand {
        op,
        pulse_ms: if active && op != "Stop" {
            None
        } else {
            Some(0)
        },
        desired_pose: parse_requested_pose(ptz_payload)
            .map(camera_pose_from_requested_pose)
            .unwrap_or_default(),
        pose_status: if active && op != "Stop" {
            "moving".to_string()
        } else if op == "Stop" {
            "stopped".to_string()
        } else {
            "directed".to_string()
        },
    })
}

async fn control_reolink_cgi_fallback(
    camera: &CameraConfig,
    ptz_payload: &Value,
    native_error: Option<&str>,
) -> Result<CameraPtzControlResult> {
    // Current lab failure mode: native absolute still returns 405/no-move on the E1, and this CGI
    // fallback can exhaust camera-side login/session limits (`rspCode -5: max session`) under
    // repeated PTZ attempts because the camera is not yet accepting a reusable control session.
    let command = reolink_fallback_command(ptz_payload).ok_or_else(|| {
        anyhow!("Reolink CGI fallback could not derive a PTZ command from the request")
    })?;
    let connection = resolve_reolink_connection_for(
        &camera.onvif_host,
        &camera.username,
        &reolink_password_candidates(camera),
    )
    .await?;

    if command.op == "Stop" {
        reolink_cgi::ptz_stop(&connection).await?;
    } else {
        reolink_cgi::ptz_command(&connection, command.op, REOLINK_CGI_FALLBACK_SPEED).await?;
        if let Some(pulse_ms) = command.pulse_ms {
            if pulse_ms > 0 {
                sleep(Duration::from_millis(pulse_ms)).await;
                reolink_cgi::ptz_stop(&connection).await?;
            }
        }
    }

    let native_observation =
        try_reolink_native_ptz_observation(camera, &[connection.password.clone()]).await;

    Ok(CameraPtzControlResult {
        current_pose: native_observation
            .as_ref()
            .map(|observation| observation.normalized.clone())
            .unwrap_or_default(),
        desired_pose: command.desired_pose,
        pose_status: command.pose_status,
        management_plane: "cgi_fallback".to_string(),
        ptz_diagnostics: json!({
            "fallback": {
                "op": command.op,
                "pulseMs": command.pulse_ms,
                "speed": REOLINK_CGI_FALLBACK_SPEED,
            },
            "nativeObservation": native_observation.as_ref().map(reolink_native_ptz_json),
            "nativeError": native_error,
        }),
        ..Default::default()
    })
}

fn match_candidate(candidate: &DiscoveredCameraCandidate) -> DriverMatch {
    if let Some(matched) = ReolinkDriver.match_candidate(candidate) {
        return matched;
    }
    if let Some(matched) = Xm40eDriver.match_candidate(candidate) {
        return matched;
    }
    if let Some(matched) = GenericOnvifRtspDriver.match_candidate(candidate) {
        return matched;
    }
    DriverMatch {
        driver_id: String::new(),
        kind: "unmounted_candidate".to_string(),
        confidence: 0,
        reason: "no supported driver match yet".to_string(),
        mountable: false,
    }
}

fn driver_capabilities(camera: &CameraConfig) -> CameraCapabilitySet {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        ReolinkDriver.capabilities(camera)
    } else if driver_is_xm(&camera.driver_id) {
        Xm40eDriver.capabilities(camera)
    } else if camera.driver_id.trim() == DRIVER_ID_GENERIC_ONVIF_RTSP {
        GenericOnvifRtspDriver.capabilities(camera)
    } else {
        CameraCapabilitySet {
            live_view: true,
            ptz: camera.ptz_capable,
            raw_probe: true,
            ..Default::default()
        }
    }
}

fn capabilities_for_observed(
    camera: &CameraConfig,
    mut capabilities: CameraCapabilitySet,
    observed: &ObservedCameraState,
) -> CameraCapabilitySet {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        capabilities = reolink_runtime_capabilities(capabilities, observed);
    } else if camera.driver_id.trim() == DRIVER_ID_GENERIC_ONVIF_RTSP {
        capabilities = generic_onvif_runtime_capabilities(capabilities, observed);
    }
    if observed.ptz_capable {
        capabilities.ptz = true;
    }
    capabilities
}

fn reolink_runtime_capabilities(
    mut capabilities: CameraCapabilitySet,
    observed: &ObservedCameraState,
) -> CameraCapabilitySet {
    match observed_management_plane(observed).as_deref() {
        Some("hybrid") | Some("onvif") => {
            capabilities.time_sync = true;
            capabilities.manual_time = false;
            capabilities.timezone = true;
            capabilities.overlay_text = true;
            capabilities.overlay_timestamp = true;
            capabilities.password_rotate = true;
            capabilities.hardening_profile = true;
            capabilities.raw_probe = true;
            capabilities.ptz = observed.ptz_capable;
        }
        Some("cgi") => {
            capabilities.time_sync = false;
            capabilities.manual_time = false;
            capabilities.timezone = false;
            capabilities.overlay_text = true;
            capabilities.overlay_timestamp = true;
            capabilities.password_rotate = true;
            capabilities.hardening_profile = true;
            capabilities.raw_probe = true;
            capabilities.ptz = observed.ptz_capable;
        }
        Some("transport_only") | Some("unreachable") => {
            capabilities.time_sync = false;
            capabilities.manual_time = false;
            capabilities.timezone = false;
            capabilities.overlay_text = false;
            capabilities.overlay_timestamp = false;
            capabilities.password_rotate = false;
            capabilities.hardening_profile = false;
            capabilities.ptz = false;
            capabilities.raw_probe = true;
        }
        _ => {}
    }
    capabilities
}

fn generic_onvif_runtime_capabilities(
    mut capabilities: CameraCapabilitySet,
    observed: &ObservedCameraState,
) -> CameraCapabilitySet {
    match observed_management_plane(observed).as_deref() {
        Some("onvif") => {
            capabilities.time_sync = true;
            capabilities.manual_time = false;
            capabilities.timezone = true;
            capabilities.raw_probe = true;
        }
        Some("transport_only") | Some("unreachable") => {
            capabilities.time_sync = false;
            capabilities.manual_time = false;
            capabilities.timezone = false;
            capabilities.ptz = false;
            capabilities.raw_probe = true;
        }
        _ => {}
    }
    capabilities
}

fn observed_management_plane(observed: &ObservedCameraState) -> Option<String> {
    observed
        .raw
        .get("managementPlane")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

async fn apply_driver_mount(cfg: &Config, camera: &CameraConfig) -> Result<CameraConfig> {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        return apply_driver_desired(cfg, camera, camera).await;
    }
    if driver_is_xm(&camera.driver_id) {
        return apply_xm_40e_desired(cfg, camera, camera).await;
    }
    Ok(camera.clone())
}

async fn apply_driver_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    if next.driver_id.trim() == DRIVER_ID_REOLINK {
        apply_reolink_desired(cfg, existing, next).await
    } else if driver_is_xm(&next.driver_id) {
        apply_xm_40e_desired(cfg, existing, next).await
    } else if next.driver_id.trim() == DRIVER_ID_GENERIC_ONVIF_RTSP {
        apply_generic_onvif_desired(cfg, next).await
    } else {
        Ok(next.clone())
    }
}

async fn apply_generic_onvif_desired(cfg: &Config, next: &CameraConfig) -> Result<CameraConfig> {
    let policy = effective_site_time_policy(cfg, next);
    if !policy.ntp_enabled {
        return Ok(next.clone());
    }
    let _ = onvif::apply_site_time_settings(
        &next.onvif_host,
        next.onvif_port.max(1),
        &next.username,
        &next.password,
        &to_onvif_site_time_policy(&policy),
    )
    .await;
    Ok(next.clone())
}

async fn apply_xm_40e_desired(
    cfg: &Config,
    _existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    let _ = ffprobe_rtsp_stream(&next.rtsp_url)
        .await
        .with_context(|| format!("XM RTSP apply validation failed for {}", next.onvif_host))?;
    let request = xm_connect_request(next)?;
    let policy = effective_site_time_policy(cfg, next);
    let desired_display_title = nonempty_option(&camera_display_name(next));
    let site_time = if policy.ntp_enabled
        && !policy.ntp_server.trim().is_empty()
        && !policy.timezone.trim().is_empty()
    {
        Some(xm::XmSiteTimePolicy {
            ntp_server: policy.ntp_server.clone(),
            timezone_code: site_timezone_code(&policy.timezone, Utc::now())
                .ok_or_else(|| anyhow!("invalid site timezone {:?}", policy.timezone))?,
            current_local_time: site_local_time_string_for_xm(&policy.timezone, Utc::now())
                .ok_or_else(|| anyhow!("invalid site timezone {:?}", policy.timezone))?,
        })
    } else {
        None
    };
    let applied = xm::apply_state(
        &request,
        desired_display_title.as_deref(),
        None,
        site_time.as_ref(),
    )
    .await?;
    let model = applied.system.model_family.trim();
    let mut updated = next.clone();
    updated.driver_id = DRIVER_ID_XM_40E.to_string();
    updated.vendor = "XM/NetSurveillance".to_string();
    if !model.is_empty() {
        updated.model = model.to_string();
    }
    updated.desired.overlay_text.clear();
    updated.desired.overlay_timestamp = false;
    Ok(updated)
}

async fn apply_reolink_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    let ports = probe_common_ports(&next.onvif_host).await;
    if (ports.http || ports.https)
        && resolve_reolink_connection_for(
            &next.onvif_host,
            &next.username,
            &reolink_password_candidates(existing),
        )
        .await
        .is_ok()
    {
        return apply_reolink_cgi_desired(
            cfg,
            existing,
            next,
            ports.onvif && next.desired.hardening.enable_onvif,
            ports.onvif && next.desired.hardening.enable_onvif,
        )
        .await;
    }
    if ports.onvif {
        if reolink_desired_requires_cgi(existing, next) {
            return apply_reolink_onvif_bridge_desired(cfg, existing, next).await;
        }
        return apply_reolink_onvif_desired(cfg, existing, next).await;
    }
    Err(anyhow!(
        "no supported management plane is reachable for {} (cgi on 80/443 unavailable and ONVIF unavailable)",
        next.onvif_host
    ))
}

fn reolink_desired_requires_cgi(existing: &CameraConfig, next: &CameraConfig) -> bool {
    let current = &existing.desired;
    let desired = &next.desired;
    desired.generate_password
        || !desired.desired_password.trim().is_empty()
        || desired.overlay_text != current.overlay_text
        || desired.overlay_timestamp != current.overlay_timestamp
        || desired.hardening.enable_onvif != current.hardening.enable_onvif
        || desired.hardening.enable_rtsp != current.hardening.enable_rtsp
        || desired.hardening.disable_p2p != current.hardening.disable_p2p
        || desired.hardening.disable_http != current.hardening.disable_http
        || desired.hardening.disable_https != current.hardening.disable_https
        || desired.hardening.preserve_proprietary_9000
            != current.hardening.preserve_proprietary_9000
}

async fn apply_reolink_onvif_bridge_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    let _ = apply_reolink_onvif_desired(cfg, existing, next).await?;
    ensure_reolink_cgi_lane_via_onvif(existing).await?;
    apply_reolink_cgi_desired(cfg, existing, next, true, true).await
}

async fn apply_reolink_cgi_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
    allow_onvif_only_final_state: bool,
    apply_site_time_via_onvif: bool,
) -> Result<CameraConfig> {
    let desired = &next.desired;
    let final_cgi_disabled = desired.hardening.disable_http && desired.hardening.disable_https;
    if final_cgi_disabled && !(allow_onvif_only_final_state && desired.hardening.enable_onvif) {
        return Err(anyhow!(
            "refusing to disable both HTTP and HTTPS without a verified ONVIF recovery lane"
        ));
    }

    let mut updated = next.clone();
    let mut interim_hardening = desired.hardening.clone();
    if final_cgi_disabled {
        interim_hardening.disable_http = false;
        interim_hardening.disable_https = false;
    }
    let setup_request = build_reolink_setup_request(
        next,
        existing.password.clone(),
        desired.desired_password.clone(),
        desired.generate_password,
        &interim_hardening,
    )
    .context("invalid Reolink apply request")?;
    let rotation_requested = !setup_request.desired_password.trim().is_empty()
        && setup_request.desired_password.trim() != existing.password.trim();
    if rotation_requested {
        mark_camera_rotation_pending(
            &mut updated,
            &setup_request.desired_password,
            "rotation requested during camera apply",
        );
    }

    let setup =
        match try_reolink_setup(&setup_request, &reolink_password_candidates(existing)).await {
            Ok(setup) => setup,
            Err(error) => {
                mark_camera_rotation_failed(
                    &mut updated,
                    &format!("failed applying hardening/password state: {error}"),
                );
                return Ok(updated);
            }
        };

    let requested_password = if !setup.generated_password.trim().is_empty() {
        setup.generated_password.trim().to_string()
    } else {
        setup_request.desired_password.trim().to_string()
    };
    let active_connection = match resolve_reolink_connection_for(
        &next.onvif_host,
        &next.username,
        &reolink_post_apply_candidates(existing, &updated, &requested_password),
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            mark_camera_rotation_failed(
                &mut updated,
                &format!("unable to verify any camera credential after apply: {error}"),
            );
            return Ok(updated);
        }
    };
    let active_password = active_connection.password.clone();

    if rotation_requested {
        if !requested_password.is_empty() && active_password == requested_password {
            finalize_camera_password_rotation(
                &mut updated,
                &active_password,
                "verified",
                "credential rotation verified after apply",
            );
        } else {
            let recovery_error =
                "rotated credential was not verified; retained recovered credential instead";
            mark_camera_rotation_failed(&mut updated, recovery_error);
            adopt_camera_active_password(
                &mut updated,
                &active_password,
                "recovered",
                "recovered active credential after failed rotation verification",
                true,
            );
            updated.credentials.last_rotation_error = recovery_error.to_string();
        }
    } else {
        adopt_camera_active_password(
            &mut updated,
            &active_password,
            if active_password == existing.password {
                "verified"
            } else {
                "recovered"
            },
            if active_password == existing.password {
                "verified active credential after apply"
            } else {
                "recovered active credential from stored history"
            },
            true,
        );
    }

    let site_time = site_time_policy(cfg);
    if apply_site_time_via_onvif && site_time.ntp_enabled {
        if let Err(error) = onvif::apply_site_time_settings(
            &next.onvif_host,
            next.onvif_port.max(1),
            &next.username,
            &active_password,
            &to_onvif_site_time_policy(&site_time),
        )
        .await
        {
            let suffix = format!("failed applying site time policy through ONVIF: {error}");
            updated.credentials.last_rotation_error =
                if updated.credentials.last_rotation_error.trim().is_empty() {
                    suffix
                } else {
                    format!("{}; {}", updated.credentials.last_rotation_error, suffix)
                };
        }
    }

    if let Err(error) = reolink_cgi::apply_presentation_state(&reolink_cgi::ReolinkPresentationApplyRequest {
        connection: active_connection.clone(),
        // Reolink keeps the feed-facing clock presentation in CGI. Apply the
        // feed-facing fields on that lane and seed the current site-local wall
        // clock so the baked timestamp converges immediately instead of waiting
        // for the camera's next NTP poll. NTP mode/server remain ONVIF-owned.
        time_mode: None,
        ntp_server: None,
        manual_time: site_local_time_string(&site_time.timezone, Utc::now()),
        timezone: nonempty_option(&site_time.timezone),
        enforce_clock_display: true,
        overlay_text: nonempty_option(&desired.overlay_text),
        overlay_timestamp: Some(desired.overlay_timestamp),
    })
    .await {
        let suffix = format!("failed applying presentation state: {error}");
        updated.credentials.last_rotation_error =
            if updated.credentials.last_rotation_error.trim().is_empty() {
                suffix
            } else {
                format!("{}; {}", updated.credentials.last_rotation_error, suffix)
            };
    }

    if final_cgi_disabled {
        let finalize_request = build_reolink_setup_request(
            next,
            active_password.clone(),
            String::new(),
            false,
            &desired.hardening,
        )
        .context("invalid Reolink finalize request")?;
        if let Err(error) = try_reolink_setup(&finalize_request, &[active_password]).await {
            let suffix = format!("failed applying final hardening state: {error}");
            updated.credentials.last_rotation_error =
                if updated.credentials.last_rotation_error.trim().is_empty() {
                    suffix
                } else {
                    format!("{}; {}", updated.credentials.last_rotation_error, suffix)
                };
        }
    }

    Ok(updated)
}

fn build_reolink_setup_request(
    next: &CameraConfig,
    password: String,
    desired_password: String,
    generate_password: bool,
    hardening: &crate::config::CameraHardeningConfig,
) -> Result<reolink::ReolinkSetupRequest> {
    reolink::ReolinkSetupRequest {
        ip: next.onvif_host.clone(),
        username: next.username.clone(),
        password,
        desired_password,
        generate_password,
        normal: Some(reolink::ReolinkNormalPortConfig {
            i_surv_port_enable: 1,
            i_surv_port: 9000,
            i_http_port_enable: i32::from(!hardening.disable_http),
            i_http_port: 80,
            i_https_port_enable: i32::from(!hardening.disable_https),
            i_https_port: 443,
        }),
        advanced: Some(reolink::ReolinkAdvancedPortConfig {
            i_onvif_port_enable: i32::from(hardening.enable_onvif),
            i_onvif_port: next.onvif_port.max(1) as i32,
            i_rtsp_port_enable: i32::from(hardening.enable_rtsp),
            i_rtsp_port: next.rtsp_port.max(1) as i32,
            i_rtmp_port_enable: 0,
            i_rtmp_port: 1935,
        }),
        p2p: Some(reolink::ReolinkP2PConfig {
            i_enable: i32::from(!hardening.disable_p2p),
            i_port: 0,
            server_domain_name: String::new(),
        }),
    }
    .normalized()
}

async fn apply_reolink_onvif_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    let mut updated = next.clone();
    let site_time = site_time_policy(cfg);
    onvif::apply_site_time_settings(
        &next.onvif_host,
        next.onvif_port.max(1),
        &next.username,
        &existing.password,
        &to_onvif_site_time_policy(&site_time),
    )
    .await?;
    adopt_camera_active_password(
        &mut updated,
        &existing.password,
        "verified",
        "verified active credential through ONVIF management plane",
        false,
    );
    Ok(updated)
}

async fn ensure_reolink_cgi_lane_via_onvif(camera: &CameraConfig) -> Result<()> {
    let onvif_state = onvif::read_state(
        &camera.onvif_host,
        camera.onvif_port.max(1),
        &camera.username,
        &camera.password,
    )
    .await?;
    if !onvif_state.network_protocols_writable {
        return Err(anyhow!(
            "ONVIF network protocol control is unavailable, so a temporary Reolink CGI lane cannot be opened"
        ));
    }
    if resolve_reolink_connection_for(
        &camera.onvif_host,
        &camera.username,
        &reolink_password_candidates(camera),
    )
    .await
    .is_ok()
    {
        return Ok(());
    }

    let http = find_onvif_protocol(&onvif_state.network_protocols, "http", 80);
    let https = find_onvif_protocol(&onvif_state.network_protocols, "https", 443);
    let mut errors = Vec::new();
    for protocol in [http, https] {
        match onvif::set_network_protocol(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
            &protocol.name,
            true,
            protocol.port,
        )
        .await
        {
            Ok(()) => {
                for _ in 0..10 {
                    if probe_port(&camera.onvif_host, protocol.port).await {
                        break;
                    }
                    sleep(Duration::from_millis(250)).await;
                }
                if resolve_reolink_connection_for(
                    &camera.onvif_host,
                    &camera.username,
                    &reolink_password_candidates(camera),
                )
                .await
                .is_ok()
                {
                    return Ok(());
                }
            }
            Err(error) => errors.push(format!("{}: {error}", protocol.name)),
        }
    }

    Err(anyhow!(
        "failed to open a temporary Reolink CGI lane via ONVIF: {}",
        if errors.is_empty() {
            "camera did not expose a usable HTTP/HTTPS management protocol".to_string()
        } else {
            errors.join(" | ")
        }
    ))
}

fn find_onvif_protocol(
    protocols: &[onvif::OnvifNetworkProtocol],
    protocol_name: &str,
    default_port: u16,
) -> onvif::OnvifNetworkProtocol {
    protocols
        .iter()
        .find(|protocol| protocol.name.eq_ignore_ascii_case(protocol_name))
        .cloned()
        .unwrap_or(onvif::OnvifNetworkProtocol {
            name: protocol_name.to_ascii_uppercase(),
            enabled: false,
            port: default_port,
        })
}

async fn read_reolink_presentation_via_onvif_bridge(
    camera: &CameraConfig,
    onvif_state: &onvif::OnvifState,
) -> Result<reolink_cgi::ReolinkPresentationState> {
    if let Ok(connection) = resolve_reolink_connection_for(
        &camera.onvif_host,
        &camera.username,
        &reolink_password_candidates(camera),
    )
    .await
    {
        return reolink_cgi::read_presentation_state(&connection).await;
    }
    if !onvif_state.network_protocols_writable {
        return Err(anyhow!(
            "ONVIF network protocol control is unavailable, so Reolink presentation state cannot be read safely"
        ));
    }

    let http = find_onvif_protocol(&onvif_state.network_protocols, "http", 80);
    let https = find_onvif_protocol(&onvif_state.network_protocols, "https", 443);
    let originals = vec![http.clone(), https.clone()];
    let mut errors = Vec::new();

    for protocol in [http, https] {
        match onvif::set_network_protocol(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
            &protocol.name,
            true,
            protocol.port,
        )
        .await
        {
            Ok(()) => {
                for _ in 0..10 {
                    if probe_port(&camera.onvif_host, protocol.port).await {
                        break;
                    }
                    sleep(Duration::from_millis(250)).await;
                }
                match resolve_reolink_connection_for(
                    &camera.onvif_host,
                    &camera.username,
                    &reolink_password_candidates(camera),
                )
                .await
                {
                    Ok(connection) => {
                        let read = reolink_cgi::read_presentation_state(&connection).await;
                        let _ = restore_reolink_onvif_protocols(camera, &originals).await;
                        return read;
                    }
                    Err(error) => errors.push(format!("{} open/read: {error}", protocol.name)),
                }
            }
            Err(error) => errors.push(format!("{} enable: {error}", protocol.name)),
        }
    }

    let _ = restore_reolink_onvif_protocols(camera, &originals).await;
    Err(anyhow!(
        "failed to read Reolink presentation state via ONVIF bridge: {}",
        if errors.is_empty() {
            "camera did not expose a usable temporary HTTP/HTTPS lane".to_string()
        } else {
            errors.join(" | ")
        }
    ))
}

async fn restore_reolink_onvif_protocols(
    camera: &CameraConfig,
    protocols: &[onvif::OnvifNetworkProtocol],
) -> Result<()> {
    for protocol in protocols {
        onvif::set_network_protocol(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
            &protocol.name,
            protocol.enabled,
            protocol.port,
        )
        .await?;
    }
    Ok(())
}

async fn read_observed_state(camera: &CameraConfig) -> Result<ObservedCameraState> {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        read_reolink_observed_state(camera).await
    } else if driver_is_xm(&camera.driver_id) {
        read_xm_observed_state(camera).await
    } else {
        read_generic_observed_state(camera).await
    }
}

async fn read_reolink_observed_state(camera: &CameraConfig) -> Result<ObservedCameraState> {
    let ports = probe_common_ports(&camera.onvif_host).await;
    let probe = reolink::probe(&camera.onvif_host, 2)
        .await
        .unwrap_or_default();
    if ports.http || ports.https {
        if let Ok((connection, state)) = resolve_reolink_state(camera).await {
            let presentation = reolink_cgi::read_presentation_state(&connection)
                .await
                .unwrap_or_default();
            let onvif_state = if ports.onvif {
                onvif::read_state(
                    &camera.onvif_host,
                    camera.onvif_port.max(1),
                    &camera.username,
                    &connection.password,
                )
                .await
                .ok()
            } else {
                None
            };
            let ptz_capable = reolink_ptz_capable(camera, &probe, &presentation);
            let native_ptz = if probe.proprietary_port_open {
                try_reolink_native_ptz_observation(camera, &[connection.password.clone()]).await
            } else {
                None
            };
            let management_plane = if onvif_state.is_some() {
                "hybrid"
            } else {
                "cgi"
            };
            return Ok(ObservedCameraState {
                display_name: presentation.overlay_text.trim().to_string(),
                driver_id: camera.driver_id.clone(),
                vendor: first_nonempty(
                    &camera.vendor,
                    &onvif_state
                        .as_ref()
                        .map(|state| first_nonempty(&state.manufacturer, "Reolink"))
                        .unwrap_or_else(|| "Reolink".to_string()),
                ),
                model: first_nonempty(
                    &camera.model,
                    &onvif_state
                        .as_ref()
                        .map(|state| first_nonempty(&state.model, &presentation.model))
                        .unwrap_or_else(|| presentation.model.clone()),
                ),
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                time_mode: reolink_observed_time_mode(onvif_state.as_ref(), &presentation),
                ntp_server: reolink_observed_ntp_server(onvif_state.as_ref(), &presentation),
                manual_time: reolink_observed_manual_time(onvif_state.as_ref(), &presentation),
                timezone: reolink_observed_timezone(onvif_state.as_ref(), &presentation),
                overlay_text: presentation.overlay_text.clone(),
                overlay_timestamp: presentation.overlay_timestamp,
                ptz_capable,
                current_pose: native_ptz
                    .as_ref()
                    .map(|native| native.normalized.clone())
                    .unwrap_or_default(),
                pose_status: if native_ptz.is_some() {
                    "settled".to_string()
                } else {
                    String::new()
                },
                pose_source: if native_ptz.is_some() {
                    "reolink_native".to_string()
                } else {
                    "cgi".to_string()
                },
                services: json!({
                    "managementPlane": management_plane,
                    "timeManagementPlane": if onvif_state.is_some() { "hybrid" } else { "cgi" },
                    "normalizedTimeManagementPlane": if onvif_state.is_some() { "onvif" } else { "cgi" },
                    "feedClockManagementPlane": "cgi",
                    "presentationManagementPlane": "cgi",
                    "ptzManagementPlane": if native_ptz.is_some() { "reolink_native_absolute" } else { "cgi" },
                    "http": state.state.normal.get("iHttpPortEnable").cloned().unwrap_or(json!(0)),
                    "https": state.state.normal.get("iHttpsPortEnable").cloned().unwrap_or(json!(0)),
                    "onvif": state.state.advanced.get("iOnvifPortEnable").cloned().unwrap_or(json!(0)),
                    "rtsp": state.state.advanced.get("iRtspPortEnable").cloned().unwrap_or(json!(0)),
                    "p2p": state.state.p2p.get("iEnable").cloned().unwrap_or(json!(0)),
                    "proprietary9000": probe.proprietary_port_open,
                    "onvifXAddr": probe.onvif_xaddr,
                    "networkProtocols": onvif_state.as_ref().map(|state| state.network_protocols.clone()).unwrap_or_default(),
                    "networkProtocolsSupported": onvif_state.as_ref().map(|state| state.network_protocols_writable).unwrap_or(false),
                }),
                raw: json!({
                    "managementPlane": management_plane,
                    "probe": probe,
                    "state": state.state,
                    "presentation": presentation,
                    "onvif": onvif_state.as_ref().map(|state| state.raw.clone()),
                    "nativePtz": native_ptz.as_ref().map(reolink_native_ptz_json),
                }),
            });
        }
    }
    if ports.onvif {
        if let Ok(onvif_state) = onvif::read_state(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
        )
        .await
        {
            let presentation = read_reolink_presentation_via_onvif_bridge(camera, &onvif_state)
                .await
                .unwrap_or_default();
            let ptz_capable = reolink_ptz_capable_from_strings(
                onvif_state.ptz_capable || camera.ptz_capable,
                &[
                    &camera.model,
                    &camera.name,
                    &onvif_state.model,
                    &presentation.model,
                ],
            );
            let native_ptz = if probe.proprietary_port_open {
                try_reolink_native_ptz_observation(camera, &[]).await
            } else {
                None
            };
            let management_plane = if !presentation.overlay_text.trim().is_empty()
                || presentation.overlay_timestamp.is_some()
                || !presentation.clock_date_format.trim().is_empty()
            {
                "hybrid"
            } else {
                "onvif"
            };
            return Ok(ObservedCameraState {
                display_name: presentation.overlay_text.trim().to_string(),
                driver_id: camera.driver_id.clone(),
                vendor: first_nonempty(
                    &camera.vendor,
                    &first_nonempty(&onvif_state.manufacturer, "Reolink"),
                ),
                model: first_nonempty(&camera.model, &onvif_state.model),
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                time_mode: reolink_observed_time_mode(Some(&onvif_state), &presentation),
                ntp_server: reolink_observed_ntp_server(Some(&onvif_state), &presentation),
                manual_time: reolink_observed_manual_time(Some(&onvif_state), &presentation),
                timezone: reolink_observed_timezone(Some(&onvif_state), &presentation),
                overlay_text: presentation.overlay_text.clone(),
                overlay_timestamp: presentation.overlay_timestamp,
                ptz_capable,
                current_pose: native_ptz
                    .as_ref()
                    .map(|native| native.normalized.clone())
                    .unwrap_or_else(|| CameraPose {
                        pan: onvif_state.current_pose.as_ref().and_then(|pose| pose.pan),
                        tilt: onvif_state.current_pose.as_ref().and_then(|pose| pose.tilt),
                        zoom: onvif_state.current_pose.as_ref().and_then(|pose| pose.zoom),
                    }),
                pose_status: if native_ptz.is_some() {
                    "settled".to_string()
                } else {
                    first_nonempty(&onvif_state.pose_status, "idle")
                },
                pose_source: if native_ptz.is_some() {
                    "reolink_native".to_string()
                } else {
                    "onvif".to_string()
                },
                services: json!({
                    "managementPlane": management_plane,
                    "timeManagementPlane": if management_plane == "hybrid" { "hybrid" } else { "onvif" },
                    "normalizedTimeManagementPlane": "onvif",
                    "feedClockManagementPlane": if management_plane == "hybrid" { "cgi" } else { "onvif" },
                    "presentationManagementPlane": if management_plane == "hybrid" { "cgi" } else { "onvif" },
                    "ptzManagementPlane": if native_ptz.is_some() { "reolink_native_absolute" } else { "onvif" },
                    "http": ports.http,
                    "https": ports.https,
                    "onvif": ports.onvif,
                    "rtsp": ports.rtsp,
                    "proprietary9000": ports.proprietary_9000,
                    "onvifXAddr": probe.onvif_xaddr,
                    "mediaService": onvif_state.media_service_url,
                    "ptzService": onvif_state.ptz_service_url,
                    "profileToken": onvif_state.profile_token,
                    "networkProtocols": onvif_state.network_protocols,
                    "networkProtocolsSupported": onvif_state.network_protocols_writable,
                }),
                raw: json!({
                    "managementPlane": management_plane,
                    "probe": probe,
                    "onvif": onvif_state.raw,
                    "presentation": presentation,
                    "nativePtz": native_ptz.as_ref().map(reolink_native_ptz_json),
                }),
            });
        }
    }
    Err(anyhow!(
        "no supported management plane could read state for {} (cgi on 80/443 unavailable and ONVIF authentication/read failed)",
        camera.onvif_host
    ))
}

async fn probe_reolink_candidate(
    candidate: &DiscoveredCameraCandidate,
    request: &ProbeCameraRequest,
) -> Result<Value> {
    let probe = reolink::probe(&candidate.ip, 2).await.unwrap_or_default();
    let ports = probe_common_ports(&candidate.ip).await;
    if ports.http || ports.https {
        if let Ok(connection) = resolve_reolink_connection_for(
            &candidate.ip,
            request.username.trim(),
            &[request.password.trim().to_string()],
        )
        .await
        {
            let state = reolink_cgi::read_state(&connection).await?;
            let presentation = reolink_cgi::read_presentation_state(&connection)
                .await
                .unwrap_or_default();
            let ptz_capable = reolink_ptz_capable_from_strings(
                false,
                &[
                    &candidate.signatures.model,
                    &candidate.signatures.public_title,
                    &presentation.model,
                ],
            );
            return Ok(json!({
                "driverId": DRIVER_ID_REOLINK,
                "status": "ok",
                "message": "Reolink CGI management plane authenticated and read current device state.",
                "observed": {
                    "vendor": first_nonempty(&candidate.signatures.vendor, "Reolink"),
                    "model": first_nonempty(&presentation.model, &candidate.signatures.model),
                    "ip": candidate.ip,
                    "timeMode": presentation.time_mode,
                    "ntpServer": presentation.ntp_server,
                    "manualTime": presentation.manual_time,
                    "timezone": presentation.timezone,
                    "overlayText": presentation.overlay_text,
                    "overlayTimestamp": presentation.overlay_timestamp,
                    "ptzCapable": ptz_capable,
                },
                "services": {
                    "managementPlane": "cgi",
                    "http": state.state.normal.get("iHttpPortEnable").cloned().unwrap_or(json!(0)),
                    "https": state.state.normal.get("iHttpsPortEnable").cloned().unwrap_or(json!(0)),
                    "onvif": state.state.advanced.get("iOnvifPortEnable").cloned().unwrap_or(json!(0)),
                    "rtsp": state.state.advanced.get("iRtspPortEnable").cloned().unwrap_or(json!(0)),
                    "p2p": state.state.p2p.get("iEnable").cloned().unwrap_or(json!(0)),
                    "proprietary9000": probe.proprietary_port_open,
                    "onvifXAddr": probe.onvif_xaddr,
                },
                "raw": {
                    "managementPlane": "cgi",
                    "probe": probe,
                    "state": state.state,
                    "presentation": presentation,
                }
            }));
        }
    }
    if ports.onvif {
        let onvif_state = onvif::read_state(
            &candidate.ip,
            derive_onvif_port(candidate),
            request.username.trim(),
            request.password.trim(),
        )
        .await?;
        let temp_camera = CameraConfig {
            source_id: build_source_id(candidate, DRIVER_ID_REOLINK),
            name: candidate_display_name(candidate),
            onvif_host: candidate.ip.clone(),
            onvif_port: derive_onvif_port(candidate),
            rtsp_url: derive_rtsp_url(
                candidate,
                DRIVER_ID_REOLINK,
                request.username.trim(),
                request.password.trim(),
                "",
            ),
            username: request.username.trim().to_string(),
            password: request.password.trim().to_string(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: first_nonempty(&candidate.signatures.vendor, "Reolink"),
            model: candidate.signatures.model.clone(),
            mac_address: candidate.mac.clone(),
            rtsp_port: 554,
            ptz_capable: candidate_ptz_capable(candidate),
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig::default(),
            credentials: Default::default(),
        };
        let presentation = read_reolink_presentation_via_onvif_bridge(&temp_camera, &onvif_state)
            .await
            .unwrap_or_default();
        let ptz_capable = reolink_ptz_capable_from_strings(
            onvif_state.ptz_capable,
            &[
                &candidate.signatures.model,
                &candidate.signatures.public_title,
                &onvif_state.model,
                &presentation.model,
            ],
        );
        return Ok(json!({
            "driverId": DRIVER_ID_REOLINK,
            "status": "ok",
            "message": "Reolink ONVIF management plane authenticated and read current device state.",
            "observed": {
                "vendor": first_nonempty(&candidate.signatures.vendor, &first_nonempty(&onvif_state.manufacturer, "Reolink")),
                "model": first_nonempty(&onvif_state.model, &candidate.signatures.model),
                "ip": candidate.ip,
                "timeMode": reolink_observed_time_mode(Some(&onvif_state), &presentation),
                "ntpServer": reolink_observed_ntp_server(Some(&onvif_state), &presentation),
                "manualTime": first_nonempty(&onvif_state.manual_time, &presentation.manual_time),
                "timezone": reolink_observed_timezone(Some(&onvif_state), &presentation),
                "overlayText": presentation.overlay_text,
                "overlayTimestamp": presentation.overlay_timestamp,
                "ptzCapable": ptz_capable,
            },
            "services": {
                "managementPlane": "onvif",
                "timeManagementPlane": if presentation.timezone.trim().is_empty() { "onvif" } else { "hybrid" },
                "normalizedTimeManagementPlane": "onvif",
                "feedClockManagementPlane": if presentation.timezone.trim().is_empty() { "onvif" } else { "cgi" },
                "http": ports.http,
                "https": ports.https,
                "onvif": ports.onvif,
                "rtsp": ports.rtsp,
                "proprietary9000": probe.proprietary_port_open,
                "onvifXAddr": probe.onvif_xaddr,
                "mediaService": onvif_state.media_service_url,
                "ptzService": onvif_state.ptz_service_url,
                "profileToken": onvif_state.profile_token,
                "networkProtocols": onvif_state.network_protocols,
                "networkProtocolsSupported": onvif_state.network_protocols_writable,
            },
            "raw": {
                "managementPlane": "onvif",
                "probe": probe,
                "onvif": onvif_state.raw,
                "presentation": presentation,
            }
        }));
    }
    Err(anyhow!(
        "no supported management plane could probe {} (cgi on 80/443 unavailable and ONVIF authentication/read failed)",
        candidate.ip
    ))
}

fn xm_connect_request(camera: &CameraConfig) -> Result<xm::XmConnectRequest> {
    let host = camera.onvif_host.trim();
    let username = camera.username.trim();
    let password = camera.password.trim();
    if host.is_empty() {
        return Err(anyhow!("XM host is not configured"));
    }
    if username.is_empty() || password.is_empty() {
        return Err(anyhow!(
            "XM management credentials are required for {}",
            camera.source_id
        ));
    }
    Ok(xm::XmConnectRequest {
        host: host.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    })
}

async fn probe_xm_candidate(
    candidate: &DiscoveredCameraCandidate,
    request: &ProbeCameraRequest,
) -> Result<Value> {
    let xm_request = xm::XmConnectRequest {
        host: candidate.ip.trim().to_string(),
        username: request.username.trim().to_string(),
        password: request.password.trim().to_string(),
    };
    let xm_state = xm::read_state(&xm_request)
        .await
        .context("XM management probe failed")?;
    let main_url = derive_rtsp_url(
        candidate,
        DRIVER_ID_XM_40E,
        request.username.trim(),
        request.password.trim(),
        "",
    );
    let preview_url = xm_preview_rtsp_url(&main_url);
    let main = ffprobe_rtsp_stream(&main_url)
        .await
        .context("XM RTSP main stream probe failed")?;
    let preview = ffprobe_rtsp_stream(&preview_url)
        .await
        .unwrap_or(Value::Null);
    let ports = probe_common_ports(&candidate.ip).await;
    Ok(json!({
        "driverId": DRIVER_ID_XM_40E,
        "status": "ok",
        "message": "XM 40E management and RTSP paths authenticated and returned live state.",
        "observed": {
            "vendor": xm_state.system.vendor,
            "model": xm_state.system.model_family,
            "ip": candidate.ip,
            "displayName": xm_state.video.title_text,
            "timeMode": xm_state.time.time_mode,
            "ntpServer": xm_state.time.ntp_server,
            "manualTime": xm_state.time.current_time_iso,
            "timezone": xm_state.time.timezone_offset_label,
        },
        "services": {
            "managementPlane": DRIVER_ID_XM_40E,
            "http": ports.http,
            "https": ports.https,
            "rtsp": ports.rtsp,
            "onvif": ports.onvif,
            "proprietary9000": ports.proprietary_9000,
        },
        "raw": {
            "managementPlane": DRIVER_ID_XM_40E,
            "system": xm_state.system,
            "time": xm_state.time,
            "video": xm_state.video,
            "mainStream": main,
            "previewStream": preview,
        }
    }))
}

async fn ffprobe_rtsp_stream(url: &str) -> Result<Value> {
    let output = timeout(
        Duration::from_secs(12),
        TokioCommand::new("ffprobe")
            .arg("-v")
            .arg("error")
            .arg("-rtsp_transport")
            .arg("tcp")
            .arg("-timeout")
            .arg("5000000")
            .arg("-i")
            .arg(url)
            .arg("-show_entries")
            .arg("stream=codec_name,codec_type,width,height")
            .arg("-of")
            .arg("json")
            .output(),
    )
    .await
    .context("ffprobe timed out")??;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(if stderr.is_empty() {
            "ffprobe failed to read stream".to_string()
        } else {
            stderr
        }));
    }
    serde_json::from_slice(&output.stdout).context("ffprobe returned invalid json")
}

async fn read_generic_observed_state(camera: &CameraConfig) -> Result<ObservedCameraState> {
    let ports = probe_common_ports(&camera.onvif_host).await;
    if ports.onvif {
        if let Ok(onvif_state) = onvif::read_state(
            &camera.onvif_host,
            camera.onvif_port.max(1),
            &camera.username,
            &camera.password,
        )
        .await
        {
            return Ok(ObservedCameraState {
                display_name: camera_display_name(camera),
                driver_id: camera.driver_id.clone(),
                vendor: first_nonempty(&camera.vendor, &onvif_state.manufacturer),
                model: first_nonempty(&camera.model, &onvif_state.model),
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                time_mode: onvif_state.time_mode.clone(),
                ntp_server: onvif_state.ntp_server.clone(),
                manual_time: onvif_state.manual_time.clone(),
                timezone: onvif_state.timezone.clone(),
                overlay_text: camera.desired.overlay_text.clone(),
                overlay_timestamp: Some(camera.desired.overlay_timestamp),
                ptz_capable: camera.ptz_capable || onvif_state.ptz_capable,
                current_pose: CameraPose {
                    pan: onvif_state.current_pose.as_ref().and_then(|pose| pose.pan),
                    tilt: onvif_state.current_pose.as_ref().and_then(|pose| pose.tilt),
                    zoom: onvif_state.current_pose.as_ref().and_then(|pose| pose.zoom),
                },
                pose_status: onvif_state.pose_status.clone(),
                pose_source: "onvif".to_string(),
                services: json!({
                    "managementPlane": "onvif",
                    "http": ports.http,
                    "https": ports.https,
                    "rtsp": ports.rtsp,
                    "onvif": ports.onvif,
                    "proprietary9000": ports.proprietary_9000,
                    "mediaService": onvif_state.media_service_url,
                    "ptzService": onvif_state.ptz_service_url,
                }),
                raw: json!({
                    "managementPlane": "onvif",
                    "onvif": onvif_state.raw,
                }),
            });
        }
    }
    Ok(ObservedCameraState {
        display_name: camera_display_name(camera),
        driver_id: camera.driver_id.clone(),
        vendor: camera.vendor.clone(),
        model: camera.model.clone(),
        ip: camera.onvif_host.clone(),
        mac_address: camera.mac_address.clone(),
        time_mode: String::new(),
        ntp_server: String::new(),
        manual_time: String::new(),
        timezone: String::new(),
        overlay_text: camera.desired.overlay_text.clone(),
        overlay_timestamp: Some(camera.desired.overlay_timestamp),
        ptz_capable: camera.ptz_capable,
        current_pose: CameraPose::default(),
        pose_status: String::new(),
        pose_source: String::new(),
        services: json!({
            "managementPlane": if ports.onvif { "transport_only" } else { "unreachable" },
            "http": ports.http,
            "https": ports.https,
            "rtsp": ports.rtsp,
            "onvif": ports.onvif,
            "proprietary9000": ports.proprietary_9000,
        }),
        raw: json!({
            "managementPlane": if ports.onvif { "transport_only" } else { "unreachable" },
        }),
    })
}

async fn read_xm_observed_state(camera: &CameraConfig) -> Result<ObservedCameraState> {
    let ports = probe_common_ports(&camera.onvif_host).await;
    let xm_state = xm::read_state(&xm_connect_request(camera)?).await?;
    Ok(ObservedCameraState {
        display_name: first_nonempty(&xm_state.video.title_text, &camera_display_name(camera)),
        driver_id: DRIVER_ID_XM_40E.to_string(),
        vendor: first_nonempty(&xm_state.system.vendor, "XM/NetSurveillance"),
        model: first_nonempty(&xm_state.system.model_family, "XM Camera"),
        ip: camera.onvif_host.clone(),
        mac_address: camera.mac_address.clone(),
        time_mode: xm_state.time.time_mode.clone(),
        ntp_server: xm_state.time.ntp_server.clone(),
        manual_time: xm_state.time.current_time_iso.clone(),
        timezone: xm_state.time.timezone_offset_label.clone(),
        overlay_text: xm_state.video.user_title_text.clone(),
        overlay_timestamp: None,
        ptz_capable: false,
        current_pose: CameraPose::default(),
        pose_status: "unsupported".to_string(),
        pose_source: String::new(),
        services: json!({
            "managementPlane": DRIVER_ID_XM_40E,
            "timeManagementPlane": "xm_time_config",
            "nameManagementPlane": "xm_osd_title",
            "http": ports.http,
            "https": ports.https,
            "rtsp": ports.rtsp,
            "onvif": ports.onvif,
            "proprietary9000": ports.proprietary_9000,
            "serialNumber": xm_state.system.serial_number,
            "firmwareVersion": xm_state.system.firmware_version,
        }),
        raw: json!({
            "managementPlane": DRIVER_ID_XM_40E,
            "timeManagementPlane": "xm_time_config",
            "nameManagementPlane": "xm_osd_title",
            "system": xm_state.system,
            "time": xm_state.time,
            "video": xm_state.video,
        }),
    })
}

async fn fallback_observed_state(camera: &CameraConfig) -> ObservedCameraState {
    let ports = probe_common_ports(&camera.onvif_host).await;
    ObservedCameraState {
        display_name: camera_display_name(camera),
        driver_id: camera.driver_id.clone(),
        vendor: camera.vendor.clone(),
        model: camera.model.clone(),
        ip: camera.onvif_host.clone(),
        mac_address: camera.mac_address.clone(),
        time_mode: String::new(),
        ntp_server: String::new(),
        manual_time: String::new(),
        timezone: String::new(),
        overlay_text: String::new(),
        overlay_timestamp: None,
        ptz_capable: camera.ptz_capable,
        current_pose: CameraPose::default(),
        pose_status: String::new(),
        pose_source: String::new(),
        services: json!({
            "managementPlane": if ports.onvif { "transport_only" } else { "unreachable" },
            "http": ports.http,
            "https": ports.https,
            "rtsp": ports.rtsp,
            "onvif": ports.onvif,
            "proprietary9000": ports.proprietary_9000,
        }),
        raw: json!({
            "managementPlane": if ports.onvif { "transport_only" } else { "unreachable" },
        }),
    }
}

fn verification_for_observed(
    cfg: &Config,
    camera: &CameraConfig,
    observed: &ObservedCameraState,
    capabilities: &CameraCapabilitySet,
    failed_fields: Vec<String>,
) -> CameraReconcileResult {
    let site_time = effective_site_time_policy(cfg, camera);
    let mut drift_fields = Vec::new();
    if !camera.desired.display_name.trim().is_empty()
        && camera.desired.display_name.trim() != observed.display_name.trim()
    {
        drift_fields.push("display_name".to_string());
    }
    if capabilities.time_sync
        && site_time.ntp_enabled
        && observed.time_mode.trim() != "ntp"
    {
        drift_fields.push("time_mode".to_string());
    }
    if capabilities.time_sync
        && site_time.ntp_enabled
        && !site_time.ntp_server.trim().is_empty()
        && !site_time
            .ntp_server
            .trim()
            .eq_ignore_ascii_case(observed.ntp_server.trim())
    {
        drift_fields.push("ntp_server".to_string());
    }
    if capabilities.timezone
        && site_time.ntp_enabled
        && !site_time.timezone.trim().is_empty()
        && !observed_timezone_matches(&site_time, observed)
    {
        drift_fields.push("timezone".to_string());
    }
    if capabilities.time_sync
        && site_time.ntp_enabled
        && !site_time.timezone.trim().is_empty()
        && !observed.manual_time.trim().is_empty()
        && observed_site_time_offset_secs(
            &site_time.timezone,
            &observed.manual_time,
            Utc::now(),
        )
        .is_some_and(|offset| offset > CAMERA_TIME_MAX_DRIFT_SECS)
    {
        drift_fields.push("time_clock".to_string());
    }
    if capabilities.overlay_text
        && !camera.desired.overlay_text.trim().is_empty()
        && camera.desired.overlay_text.trim() != observed.overlay_text.trim()
    {
        drift_fields.push("overlay_text".to_string());
    }
    if capabilities.overlay_timestamp
        && observed.overlay_timestamp != Some(camera.desired.overlay_timestamp)
    {
        drift_fields.push("overlay_timestamp".to_string());
    }

    let status = if !failed_fields.is_empty() {
        "failed"
    } else if !drift_fields.is_empty() {
        "drift"
    } else {
        "verified"
    };
    CameraReconcileResult {
        status: status.to_string(),
        message: match status {
            "failed" => "camera configuration apply failed".to_string(),
            "drift" => "camera configuration drift detected".to_string(),
            _ => "camera configuration verified".to_string(),
        },
        applied_fields: applied_fields(cfg, camera, capabilities),
        failed_fields,
        unsupported_fields: unsupported_fields(cfg, camera, capabilities),
        drift_fields,
        verified: status == "verified",
    }
}

fn applied_fields(
    cfg: &Config,
    camera: &CameraConfig,
    capabilities: &CameraCapabilitySet,
) -> Vec<String> {
    let site_time = effective_site_time_policy(cfg, camera);
    let mut fields = vec!["display_name".to_string()];
    if capabilities.time_sync && site_time.ntp_enabled {
        fields.extend(
            ["time_mode", "ntp_server", "timezone"]
                .into_iter()
                .map(String::from),
        );
    }
    if capabilities.overlay_text {
        fields.push("overlay_text".to_string());
    }
    if capabilities.overlay_timestamp {
        fields.push("overlay_timestamp".to_string());
    }
    if capabilities.password_rotate
        && (!camera.desired.desired_password.trim().is_empty() || camera.desired.generate_password)
    {
        fields.push("password_rotate".to_string());
    }
    if capabilities.hardening_profile {
        fields.push("hardening".to_string());
    }
    fields
}

fn unsupported_fields(
    cfg: &Config,
    camera: &CameraConfig,
    capabilities: &CameraCapabilitySet,
) -> Vec<String> {
    let site_time = effective_site_time_policy(cfg, camera);
    let mut fields = Vec::new();
    if !capabilities.time_sync && site_time.ntp_enabled {
        fields.push("ntp_server".to_string());
    }
    if !capabilities.timezone && site_time.ntp_enabled {
        fields.push("timezone".to_string());
    }
    if !capabilities.overlay_text && !camera.desired.overlay_text.trim().is_empty() {
        fields.push("overlay_text".to_string());
    }
    if !capabilities.overlay_timestamp {
        fields.push("overlay_timestamp".to_string());
    }
    if !capabilities.password_rotate
        && (!camera.desired.desired_password.trim().is_empty() || camera.desired.generate_password)
    {
        fields.push("password_rotate".to_string());
    }
    if !capabilities.hardening_profile {
        fields.push("hardening".to_string());
    }
    fields.sort();
    fields.dedup();
    fields
}

async fn hydrate_candidate(
    candidate: &mut DiscoveredCameraCandidate,
    client: &Client,
) -> Result<()> {
    let probe = probe_common_ports(&candidate.ip).await;
    candidate.transports.http = candidate.transports.http || probe.http;
    candidate.transports.https = candidate.transports.https || probe.https;
    candidate.transports.rtsp = candidate.transports.rtsp || probe.rtsp;
    candidate.transports.onvif = candidate.transports.onvif || probe.onvif;
    candidate.transports.proprietary_9000 =
        candidate.transports.proprietary_9000 || probe.proprietary_9000;
    let fingerprint = if candidate.signatures.public_title.trim().is_empty()
        || candidate.signatures.vendor.trim().is_empty()
        || candidate.signatures.model.trim().is_empty()
    {
        fetch_http_fingerprint(client, &candidate.ip, probe.http, probe.https)
            .await
            .unwrap_or_default()
    } else {
        HttpFingerprint::default()
    };
    if candidate.signatures.public_title.trim().is_empty() && !fingerprint.title.trim().is_empty() {
        candidate.signatures.public_title = fingerprint.title.clone();
    }
    if is_xm_http_fingerprint(&fingerprint) {
        candidate.signatures.vendor =
            first_nonempty(&candidate.signatures.vendor, "XM/NetSurveillance");
        candidate.signatures.model =
            first_nonempty(&candidate.signatures.model, "XM 40E-class camera");
        if candidate.signatures.public_title.trim().is_empty() {
            candidate.signatures.public_title = "XM/NetSurveillance 40E-class camera".to_string();
        }
    }
    if candidate.signatures.vendor.trim().is_empty() {
        candidate.signatures.vendor = vendor_from_candidate(candidate);
    }
    if candidate.signatures.model.trim().is_empty() {
        candidate.signatures.model = model_from_candidate(candidate);
    }
    Ok(())
}

fn blank_candidate(ip: &str) -> DiscoveredCameraCandidate {
    DiscoveredCameraCandidate {
        ip: ip.trim().to_string(),
        ..Default::default()
    }
}

fn candidate_sort_key(candidate: &DiscoveredCameraCandidate) -> String {
    format!(
        "{}|{}",
        candidate_display_name(candidate).to_ascii_lowercase(),
        candidate.ip
    )
}

fn candidate_display_name(candidate: &DiscoveredCameraCandidate) -> String {
    first_nonempty(
        &candidate.signatures.model,
        &first_nonempty(
            &candidate.signatures.public_title,
            &first_nonempty(&candidate.lease_hostname, &candidate.ip),
        ),
    )
}

fn candidate_ptz_capable(candidate: &DiscoveredCameraCandidate) -> bool {
    reolink_ptz_capable_from_strings(
        false,
        &[
            &candidate.signatures.model,
            &candidate.signatures.public_title,
        ],
    )
}

fn reolink_ptz_capable(
    camera: &CameraConfig,
    probe: &reolink::ReolinkProbe,
    presentation: &reolink_cgi::ReolinkPresentationState,
) -> bool {
    reolink_ptz_capable_from_strings(
        camera.ptz_capable
            || probe.proprietary_port_open
                && camera.model.to_ascii_lowercase().contains("trackmix"),
        &[&camera.model, &camera.name, &presentation.model],
    )
}

fn reolink_ptz_capable_from_strings(base: bool, labels: &[&str]) -> bool {
    if base {
        return true;
    }
    labels.iter().any(|label| {
        let lowered = label.to_ascii_lowercase();
        lowered.contains("ptz")
            || lowered.contains("trackmix")
            || lowered.contains("e1")
            || lowered.contains("duo floodlight")
    })
}

fn candidate_id(candidate: &DiscoveredCameraCandidate) -> String {
    sanitize_id(if !candidate.mac.trim().is_empty() {
        &candidate.mac
    } else {
        &candidate.ip
    })
}

fn build_source_id(candidate: &DiscoveredCameraCandidate, driver_id: &str) -> String {
    let raw =
        if driver_id == DRIVER_ID_REOLINK && !candidate.signatures.reolink_uid.trim().is_empty() {
            format!("reolink-{}", candidate.signatures.reolink_uid.trim())
        } else if driver_id == DRIVER_ID_REOLINK {
            format!("reolink-{}", candidate.ip.trim())
        } else if driver_is_xm(driver_id) {
            format!("xm-{}", candidate.ip.trim())
        } else {
            format!(
                "camera-{}-{}",
                first_nonempty(&candidate.signatures.vendor, "generic"),
                first_nonempty(&candidate.signatures.model, &candidate.ip),
            )
        };
    sanitize_id(&raw)
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn derive_vendor(candidate: &DiscoveredCameraCandidate, driver_id: &str) -> String {
    if !candidate.signatures.vendor.trim().is_empty() {
        candidate.signatures.vendor.trim().to_string()
    } else if driver_id == DRIVER_ID_REOLINK {
        "Reolink".to_string()
    } else if driver_is_xm(driver_id) {
        "XM/NetSurveillance".to_string()
    } else {
        "ONVIF/RTSP".to_string()
    }
}

fn derive_onvif_port(candidate: &DiscoveredCameraCandidate) -> u16 {
    host_and_port_from_xaddr(&candidate.transports.onvif_xaddr)
        .map(|(_, port)| port)
        .unwrap_or(8000)
}

fn derive_rtsp_port(candidate: &DiscoveredCameraCandidate, explicit_rtsp_url: &str) -> u16 {
    if let Ok(url) = Url::parse(explicit_rtsp_url) {
        if let Some(port) = url.port() {
            return port;
        }
    }
    let _ = candidate;
    554
}

fn derive_rtsp_url(
    candidate: &DiscoveredCameraCandidate,
    driver_id: &str,
    username: &str,
    password: &str,
    explicit_rtsp_url: &str,
) -> String {
    let explicit = explicit_rtsp_url.trim();
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    let auth = if username.trim().is_empty() {
        String::new()
    } else {
        format!("{}:{}@", username.trim(), password.trim())
    };
    if driver_id == DRIVER_ID_REOLINK {
        return format!(
            "rtsp://{auth}{}:554/h264Preview_01_main",
            candidate.ip.trim()
        );
    }
    if driver_is_xm(driver_id) {
        let user = if username.trim().is_empty() {
            "admin"
        } else {
            username.trim()
        };
        let pass = password.trim();
        return format!(
            "rtsp://{auth}{}:554/user={}_password={}_channel=1_stream=0.sdp?real_stream",
            candidate.ip.trim(),
            user,
            pass
        );
    }
    format!("rtsp://{auth}{}:554/", candidate.ip.trim())
}

fn xm_preview_rtsp_url(url: &str) -> String {
    url.replace("_stream=0.sdp?real_stream", "_stream=1.sdp?real_stream")
        .replace("_stream=0.sdp", "_stream=1.sdp")
}

fn normalize_camera_defaults(cfg: &Config, camera: &mut CameraConfig) {
    let mut snapshot = cfg.clone();
    snapshot.camera_devices.push(camera.clone());
    snapshot.apply_defaults();
    if let Some(last) = snapshot.camera_devices.into_iter().last() {
        *camera = last;
    }
}

fn credential_safety(camera: &CameraConfig) -> CameraCredentialSafety {
    CameraCredentialSafety {
        status: if camera.credentials.last_rotation_status.trim().is_empty() {
            "ready".to_string()
        } else {
            camera.credentials.last_rotation_status.trim().to_string()
        },
        pending: !camera.credentials.pending_password.trim().is_empty(),
        history_depth: camera.credentials.history.len(),
        last_error: camera.credentials.last_rotation_error.trim().to_string(),
    }
}

fn reolink_password_candidates(camera: &CameraConfig) -> Vec<String> {
    let mut candidates = camera_credential_candidates(camera);
    if candidates.is_empty() {
        candidates.push(String::new());
    }
    candidates
}

fn reolink_post_apply_candidates(
    existing: &CameraConfig,
    updated: &CameraConfig,
    requested_password: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();
    push_unique_string(&mut candidates, requested_password);
    for candidate in camera_credential_candidates(updated) {
        push_unique_string(&mut candidates, &candidate);
    }
    for candidate in camera_credential_candidates(existing) {
        push_unique_string(&mut candidates, &candidate);
    }
    if candidates.is_empty() {
        candidates.push(String::new());
    }
    candidates
}

async fn try_reolink_setup(
    setup_request: &reolink::ReolinkSetupRequest,
    login_candidates: &[String],
) -> Result<reolink::ReolinkSetupResult> {
    let mut errors = Vec::new();
    for candidate in login_candidates {
        let mut attempt = setup_request.clone();
        attempt.password = candidate.clone();
        match reolink::setup(attempt).await {
            Ok(result) => return Ok(result),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(anyhow!(
        "failed for all stored credential candidates: {}",
        errors.join(" | ")
    ))
}

async fn resolve_reolink_state(
    camera: &CameraConfig,
) -> Result<(reolink::ReolinkConnectRequest, reolink::ReolinkStateResult)> {
    let connection = resolve_reolink_connection_for(
        &camera.onvif_host,
        &camera.username,
        &reolink_password_candidates(camera),
    )
    .await?;
    let state = reolink_cgi::read_state(&connection).await?;
    Ok((connection, state))
}

async fn resolve_reolink_connection_for(
    ip: &str,
    username: &str,
    candidates: &[String],
) -> Result<reolink::ReolinkConnectRequest> {
    let mut errors = Vec::new();
    for candidate in candidates {
        let connection = reolink::ReolinkConnectRequest {
            ip: ip.to_string(),
            username: username.to_string(),
            channel: 0,
            password: candidate.clone(),
        };
        match reolink_cgi::read_state(&connection).await {
            Ok(_) => return Ok(connection),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(anyhow!(
        "no working credential candidate could authenticate: {}",
        errors.join(" | ")
    ))
}

fn camera_display_name(camera: &CameraConfig) -> String {
    first_nonempty(&camera.desired.display_name, &camera.name)
}

fn vendor_from_candidate(candidate: &DiscoveredCameraCandidate) -> String {
    let title = candidate.signatures.public_title.to_ascii_lowercase();
    if title.contains("reolink") || !candidate.signatures.reolink_uid.trim().is_empty() {
        "Reolink".to_string()
    } else if candidate_looks_like_xm(candidate) {
        "XM/NetSurveillance".to_string()
    } else if candidate.transports.onvif || candidate.transports.rtsp {
        "ONVIF/RTSP".to_string()
    } else {
        String::new()
    }
}

fn candidate_looks_like_xm(candidate: &DiscoveredCameraCandidate) -> bool {
    let vendor = candidate.signatures.vendor.to_ascii_lowercase();
    let model = candidate.signatures.model.to_ascii_lowercase();
    let title = candidate.signatures.public_title.to_ascii_lowercase();
    vendor.contains("xm")
        || vendor.contains("netsurveillance")
        || model.contains("40e")
        || model.contains("xm rtsp")
        || model.contains("netsurveillance")
        || title.contains("40e")
        || title.contains("xm")
        || title.contains("netsurveillance")
}

fn model_from_candidate(candidate: &DiscoveredCameraCandidate) -> String {
    if !candidate.signatures.model.trim().is_empty() {
        candidate.signatures.model.trim().to_string()
    } else {
        candidate.signatures.public_title.trim().to_string()
    }
}

fn parse_lease_file(path: &str) -> Vec<LeaseEntry> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return Vec::new(),
    };
    raw.lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 4 {
                return None;
            }
            Some(LeaseEntry {
                mac: parts[1].trim().to_string(),
                ip: parts[2].trim().to_string(),
                hostname: parts[3].trim().trim_matches('*').to_string(),
            })
        })
        .collect()
}

async fn discover_interface_scan_candidates(cfg: &Config) -> Vec<DiscoveredCameraCandidate> {
    let ips = camera_interface_scan_ips(cfg);
    if ips.is_empty() {
        return Vec::new();
    }
    stream::iter(ips)
        .map(|ip| async move { active_scan_candidate(&ip).await })
        .buffer_unordered(96)
        .filter_map(|candidate| async move { candidate })
        .collect::<Vec<_>>()
        .await
}

fn camera_interface_scan_ips(cfg: &Config) -> Vec<String> {
    let iface = cfg.camera_network.interface.trim();
    if iface.is_empty() {
        return Vec::new();
    }
    let primary_host = cfg.camera_network.host_ip.trim();
    let mut out = HashSet::new();
    for (addr, prefix) in interface_ipv4_cidrs(iface) {
        if !primary_host.is_empty() && addr.to_string() == primary_host {
            continue;
        }
        if prefix != 24 {
            continue;
        }
        let network = u32::from(addr) & 0xFFFF_FF00;
        for host in 1..=254u32 {
            let ip = Ipv4Addr::from(network + host);
            if ip == addr {
                continue;
            }
            out.insert(ip.to_string());
        }
    }
    let mut sorted = out.into_iter().collect::<Vec<_>>();
    sorted.sort();
    sorted
}

fn interface_ipv4_cidrs(iface: &str) -> Vec<(Ipv4Addr, u8)> {
    let output = match Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface.trim()])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let idx = parts.iter().position(|part| *part == "inet")?;
            let cidr = parts.get(idx + 1)?.trim();
            let (ip, prefix) = cidr.split_once('/')?;
            Some((ip.parse::<Ipv4Addr>().ok()?, prefix.parse::<u8>().ok()?))
        })
        .collect()
}

async fn active_scan_candidate(ip: &str) -> Option<DiscoveredCameraCandidate> {
    let ports = probe_common_ports(ip).await;
    if !(ports.rtsp || ports.onvif) {
        return None;
    }
    let mut candidate = blank_candidate(ip);
    candidate.transports.http = ports.http;
    candidate.transports.https = ports.https;
    candidate.transports.rtsp = ports.rtsp;
    candidate.transports.onvif = ports.onvif;
    candidate.transports.proprietary_9000 = ports.proprietary_9000;
    push_unique_string(&mut candidate.discovered_via, "interface_scan");
    Some(candidate)
}

fn host_and_port_from_xaddr(value: &str) -> Option<(String, u16)> {
    let url = Url::parse(value.trim()).ok()?;
    Some((
        url.host_str()?.trim().to_string(),
        url.port_or_known_default().unwrap_or(80),
    ))
}

#[derive(Clone, Copy, Debug, Default)]
struct PortProbe {
    http: bool,
    https: bool,
    rtsp: bool,
    onvif: bool,
    proprietary_9000: bool,
}

async fn probe_common_ports(ip: &str) -> PortProbe {
    PortProbe {
        http: probe_port(ip, 80).await,
        https: probe_port(ip, 443).await,
        rtsp: probe_port(ip, 554).await,
        onvif: probe_port(ip, 8000).await || probe_port(ip, 8899).await,
        proprietary_9000: probe_port(ip, 9000).await,
    }
}

async fn probe_port(ip: &str, port: u16) -> bool {
    matches!(
        timeout(
            Duration::from_millis(700),
            TcpStream::connect(format!("{ip}:{port}"))
        )
        .await,
        Ok(Ok(_))
    )
}

fn http_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed building camera discovery http client")
}

#[derive(Clone, Debug, Default)]
struct HttpFingerprint {
    title: String,
    server: String,
    body: String,
}

async fn fetch_http_fingerprint(
    client: &Client,
    ip: &str,
    http: bool,
    https: bool,
) -> Result<HttpFingerprint> {
    let title_re = Regex::new("(?is)<title>(.*?)</title>").context("invalid title regex")?;
    for url in [
        http.then(|| format!("http://{ip}/")),
        https.then(|| format!("https://{ip}/")),
    ]
    .into_iter()
    .flatten()
    {
        let response = match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => response,
            _ => continue,
        };
        let server = response
            .headers()
            .get("server")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim()
            .to_string();
        let body = response.text().await.unwrap_or_default();
        let title = title_re
            .captures(&body)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        return Ok(HttpFingerprint {
            title,
            server,
            body,
        });
    }
    Ok(HttpFingerprint::default())
}

fn is_xm_http_fingerprint(fingerprint: &HttpFingerprint) -> bool {
    if fingerprint.body.trim().is_empty() && fingerprint.server.trim().is_empty() {
        return false;
    }
    let server = fingerprint.server.to_ascii_lowercase();
    let body = fingerprint.body.to_ascii_lowercase();
    let markers = [
        "api_pluginplay/api_plugin.js",
        "api_pluginplay/commonnew.js",
        "jscore/browserwindow.js",
        "ipcconfigctrl",
        "raw_player.js",
        "pubversion=",
    ];
    let hits = markers.iter().filter(|marker| body.contains(**marker)).count();
    hits >= 2 || (server.contains("gsoap/2.8") && body.contains("api_pluginplay/api_plugin.js"))
}

fn first_nonempty(preferred: &str, fallback: &str) -> String {
    if !preferred.trim().is_empty() {
        preferred.trim().to_string()
    } else {
        fallback.trim().to_string()
    }
}

fn nonempty_option(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value.trim().to_string())
    }
}

fn push_unique_string(items: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !items.iter().any(|item| item == value) {
        items.push(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reolink_match_wins_over_generic() {
        let candidate = DiscoveredCameraCandidate {
            ip: "10.0.0.10".to_string(),
            signatures: CameraSignatureSet {
                vendor: "Reolink".to_string(),
                model: "E1 Outdoor".to_string(),
                ..Default::default()
            },
            transports: CameraTransportFacts {
                rtsp: true,
                onvif: true,
                proprietary_9000: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let matched = match_candidate(&candidate);
        assert_eq!(matched.driver_id, DRIVER_ID_REOLINK);
        assert_eq!(matched.kind, "vendor_driver");
        assert!(matched.mountable);
    }

    #[test]
    fn generic_driver_matches_standards_camera() {
        let candidate = DiscoveredCameraCandidate {
            ip: "10.0.0.12".to_string(),
            transports: CameraTransportFacts {
                rtsp: true,
                onvif: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let matched = match_candidate(&candidate);
        assert_eq!(matched.driver_id, DRIVER_ID_GENERIC_ONVIF_RTSP);
        assert!(matched.mountable);
    }

    #[test]
    fn xm_driver_matches_xm_fingerprint_before_generic() {
        let candidate = DiscoveredCameraCandidate {
            ip: "192.168.0.201".to_string(),
            signatures: CameraSignatureSet {
                vendor: "XM/NetSurveillance".to_string(),
                model: "XM RTSP camera".to_string(),
                ..Default::default()
            },
            transports: CameraTransportFacts {
                http: true,
                rtsp: true,
                onvif: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let matched = match_candidate(&candidate);
        assert_eq!(matched.driver_id, DRIVER_ID_XM_40E);
        assert_eq!(matched.kind, "vendor_driver");
        assert!(matched.mountable);
    }

    #[test]
    fn derive_rtsp_url_uses_xm_path_shape() {
        let candidate = DiscoveredCameraCandidate {
            ip: "192.168.0.201".to_string(),
            ..Default::default()
        };
        assert_eq!(
            derive_rtsp_url(&candidate, DRIVER_ID_XM_40E, "admin", "123456", ""),
            "rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=0.sdp?real_stream"
        );
    }

    #[test]
    fn candidate_display_name_prefers_model_then_title_then_hostname() {
        let candidate = DiscoveredCameraCandidate {
            ip: "10.0.0.9".to_string(),
            lease_hostname: "yard-cam".to_string(),
            signatures: CameraSignatureSet {
                model: "Reolink E1 Outdoor SE".to_string(),
                public_title: "Camera".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(candidate_display_name(&candidate), "Reolink E1 Outdoor SE");

        let title_only = DiscoveredCameraCandidate {
            ip: "10.0.0.8".to_string(),
            signatures: CameraSignatureSet {
                public_title: "Entrance Camera".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(candidate_display_name(&title_only), "Entrance Camera");
    }

    #[test]
    fn candidate_ptz_detection_recognizes_reolink_e1_family() {
        let candidate = DiscoveredCameraCandidate {
            signatures: CameraSignatureSet {
                model: "Reolink E1 Outdoor SE".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(candidate_ptz_capable(&candidate));
    }

    #[test]
    fn observed_ptz_capability_promotes_rendered_capabilities() {
        let camera = CameraConfig {
            source_id: "cam".to_string(),
            name: "Camera".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        };
        let base = CameraCapabilitySet {
            live_view: true,
            ptz: false,
            ..Default::default()
        };
        let observed = ObservedCameraState {
            ptz_capable: true,
            ..Default::default()
        };
        let promoted = capabilities_for_observed(&camera, base, &observed);
        assert!(promoted.ptz);
    }

    #[test]
    fn reolink_onvif_plane_gates_capabilities_to_supported_fields() {
        let camera = CameraConfig {
            source_id: "cam".to_string(),
            name: "Camera".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: "Reolink E1 Outdoor SE".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        };
        let observed = ObservedCameraState {
            ptz_capable: true,
            raw: json!({ "managementPlane": "onvif" }),
            ..Default::default()
        };
        let caps = capabilities_for_observed(&camera, driver_capabilities(&camera), &observed);
        assert!(caps.time_sync);
        assert!(!caps.manual_time);
        assert!(caps.timezone);
        assert!(caps.ptz);
        assert!(caps.overlay_text);
        assert!(caps.overlay_timestamp);
        assert!(caps.password_rotate);
        assert!(caps.hardening_profile);
    }

    #[test]
    fn transport_only_fallback_does_not_advertise_config_controls() {
        let camera = CameraConfig {
            source_id: "cam".to_string(),
            name: "Camera".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        };
        let observed = ObservedCameraState {
            raw: json!({ "managementPlane": "transport_only" }),
            ..Default::default()
        };
        let caps = capabilities_for_observed(&camera, driver_capabilities(&camera), &observed);
        assert!(!caps.time_sync);
        assert!(!caps.manual_time);
        assert!(!caps.timezone);
        assert!(!caps.overlay_text);
        assert!(!caps.overlay_timestamp);
        assert!(!caps.password_rotate);
        assert!(!caps.hardening_profile);
        assert!(!caps.ptz);
    }

    #[test]
    fn reolink_e1_native_profile_round_trips_normalized_pose() {
        let camera = CameraConfig {
            source_id: "cam".to_string(),
            name: "Reolink E1 Outdoor SE".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: "Reolink".to_string(),
            model: "Reolink E1 Outdoor SE".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        };
        let profile = reolink_native_ptz_profile(&camera).expect("native PTZ profile");
        let requested = RequestedPose {
            pan: Some(0.5),
            tilt: Some(-0.25),
            zoom: None,
        };
        let target = reolink_native_target_pose(
            profile,
            reolink::ReolinkNativePtzPosition {
                pan: 1775,
                tilt: 250,
                zoom: 0,
            },
            requested,
        );
        let observed = reolink_native_observation(profile, target);
        assert!((observed.normalized.pan.unwrap_or_default() - 0.5).abs() < 0.02);
        assert!((observed.normalized.tilt.unwrap_or_default() + 0.25).abs() < 0.03);
    }

    #[test]
    fn reolink_native_settle_checks_only_requested_axes() {
        let profile = ReolinkNativePtzProfile {
            label: "test",
            pan: ReolinkNativeAxisRange {
                min: 0,
                max: 3550,
                tolerance: 18,
            },
            tilt: ReolinkNativeAxisRange {
                min: 0,
                max: 500,
                tolerance: 12,
            },
            zoom: Some(ReolinkNativeAxisRange {
                min: 0,
                max: 100,
                tolerance: 4,
            }),
        };
        let requested = RequestedPose {
            pan: Some(0.0),
            tilt: None,
            zoom: None,
        };
        let target = reolink::ReolinkNativePtzPosition {
            pan: 1775,
            tilt: 250,
            zoom: 0,
        };
        let observed = reolink::ReolinkNativePtzPosition {
            pan: 1780,
            tilt: 499,
            zoom: 0,
        };
        assert!(reolink_native_target_reached(
            profile, requested, target, observed
        ));
    }

    #[test]
    fn reolink_cgi_fallback_uses_directional_pulse_for_steps() {
        let payload = json!({
            "targetPose": {
                "pan": -0.2,
            },
            "step": {
                "pan": -0.0555555556,
                "tilt": 0,
                "zoom": 0,
            },
            "mode": "step",
        });
        let command = reolink_fallback_command(&payload).expect("fallback command");
        assert_eq!(command.op, "Left");
        assert_eq!(command.pose_status, "directed");
        assert!(command.pulse_ms.unwrap_or_default() >= REOLINK_CGI_FALLBACK_MIN_PULSE_MS);
        assert_eq!(command.desired_pose.pan, Some(-0.2));
    }

    #[test]
    fn reolink_observed_step_plan_prefers_largest_remaining_axis() {
        let profile = ReolinkNativePtzProfile {
            label: "test",
            pan: ReolinkNativeAxisRange {
                min: 0,
                max: 3550,
                tolerance: 18,
            },
            tilt: ReolinkNativeAxisRange {
                min: 0,
                max: 500,
                tolerance: 12,
            },
            zoom: None,
        };
        let requested = RequestedPose {
            pan: Some(0.5),
            tilt: Some(0.3),
            zoom: None,
        };
        let target = reolink::ReolinkNativePtzPosition {
            pan: 2663,
            tilt: 325,
            zoom: 0,
        };
        let observed = reolink::ReolinkNativePtzPosition {
            pan: 1200,
            tilt: 310,
            zoom: 0,
        };

        let plan =
            reolink_observed_step_plan(profile, requested, target, observed).expect("step plan");
        assert_eq!(plan.axis, "pan");
        assert_eq!(plan.op, "Right");
        assert!(plan.pulse_ms >= REOLINK_CGI_FALLBACK_MIN_PULSE_MS);
    }

    #[test]
    fn reolink_observed_step_plan_returns_none_inside_tolerance() {
        let profile = ReolinkNativePtzProfile {
            label: "test",
            pan: ReolinkNativeAxisRange {
                min: 0,
                max: 3550,
                tolerance: 18,
            },
            tilt: ReolinkNativeAxisRange {
                min: 0,
                max: 500,
                tolerance: 12,
            },
            zoom: None,
        };
        let requested = RequestedPose {
            pan: Some(0.0),
            tilt: Some(0.0),
            zoom: None,
        };
        let target = reolink::ReolinkNativePtzPosition {
            pan: 1775,
            tilt: 250,
            zoom: 0,
        };
        let observed = reolink::ReolinkNativePtzPosition {
            pan: 1786,
            tilt: 243,
            zoom: 0,
        };

        assert!(reolink_observed_step_plan(profile, requested, target, observed).is_none());
    }

    #[test]
    fn display_name_change_keeps_overlay_text_linked_by_default() {
        let existing = CameraConfig {
            source_id: "cam".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                display_name: "Front Door".to_string(),
                overlay_text: "Front Door".to_string(),
                ..Default::default()
            },
            credentials: Default::default(),
        };
        let mut next = existing.clone();
        next.desired.display_name = "Driveway".to_string();
        next.desired.overlay_text = "Front Door".to_string();

        sync_display_name_and_linked_overlay(&existing, &mut next);

        assert_eq!(next.name, "Driveway");
        assert_eq!(next.desired.overlay_text, "Driveway");
    }

    #[test]
    fn display_name_change_preserves_custom_overlay_text() {
        let existing = CameraConfig {
            source_id: "cam".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                display_name: "Front Door".to_string(),
                overlay_text: "Package Zone".to_string(),
                ..Default::default()
            },
            credentials: Default::default(),
        };
        let mut next = existing.clone();
        next.desired.display_name = "Driveway".to_string();
        next.desired.overlay_text = "Package Zone".to_string();

        sync_display_name_and_linked_overlay(&existing, &mut next);

        assert_eq!(next.name, "Driveway");
        assert_eq!(next.desired.overlay_text, "Package Zone");
    }

    #[test]
    fn xm_display_name_change_does_not_link_hidden_overlay_fields() {
        let existing = CameraConfig {
            source_id: "cam".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_XM_40E.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                display_name: "Front Door".to_string(),
                overlay_text: String::new(),
                overlay_timestamp: false,
                ..Default::default()
            },
            credentials: Default::default(),
        };
        let mut next = existing.clone();
        next.desired.display_name = "Driveway".to_string();
        next.desired.overlay_text = "Front Door".to_string();
        next.desired.overlay_timestamp = true;

        sync_display_name_and_linked_overlay(&existing, &mut next);

        assert_eq!(next.name, "Driveway");
        assert_eq!(next.desired.overlay_text, "Front Door");
        assert!(next.desired.overlay_timestamp);
    }

    #[test]
    fn reolink_observed_timezone_prefers_feed_truth_from_presentation() {
        let onvif_state = onvif::OnvifState {
            timezone: "UTC+7:00:00DST+6:00:00,M3.2.0/02:00:00,M10.5.0/02:00:00".to_string(),
            ..Default::default()
        };
        let presentation = reolink_cgi::ReolinkPresentationState {
            timezone: "America/Phoenix".to_string(),
            ..Default::default()
        };
        assert_eq!(
            reolink_observed_timezone(Some(&onvif_state), &presentation),
            "America/Phoenix"
        );
    }

    #[test]
    fn reolink_observed_manual_time_prefers_feed_truth_from_presentation() {
        let onvif_state = onvif::OnvifState {
            manual_time: "2026-04-17T18:04:28".to_string(),
            ..Default::default()
        };
        let presentation = reolink_cgi::ReolinkPresentationState {
            manual_time: "2026-04-17T17:59:13".to_string(),
            ..Default::default()
        };
        assert_eq!(
            reolink_observed_manual_time(Some(&onvif_state), &presentation),
            "2026-04-17T17:59:13"
        );
    }

    #[test]
    fn reolink_verification_accepts_site_timezone_when_feed_truth_matches() {
        let cfg: Config = serde_json::from_value(json!({
            "node_id": "nvr-test",
            "service_version": "0.1.0",
            "nostr_pubkey": "pk",
            "nostr_sk_hex": "sk",
            "swarm": {
                "bind": "0.0.0.0:4050",
                "peers": [],
                "zones": [],
                "endpoint_hint": ""
            },
            "api": {
                "bind": "127.0.0.1:8456",
                "identity_id": "id-test",
                "identity_secret_hex": "secret",
                "server_secret_hex": "server"
            },
            "storage": {
                "root": "/tmp/constitute-nvr",
                "encryption_key_hex": "key"
            },
            "update": {},
            "camera_network": {
                "ntp_enabled": true,
                "ntp_server": "192.168.250.1",
                "timezone": "America/Phoenix"
            }
        }))
        .expect("config");

        let camera = CameraConfig {
            source_id: "cam".to_string(),
            name: "Carport".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor SE".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                display_name: "Carport".to_string(),
                overlay_text: "Carport".to_string(),
                overlay_timestamp: true,
                ..Default::default()
            },
            credentials: Default::default(),
        };
        let observed = ObservedCameraState {
            display_name: "Carport".to_string(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            time_mode: "ntp".to_string(),
            ntp_server: "192.168.250.1".to_string(),
            timezone: "America/Phoenix".to_string(),
            overlay_text: "Carport".to_string(),
            overlay_timestamp: Some(true),
            raw: json!({
                "managementPlane": "hybrid",
                "presentation": { "timezone": "America/Phoenix" },
                "onvif": { "time": { "timezone": "UTC+7:00:00DST+6:00:00,M3.2.0/02:00:00,M10.5.0/02:00:00" } }
            }),
            ..Default::default()
        };
        let verification = verification_for_observed(
            &cfg,
            &camera,
            &observed,
            &CameraCapabilitySet {
                time_sync: true,
                timezone: true,
                overlay_text: true,
                overlay_timestamp: true,
                ..Default::default()
            },
            Vec::new(),
        );
        assert!(verification.verified);
        assert!(verification.drift_fields.is_empty());
    }

    #[test]
    fn observed_site_time_offset_secs_accepts_current_phoenix_time() {
        let now = Utc.with_ymd_and_hms(2026, 4, 18, 0, 45, 0).single().unwrap();
        assert_eq!(
            observed_site_time_offset_secs("America/Phoenix", "2026-04-17T17:45:30", now),
            Some(30)
        );
    }

    #[test]
    fn site_local_time_string_formats_current_phoenix_time() {
        let now = Utc.with_ymd_and_hms(2026, 4, 18, 0, 45, 0).single().unwrap();
        assert_eq!(
            site_local_time_string("America/Phoenix", now).as_deref(),
            Some("2026-04-17T17:45:00")
        );
    }

    #[test]
    fn observed_site_time_offset_secs_detects_large_clock_lead() {
        let now = Utc.with_ymd_and_hms(2026, 4, 18, 0, 45, 0).single().unwrap();
        assert_eq!(
            observed_site_time_offset_secs("America/Phoenix", "2026-04-17T17:50:30", now),
            Some(330)
        );
    }

    #[test]
    fn requested_apply_fields_include_display_and_overlay_changes() {
        let existing = CameraConfig {
            source_id: "cam".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "10.0.0.1".to_string(),
            onvif_port: 8000,
            rtsp_url: String::new(),
            username: String::new(),
            password: String::new(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDesiredConfig {
                display_name: "Front Door".to_string(),
                overlay_text: "Front Door".to_string(),
                ..Default::default()
            },
            credentials: Default::default(),
        };
        let mut next = existing.clone();
        next.desired.display_name = "Carport".to_string();
        next.desired.overlay_text = "Carport".to_string();
        next.name = "Carport".to_string();

        let fields = requested_apply_fields(&existing, &next);
        assert!(fields.iter().any(|field| field == "display_name"));
        assert!(fields.iter().any(|field| field == "overlay_text"));
    }

    #[test]
    fn requested_verification_failures_intersect_requested_fields_only() {
        let verification = CameraReconcileResult {
            status: "drift".to_string(),
            message: "camera configuration drift detected".to_string(),
            drift_fields: vec![
                "display_name".to_string(),
                "timezone".to_string(),
                "overlay_text".to_string(),
            ],
            ..Default::default()
        };

        let failures = requested_verification_failures(
            &verification,
            &["display_name".to_string(), "overlay_text".to_string()],
        );
        assert_eq!(failures, vec!["display_name".to_string(), "overlay_text".to_string()]);
    }
}

fn requested_apply_fields(existing: &CameraConfig, next: &CameraConfig) -> Vec<String> {
    let mut fields = Vec::new();
    if next.desired.display_name.trim() != existing.desired.display_name.trim()
        || next.name.trim() != existing.name.trim()
    {
        fields.push("display_name".to_string());
    }
    if next.desired.overlay_text.trim() != existing.desired.overlay_text.trim() {
        fields.push("overlay_text".to_string());
    }
    if next.desired.overlay_timestamp != existing.desired.overlay_timestamp {
        fields.push("overlay_timestamp".to_string());
    }
    if next.desired.desired_password.trim() != existing.desired.desired_password.trim()
        || next.desired.generate_password != existing.desired.generate_password
    {
        fields.push("password_rotate".to_string());
    }
    if next.desired.hardening != existing.desired.hardening {
        fields.push("hardening".to_string());
    }
    fields
}

fn requested_verification_failures(
    verification: &CameraReconcileResult,
    requested_fields: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();
    for field in requested_fields {
        if verification.failed_fields.iter().any(|item| item == field)
            || verification.drift_fields.iter().any(|item| item == field)
        {
            failures.push(field.clone());
        }
    }
    failures.sort();
    failures.dedup();
    failures
}
