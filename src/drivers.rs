use crate::camera;
use crate::config::{
    CameraConfig, CameraDesiredConfig, CameraTimeMode, Config, adopt_camera_active_password,
    camera_credential_candidates, finalize_camera_password_rotation, mark_camera_rotation_failed,
    mark_camera_rotation_pending,
};
use crate::onvif;
use crate::reolink;
use crate::reolink_cgi;
use anyhow::{Context, Result, anyhow};
use regex::Regex;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, sleep, timeout};

pub const DRIVER_ID_REOLINK: &str = "reolink";
pub const DRIVER_ID_GENERIC_ONVIF_RTSP: &str = "generic_onvif_rtsp";
const REOLINK_NATIVE_PTZ_SETTLE_TIMEOUT_MS: u64 = 5_000;
const REOLINK_NATIVE_PTZ_POLL_INTERVAL_MS: u64 = 250;
const REOLINK_CGI_FALLBACK_MIN_PULSE_MS: u64 = 180;
const REOLINK_CGI_FALLBACK_MAX_PULSE_MS: u64 = 1_200;
const REOLINK_CGI_FALLBACK_SPEED: i32 = 32;
const REOLINK_OBSERVED_STEP_MAX_ATTEMPTS: usize = 8;

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
    pub dns_server: String,
    pub lease_file: String,
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
    pub mounted: Vec<MountedCamera>,
    pub candidates: Vec<DiscoveredCameraCandidate>,
    pub camera_network: CameraNetworkSummary,
}

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
pub struct CameraMountResult {
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
pub struct CameraApplyResult {
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
            manual_time: true,
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
        dns_server: cfg.camera_network.dns_server.clone(),
        lease_file: cfg.camera_network.lease_file.clone(),
    }
}

pub async fn list_inventory(cfg: &Config) -> Result<CameraInventory> {
    let mut mounted = Vec::with_capacity(cfg.cameras.len());
    for camera in &cfg.cameras {
        mounted.push(read_mounted_camera(camera).await);
    }
    Ok(CameraInventory {
        mounted,
        candidates: discover_candidates(cfg).await?,
        camera_network: camera_network_summary(cfg),
    })
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

    for discovered in camera::discover_onvif(2).await.unwrap_or_default() {
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

pub async fn mount_candidate(
    cfg: &Config,
    request: MountCameraRequest,
) -> Result<CameraMountResult> {
    let candidate = request.candidate.clone();
    let driver_match = if request.candidate.driver_match.mountable {
        request.candidate.driver_match.clone()
    } else {
        match_candidate(&candidate)
    };
    if !driver_match.mountable {
        return Err(anyhow!("camera candidate is not mountable yet"));
    }

    let display_name = if request.display_name.trim().is_empty() {
        candidate_display_name(&candidate)
    } else {
        request.display_name.trim().to_string()
    };
    let username = if request.username.trim().is_empty() {
        "admin".to_string()
    } else {
        request.username.trim().to_string()
    };
    let mut camera = CameraConfig {
        source_id: build_source_id(&candidate, &driver_match.driver_id),
        name: display_name.clone(),
        onvif_host: candidate.ip.trim().to_string(),
        onvif_port: derive_onvif_port(&candidate),
        rtsp_url: derive_rtsp_url(
            &candidate,
            &driver_match.driver_id,
            &username,
            &request.password,
            &request.rtsp_url,
        ),
        username,
        password: request.password.trim().to_string(),
        driver_id: driver_match.driver_id.clone(),
        vendor: derive_vendor(&candidate, &driver_match.driver_id),
        model: candidate.signatures.model.clone(),
        mac_address: candidate.mac.clone(),
        rtsp_port: derive_rtsp_port(&candidate, &request.rtsp_url),
        ptz_capable: candidate_ptz_capable(&candidate),
        enabled: true,
        segment_secs: 10,
        desired: CameraDesiredConfig {
            display_name: display_name.clone(),
            ntp_server: cfg.camera_network.ntp_server.clone(),
            timezone: "UTC".to_string(),
            overlay_text: display_name.clone(),
            overlay_timestamp: true,
            desired_password: request.desired_password.trim().to_string(),
            generate_password: request.generate_password,
            ..Default::default()
        },
        credentials: Default::default(),
    };
    normalize_camera_defaults(cfg, &mut camera);
    camera = apply_driver_mount(cfg, &camera).await?;
    Ok(CameraMountResult {
        configured: camera.clone(),
        mounted: read_mounted_camera(&camera).await,
    })
}

pub async fn apply_mounted_camera(
    cfg: &Config,
    request: ApplyMountedCameraRequest,
) -> Result<CameraApplyResult> {
    let existing = cfg
        .cameras
        .iter()
        .find(|camera| camera.source_id.trim() == request.source_id.trim())
        .cloned()
        .ok_or_else(|| anyhow!("camera source is not configured"))?;
    let mut next = existing.clone();
    next.desired = request.desired.clone();
    if !request.desired.display_name.trim().is_empty() {
        next.name = request.desired.display_name.trim().to_string();
    }
    normalize_camera_defaults(cfg, &mut next);
    next = apply_driver_desired(cfg, &existing, &next).await?;
    Ok(CameraApplyResult {
        configured: next.clone(),
        mounted: read_mounted_camera(&next).await,
    })
}

pub async fn read_camera(cfg: &Config, source_id: &str) -> Result<MountedCamera> {
    let camera = cfg
        .cameras
        .iter()
        .find(|camera| camera.source_id.trim() == source_id.trim())
        .cloned()
        .ok_or_else(|| anyhow!("camera source is not configured"))?;
    Ok(read_mounted_camera(&camera).await)
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

pub async fn probe_camera(cfg: &Config, request: ProbeCameraRequest) -> Result<Value> {
    if !request.source_id.trim().is_empty() {
        let camera = read_camera(cfg, &request.source_id).await?;
        return Ok(json!({
            "mode": "mounted",
            "camera": camera,
            "cameraNetwork": camera_network_summary(cfg),
        }));
    }
    if request.ip.trim().is_empty() {
        return Err(anyhow!("probe_camera requires source_id or ip"));
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

pub async fn read_mounted_camera(camera: &CameraConfig) -> MountedCamera {
    let base_capabilities = driver_capabilities(camera);
    match read_observed_state(camera).await {
        Ok(observed) => {
            let capabilities =
                capabilities_for_observed(camera, base_capabilities.clone(), &observed);
            let display_name = first_nonempty(&camera_display_name(camera), &observed.display_name);
            let vendor = first_nonempty(&camera.vendor, &observed.vendor);
            let model = first_nonempty(&camera.model, &observed.model);
            MountedCamera {
                source_id: camera.source_id.clone(),
                driver_id: camera.driver_id.clone(),
                display_name,
                vendor,
                model,
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                enabled: camera.enabled,
                rtsp_url: camera.rtsp_url.clone(),
                capabilities: capabilities.clone(),
                credential_safety: credential_safety(camera),
                desired: camera.desired.clone(),
                current_pose: observed.current_pose.clone(),
                desired_pose: observed.current_pose.clone(),
                pose_status: observed.pose_status.clone(),
                verification: verification_for_observed(
                    camera,
                    &observed,
                    &capabilities,
                    Vec::new(),
                ),
                observed,
            }
        }
        Err(error) => {
            let observed = fallback_observed_state(camera).await;
            let capabilities =
                capabilities_for_observed(camera, base_capabilities.clone(), &observed);
            let display_name = first_nonempty(&camera_display_name(camera), &observed.display_name);
            let vendor = first_nonempty(&camera.vendor, &observed.vendor);
            let model = first_nonempty(&camera.model, &observed.model);
            MountedCamera {
                source_id: camera.source_id.clone(),
                driver_id: camera.driver_id.clone(),
                display_name,
                vendor,
                model,
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                enabled: camera.enabled,
                rtsp_url: camera.rtsp_url.clone(),
                capabilities: capabilities.clone(),
                credential_safety: credential_safety(camera),
                desired: camera.desired.clone(),
                current_pose: observed.current_pose.clone(),
                desired_pose: observed.current_pose.clone(),
                pose_status: observed.pose_status.clone(),
                observed,
                verification: CameraReconcileResult {
                    status: "failed".to_string(),
                    message: error.to_string(),
                    failed_fields: vec!["read_state".to_string()],
                    unsupported_fields: unsupported_fields(camera, &capabilities),
                    ..Default::default()
                },
            }
        }
    }
}

fn match_candidate(candidate: &DiscoveredCameraCandidate) -> DriverMatch {
    if let Some(matched) = ReolinkDriver.match_candidate(candidate) {
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
    match camera.driver_id.trim() {
        DRIVER_ID_REOLINK => ReolinkDriver.capabilities(camera),
        DRIVER_ID_GENERIC_ONVIF_RTSP => GenericOnvifRtspDriver.capabilities(camera),
        _ => CameraCapabilitySet {
            live_view: true,
            ptz: camera.ptz_capable,
            raw_probe: true,
            ..Default::default()
        },
    }
}

fn capabilities_for_observed(
    camera: &CameraConfig,
    mut capabilities: CameraCapabilitySet,
    observed: &ObservedCameraState,
) -> CameraCapabilitySet {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        capabilities = reolink_runtime_capabilities(capabilities, observed);
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
        Some("onvif") => {
            capabilities.time_sync = true;
            let bridge_capable = reolink_onvif_bridge_capable(observed);
            capabilities.manual_time = bridge_capable;
            capabilities.timezone = bridge_capable;
            capabilities.overlay_text = bridge_capable;
            capabilities.overlay_timestamp = bridge_capable;
            capabilities.password_rotate = bridge_capable;
            capabilities.hardening_profile = bridge_capable;
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

fn observed_management_plane(observed: &ObservedCameraState) -> Option<String> {
    observed
        .raw
        .get("managementPlane")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn reolink_onvif_bridge_capable(observed: &ObservedCameraState) -> bool {
    observed
        .raw
        .get("onvif")
        .and_then(|value| value.get("networkProtocolsSupported"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

async fn apply_driver_mount(cfg: &Config, camera: &CameraConfig) -> Result<CameraConfig> {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        return apply_driver_desired(cfg, camera, camera).await;
    }
    Ok(camera.clone())
}

async fn apply_driver_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
) -> Result<CameraConfig> {
    match next.driver_id.trim() {
        DRIVER_ID_REOLINK => apply_reolink_desired(cfg, existing, next).await,
        _ => Ok(next.clone()),
    }
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
            !ports.onvif,
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
        || desired.timezone != current.timezone
        || desired.manual_time != current.manual_time
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
    apply_reolink_cgi_desired(cfg, existing, next, true, false).await
}

async fn apply_reolink_cgi_desired(
    cfg: &Config,
    existing: &CameraConfig,
    next: &CameraConfig,
    allow_onvif_only_final_state: bool,
    apply_time_via_cgi: bool,
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

    if let Err(error) =
        reolink_cgi::apply_presentation_state(&reolink_cgi::ReolinkPresentationApplyRequest {
            connection: active_connection.clone(),
            time_mode: apply_time_via_cgi.then(|| time_mode_label(&desired.time_mode).to_string()),
            ntp_server: if apply_time_via_cgi {
                nonempty_option(&first_nonempty(
                    &desired.ntp_server,
                    &cfg.camera_network.ntp_server,
                ))
            } else {
                None
            },
            manual_time: if apply_time_via_cgi {
                nonempty_option(&desired.manual_time)
            } else {
                None
            },
            timezone: if apply_time_via_cgi {
                nonempty_option(&desired.timezone)
            } else {
                None
            },
            overlay_text: nonempty_option(&desired.overlay_text),
            overlay_timestamp: Some(desired.overlay_timestamp),
        })
        .await
    {
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
    let desired = &next.desired;
    let mut updated = next.clone();
    let ntp_server = first_nonempty(&desired.ntp_server, &cfg.camera_network.ntp_server);
    let mut normalized_desired = desired.clone();
    normalized_desired.ntp_server = ntp_server;
    onvif::apply_time_settings(
        &next.onvif_host,
        next.onvif_port.max(1),
        &next.username,
        &existing.password,
        &normalized_desired,
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
    match camera.driver_id.trim() {
        DRIVER_ID_REOLINK => read_reolink_observed_state(camera).await,
        _ => read_generic_observed_state(camera).await,
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
            let ptz_capable = reolink_ptz_capable(camera, &probe, &presentation);
            let native_ptz = if probe.proprietary_port_open {
                try_reolink_native_ptz_observation(camera, &[connection.password.clone()]).await
            } else {
                None
            };
            return Ok(ObservedCameraState {
                display_name: camera_display_name(camera),
                driver_id: camera.driver_id.clone(),
                vendor: first_nonempty(&camera.vendor, "Reolink"),
                model: first_nonempty(&camera.model, &presentation.model),
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                time_mode: first_nonempty(
                    &presentation.time_mode,
                    time_mode_label(&camera.desired.time_mode),
                ),
                ntp_server: first_nonempty(&presentation.ntp_server, &camera.desired.ntp_server),
                manual_time: first_nonempty(&presentation.manual_time, &camera.desired.manual_time),
                timezone: first_nonempty(&presentation.timezone, &camera.desired.timezone),
                overlay_text: first_nonempty(
                    &presentation.overlay_text,
                    &camera.desired.overlay_text,
                ),
                overlay_timestamp: presentation
                    .overlay_timestamp
                    .or(Some(camera.desired.overlay_timestamp)),
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
                    "managementPlane": "cgi",
                    "ptzManagementPlane": if native_ptz.is_some() { "reolink_native_absolute" } else { "cgi" },
                    "http": state.state.normal.get("iHttpPortEnable").cloned().unwrap_or(json!(0)),
                    "https": state.state.normal.get("iHttpsPortEnable").cloned().unwrap_or(json!(0)),
                    "onvif": state.state.advanced.get("iOnvifPortEnable").cloned().unwrap_or(json!(0)),
                    "rtsp": state.state.advanced.get("iRtspPortEnable").cloned().unwrap_or(json!(0)),
                    "p2p": state.state.p2p.get("iEnable").cloned().unwrap_or(json!(0)),
                    "proprietary9000": probe.proprietary_port_open,
                    "onvifXAddr": probe.onvif_xaddr,
                }),
                raw: json!({
                    "managementPlane": "cgi",
                    "probe": probe,
                    "state": state.state,
                    "presentation": presentation,
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
            return Ok(ObservedCameraState {
                display_name: camera_display_name(camera),
                driver_id: camera.driver_id.clone(),
                vendor: first_nonempty(
                    &camera.vendor,
                    &first_nonempty(&onvif_state.manufacturer, "Reolink"),
                ),
                model: first_nonempty(&camera.model, &onvif_state.model),
                ip: camera.onvif_host.clone(),
                mac_address: camera.mac_address.clone(),
                time_mode: first_nonempty(
                    &onvif_state.time_mode,
                    &first_nonempty(
                        &presentation.time_mode,
                        time_mode_label(&camera.desired.time_mode),
                    ),
                ),
                ntp_server: first_nonempty(&onvif_state.ntp_server, &camera.desired.ntp_server),
                manual_time: first_nonempty(
                    &onvif_state.manual_time,
                    &first_nonempty(&presentation.manual_time, &camera.desired.manual_time),
                ),
                timezone: first_nonempty(
                    &onvif_state.timezone,
                    &first_nonempty(&presentation.timezone, &camera.desired.timezone),
                ),
                overlay_text: first_nonempty(
                    &presentation.overlay_text,
                    &camera.desired.overlay_text,
                ),
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
                    "managementPlane": "onvif",
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
                    "managementPlane": "onvif",
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
                "timeMode": onvif_state.time_mode,
                "ntpServer": onvif_state.ntp_server,
                "manualTime": first_nonempty(&onvif_state.manual_time, &presentation.manual_time),
                "timezone": first_nonempty(&onvif_state.timezone, &presentation.timezone),
                "overlayText": presentation.overlay_text,
                "overlayTimestamp": presentation.overlay_timestamp,
                "ptzCapable": ptz_capable,
            },
            "services": {
                "managementPlane": "onvif",
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

async fn read_generic_observed_state(camera: &CameraConfig) -> Result<ObservedCameraState> {
    let ports = probe_common_ports(&camera.onvif_host).await;
    Ok(ObservedCameraState {
        display_name: camera_display_name(camera),
        driver_id: camera.driver_id.clone(),
        vendor: camera.vendor.clone(),
        model: camera.model.clone(),
        ip: camera.onvif_host.clone(),
        mac_address: camera.mac_address.clone(),
        time_mode: time_mode_label(&camera.desired.time_mode).to_string(),
        ntp_server: camera.desired.ntp_server.clone(),
        manual_time: camera.desired.manual_time.clone(),
        timezone: camera.desired.timezone.clone(),
        overlay_text: camera.desired.overlay_text.clone(),
        overlay_timestamp: Some(camera.desired.overlay_timestamp),
        ptz_capable: camera.ptz_capable,
        current_pose: CameraPose::default(),
        pose_status: String::new(),
        pose_source: String::new(),
        services: json!({
            "http": ports.http,
            "https": ports.https,
            "rtsp": ports.rtsp,
            "onvif": ports.onvif,
            "proprietary9000": ports.proprietary_9000,
        }),
        raw: json!({}),
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
    camera: &CameraConfig,
    observed: &ObservedCameraState,
    capabilities: &CameraCapabilitySet,
    failed_fields: Vec<String>,
) -> CameraReconcileResult {
    let mut drift_fields = Vec::new();
    if capabilities.time_sync
        && observed.time_mode.trim() != time_mode_label(&camera.desired.time_mode)
    {
        drift_fields.push("time_mode".to_string());
    }
    if capabilities.time_sync
        && !camera.desired.ntp_server.trim().is_empty()
        && !camera
            .desired
            .ntp_server
            .trim()
            .eq_ignore_ascii_case(observed.ntp_server.trim())
    {
        drift_fields.push("ntp_server".to_string());
    }
    if capabilities.timezone
        && !camera.desired.timezone.trim().is_empty()
        && camera.desired.timezone.trim() != observed.timezone.trim()
    {
        drift_fields.push("timezone".to_string());
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
        applied_fields: applied_fields(camera, capabilities),
        failed_fields,
        unsupported_fields: unsupported_fields(camera, capabilities),
        drift_fields,
        verified: status == "verified",
    }
}

fn applied_fields(camera: &CameraConfig, capabilities: &CameraCapabilitySet) -> Vec<String> {
    let mut fields = vec!["display_name".to_string()];
    if capabilities.time_sync {
        fields.extend(
            ["time_mode", "ntp_server", "timezone"]
                .into_iter()
                .map(String::from),
        );
    }
    if capabilities.manual_time {
        fields.push("manual_time".to_string());
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

fn unsupported_fields(camera: &CameraConfig, capabilities: &CameraCapabilitySet) -> Vec<String> {
    let mut fields = Vec::new();
    if !capabilities.time_sync && !camera.desired.ntp_server.trim().is_empty() {
        fields.push("ntp_server".to_string());
    }
    if !capabilities.manual_time && !camera.desired.manual_time.trim().is_empty() {
        fields.push("manual_time".to_string());
    }
    if !capabilities.timezone && !camera.desired.timezone.trim().is_empty() {
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
    if candidate.signatures.public_title.trim().is_empty() {
        candidate.signatures.public_title =
            fetch_public_title(client, &candidate.ip, probe.http, probe.https)
                .await
                .unwrap_or_default();
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
    format!("rtsp://{auth}{}:554/", candidate.ip.trim())
}

fn normalize_camera_defaults(cfg: &Config, camera: &mut CameraConfig) {
    let mut snapshot = cfg.clone();
    snapshot.cameras.push(camera.clone());
    snapshot.apply_defaults();
    if let Some(last) = snapshot.cameras.into_iter().last() {
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
    } else if candidate.transports.onvif || candidate.transports.rtsp {
        "ONVIF/RTSP".to_string()
    } else {
        String::new()
    }
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

async fn fetch_public_title(client: &Client, ip: &str, http: bool, https: bool) -> Result<String> {
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
        let body = response.text().await.unwrap_or_default();
        if let Some(captures) = title_re.captures(&body) {
            let title = captures
                .get(1)
                .map(|m| m.as_str().trim())
                .unwrap_or_default();
            if !title.is_empty() {
                return Ok(title.to_string());
            }
        }
    }
    Ok(String::new())
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

fn time_mode_label(mode: &CameraTimeMode) -> &'static str {
    match mode {
        CameraTimeMode::Ntp => "ntp",
        CameraTimeMode::Manual => "manual",
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
        assert!(!caps.timezone);
        assert!(caps.ptz);
        assert!(!caps.overlay_text);
        assert!(!caps.overlay_timestamp);
        assert!(!caps.password_rotate);
        assert!(!caps.hardening_profile);
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
}
