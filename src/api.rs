use crate::camera_device;
use crate::config::{CameraDeviceConfig, CameraDeviceDesiredConfig, Config};
use crate::hosted_registry;
use crate::live::PreviewManager;
use crate::recording::RecorderManager;
use crate::storage::StorageManager;
use anyhow::Result;
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use constitute_protocol::{LogCategory, LogOutcome, LogSeverity, LogSubjectRef};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{info, warn};

const CAMERA_RECONCILE_INITIAL_DELAY_SECS: u64 = 5;
const CAMERA_RECONCILE_INTERVAL_SECS: u64 = 20;

#[derive(Clone)]
pub struct ApiState {
    pub cfg: Arc<Mutex<Config>>,
    pub cfg_path: PathBuf,
    pub storage: StorageManager,
    pub recorder: RecorderManager,
    pub preview: PreviewManager,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthCameraView {
    source_id: String,
    name: String,
    onvif_host: String,
    onvif_port: u16,
    enabled: bool,
    segment_secs: u64,
    rtsp_configured: bool,
    ptz_capable: bool,
    driver_id: String,
    vendor: String,
    model: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthCameraNetworkView {
    managed: bool,
    interface: String,
    subnet_cidr: String,
    host_ip: String,
    dhcp_enabled: bool,
    dhcp_range_start: String,
    dhcp_range_end: String,
    ntp_enabled: bool,
    ntp_server: String,
    timezone: String,
    dns_server: String,
}

pub async fn run(
    cfg: Arc<Mutex<Config>>,
    cfg_path: PathBuf,
    storage: StorageManager,
    recorder: RecorderManager,
    preview: PreviewManager,
) -> Result<()> {
    let bind = cfg.lock().await.api.bind.clone();
    let state = Arc::new(ApiState {
        preview,
        cfg,
        cfg_path,
        storage,
        recorder,
    });
    spawn_camera_reconcile_loop(Arc::clone(&state));

    let app = api_router(state);

    let listener = TcpListener::bind(&bind).await?;
    info!(bind = %bind, "api listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}

fn api_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/logging/events", get(logging_events))
        .with_state(state)
}

pub(crate) fn api_route_manifest() -> &'static [&'static str] {
    &["/health", "/v1/logging/events"]
}

fn spawn_camera_reconcile_loop(state: Arc<ApiState>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(CAMERA_RECONCILE_INITIAL_DELAY_SECS)).await;
        let mut ticker = interval(Duration::from_secs(CAMERA_RECONCILE_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(err) = run_camera_reconcile_cycle(state.as_ref()).await {
                warn!(error = %err, "camera reconcile cycle failed");
            }
        }
    });
}

async fn run_camera_reconcile_cycle(state: &ApiState) -> Result<()> {
    let cfg = state.cfg.lock().await.clone();
    for camera in cfg
        .camera_devices
        .iter()
        .filter(|camera| camera.enabled)
        .cloned()
    {
        let mut camera = camera;
        match camera_device::reconcile_camera_identity_and_endpoint(&cfg, &camera).await {
            Ok(Some(outcome)) => {
                persist_camera_source_replacing(
                    state,
                    &outcome.previous_source_id,
                    &outcome.previous_host,
                    outcome.configured.clone(),
                )
                .await?;
                submit_camera_identity_reconcile_event(&outcome).await;
                info!(
                    previous_source = %outcome.previous_source_id,
                    source = %outcome.configured.source_id,
                    match_kind = %outcome.match_kind,
                    confidence = outcome.confidence,
                    "camera identity endpoint reconcile applied"
                );
                camera = outcome.configured;
            }
            Ok(None) => {}
            Err(err) => {
                warn!(
                    source = %camera.source_id,
                    error = %err,
                    "camera identity endpoint reconcile failed"
                );
            }
        }

        match camera_device::reconcile_camera_device(&cfg, &camera).await {
            Ok(Some(outcome)) => {
                let changed =
                    camera_device::reconcile::camera_config_changed(&camera, &outcome.configured);
                if changed {
                    persist_camera_source(state, outcome.configured.clone()).await?;
                }
                submit_camera_drift_reconcile_event(&outcome, changed).await;
                info!(
                    source = %camera.source_id,
                    changed,
                    drift_fields = ?outcome.initial_drift_fields,
                    verification_status = %outcome.mounted.verification.status,
                    "camera drift reconcile applied"
                );
            }
            Ok(None) => {}
            Err(err) => {
                submit_camera_drift_reconcile_failed_event(&camera).await;
                warn!(
                    source = %camera.source_id,
                    error = %err,
                    "camera drift reconcile failed"
                );
            }
        }
    }
    Ok(())
}

async fn submit_camera_identity_reconcile_event(
    outcome: &camera_device::reconcile::CameraIdentityReconcileOutcome,
) {
    crate::logging_surface::submit_safe_event(
        "camera_device",
        LogCategory::CameraDevice,
        LogSeverity::Notice,
        LogOutcome::Recovered,
        LogSubjectRef {
            kind: "camera".to_string(),
            id: Some(outcome.configured.source_id.clone()),
            display: Some(outcome.configured.name.clone()),
        },
        &["nvr", "camera_device", "identity_reconcile"],
        json!({
            "eventType": "camera_identity_endpoint_reconciled",
            "sourceId": outcome.configured.source_id,
            "previousSourceId": outcome.previous_source_id,
            "driverId": outcome.configured.driver_id,
            "vendor": outcome.configured.vendor,
            "model": outcome.configured.model,
            "matchKind": outcome.match_kind,
            "confidence": outcome.confidence,
            "endpointChanged": outcome.previous_host != outcome.configured.onvif_host,
        }),
    )
    .await;
}

async fn submit_camera_drift_reconcile_event(
    outcome: &camera_device::reconcile::CameraDriftReconcileOutcome,
    changed: bool,
) {
    crate::logging_surface::submit_safe_event(
        "camera_device",
        LogCategory::CameraDevice,
        LogSeverity::Notice,
        LogOutcome::Recovered,
        camera_log_subject(&outcome.configured),
        &["nvr", "camera_device", "drift_reconcile"],
        camera_drift_reconcile_safe_facts(outcome, changed),
    )
    .await;
}

async fn submit_camera_drift_reconcile_failed_event(camera: &CameraDeviceConfig) {
    crate::logging_surface::submit_safe_event(
        "camera_device",
        LogCategory::CameraDevice,
        LogSeverity::Warning,
        LogOutcome::Failed,
        camera_log_subject(camera),
        &["nvr", "camera_device", "drift_reconcile", "repair_needed"],
        json!({
            "eventType": "camera_drift_reconcile_failed",
            "sourceId": camera.source_id,
            "cameraName": camera.name,
            "driverId": camera.driver_id,
            "vendor": camera.vendor,
            "model": camera.model,
            "repairNeeded": true,
            "errorClass": "camera_drift_reconcile_failed",
        }),
    )
    .await;
}

fn camera_log_subject(camera: &CameraDeviceConfig) -> LogSubjectRef {
    LogSubjectRef {
        kind: "camera".to_string(),
        id: Some(camera.source_id.clone()),
        display: Some(camera.name.clone()),
    }
}

fn camera_drift_reconcile_safe_facts(
    outcome: &camera_device::reconcile::CameraDriftReconcileOutcome,
    changed: bool,
) -> Value {
    json!({
        "eventType": "camera_drift_reconciled",
        "sourceId": outcome.configured.source_id,
        "cameraName": outcome.configured.name,
        "driverId": outcome.configured.driver_id,
        "vendor": outcome.configured.vendor,
        "model": outcome.configured.model,
        "driftFields": outcome.initial_drift_fields,
        "changed": changed,
        "verificationStatus": outcome.mounted.verification.status,
        "remainingDriftFields": outcome.mounted.verification.drift_fields,
        "repairNeeded": false,
    })
}

async fn nvr_health_body(state: &ApiState) -> Value {
    let retained_sources = state.storage.list_sources().await.unwrap_or_default();
    let runtime = state.recorder.list_states().await;
    let cfg = state.cfg.lock().await.clone();
    let media_projection = state.preview.media_projection_health(&cfg).await;
    let sources = cfg
        .camera_devices
        .iter()
        .map(|cam| cam.source_id.clone())
        .collect::<Vec<_>>();
    let cameras = cfg
        .camera_devices
        .iter()
        .map(|cam| HealthCameraView {
            source_id: cam.source_id.clone(),
            name: cam.name.clone(),
            onvif_host: cam.onvif_host.clone(),
            onvif_port: cam.onvif_port,
            enabled: cam.enabled,
            segment_secs: cam.segment_secs,
            rtsp_configured: !cam.rtsp_url.trim().is_empty(),
            ptz_capable: cam.ptz_capable,
            driver_id: cam.driver_id.clone(),
            vendor: cam.vendor.clone(),
            model: cam.model.clone(),
        })
        .collect::<Vec<_>>();
    let camera_network = HealthCameraNetworkView {
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
    };
    json!({
        "ok": true,
        "service": "nvr",
        "deviceKind": "service",
        "version": cfg.service_version,
        "nodeRole": cfg.node_role,
        "identityId": cfg.api.identity_id,
        "devicePk": cfg.nostr_pubkey,
        "hostGatewayPk": cfg.gateway.host_gateway_pk,
        "sources": sources,
        "retainedSources": retained_sources,
        "cameraDevices": cameras,
        "cameraNetwork": camera_network,
        "mediaProjection": media_projection,
        "sourceRuntime": runtime,
        "configuredSources": cfg.camera_devices.len(),
    })
}

async fn health(State(state): State<Arc<ApiState>>) -> Json<Value> {
    Json(nvr_health_body(&state).await)
}

async fn logging_events(
    Query(query): Query<crate::logging_surface::LoggingEventsQuery>,
) -> Json<crate::logging_surface::ProducerEventsResponse> {
    Json(crate::logging_surface::read_events(query))
}

async fn persist_camera_source(state: &ApiState, camera_cfg: CameraDeviceConfig) -> Result<()> {
    persist_camera_source_replacing(state, "", "", camera_cfg).await
}

async fn persist_camera_source_replacing(
    state: &ApiState,
    previous_source_id: &str,
    previous_host: &str,
    camera_cfg: CameraDeviceConfig,
) -> Result<()> {
    let storage_root = {
        let mut guard = state.cfg.lock().await;
        if let Some(index) = guard.camera_devices.iter().position(|c| {
            (!previous_source_id.trim().is_empty()
                && c.source_id.trim() == previous_source_id.trim())
                || c.source_id == camera_cfg.source_id
                || (!previous_host.trim().is_empty() && c.onvif_host.trim() == previous_host.trim())
                || c.onvif_host == camera_cfg.onvif_host
        }) {
            guard.camera_devices[index] = camera_cfg.clone();
        } else {
            guard.camera_devices.push(camera_cfg.clone());
        }
        guard.apply_defaults();
        let snapshot = guard.clone();
        snapshot.persist(&state.cfg_path)?;
        let _ = hosted_registry::persist_hosted_service_manifest(&snapshot);
        snapshot.storage_root()
    };

    if !previous_source_id.trim().is_empty()
        && previous_source_id.trim() != camera_cfg.source_id.trim()
    {
        state
            .recorder
            .remove_camera(previous_source_id.trim())
            .await;
    }
    state
        .recorder
        .upsert_camera(storage_root, camera_cfg.clone())
        .await;

    state
        .preview
        .refresh_camera_source(previous_source_id, camera_cfg)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_camera() -> CameraDeviceConfig {
        CameraDeviceConfig {
            source_id: "xm-40e-front-door".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "192.0.2.10".to_string(),
            onvif_port: 80,
            rtsp_url: "rtsp://example.invalid/redacted".to_string(),
            username: "admin".to_string(),
            password: "redacted".to_string(),
            driver_id: "xm_40e".to_string(),
            vendor: "XM".to_string(),
            model: "40E".to_string(),
            mac_address: "00:00:00:00:00:00".to_string(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDeviceDesiredConfig::default(),
            credentials: Default::default(),
        }
    }

    #[test]
    fn camera_drift_reconcile_safe_facts_do_not_expose_transport_or_secrets() {
        let camera = test_camera();
        let mut mounted = camera_device::MountedCamera {
            source_id: camera.source_id.clone(),
            driver_id: camera.driver_id.clone(),
            display_name: camera.name.clone(),
            vendor: camera.vendor.clone(),
            model: camera.model.clone(),
            ..Default::default()
        };
        mounted.verification.status = "verified".to_string();
        mounted.verification.drift_fields = vec!["time_clock".to_string()];
        let outcome = camera_device::reconcile::CameraDriftReconcileOutcome {
            initial_drift_fields: vec!["timezone".to_string(), "time_clock".to_string()],
            configured: camera,
            mounted,
        };

        let facts = camera_drift_reconcile_safe_facts(&outcome, true);

        assert_eq!(facts["eventType"], json!("camera_drift_reconciled"));
        assert_eq!(facts["driverId"], json!("xm_40e"));
        assert_eq!(facts["driftFields"][0], json!("timezone"));
        assert_eq!(facts["changed"], json!(true));
        assert_eq!(facts["repairNeeded"], json!(false));
        assert!(facts.get("rtsp_url").is_none());
        assert!(facts.get("rtspUrl").is_none());
        assert!(facts.get("password").is_none());
        assert!(facts.get("username").is_none());
        assert!(facts.get("onvifHost").is_none());
        assert!(facts.get("macAddress").is_none());
    }

    #[test]
    fn api_route_manifest_omits_retired_product_routes() {
        let routes = api_route_manifest();
        let retired_access_prefix = format!("/{}-{}", "service", "access");
        let retired_exchange_route = format!("/{}-{}", "service", "exchange");
        let retired_swarm_edge_route = format!("/{}{}", "swarm", "/edge");

        assert!(routes.contains(&"/health"));
        assert!(routes.contains(&"/v1/logging/events"));
        assert!(
            !routes
                .iter()
                .any(|route| route.starts_with(&retired_access_prefix))
        );
        assert!(!routes.contains(&retired_exchange_route.as_str()));
        assert!(!routes.contains(&format!("/sess{}", "ion").as_str()));
        assert!(!routes.contains(&retired_swarm_edge_route.as_str()));
    }
}
