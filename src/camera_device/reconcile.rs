use super::*;
use anyhow::{Result, anyhow};

#[derive(Clone, Debug)]
pub struct CameraDriftReconcileOutcome {
    pub initial_drift_fields: Vec<String>,
    pub configured: CameraDeviceConfig,
    pub mounted: MountedCamera,
}

pub async fn reconcile_camera_device(
    cfg: &Config,
    camera: &CameraDeviceConfig,
) -> Result<Option<CameraDriftReconcileOutcome>> {
    let mounted_before = inventory::read_mounted_camera_device(cfg, camera).await;
    let initial_actionable_drift_fields =
        actionable_drift_fields(camera, &mounted_before.verification.drift_fields);
    if initial_actionable_drift_fields.is_empty() {
        return Ok(None);
    }

    let initial_drift_fields = initial_actionable_drift_fields;
    let configured = apply_driver_desired(cfg, camera, camera).await?;
    let mounted = inventory::read_mounted_camera_device(cfg, &configured).await;
    let remaining_actionable_drift =
        actionable_drift_fields(&configured, &mounted.verification.drift_fields);

    match mounted.verification.status.trim() {
        "verified" => Ok(Some(CameraDriftReconcileOutcome {
            initial_drift_fields,
            configured,
            mounted,
        })),
        "failed" => Err(anyhow!(
            "camera drift reconcile did not restore readable state: {}",
            mounted.verification.message
        )),
        "drift" if remaining_actionable_drift.is_empty() => Ok(Some(CameraDriftReconcileOutcome {
            initial_drift_fields,
            configured,
            mounted,
        })),
        "drift" => Err(anyhow!(
            "camera drift reconcile did not clear actionable drift: {}",
            remaining_actionable_drift.join(", ")
        )),
        other => Err(anyhow!(
            "camera drift reconcile ended in unexpected status {:?}",
            other
        )),
    }
}

pub fn camera_config_changed(left: &CameraDeviceConfig, right: &CameraDeviceConfig) -> bool {
    serde_json::to_value(left).ok() != serde_json::to_value(right).ok()
}

fn actionable_drift_fields(camera: &CameraDeviceConfig, drift_fields: &[String]) -> Vec<String> {
    drift_fields
        .iter()
        .filter(|field| camera_field_is_reconcilable(camera, field))
        .cloned()
        .collect()
}

fn camera_field_is_reconcilable(camera: &CameraDeviceConfig, field: &str) -> bool {
    if camera.driver_id.trim() == DRIVER_ID_REOLINK {
        return matches!(
            field,
            "display_name"
                | "time_mode"
                | "ntp_server"
                | "timezone"
                | "time_clock"
                | "overlay_text"
                | "overlay_timestamp"
        );
    }
    if driver_is_xm(&camera.driver_id) {
        return matches!(
            field,
            "display_name" | "time_mode" | "ntp_server" | "timezone" | "time_clock"
        );
    }
    if camera.driver_id.trim() == DRIVER_ID_GENERIC_ONVIF_RTSP {
        return matches!(
            field,
            "time_mode" | "ntp_server" | "timezone" | "time_clock"
        );
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_camera() -> CameraDeviceConfig {
        CameraDeviceConfig {
            source_id: "cam-1".to_string(),
            name: "Front Door".to_string(),
            onvif_host: "192.168.0.201".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=1.sdp?real_stream".to_string(),
            username: "admin".to_string(),
            password: "123456".to_string(),
            driver_id: DRIVER_ID_XM_40E.to_string(),
            vendor: "XM/NetSurveillance".to_string(),
            model: "40E".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: CameraDeviceDesiredConfig {
                display_name: "Front Door".to_string(),
                ..Default::default()
            },
            credentials: Default::default(),
        }
    }

    #[test]
    fn reconcile_gate_only_uses_actionable_drift() {
        let mut xm_camera = sample_camera();
        let generic = CameraDeviceConfig {
            driver_id: DRIVER_ID_GENERIC_ONVIF_RTSP.to_string(),
            ..xm_camera.clone()
        };

        assert_eq!(
            actionable_drift_fields(&xm_camera, &["display_name".to_string()]),
            vec!["display_name".to_string()]
        );
        assert!(actionable_drift_fields(&generic, &["display_name".to_string()]).is_empty());
        xm_camera.driver_id = DRIVER_ID_REOLINK.to_string();
        assert_eq!(
            actionable_drift_fields(
                &xm_camera,
                &["overlay_text".to_string(), "time_clock".to_string()]
            ),
            vec!["overlay_text".to_string(), "time_clock".to_string()]
        );
    }

    #[test]
    fn camera_config_changed_detects_meaningful_delta() {
        let left = sample_camera();
        let mut right = left.clone();
        assert!(!camera_config_changed(&left, &right));
        right.desired.display_name = "Driveway".to_string();
        assert!(camera_config_changed(&left, &right));
    }
}
