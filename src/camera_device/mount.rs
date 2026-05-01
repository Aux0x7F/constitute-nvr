use super::*;

pub async fn mount_camera_device(
    cfg: &Config,
    request: MountCameraRequest,
) -> Result<CameraDeviceMountResult> {
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
    let mut camera = CameraDeviceConfig {
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
        desired: CameraDeviceDesiredConfig {
            display_name: display_name.clone(),
            overlay_text: if driver_is_xm(&driver_match.driver_id) {
                String::new()
            } else {
                display_name.clone()
            },
            overlay_timestamp: !driver_is_xm(&driver_match.driver_id),
            desired_password: request.desired_password.trim().to_string(),
            generate_password: request.generate_password,
            ..Default::default()
        },
        credentials: Default::default(),
    };
    normalize_camera_defaults(cfg, &mut camera);
    camera = apply_driver_mount(cfg, &camera).await?;
    Ok(CameraDeviceMountResult {
        configured: camera.clone(),
        mounted: inventory::read_mounted_camera_device(cfg, &camera).await,
    })
}
