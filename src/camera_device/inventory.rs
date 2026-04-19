use super::*;

pub async fn list_camera_device_inventory(cfg: &Config) -> Result<CameraInventory> {
    let mut mounted = Vec::with_capacity(cfg.camera_devices.len());
    for camera in &cfg.camera_devices {
        mounted.push(read_mounted_camera_device(cfg, camera).await);
    }
    Ok(CameraInventory {
        mounted_devices: mounted,
        candidate_devices: discover_candidates(cfg).await?,
        camera_network: camera_network_summary(cfg),
    })
}

pub async fn read_camera_device(cfg: &Config, source_id: &str) -> Result<MountedCamera> {
    let camera = cfg
        .camera_devices
        .iter()
        .find(|camera| camera.source_id.trim() == source_id.trim())
        .cloned()
        .ok_or_else(|| anyhow!("camera source is not configured"))?;
    Ok(read_mounted_camera_device(cfg, &camera).await)
}

pub async fn read_mounted_camera_device(cfg: &Config, camera: &CameraConfig) -> MountedCamera {
    let base_capabilities = driver_capabilities(camera);
    match read_observed_state(camera).await {
        Ok(observed) => {
            let capabilities =
                capabilities_for_observed(camera, base_capabilities.clone(), &observed);
            let display_name = first_nonempty(&observed.display_name, &camera_display_name(camera));
            let vendor = first_nonempty(&observed.vendor, &camera.vendor);
            let model = first_nonempty(&observed.model, &camera.model);
            MountedCamera {
                source_id: camera.source_id.clone(),
                driver_id: first_nonempty(&observed.driver_id, &camera.driver_id),
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
                    cfg,
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
            let display_name = first_nonempty(&observed.display_name, &camera_display_name(camera));
            let vendor = first_nonempty(&observed.vendor, &camera.vendor);
            let model = first_nonempty(&observed.model, &camera.model);
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
                    unsupported_fields: unsupported_fields(cfg, camera, &capabilities),
                    ..Default::default()
                },
            }
        }
    }
}
