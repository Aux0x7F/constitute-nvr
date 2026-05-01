use super::*;

pub async fn apply_camera_device_config(
    cfg: &Config,
    request: ApplyMountedCameraRequest,
) -> Result<CameraDeviceApplyResult> {
    let existing = cfg
        .camera_devices
        .iter()
        .find(|camera| camera.source_id.trim() == request.source_id.trim())
        .cloned()
        .ok_or_else(|| anyhow!("camera source is not configured"))?;
    let mut next = existing.clone();
    next.desired = request.desired.clone();
    sync_display_name_and_linked_overlay(&existing, &mut next);
    normalize_camera_defaults(cfg, &mut next);
    let requested_fields = requested_apply_fields(&existing, &next);
    next = apply_driver_desired(cfg, &existing, &next).await?;
    let mounted = inventory::read_mounted_camera_device(cfg, &next).await;
    let verification_failures =
        requested_verification_failures(&mounted.verification, &requested_fields);
    if !verification_failures.is_empty() {
        let requested_name = next.desired.display_name.trim();
        let observed_name = mounted.observed.display_name.trim();
        let detail = if verification_failures
            .iter()
            .any(|field| field == "display_name")
            && !requested_name.is_empty()
        {
            format!(
                "requested camera name {:?}, observed {:?}",
                requested_name,
                if observed_name.is_empty() {
                    "<empty>"
                } else {
                    observed_name
                }
            )
        } else {
            mounted.verification.message.clone()
        };
        return Err(anyhow!(
            "camera apply did not verify requested field(s): {} ({})",
            verification_failures.join(", "),
            detail
        ));
    }
    Ok(CameraDeviceApplyResult {
        configured: next.clone(),
        mounted,
    })
}
