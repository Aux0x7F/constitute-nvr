use super::*;
use anyhow::{Result, anyhow};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct CameraDriftReconcileOutcome {
    pub initial_drift_fields: Vec<String>,
    pub configured: CameraDeviceConfig,
    pub mounted: MountedCamera,
}

#[derive(Clone, Debug)]
pub struct CameraIdentityReconcileOutcome {
    pub previous_source_id: String,
    pub previous_host: String,
    pub configured: CameraDeviceConfig,
    pub match_kind: String,
    pub confidence: u8,
}

#[derive(Clone, Debug)]
struct ReolinkIdentityMatch {
    candidate: DiscoveredCameraCandidate,
    confidence: u8,
    match_kind: String,
}

#[derive(Clone, Debug)]
struct AuthenticatedReolinkCandidate {
    candidate: DiscoveredCameraCandidate,
    strong_context_match: bool,
}

pub async fn reconcile_camera_identity_and_endpoint(
    cfg: &Config,
    camera: &CameraDeviceConfig,
) -> Result<Option<CameraIdentityReconcileOutcome>> {
    if camera.driver_id.trim() != DRIVER_ID_REOLINK {
        return Ok(None);
    }

    let source_is_noncompliant = !camera.source_id.trim().starts_with("reolink-")
        || reolink_source_id_is_ip_derived(&camera.source_id);
    let host_is_reachable = current_reolink_host_is_reachable(camera).await;
    if !source_is_noncompliant && host_is_reachable {
        return Ok(None);
    }

    let discovered = discover_candidates(cfg).await?;
    let mut candidates = discovered
        .into_iter()
        .filter(|candidate| candidate.driver_match.driver_id.trim() == DRIVER_ID_REOLINK)
        .collect::<Vec<_>>();
    if !host_is_reachable
        && let Some(candidate) = reolink_neighbor_identity_candidate(cfg, camera).await?
        && !candidates
            .iter()
            .any(|existing| existing.ip.trim() == candidate.ip.trim())
    {
        candidates.push(candidate);
    }
    if let Some(current) = current_host_reolink_candidate(camera).await? {
        if !candidates
            .iter()
            .any(|candidate| candidate.ip.trim() == current.ip.trim())
        {
            candidates.push(current);
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    let mut matches = candidates
        .iter()
        .filter_map(|candidate| {
            known_reolink_identity_match(camera, candidate, source_is_noncompliant)
        })
        .collect::<Vec<_>>();

    if matches
        .iter()
        .all(|candidate_match| candidate_match.confidence < 85)
    {
        matches.extend(authenticated_reolink_matches(camera, &candidates).await?);
    }

    let Some(selected) = select_unique_reolink_identity_match(matches)? else {
        return Ok(None);
    };
    let configured = reolink_config_resolved_to_candidate(cfg, camera, &selected.candidate);
    if !camera_config_changed(camera, &configured) {
        return Ok(None);
    }
    Ok(Some(CameraIdentityReconcileOutcome {
        previous_source_id: camera.source_id.clone(),
        previous_host: camera.onvif_host.clone(),
        configured,
        match_kind: selected.match_kind,
        confidence: selected.confidence,
    }))
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

async fn current_reolink_host_is_reachable(camera: &CameraDeviceConfig) -> bool {
    let host = camera.onvif_host.trim();
    if host.is_empty() {
        return false;
    }
    let ports = probe_common_ports(host).await;
    ports.http || ports.https || ports.rtsp || ports.onvif || ports.proprietary_9000
}

async fn current_host_reolink_candidate(
    camera: &CameraDeviceConfig,
) -> Result<Option<DiscoveredCameraCandidate>> {
    let host = camera.onvif_host.trim();
    if host.is_empty() {
        return Ok(None);
    }
    let ports = probe_common_ports(host).await;
    if !(ports.http || ports.https || ports.rtsp || ports.onvif || ports.proprietary_9000) {
        return Ok(None);
    }

    let mut candidate = blank_candidate(host);
    candidate.mac = neighbor_mac_for_ip(host);
    candidate.transports.http = ports.http;
    candidate.transports.https = ports.https;
    candidate.transports.rtsp = ports.rtsp;
    candidate.transports.onvif = ports.onvif;
    candidate.transports.proprietary_9000 = ports.proprietary_9000;
    push_unique_string(&mut candidate.discovered_via, "configured_endpoint_probe");

    if let Some(discovered) = reolink::discover_with_hint(host, 2)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|entry| entry.ip.trim() == host)
    {
        candidate.mac = first_nonempty(&candidate.mac, &discovered.mac);
        candidate.signatures.vendor = "Reolink".to_string();
        candidate.signatures.model = first_nonempty(&candidate.signatures.model, &discovered.model);
        candidate.signatures.reolink_uid =
            first_nonempty(&candidate.signatures.reolink_uid, &discovered.uid);
        push_unique_string(&mut candidate.discovered_via, &discovered.from);
    }

    hydrate_candidate(&mut candidate, &http_client()?).await?;
    candidate.driver_match = match_candidate(&candidate);
    if candidate.driver_match.driver_id.trim() != DRIVER_ID_REOLINK {
        return Ok(None);
    }
    candidate.candidate_id = candidate_id(&candidate);
    Ok(Some(candidate))
}

fn known_reolink_identity_match(
    camera: &CameraDeviceConfig,
    candidate: &DiscoveredCameraCandidate,
    source_is_noncompliant: bool,
) -> Option<ReolinkIdentityMatch> {
    let candidate_uid_source = reolink_stable_source_id(&candidate.signatures.reolink_uid, "");
    let candidate_mac_source = reolink_stable_source_id("", &candidate.mac);
    let candidate_stable_source = reolink_candidate_stable_source_id(candidate);
    let configured_source = camera.source_id.trim();

    if candidate_uid_source
        .as_deref()
        .is_some_and(|source| source == configured_source)
    {
        return Some(identity_match(candidate, 100, "reolink_uid_source_id"));
    }
    if candidate_mac_source
        .as_deref()
        .is_some_and(|source| source == configured_source)
    {
        return Some(identity_match(candidate, 96, "reolink_mac_source_id"));
    }
    if !camera.mac_address.trim().is_empty()
        && !candidate.mac.trim().is_empty()
        && sanitize_id(&camera.mac_address) == sanitize_id(&candidate.mac)
    {
        return Some(identity_match(candidate, 95, "reolink_mac_config"));
    }
    if source_is_noncompliant
        && candidate_stable_source.is_some()
        && !camera.onvif_host.trim().is_empty()
        && camera.onvif_host.trim() == candidate.ip.trim()
    {
        return Some(identity_match(
            candidate,
            88,
            "reolink_current_endpoint_identity_convergence",
        ));
    }
    None
}

async fn authenticated_reolink_matches(
    camera: &CameraDeviceConfig,
    candidates: &[DiscoveredCameraCandidate],
) -> Result<Vec<ReolinkIdentityMatch>> {
    let mut authenticated = Vec::new();
    for candidate in candidates {
        if let Some(authenticated_candidate) =
            authenticate_reolink_candidate(camera, candidate).await?
        {
            authenticated.push(authenticated_candidate);
        }
    }

    let strong = authenticated
        .iter()
        .filter(|candidate| candidate.strong_context_match)
        .cloned()
        .collect::<Vec<_>>();
    if strong.len() == 1 {
        return Ok(vec![identity_match(
            &strong[0].candidate,
            90,
            "reolink_authenticated_context_match",
        )]);
    }
    if authenticated.len() == 1 {
        return Ok(vec![identity_match(
            &authenticated[0].candidate,
            86,
            "reolink_authenticated_single_candidate",
        )]);
    }
    Ok(Vec::new())
}

async fn authenticate_reolink_candidate(
    camera: &CameraDeviceConfig,
    candidate: &DiscoveredCameraCandidate,
) -> Result<Option<AuthenticatedReolinkCandidate>> {
    for password in crate::config::camera_device_credential_candidates(camera) {
        let request = ProbeCameraRequest {
            source_id: String::new(),
            ip: candidate.ip.clone(),
            username: camera.username.clone(),
            password,
            driver_id: DRIVER_ID_REOLINK.to_string(),
        };
        if let Ok(probe) = probe_reolink_candidate(candidate, &request).await
            && probe
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "ok")
        {
            return Ok(Some(AuthenticatedReolinkCandidate {
                candidate: candidate.clone(),
                strong_context_match: reolink_probe_matches_config(camera, &probe),
            }));
        }
    }
    Ok(None)
}

fn reolink_probe_matches_config(camera: &CameraDeviceConfig, probe: &Value) -> bool {
    let observed_model = probe
        .get("observed")
        .unwrap_or(&Value::Null)
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let observed_overlay = probe
        .get("observed")
        .unwrap_or(&Value::Null)
        .get("overlayText")
        .and_then(Value::as_str)
        .unwrap_or_default();

    labels_match(&camera.model, observed_model)
        || labels_match(&camera.name, observed_overlay)
        || labels_match(&camera.desired.display_name, observed_overlay)
        || labels_match(&camera.desired.overlay_text, observed_overlay)
}

fn labels_match(left: &str, right: &str) -> bool {
    let left = left.trim().to_ascii_lowercase();
    let right = right.trim().to_ascii_lowercase();
    !left.is_empty() && !right.is_empty() && (left.contains(&right) || right.contains(&left))
}

fn select_unique_reolink_identity_match(
    mut matches: Vec<ReolinkIdentityMatch>,
) -> Result<Option<ReolinkIdentityMatch>> {
    matches.sort_by(|left, right| right.confidence.cmp(&left.confidence));
    let Some(best) = matches.first().cloned() else {
        return Ok(None);
    };
    if best.confidence < 85 {
        return Ok(None);
    }
    if matches
        .iter()
        .skip(1)
        .any(|candidate_match| candidate_match.confidence == best.confidence)
    {
        return Err(anyhow!(
            "ambiguous Reolink identity relocation match at confidence {}",
            best.confidence
        ));
    }
    Ok(Some(best))
}

fn identity_match(
    candidate: &DiscoveredCameraCandidate,
    confidence: u8,
    match_kind: &str,
) -> ReolinkIdentityMatch {
    ReolinkIdentityMatch {
        candidate: candidate.clone(),
        confidence,
        match_kind: match_kind.to_string(),
    }
}

async fn reolink_neighbor_identity_candidate(
    cfg: &Config,
    camera: &CameraDeviceConfig,
) -> Result<Option<DiscoveredCameraCandidate>> {
    let iface = cfg.camera_network.interface.trim();
    if iface.is_empty() {
        return Ok(None);
    }
    let known_macs = configured_reolink_identity_macs(camera);
    if known_macs.is_empty() {
        return Ok(None);
    }
    let client = http_client()?;
    for (ip, mac) in interface_neighbor_entries(iface) {
        let normalized = normalize_mac(&mac).unwrap_or_default();
        if !known_macs.iter().any(|known| known == &normalized) {
            continue;
        }
        let ports = probe_common_ports(&ip).await;
        if !(ports.http || ports.https || ports.rtsp || ports.onvif || ports.proprietary_9000) {
            continue;
        }
        let mut candidate = blank_candidate(&ip);
        candidate.mac = normalized;
        candidate.signatures.vendor = "Reolink".to_string();
        candidate.transports.http = ports.http;
        candidate.transports.https = ports.https;
        candidate.transports.rtsp = ports.rtsp;
        candidate.transports.onvif = ports.onvif;
        candidate.transports.proprietary_9000 = ports.proprietary_9000;
        push_unique_string(&mut candidate.discovered_via, "interface_neighbor_mac");
        hydrate_candidate(&mut candidate, &client).await?;
        candidate.driver_match = match_candidate(&candidate);
        if candidate.driver_match.driver_id.trim() == DRIVER_ID_REOLINK {
            candidate.candidate_id = candidate_id(&candidate);
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn configured_reolink_identity_macs(camera: &CameraDeviceConfig) -> Vec<String> {
    let mut out = Vec::new();
    for value in [
        camera.mac_address.as_str(),
        camera
            .source_id
            .trim()
            .strip_prefix("reolink-")
            .unwrap_or_default(),
    ] {
        if let Some(mac) = normalize_mac(value)
            && !out.contains(&mac)
        {
            out.push(mac);
        }
    }
    out
}

fn interface_neighbor_entries(iface: &str) -> Vec<(String, String)> {
    let output = match Command::new("ip")
        .args(["neigh", "show", "dev", iface.trim()])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_neighbor_entries(&String::from_utf8_lossy(&output.stdout))
}

fn parse_neighbor_entries(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let ip = parts.first()?.trim();
            let mac = parts
                .windows(2)
                .find_map(|window| (window[0] == "lladdr").then(|| window[1].trim()))?;
            Some((ip.to_string(), mac.to_string()))
        })
        .collect()
}

fn normalize_mac(value: &str) -> Option<String> {
    let hex = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>();
    if hex.len() != 12 {
        return None;
    }
    Some(
        (0..6)
            .map(|idx| &hex[idx * 2..idx * 2 + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn reolink_config_resolved_to_candidate(
    cfg: &Config,
    camera: &CameraDeviceConfig,
    candidate: &DiscoveredCameraCandidate,
) -> CameraDeviceConfig {
    let mut updated = camera.clone();
    if let Some(stable_source_id) = reolink_candidate_stable_source_id(candidate) {
        updated.source_id = stable_source_id;
    }
    if !candidate.ip.trim().is_empty() {
        updated.onvif_host = candidate.ip.trim().to_string();
        if !updated.rtsp_url.trim().is_empty() {
            updated.rtsp_url =
                rewrite_rtsp_url_host(&updated.rtsp_url, &updated.onvif_host, updated.rtsp_port);
        } else {
            updated.rtsp_url = derive_rtsp_url(
                candidate,
                DRIVER_ID_REOLINK,
                &updated.username,
                &updated.password,
                "",
            );
        }
    }
    updated.onvif_port = derive_onvif_port(candidate);
    updated.rtsp_port = derive_rtsp_port(candidate, &updated.rtsp_url);
    if !candidate.mac.trim().is_empty() {
        updated.mac_address = candidate.mac.trim().to_string();
    }
    if !candidate.signatures.vendor.trim().is_empty() {
        updated.vendor = candidate.signatures.vendor.trim().to_string();
    } else if updated.vendor.trim().is_empty() {
        updated.vendor = "Reolink".to_string();
    }
    if !candidate.signatures.model.trim().is_empty() {
        updated.model = candidate.signatures.model.trim().to_string();
    }
    updated.ptz_capable = updated.ptz_capable || candidate_ptz_capable(candidate);
    normalize_camera_defaults(cfg, &mut updated);
    updated
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

    fn reolink_candidate(ip: &str, uid: &str, mac: &str) -> DiscoveredCameraCandidate {
        DiscoveredCameraCandidate {
            candidate_id: sanitize_id(if mac.is_empty() { ip } else { mac }),
            ip: ip.to_string(),
            mac: mac.to_string(),
            signatures: CameraSignatureSet {
                vendor: "Reolink".to_string(),
                model: "E1 Outdoor SE".to_string(),
                reolink_uid: uid.to_string(),
                ..Default::default()
            },
            transports: CameraTransportFacts {
                rtsp: true,
                onvif: true,
                proprietary_9000: true,
                ..Default::default()
            },
            driver_match: DriverMatch {
                driver_id: DRIVER_ID_REOLINK.to_string(),
                confidence: 100,
                mountable: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn legacy_reolink_camera() -> CameraDeviceConfig {
        CameraDeviceConfig {
            source_id: "reolink-192-168-250-97".to_string(),
            name: "Reolink Patio".to_string(),
            onvif_host: "192.168.250.97".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:secret@192.168.250.97:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "secret".to_string(),
            driver_id: DRIVER_ID_REOLINK.to_string(),
            vendor: "Reolink".to_string(),
            model: "E1 Outdoor SE".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDeviceDesiredConfig {
                display_name: "Reolink Patio".to_string(),
                overlay_text: "Reolink Patio".to_string(),
                overlay_timestamp: true,
                ..Default::default()
            },
            credentials: Default::default(),
        }
    }

    fn sample_config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-reconcile-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (cfg, _) = Config::load_or_create(&path).expect("config");
        let _ = std::fs::remove_file(path);
        cfg
    }

    #[test]
    fn reolink_source_id_detects_ip_derived_legacy() {
        assert!(reolink_source_id_is_ip_derived("reolink-192-168-250-97"));
        assert!(!reolink_source_id_is_ip_derived("reolink-95270001abc"));
        assert!(!reolink_source_id_is_ip_derived(
            "reolink-ec-71-db-32-0a-8f"
        ));
    }

    #[test]
    fn reolink_resolved_config_prefers_uid_source_id_and_rewrites_endpoint() {
        let cfg = sample_config();
        let camera = legacy_reolink_camera();
        let candidate = reolink_candidate("192.168.250.98", "95270001ABC", "ec:71:db:32:0a:8f");

        let updated = reolink_config_resolved_to_candidate(&cfg, &camera, &candidate);

        assert_eq!(updated.source_id, "reolink-95270001abc");
        assert_eq!(updated.onvif_host, "192.168.250.98");
        assert_eq!(updated.mac_address, "ec:71:db:32:0a:8f");
        assert!(updated.rtsp_url.contains("192.168.250.98"));
        assert!(!updated.rtsp_url.contains("192.168.250.97"));
    }

    #[test]
    fn reolink_identity_match_accepts_existing_mac_source_id() {
        let mut camera = legacy_reolink_camera();
        camera.source_id = "reolink-ec-71-db-32-0a-8f".to_string();
        let candidate = reolink_candidate("192.168.250.98", "", "ec:71:db:32:0a:8f");

        let matched = known_reolink_identity_match(&camera, &candidate, false)
            .expect("mac source id should match");

        assert_eq!(matched.confidence, 96);
        assert_eq!(matched.match_kind, "reolink_mac_source_id");
    }

    #[test]
    fn reolink_identity_macs_include_source_id_suffix() {
        let mut camera = legacy_reolink_camera();
        camera.source_id = "reolink-ec-71-db-32-0a-8f".to_string();
        camera.mac_address.clear();

        assert_eq!(
            configured_reolink_identity_macs(&camera),
            vec!["ec:71:db:32:0a:8f".to_string()]
        );
    }

    #[test]
    fn neighbor_entries_parse_lladdr_rows() {
        let entries = parse_neighbor_entries(
            "192.168.250.97 dev enp21s0f0u5 lladdr ec:71:db:32:0a:8f STALE\n\
             192.168.250.98 dev enp21s0f0u5 INCOMPLETE\n",
        );

        assert_eq!(
            entries,
            vec![(
                "192.168.250.97".to_string(),
                "ec:71:db:32:0a:8f".to_string()
            )]
        );
    }
}
