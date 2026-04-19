use crate::camera_device::registry::driver_is_xm;
use crate::config::{CameraDeviceConfig as CameraConfig, Config, LivePreviewConfig};
use crate::media::{ffmpeg, planner, types::OutputCodec};
use crate::nostr::{self, NostrEvent};
use anyhow::{Context, Result, anyhow};
use rtp::packet::Packet as RtpPacket;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::{Mutex, watch};
use tracing::{info, warn};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_H264, MIME_TYPE_VP8, MediaEngine};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::udp_network::{EphemeralUDP, UDPNetwork};
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::{RTCRtpTransceiver, RTCRtpTransceiverInit};
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::TrackLocalWriter;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
use util::marshal::Unmarshal;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ManagedIceServerHints {
    #[serde(default)]
    pub stun: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub turn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedOfferRequest {
    #[serde(rename = "launchToken")]
    pub launch_token: String,
    pub offer: Value,
    #[serde(rename = "iceServers", default)]
    pub ice_servers: ManagedIceServerHints,
    #[serde(default)]
    pub candidates: Vec<RTCIceCandidateInit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedCloseRequest {
    #[serde(rename = "launchToken")]
    pub launch_token: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedControlRequest {
    #[serde(rename = "launchToken")]
    pub launch_token: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(rename = "controlLease", default)]
    pub control_lease: Value,
    #[serde(default)]
    pub preempted: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedAdminRequest {
    #[serde(rename = "launchToken")]
    pub launch_token: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedSourceInfo {
    #[serde(rename = "sourceId")]
    pub source_id: String,
    pub name: String,
    #[serde(rename = "rtspPreviewUrl")]
    pub rtsp_preview_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedOfferResponse {
    #[serde(rename = "signalType")]
    pub signal_type: String,
    pub answer: RTCSessionDescription,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub sources: Vec<ManagedSourceInfo>,
    #[serde(default)]
    pub candidates: Vec<RTCIceCandidateInit>,
}

fn push_unique_ice_candidate(into: &mut Vec<RTCIceCandidateInit>, candidate: &RTCIceCandidateInit) {
    if candidate.candidate.trim().is_empty() {
        return;
    }
    if into
        .iter()
        .any(|existing| ice_candidates_equal(existing, candidate))
    {
        return;
    }
    into.push(candidate.clone());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedLaunchTokenPayload {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "gatewayPk")]
    gateway_pk: String,
    #[serde(rename = "servicePk")]
    service_pk: String,
    service: String,
    #[serde(rename = "identityId")]
    identity_id: String,
    #[serde(rename = "devicePk")]
    device_pk: String,
    capability: String,
    #[serde(default)]
    owner: bool,
    #[serde(rename = "viewSources", default)]
    view_sources: Vec<String>,
    #[serde(rename = "controlSources", default)]
    control_sources: Vec<String>,
    #[serde(rename = "launchNonce")]
    launch_nonce: String,
    #[serde(rename = "issuedAt")]
    issued_at: u64,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewCodec {
    H264,
    Vp8,
}

impl PreviewCodec {
    fn label(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Vp8 => "vp8",
        }
    }

    fn capability(self) -> RTCRtpCodecCapability {
        match self {
            Self::H264 => RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_owned(),
                clock_rate: 90_000,
                sdp_fmtp_line:
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                        .to_string(),
                ..Default::default()
            },
            Self::Vp8 => RTCRtpCodecCapability {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90_000,
                ..Default::default()
            },
        }
    }
}

#[derive(Debug)]
struct PreviewSessionHandle {
    session_id: String,
    peer_connection: Arc<RTCPeerConnection>,
    stops: Vec<watch::Sender<bool>>,
}

impl Clone for PreviewSessionHandle {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            peer_connection: Arc::clone(&self.peer_connection),
            stops: self.stops.clone(),
        }
    }
}

impl PreviewSessionHandle {
    async fn close(&self) {
        for stop in &self.stops {
            let _ = stop.send(true);
        }
        let _ = self.peer_connection.close().await;
    }
}

#[derive(Clone)]
pub struct PreviewManager {
    api: Arc<webrtc::api::API>,
    sessions: Arc<Mutex<HashMap<String, PreviewSessionHandle>>>,
}

impl PreviewManager {
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut setting_engine =
            build_setting_engine(&cfg.live_preview, cfg.camera_network.interface.trim())?;
        setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::QueryOnly);
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(setting_engine)
            .build();
        Ok(Self {
            api: Arc::new(api),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn handle_offer(
        &self,
        cfg: &Config,
        request: ManagedOfferRequest,
    ) -> Result<ManagedOfferResponse> {
        let token = validate_launch_token(cfg, &request.launch_token)?;
        let offer = parse_offer_description(&request.offer)?;
        let selected = select_sources(cfg, source_ids_from_offer(&request.offer), &token)?;
        let remote_candidates = request_candidates(&request);
        if selected.is_empty() {
            return Err(anyhow!(
                "no enabled camera sources available for live preview"
            ));
        }

        let session_key = session_key_for_token(&token);
        if let Some(existing) = self.sessions.lock().await.remove(&session_key) {
            existing.close().await;
        }

        let pc = Arc::new(
            self.api
                .new_peer_connection(build_rtc_configuration(&request.ice_servers))
                .await?,
        );
        let gathered_candidates: Arc<Mutex<Vec<RTCIceCandidateInit>>> =
            Arc::new(Mutex::new(Vec::new()));
        let gathered_candidates_handle = Arc::clone(&gathered_candidates);
        pc.on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
            let gathered_candidates = Arc::clone(&gathered_candidates_handle);
            Box::pin(async move {
                let Some(candidate) = candidate else {
                    return;
                };
                let Ok(json) = candidate.to_json() else {
                    return;
                };
                let mut candidates = gathered_candidates.lock().await;
                if !candidates
                    .iter()
                    .any(|existing| ice_candidates_equal(existing, &json))
                {
                    candidates.push(json);
                }
            })
        }));
        let session_id = format!("nvr-preview-{}", token.launch_nonce);
        let cleanup_sessions = Arc::clone(&self.sessions);
        let cleanup_key = session_key.clone();
        let cleanup_pc = Arc::clone(&pc);
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let sessions = Arc::clone(&cleanup_sessions);
            let key = cleanup_key.clone();
            let pc = Arc::clone(&cleanup_pc);
            Box::pin(async move {
                if matches!(
                    state,
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) {
                    let handle = sessions.lock().await.remove(&key);
                    if let Some(handle) = handle {
                        handle.close().await;
                    } else {
                        let _ = pc.close().await;
                    }
                }
            })
        }));

        pc.set_remote_description(offer).await?;
        apply_remote_candidates(&pc, &remote_candidates).await?;
        let mut offered_video_transceivers = available_offer_video_transceivers(&pc).await;

        let mut stops = Vec::new();
        let mut response_sources = Vec::new();
        let mut answer_msid_tracks = Vec::new();
        for camera in &selected {
            let preview_codec = select_preview_codec_for_camera(&request.offer, camera)?;
            let media_stream_id = format!("{session_id}-{}", camera.source_id);
            let track = Arc::new(TrackLocalStaticRTP::new(
                preview_codec.capability(),
                camera.source_id.clone(),
                media_stream_id.clone(),
            ));
            answer_msid_tracks.push((media_stream_id, camera.source_id.clone()));
            attach_preview_track(
                &pc,
                &mut offered_video_transceivers,
                Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>,
            )
            .await?;
            let (stop_tx, stop_rx) = watch::channel(false);
            stops.push(stop_tx);
            tokio::spawn(run_camera_forwarder(
                camera.clone(),
                track,
                stop_rx,
                preview_codec,
            ));
            response_sources.push(ManagedSourceInfo {
                source_id: camera.source_id.clone(),
                name: camera.name.clone(),
                rtsp_preview_url: planner::preview_rtsp_url(camera),
            });
        }

        let mut gather_complete = pc.gathering_complete_promise().await;
        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer).await?;
        let _ = gather_complete.recv().await;
        let local_desc = pc
            .local_description()
            .await
            .ok_or_else(|| anyhow!("missing local description"))?;
        let local_desc = RTCSessionDescription::answer(with_firefox_compatible_answer_msid(
            &local_desc.sdp,
            &answer_msid_tracks,
        ))?;
        let response_candidates = gathered_candidates.lock().await.clone();

        self.sessions.lock().await.insert(
            session_key,
            PreviewSessionHandle {
                session_id: session_id.clone(),
                peer_connection: Arc::clone(&pc),
                stops,
            },
        );

        Ok(ManagedOfferResponse {
            signal_type: "answer".to_string(),
            answer: local_desc,
            session_id,
            sources: response_sources,
            candidates: response_candidates,
        })
    }

    pub async fn handle_close(&self, cfg: &Config, request: ManagedCloseRequest) -> Result<Value> {
        let token = validate_launch_token(cfg, &request.launch_token)?;
        let session_key = session_key_for_token(&token);
        if let Some(session) = self.sessions.lock().await.remove(&session_key) {
            session.close().await;
        }
        Ok(json!({
            "ok": true,
            "sessionId": format!("nvr-preview-{}", token.launch_nonce),
            "reason": request.payload.get("reason").cloned().unwrap_or_else(|| json!("closed")),
        }))
    }
}

pub fn resolve_control_camera(
    cfg: &Config,
    request: &ManagedControlRequest,
) -> Result<CameraConfig> {
    let token = validate_launch_token(cfg, &request.launch_token)?;
    let source_id = request
        .payload
        .get("sourceId")
        .or_else(|| request.payload.get("source_id"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if source_id.is_empty() {
        return Err(anyhow!("control request is missing sourceId"));
    }
    if !token.owner
        && !token
            .control_sources
            .iter()
            .any(|allowed| allowed.trim() == source_id.trim())
    {
        return Err(anyhow!("control is not granted for this camera"));
    }
    cfg.camera_devices
        .iter()
        .find(|camera| camera.enabled && camera.source_id.trim() == source_id.trim())
        .cloned()
        .ok_or_else(|| anyhow!("camera source is not available for control"))
}

fn build_setting_engine(cfg: &LivePreviewConfig, camera_iface: &str) -> Result<SettingEngine> {
    let mut setting_engine = SettingEngine::default();
    let udp_network = UDPNetwork::Ephemeral(
        EphemeralUDP::new(cfg.udp_port_min, cfg.udp_port_max)
            .map_err(|err| anyhow!("invalid live preview udp port range: {err}"))?,
    );
    setting_engine.set_udp_network(udp_network);
    setting_engine.set_network_types(vec![NetworkType::Udp4]);
    let blocked_iface = camera_iface.trim().to_string();
    setting_engine.set_interface_filter(Box::new(move |iface| {
        let trimmed = iface.trim();
        !trimmed.eq_ignore_ascii_case("lo") && trimmed != blocked_iface
    }));
    Ok(setting_engine)
}

fn build_rtc_configuration(hints: &ManagedIceServerHints) -> RTCConfiguration {
    let mut ice_servers = Vec::new();
    let stun_urls = dedup_urls(&hints.stun);
    if !stun_urls.is_empty() {
        ice_servers.push(RTCIceServer {
            urls: stun_urls,
            ..Default::default()
        });
    }
    RTCConfiguration {
        ice_servers,
        ..Default::default()
    }
}

fn dedup_urls(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let item = trimmed.to_string();
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn ice_candidates_equal(left: &RTCIceCandidateInit, right: &RTCIceCandidateInit) -> bool {
    left.candidate == right.candidate
        && left.sdp_mid == right.sdp_mid
        && left.sdp_mline_index == right.sdp_mline_index
        && left.username_fragment == right.username_fragment
}

async fn apply_remote_candidates(
    pc: &Arc<RTCPeerConnection>,
    candidates: &[RTCIceCandidateInit],
) -> Result<()> {
    for candidate in candidates {
        if candidate.candidate.trim().is_empty() {
            continue;
        }
        pc.add_ice_candidate(candidate.clone())
            .await
            .context("remote ice candidate rejected")?;
    }
    Ok(())
}

fn validate_launch_token(cfg: &Config, token: &str) -> Result<ManagedLaunchTokenPayload> {
    let event: NostrEvent =
        serde_json::from_str(token).context("invalid gateway launch token json")?;
    if !nostr::verify_event(&event)? {
        return Err(anyhow!("invalid gateway launch token signature"));
    }
    let payload: ManagedLaunchTokenPayload =
        serde_json::from_str(&event.content).context("invalid gateway launch token payload")?;
    if payload.kind.trim() != "managed_launch_token" {
        return Err(anyhow!("unexpected launch token type"));
    }
    let gateway_pk = cfg.gateway.host_gateway_pk.trim();
    if gateway_pk.is_empty() {
        return Err(anyhow!("host gateway pk is not configured"));
    }
    if event.pubkey.trim() != gateway_pk || payload.gateway_pk.trim() != gateway_pk {
        return Err(anyhow!("launch token gateway mismatch"));
    }
    if payload.service.trim() != "nvr" {
        return Err(anyhow!("launch token service mismatch"));
    }
    if payload.service_pk.trim() != cfg.nostr_pubkey.trim() {
        return Err(anyhow!("launch token target service mismatch"));
    }
    if payload.identity_id.trim() != cfg.api.identity_id.trim() {
        return Err(anyhow!("launch token identity mismatch"));
    }
    let now_ms = crate::util::now_ms();
    if payload.expires_at < now_ms {
        return Err(anyhow!("launch token expired"));
    }
    Ok(payload)
}

fn parse_offer_description(value: &Value) -> Result<RTCSessionDescription> {
    if value.get("type").is_some() && value.get("sdp").is_some() {
        return serde_json::from_value(value.clone()).context("invalid rtc offer description");
    }
    if let Some(description) = value.get("description") {
        return serde_json::from_value(description.clone())
            .context("invalid rtc offer description");
    }
    Err(anyhow!("missing rtc offer description"))
}

fn source_ids_from_offer(value: &Value) -> Vec<String> {
    value
        .get("sourceIds")
        .or_else(|| value.get("sources"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    if let Some(raw) = entry.as_str() {
                        let trimmed = raw.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                    entry
                        .get("sourceId")
                        .and_then(|v| v.as_str())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn resolve_admin_token(cfg: &Config, token: &str) -> Result<()> {
    let payload = validate_launch_token(cfg, token)?;
    if !payload.owner {
        return Err(anyhow!(
            "owner launch is required for camera administration"
        ));
    }
    Ok(())
}

fn collect_offer_candidates(value: &Value) -> Vec<RTCIceCandidateInit> {
    let mut out = Vec::new();
    for candidate_set in [
        value.get("candidates"),
        value
            .get("description")
            .and_then(|description| description.get("candidates")),
    ] {
        let Some(entries) = candidate_set.and_then(|item| item.as_array()) else {
            continue;
        };
        for entry in entries {
            let Ok(candidate) = serde_json::from_value::<RTCIceCandidateInit>(entry.clone()) else {
                continue;
            };
            push_unique_ice_candidate(&mut out, &candidate);
        }
    }
    out
}

fn request_candidates(request: &ManagedOfferRequest) -> Vec<RTCIceCandidateInit> {
    let mut out = Vec::new();
    for candidate in &request.candidates {
        push_unique_ice_candidate(&mut out, candidate);
    }
    for candidate in collect_offer_candidates(&request.offer) {
        push_unique_ice_candidate(&mut out, &candidate);
    }
    out
}

fn offer_description_sdp(value: &Value) -> Option<&str> {
    value.get("sdp").and_then(|item| item.as_str()).or_else(|| {
        value
            .get("description")
            .and_then(|item| item.get("sdp"))
            .and_then(|item| item.as_str())
    })
}

fn select_preview_codec_for_camera(value: &Value, camera: &CameraConfig) -> Result<PreviewCodec> {
    let sdp = offer_description_sdp(value).unwrap_or_default();
    if driver_is_xm(&camera.driver_id) {
        if sdp.contains("VP8/90000") {
            return Ok(PreviewCodec::Vp8);
        }
        return Err(anyhow!(
            "browser offer does not advertise VP8, which is required for XM live preview"
        ));
    }
    if sdp.contains("H264/90000") {
        return Ok(PreviewCodec::H264);
    }
    if sdp.contains("VP8/90000") {
        return Ok(PreviewCodec::Vp8);
    }
    Err(anyhow!(
        "browser offer does not advertise a supported preview codec (need H264 or VP8)"
    ))
}

fn select_sources(
    cfg: &Config,
    requested: Vec<String>,
    token: &ManagedLaunchTokenPayload,
) -> Result<Vec<CameraConfig>> {
    let enabled = cfg
        .camera_devices
        .iter()
        .filter(|camera| camera.enabled)
        .cloned()
        .collect::<Vec<_>>();
    let allowed_ids = if token.owner || token.view_sources.is_empty() {
        enabled
            .iter()
            .map(|camera| camera.source_id.clone())
            .collect::<Vec<_>>()
    } else {
        token.view_sources.clone()
    };
    let allowed = enabled
        .iter()
        .filter(|camera| {
            allowed_ids
                .iter()
                .any(|source_id| source_id == &camera.source_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Ok(allowed);
    }
    let mut out = Vec::new();
    for source_id in requested {
        if let Some(camera) = allowed.iter().find(|camera| camera.source_id == source_id) {
            out.push(camera.clone());
        }
    }
    if out.is_empty() {
        return Err(anyhow!("requested sources are not available"));
    }
    Ok(out)
}

fn session_key_for_token(token: &ManagedLaunchTokenPayload) -> String {
    format!("{}:{}", token.device_pk.trim(), token.launch_nonce.trim())
}

async fn available_offer_video_transceivers(
    pc: &Arc<RTCPeerConnection>,
) -> Vec<Arc<RTCRtpTransceiver>> {
    pc.get_transceivers()
        .await
        .into_iter()
        .filter(|transceiver| transceiver.kind() == RTPCodecType::Video)
        .collect()
}

async fn attach_preview_track(
    pc: &Arc<RTCPeerConnection>,
    offered_video_transceivers: &mut Vec<Arc<RTCRtpTransceiver>>,
    track: Arc<dyn TrackLocal + Send + Sync>,
) -> Result<()> {
    while let Some(transceiver) = offered_video_transceivers.first().cloned() {
        offered_video_transceivers.remove(0);
        let sender = transceiver.sender().await;
        if sender.track().await.is_some() {
            continue;
        }
        sender.replace_track(Some(track)).await?;
        transceiver
            .set_direction(RTCRtpTransceiverDirection::Sendonly)
            .await;
        return Ok(());
    }

    pc.add_transceiver_from_track(
        track,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            send_encodings: vec![],
        }),
    )
    .await?;
    Ok(())
}

fn with_firefox_compatible_answer_msid(
    sdp: &str,
    media_stream_tracks: &[(String, String)],
) -> String {
    let has_msid_semantic = sdp.lines().any(|line| line.trim() == "a=msid-semantic:WMS *");
    let mut out = Vec::new();
    let mut in_video_section = false;
    let mut video_index = 0usize;
    let mut saw_msid_in_section = false;

    for raw_line in sdp.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with("m=") {
            in_video_section = line.starts_with("m=video ");
            if in_video_section {
                video_index = video_index.saturating_add(1);
            }
            saw_msid_in_section = false;
            out.push(line.to_string());
            continue;
        }

        out.push(line.to_string());
        if !has_msid_semantic && line.starts_with("a=group:BUNDLE ") {
            out.push("a=msid-semantic:WMS *".to_string());
            continue;
        }

        if in_video_section && line.starts_with("a=msid:") {
            saw_msid_in_section = true;
            continue;
        }

        if in_video_section && !saw_msid_in_section && line.starts_with("a=mid:") {
            if let Some((stream_id, track_id)) = media_stream_tracks.get(video_index.saturating_sub(1))
            {
                out.push(format!("a=msid:{stream_id} {track_id}"));
                saw_msid_in_section = true;
            }
        }
    }

    let mut normalized = out.join("\r\n");
    if !normalized.is_empty() {
        normalized.push_str("\r\n");
    }
    normalized
}

async fn run_camera_forwarder(
    camera: CameraConfig,
    track: Arc<TrackLocalStaticRTP>,
    mut stop_rx: watch::Receiver<bool>,
    codec: PreviewCodec,
) {
    let plan = planner::preview_pipeline_plan_for_codec(
        &camera,
        match codec {
            PreviewCodec::H264 => OutputCodec::H264,
            PreviewCodec::Vp8 => OutputCodec::Vp8,
        },
    );
    let preview_url = plan.input_url.clone();
    let std_socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(err) => {
            warn!(source = %camera.source_id, error = %err, "live preview UDP bind failed");
            return;
        }
    };
    if let Err(err) = std_socket.set_nonblocking(true) {
        warn!(source = %camera.source_id, error = %err, "live preview UDP nonblocking setup failed");
        return;
    }
    let local_addr = match std_socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            warn!(source = %camera.source_id, error = %err, "live preview UDP local addr failed");
            return;
        }
    };
    let socket = match UdpSocket::from_std(std_socket) {
        Ok(socket) => socket,
        Err(err) => {
            warn!(source = %camera.source_id, error = %err, "live preview UDP socket init failed");
            return;
        }
    };

    let mut ffmpeg = Command::new("ffmpeg");
    ffmpeg.args(ffmpeg::build_live_preview_ffmpeg_args(
        &plan,
        local_addr.port(),
    ));

    let mut child = match ffmpeg
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            warn!(source = %camera.source_id, error = %err, "failed to launch ffmpeg live preview");
            return;
        }
    };

    info!(
        source = %camera.source_id,
        url = %preview_url,
        codec = codec.label(),
        "live preview forwarder started"
    );
    let mut buf = vec![0u8; 1600];
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, _) = match recv {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(source = %camera.source_id, error = %err, "live preview RTP recv failed");
                        break;
                    }
                };
                let mut slice = &buf[..len];
                let packet = match RtpPacket::unmarshal(&mut slice) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!(source = %camera.source_id, error = %err, "live preview RTP unmarshal failed");
                        continue;
                    }
                };
                if let Err(err) = track.write_rtp(&packet).await {
                    warn!(source = %camera.source_id, error = %err, "live preview RTP write failed");
                }
            }
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    info!(source = %camera.source_id, "live preview forwarder stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc::api::APIBuilder;

    fn sample_config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-live-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (mut cfg, _) = Config::load_or_create(&path).expect("config");
        cfg.api.identity_id = "identity-1".to_string();
        cfg.nostr_pubkey = "service-pk".to_string();
        cfg.camera_devices.push(CameraConfig {
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
            desired: crate::config::CameraDeviceDesiredConfig {
                display_name: "Front".to_string(),
                overlay_text: "Front".to_string(),
                overlay_timestamp: true,
                ..Default::default()
            },
            credentials: Default::default(),
        });
        cfg
    }

    fn launch_token(cfg: &mut Config) -> String {
        let (gateway_pk, gateway_sk) = nostr::generate_keypair();
        cfg.gateway.host_gateway_pk = gateway_pk.clone();
        let payload = ManagedLaunchTokenPayload {
            kind: "managed_launch_token".to_string(),
            gateway_pk: gateway_pk.clone(),
            service_pk: cfg.nostr_pubkey.clone(),
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk: "device-pk".to_string(),
            capability: "nvr.view".to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            launch_nonce: "nonce-1".to_string(),
            issued_at: crate::util::now_ms(),
            expires_at: crate::util::now_ms() + 60_000,
        };
        let unsigned = nostr::build_unsigned_event(
            &gateway_pk,
            27235,
            vec![
                vec!["t".to_string(), "constitute".to_string()],
                vec!["type".to_string(), "managed_launch_token".to_string()],
            ],
            serde_json::to_string(&payload).expect("payload"),
            crate::util::now_unix_seconds(),
        );
        let event = nostr::sign_event(&unsigned, &gateway_sk).expect("sign");
        serde_json::to_string(&event).expect("event")
    }

    #[test]
    fn preview_url_prefers_reolink_substream() {
        let cfg = sample_config();
        assert_eq!(
            planner::preview_rtsp_url(&cfg.camera_devices[0]),
            "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_sub"
        );
    }

    #[test]
    fn select_sources_defaults_to_enabled() {
        let cfg = sample_config();
        let token = ManagedLaunchTokenPayload {
            kind: "managed_launch_token".to_string(),
            gateway_pk: "gateway".to_string(),
            service_pk: cfg.nostr_pubkey.clone(),
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk: "device".to_string(),
            capability: "nvr.view".to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            launch_nonce: "nonce".to_string(),
            issued_at: crate::util::now_ms(),
            expires_at: crate::util::now_ms() + 60_000,
        };
        let selected = select_sources(&cfg, Vec::new(), &token).expect("sources");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].source_id, "cam-1");
    }

    #[test]
    fn parse_offer_uses_nested_description() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "v=0\r\n"
            },
            "sourceIds": ["cam-1"]
        });
        let desc = parse_offer_description(&offer).expect("desc");
        assert_eq!(desc.sdp_type.to_string(), "offer");
        assert_eq!(source_ids_from_offer(&offer), vec!["cam-1".to_string()]);
    }

    #[test]
    fn request_candidates_accept_top_level_and_nested_offer_candidates() {
        let request = ManagedOfferRequest {
            launch_token: "token".to_string(),
            offer: json!({
                "description": {
                    "type": "offer",
                    "sdp": "v=0\r\n"
                },
                "candidates": [
                    {
                        "candidate": "candidate:2 1 udp 2122260223 10.0.229.73 54548 typ host",
                        "sdpMid": "0",
                        "sdpMLineIndex": 0
                    }
                ]
            }),
            ice_servers: ManagedIceServerHints::default(),
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 2122260223 10.0.229.73 54547 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
        };

        let out = request_candidates(&request);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .any(|candidate| candidate.candidate.contains("54547"))
        );
        assert!(
            out.iter()
                .any(|candidate| candidate.candidate.contains("54548"))
        );
    }

    #[test]
    fn select_preview_codec_prefers_h264_when_available() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 H264/90000\r\n"
            }
        });
        let cfg = sample_config();
        assert_eq!(
            select_preview_codec_for_camera(&offer, &cfg.camera_devices[0]).expect("codec"),
            PreviewCodec::H264
        );
    }

    #[test]
    fn select_preview_codec_falls_back_to_vp8() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 VP8/90000\r\n"
            }
        });
        let cfg = sample_config();
        assert_eq!(
            select_preview_codec_for_camera(&offer, &cfg.camera_devices[0]).expect("codec"),
            PreviewCodec::Vp8
        );
    }

    #[test]
    fn select_preview_codec_prefers_vp8_for_xm_sources() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 H264/90000\r\n"
            }
        });
        let mut cfg = sample_config();
        let mut camera = cfg.camera_devices.remove(0);
        camera.driver_id = "xm_40e".to_string();
        assert_eq!(
            select_preview_codec_for_camera(&offer, &camera).expect("codec"),
            PreviewCodec::Vp8
        );
    }

    #[test]
    fn select_preview_codec_rejects_xm_without_vp8_offer() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 97\r\na=rtpmap:97 H264/90000\r\n"
            }
        });
        let mut cfg = sample_config();
        let mut camera = cfg.camera_devices.remove(0);
        camera.driver_id = "xm_40e".to_string();
        let err = select_preview_codec_for_camera(&offer, &camera).expect_err("xm should require vp8");
        assert!(err.to_string().contains("required for XM live preview"));
    }

    #[test]
    fn preview_rtsp_url_uses_xm_substream() {
        let mut cfg = sample_config();
        let mut camera = cfg.camera_devices.remove(0);
        camera.driver_id = "xm_40e".to_string();
        camera.rtsp_url =
            "rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=0.sdp?real_stream"
                .to_string();
        assert_eq!(
            planner::preview_rtsp_url(&camera),
            "rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=1.sdp?real_stream"
        );
    }

    #[test]
    fn live_preview_ffmpeg_args_add_genpts_for_vp8() {
        let camera = sample_config().camera_devices.remove(0);
        let args = ffmpeg::build_live_preview_ffmpeg_args(
            &planner::preview_pipeline_plan_for_codec(&camera, OutputCodec::Vp8),
            41000,
        );
        let ff_idx = args.iter().position(|arg| arg == "-fflags").expect("fflags");
        assert_eq!(args.get(ff_idx + 1).map(String::as_str), Some("+genpts"));
        let input_idx = args.iter().position(|arg| arg == "-i").expect("input");
        assert!(ff_idx < input_idx);
        assert!(args.iter().any(|arg| arg == "libvpx"));
    }

    #[test]
    fn live_preview_ffmpeg_args_omit_genpts_for_h264_copy() {
        let camera = sample_config().camera_devices.remove(0);
        let args = ffmpeg::build_live_preview_ffmpeg_args(
            &planner::preview_pipeline_plan_for_codec(&camera, OutputCodec::H264),
            41000,
        );
        assert!(!args.iter().any(|arg| arg == "+genpts"));
        assert!(args.iter().any(|arg| arg == "copy"));
    }

    #[test]
    fn validate_launch_token_accepts_matching_gateway_and_service() {
        let mut cfg = sample_config();
        let token = launch_token(&mut cfg);
        let payload = validate_launch_token(&cfg, &token).expect("token");
        assert_eq!(payload.gateway_pk, cfg.gateway.host_gateway_pk);
        assert_eq!(payload.service_pk, cfg.nostr_pubkey);
    }

    #[tokio::test]
    async fn answer_uses_sendonly_for_recvonly_video_offer_lines() {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("register codecs");
        let api = APIBuilder::new().with_media_engine(media_engine).build();
        let offerer = Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("offerer"),
        );
        let answerer = Arc::new(
            api.new_peer_connection(RTCConfiguration::default())
                .await
                .expect("answerer"),
        );

        for _ in 0..2 {
            offerer
                .add_transceiver_from_kind(
                    RTPCodecType::Video,
                    Some(RTCRtpTransceiverInit {
                        direction: RTCRtpTransceiverDirection::Recvonly,
                        send_encodings: vec![],
                    }),
                )
                .await
                .expect("recvonly video transceiver");
        }

        let offer = offerer.create_offer(None).await.expect("offer");
        offerer
            .set_local_description(offer)
            .await
            .expect("set local offer");
        let local_offer = offerer.local_description().await.expect("local offer");
        answerer
            .set_remote_description(local_offer)
            .await
            .expect("set remote offer");

        let mut offered_video_transceivers = available_offer_video_transceivers(&answerer).await;
        for idx in 0..2 {
            let track = Arc::new(TrackLocalStaticRTP::new(
                PreviewCodec::Vp8.capability(),
                format!("cam-{idx}"),
                format!("session-cam-{idx}"),
            ));
            attach_preview_track(
                &answerer,
                &mut offered_video_transceivers,
                track as Arc<dyn TrackLocal + Send + Sync>,
            )
            .await
            .expect("attach track");
        }

        let answer = answerer.create_answer(None).await.expect("answer");
        answerer
            .set_local_description(answer)
            .await
            .expect("set local answer");
        let sdp = answerer.local_description().await.expect("local answer").sdp;

        let mut saw_video = 0usize;
        let mut pending_video = false;
        for line in sdp.lines() {
            if line.starts_with("m=video ") {
                pending_video = true;
                saw_video += 1;
                continue;
            }
            if line.starts_with("m=") {
                pending_video = false;
                continue;
            }
            if pending_video && line == "a=sendrecv" {
                panic!("video answer line negotiated sendrecv instead of sendonly");
            }
        }
        assert_eq!(saw_video, 2);
        assert_eq!(sdp.matches("a=sendonly").count(), 2);
        assert!(sdp.contains("msid:session-cam-0 cam-0"));
        assert!(sdp.contains("msid:session-cam-1 cam-1"));
    }

    #[test]
    fn firefox_compatible_answer_adds_media_stream_ids() {
        let input = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 0.0.0.0\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "a=group:BUNDLE 0 1\r\n",
            "m=video 9 UDP/TLS/RTP/SAVPF 120\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=setup:active\r\n",
            "a=mid:0\r\n",
            "a=sendonly\r\n",
            "m=video 9 UDP/TLS/RTP/SAVPF 120\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=setup:active\r\n",
            "a=mid:1\r\n",
            "a=sendonly\r\n"
        );
        let output = with_firefox_compatible_answer_msid(
            input,
            &[
                ("session-1".to_string(), "cam-1".to_string()),
                ("session-1".to_string(), "cam-2".to_string()),
            ],
        );

        assert!(output.contains("a=msid-semantic:WMS *\r\n"));
        assert!(output.contains("a=mid:0\r\na=msid:session-1 cam-1\r\n"));
        assert!(output.contains("a=mid:1\r\na=msid:session-1 cam-2\r\n"));
    }
}
