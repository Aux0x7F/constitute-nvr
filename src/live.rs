use crate::config::{CameraConfig, Config, LivePreviewConfig};
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
use util::Unmarshal;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_H264, MIME_TYPE_VP8, MediaEngine};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::udp_network::{EphemeralUDP, UDPNetwork};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::TrackLocalWriter;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;

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
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedCloseRequest {
    #[serde(rename = "launchToken")]
    pub launch_token: String,
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
        let mut setting_engine = build_setting_engine(
            &cfg.live_preview,
            cfg.camera_network.interface.trim(),
        )?;
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
        let preview_codec = select_preview_codec(&request.offer)?;
        let selected = select_sources(cfg, source_ids_from_offer(&request.offer))?;
        if selected.is_empty() {
            return Err(anyhow!("no enabled camera sources available for live preview"));
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
        let session_id = format!("nvr-preview-{}", token.launch_nonce);
        let cleanup_sessions = Arc::clone(&self.sessions);
        let cleanup_key = session_key.clone();
        let cleanup_pc = Arc::clone(&pc);
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let sessions = Arc::clone(&cleanup_sessions);
            let key = cleanup_key.clone();
            let pc = Arc::clone(&cleanup_pc);
            Box::pin(async move {
                if matches!(state, RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed)
                {
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

        let mut stops = Vec::new();
        let mut response_sources = Vec::new();
        for camera in &selected {
            let track = Arc::new(TrackLocalStaticRTP::new(
                preview_codec.capability(),
                camera.source_id.clone(),
                session_id.clone(),
            ));
            pc.add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
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
                rtsp_preview_url: preview_rtsp_url(camera),
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
                    entry.get("sourceId")
                        .and_then(|v| v.as_str())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn offer_description_sdp(value: &Value) -> Option<&str> {
    value.get("sdp")
        .and_then(|item| item.as_str())
        .or_else(|| {
            value
                .get("description")
                .and_then(|item| item.get("sdp"))
                .and_then(|item| item.as_str())
        })
}

fn select_preview_codec(value: &Value) -> Result<PreviewCodec> {
    let sdp = offer_description_sdp(value).unwrap_or_default();
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

fn select_sources(cfg: &Config, requested: Vec<String>) -> Result<Vec<CameraConfig>> {
    let enabled = cfg
        .cameras
        .iter()
        .filter(|camera| camera.enabled)
        .cloned()
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Ok(enabled);
    }
    let mut out = Vec::new();
    for source_id in requested {
        if let Some(camera) = enabled.iter().find(|camera| camera.source_id == source_id) {
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

fn preview_rtsp_url(camera: &CameraConfig) -> String {
    let mut url = camera.rtsp_url.clone();
    if url.contains("h264Preview_01_main") {
        url = url.replace("h264Preview_01_main", "h264Preview_01_sub");
    } else if url.contains("h265Preview_01_main") {
        url = url.replace("h265Preview_01_main", "h265Preview_01_sub");
    }
    url
}

async fn run_camera_forwarder(
    camera: CameraConfig,
    track: Arc<TrackLocalStaticRTP>,
    mut stop_rx: watch::Receiver<bool>,
    codec: PreviewCodec,
) {
    let preview_url = preview_rtsp_url(&camera);
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
    ffmpeg
        .arg("-nostdin")
        .arg("-loglevel")
        .arg("error")
        .arg("-rtsp_transport")
        .arg("tcp")
        .arg("-i")
        .arg(&preview_url)
        .arg("-an");

    match codec {
        PreviewCodec::H264 => {
            ffmpeg.arg("-c:v").arg("copy");
        }
        PreviewCodec::Vp8 => {
            ffmpeg
                .arg("-c:v")
                .arg("libvpx")
                .arg("-deadline")
                .arg("realtime")
                .arg("-cpu-used")
                .arg("8")
                .arg("-pix_fmt")
                .arg("yuv420p")
                .arg("-g")
                .arg("30")
                .arg("-keyint_min")
                .arg("30")
                .arg("-b:v")
                .arg("1M")
                .arg("-maxrate")
                .arg("1M")
                .arg("-bufsize")
                .arg("2M");
        }
    }

    let mut child = match ffmpeg
        .arg("-f")
        .arg("rtp")
        .arg("-payload_type")
        .arg("96")
        .arg(format!("rtp://127.0.0.1:{}?pkt_size=1200", local_addr.port()))
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

    fn sample_config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-live-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (mut cfg, _) = Config::load_or_create(&path).expect("config");
        cfg.api.identity_id = "identity-1".to_string();
        cfg.nostr_pubkey = "service-pk".to_string();
        cfg.cameras.push(CameraConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            enabled: true,
            segment_secs: 10,
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
            preview_rtsp_url(&cfg.cameras[0]),
            "rtsp://admin:pw@10.0.0.10:554/h264Preview_01_sub"
        );
    }

    #[test]
    fn select_sources_defaults_to_enabled() {
        let cfg = sample_config();
        let selected = select_sources(&cfg, Vec::new()).expect("sources");
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
    fn select_preview_codec_prefers_h264_when_available() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 H264/90000\r\n"
            }
        });
        assert_eq!(select_preview_codec(&offer).expect("codec"), PreviewCodec::H264);
    }

    #[test]
    fn select_preview_codec_falls_back_to_vp8() {
        let offer = json!({
            "description": {
                "type": "offer",
                "sdp": "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 VP8/90000\r\n"
            }
        });
        assert_eq!(select_preview_codec(&offer).expect("codec"), PreviewCodec::Vp8);
    }

    #[test]
    fn validate_launch_token_accepts_matching_gateway_and_service() {
        let mut cfg = sample_config();
        let token = launch_token(&mut cfg);
        let payload = validate_launch_token(&cfg, &token).expect("token");
        assert_eq!(payload.gateway_pk, cfg.gateway.host_gateway_pk);
        assert_eq!(payload.service_pk, cfg.nostr_pubkey);
    }
}
