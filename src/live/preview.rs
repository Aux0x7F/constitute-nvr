//! Managed preview runtime.
//!
//! `Managed*Request` values are internal service requests assembled by
//! `swarm_edge` only after `open_envelope` succeeds. This module must not read
//! service-edge sealed frame payloads directly.

use super::stream_records::{
    StreamSessionExchangeRecords, StreamSessionOfferRecords, browser_webrtc_path_id,
    parse_candidate_endpoint, session_id_for_claims, stream_session_records_for_answer,
    stream_session_records_for_offer,
};
use crate::camera_device::registry::driver_is_xm;
use crate::config::{CameraDeviceConfig, Config, LivePreviewConfig};
use crate::media::planner;
#[cfg(test)]
use crate::media::{ffmpeg, types::OutputCodec};
use crate::media_projection::{
    MediaProjectionRuntime, MediaProjectionSubscription, ProjectionCodec,
};
use anyhow::{Context, Result, anyhow};
use constitute_protocol::validate_resolved_member_ref;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::sync::{Mutex, watch};
use tokio::time::{Duration, timeout};
use tracing::{info, warn};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::{MIME_TYPE_H264, MIME_TYPE_VP8, MediaEngine};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::udp_mux::{UDPMux, UDPMuxDefault, UDPMuxParams};
use webrtc::ice::udp_network::UDPNetwork;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
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

const ANSWER_GATHER_WAIT_MS: u64 = 750;
const DISCONNECTED_RELEASE_GRACE_MS: u64 = 12_000;
const SOURCE_RTP_WAITING_GRACE_MS: u64 = 5_000;
const SOURCE_RTP_BLOCKED_GRACE_MS: u64 = 10_000;
const SOURCE_RTP_OBSERVATION_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ManagedIceServerHints {
    #[serde(default)]
    #[allow(dead_code)]
    pub stun: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub turn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamAuthorityClaims {
    pub capability_id: String,
    pub gateway_pk: String,
    pub service_pk: String,
    pub service: String,
    pub identity_id: String,
    pub device_pk: String,
    pub capability: String,
    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub view_sources: Vec<String>,
    #[serde(default)]
    pub control_sources: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedOfferRequest {
    pub authority: StreamAuthorityClaims,
    pub offer: Value,
    #[serde(rename = "iceServers", default)]
    pub ice_servers: ManagedIceServerHints,
    #[serde(default)]
    pub candidates: Vec<RTCIceCandidateInit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedCloseRequest {
    pub authority: StreamAuthorityClaims,
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedCandidateRequest {
    pub authority: StreamAuthorityClaims,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagedControlRequest {
    pub authority: StreamAuthorityClaims,
    #[serde(default)]
    pub payload: Value,
    #[serde(rename = "controlLease", default)]
    pub control_lease: Value,
    #[serde(default)]
    pub preempted: bool,
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
    #[serde(rename = "streamSession", skip_serializing_if = "Option::is_none")]
    pub stream_session: Option<StreamSessionExchangeRecords>,
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

type ValidatedStreamAuthority = StreamAuthorityClaims;

struct PreviewUdpMux {
    network: UDPNetwork,
    local_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviewCodec {
    H264,
    Vp8,
}

impl PreviewCodec {
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
    requester_ref: String,
    source_ids: Vec<String>,
    created_at: u64,
    expires_at: u64,
    peer_connection: Arc<RTCPeerConnection>,
    stops: Vec<watch::Sender<bool>>,
}

#[derive(Clone, Debug)]
pub struct PreviewTransportObservationEvent {
    pub path_id: String,
    pub session_id: String,
    pub activation_id: String,
    pub route_promise_id: String,
    pub requester_ref: String,
    pub participant_ref: String,
    pub participant_role: String,
    pub state: String,
    pub connection_state: String,
    pub ice_connection_state: Option<String>,
    pub selected_pair_state: Option<String>,
    pub inbound_rtp_state: Option<String>,
    pub render_state: Option<String>,
    pub blocked_reason: Option<String>,
    pub reason: Option<String>,
    pub source_ids: Vec<String>,
    pub grace_ms: Option<u64>,
    pub observed_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug)]
struct PreviewTransportObservationContext {
    path_id: String,
    session_id: String,
    activation_id: String,
    route_promise_id: String,
    requester_ref: String,
    participant_ref: String,
    source_ids: Vec<String>,
    expires_at: Option<u64>,
    transport_events: broadcast::Sender<PreviewTransportObservationEvent>,
}

impl Clone for PreviewSessionHandle {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            requester_ref: self.requester_ref.clone(),
            source_ids: self.source_ids.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
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
    media_projection: MediaProjectionRuntime,
    transport_events: broadcast::Sender<PreviewTransportObservationEvent>,
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
        let media_projection = MediaProjectionRuntime::new();
        if !cfg!(test) {
            let warm_runtime = media_projection.clone();
            let warm_cfg = cfg.clone();
            tokio::spawn(async move {
                warm_runtime.warm_enabled_previews(&warm_cfg).await;
            });
        }
        let (transport_events, _) = broadcast::channel(128);
        Ok(Self {
            api: Arc::new(api),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            media_projection,
            transport_events,
        })
    }

    pub fn subscribe_transport_observations(
        &self,
    ) -> broadcast::Receiver<PreviewTransportObservationEvent> {
        self.transport_events.subscribe()
    }

    pub async fn media_projection_health(
        &self,
        cfg: &Config,
    ) -> crate::media_projection::MediaProjectionHealth {
        self.media_projection.health(cfg).await
    }

    pub async fn refresh_camera_source(
        &self,
        previous_source_id: &str,
        camera: CameraDeviceConfig,
    ) {
        let stale_sessions = {
            let mut sessions = self.sessions.lock().await;
            let keys = sessions
                .iter()
                .filter_map(|(key, handle)| {
                    preview_source_ids_match_refresh(
                        &handle.source_ids,
                        previous_source_id,
                        &camera.source_id,
                    )
                    .then(|| key.clone())
                })
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| sessions.remove(&key))
                .collect::<Vec<_>>()
        };
        for handle in stale_sessions {
            handle.close().await;
        }
        self.media_projection
            .refresh_camera_projection(previous_source_id, camera)
            .await;
    }

    pub async fn handle_offer(
        &self,
        cfg: &Config,
        request: ManagedOfferRequest,
    ) -> Result<ManagedOfferResponse> {
        let authority = validate_stream_authority(cfg, &request.authority)?;
        let offer = parse_offer_description(&request.offer)?;
        let selected = select_sources(cfg, source_ids_from_offer(&request.offer), &authority)?;
        let remote_candidates = request_candidates(&request)?;
        if selected.is_empty() {
            return Err(anyhow!(
                "no enabled camera sources available for live preview"
            ));
        }

        let issued_at = crate::util::now_ms();
        let source_ids = selected
            .iter()
            .map(|camera| camera.source_id.clone())
            .collect::<Vec<_>>();
        let offer_records = stream_session_records_for_offer(cfg, &request, &authority, issued_at)?;
        let session_id = session_id_for_claims(&authority);
        let path_id = browser_webrtc_path_id(&session_id);
        let activation_id = offer_records.route_promise.activation_id.clone();
        let route_promise_id = offer_records.route_promise.promise_id.clone();
        let requester_ref = authority.device_pk.trim().to_string();
        let participant_ref = service_participant_ref(cfg);
        let session_key = session_key_for_authority(&authority);
        let stale_sessions = self
            .take_stale_preview_sessions(cfg, &authority, &source_ids, issued_at)
            .await;
        for stale in stale_sessions {
            stale.close().await;
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
        let cleanup_sessions = Arc::clone(&self.sessions);
        let cleanup_key = session_key.clone();
        let cleanup_state = Arc::new(Mutex::new(RTCPeerConnectionState::New));
        let transport_events = self.transport_events.clone();
        let event_path_id = path_id.clone();
        let event_session_id = session_id.clone();
        let event_activation_id = activation_id.clone();
        let event_route_promise_id = route_promise_id.clone();
        let event_requester_ref = requester_ref.clone();
        let event_participant_ref = participant_ref.clone();
        let event_source_ids = source_ids.clone();
        let event_expires_at = Some(authority.expires_at);
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let sessions = Arc::clone(&cleanup_sessions);
            let key = cleanup_key.clone();
            let state_ref = Arc::clone(&cleanup_state);
            let transport_events = transport_events.clone();
            let path_id = event_path_id.clone();
            let session_id = event_session_id.clone();
            let activation_id = event_activation_id.clone();
            let route_promise_id = event_route_promise_id.clone();
            let requester_ref = event_requester_ref.clone();
            let participant_ref = event_participant_ref.clone();
            let source_ids = event_source_ids.clone();
            Box::pin(async move {
                *state_ref.lock().await = state;
                let reason = media_observation_reason_for_peer_state(state).map(str::to_string);
                let _ = transport_events.send(PreviewTransportObservationEvent {
                    path_id: path_id.clone(),
                    session_id: session_id.clone(),
                    activation_id: activation_id.clone(),
                    route_promise_id: route_promise_id.clone(),
                    requester_ref: requester_ref.clone(),
                    participant_ref: participant_ref.clone(),
                    participant_role: "service".to_string(),
                    state: media_observation_state_for_peer_state(state).to_string(),
                    connection_state: peer_connection_state_label(state).to_string(),
                    ice_connection_state: None,
                    selected_pair_state: selected_pair_state_for_peer_state(state).map(str::to_string),
                    inbound_rtp_state: None,
                    render_state: None,
                    blocked_reason: reason.clone(),
                    reason,
                    source_ids: source_ids.clone(),
                    grace_ms: matches!(state, RTCPeerConnectionState::Disconnected)
                        .then_some(DISCONNECTED_RELEASE_GRACE_MS),
                    observed_at: crate::util::now_ms(),
                    expires_at: event_expires_at,
                });
                match state {
                    RTCPeerConnectionState::Disconnected => {
                        let sessions = Arc::clone(&sessions);
                        let key = key.clone();
                        let state_ref = Arc::clone(&state_ref);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(DISCONNECTED_RELEASE_GRACE_MS))
                                .await;
                            if *state_ref.lock().await == RTCPeerConnectionState::Disconnected {
                                let removed = {
                                    let mut sessions = sessions.lock().await;
                                    sessions.remove(&key)
                                };
                                if let Some(handle) = removed {
                                    let _ = transport_events.send(PreviewTransportObservationEvent {
                                        path_id,
                                        session_id: session_id.clone(),
                                        activation_id,
                                        route_promise_id,
                                        requester_ref,
                                        participant_ref,
                                        participant_role: "service".to_string(),
                                        state: "released".to_string(),
                                        connection_state: "disconnected".to_string(),
                                        ice_connection_state: None,
                                        selected_pair_state: Some("none".to_string()),
                                        inbound_rtp_state: None,
                                        render_state: None,
                                        blocked_reason: Some("disconnectedGraceExpired".to_string()),
                                        reason: Some("disconnectedGraceExpired".to_string()),
                                        source_ids,
                                        grace_ms: Some(DISCONNECTED_RELEASE_GRACE_MS),
                                        observed_at: crate::util::now_ms(),
                                        expires_at: event_expires_at,
                                    });
                                    warn!(
                                        session_id = %handle.session_id,
                                        grace_ms = DISCONNECTED_RELEASE_GRACE_MS,
                                        "preview transport disconnected past grace; releasing media path"
                                    );
                                    handle.close().await;
                                }
                            }
                        });
                    }
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                        let removed = {
                            let mut sessions = sessions.lock().await;
                            sessions.remove(&key)
                        };
                        if let Some(handle) = removed {
                            handle.close().await;
                        }
                    }
                    _ => {}
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
            let subscription = self
                .media_projection
                .subscribe_preview(camera.clone(), projection_codec_for_preview(preview_codec))
                .await;
            tokio::spawn(run_projection_subscriber(
                subscription,
                track,
                stop_rx,
                PreviewTransportObservationContext {
                    path_id: path_id.clone(),
                    session_id: session_id.clone(),
                    activation_id: activation_id.clone(),
                    route_promise_id: route_promise_id.clone(),
                    requester_ref: requester_ref.clone(),
                    participant_ref: participant_ref.clone(),
                    source_ids: vec![camera.source_id.clone()],
                    expires_at: event_expires_at,
                    transport_events: self.transport_events.clone(),
                },
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
        if timeout(
            Duration::from_millis(ANSWER_GATHER_WAIT_MS),
            gather_complete.recv(),
        )
        .await
        .is_err()
        {
            warn!(
                wait_ms = ANSWER_GATHER_WAIT_MS,
                "ice gathering incomplete before answer response; returning current local description"
            );
        }
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
                requester_ref: authority.device_pk.trim().to_string(),
                source_ids,
                created_at: issued_at,
                expires_at: authority.expires_at,
                peer_connection: Arc::clone(&pc),
                stops,
            },
        );

        let mut response = ManagedOfferResponse {
            signal_type: "answer".to_string(),
            answer: local_desc,
            session_id,
            sources: response_sources,
            candidates: response_candidates,
            stream_session: None,
        };
        let answer_records =
            stream_session_records_for_answer(&response, &offer_records, issued_at)?;
        response.stream_session = Some(StreamSessionExchangeRecords {
            offer: offer_records,
            answer: answer_records,
        });
        Ok(response)
    }

    pub fn offer_admission_records(
        &self,
        cfg: &Config,
        request: &ManagedOfferRequest,
        issued_at: u64,
    ) -> Result<StreamSessionOfferRecords> {
        let authority = validate_stream_authority(cfg, &request.authority)?;
        parse_offer_description(&request.offer)?;
        let selected = select_sources(cfg, source_ids_from_offer(&request.offer), &authority)?;
        if selected.is_empty() {
            return Err(anyhow!(
                "no enabled camera sources available for live preview"
            ));
        }
        stream_session_records_for_offer(cfg, request, &authority, issued_at)
    }

    pub async fn handle_close(&self, cfg: &Config, request: ManagedCloseRequest) -> Result<Value> {
        let authority = validate_stream_authority(cfg, &request.authority)?;
        let expected_session_id = requested_close_session_id(&request, &authority);
        if let Some(session) = self
            .take_preview_session_for_close(&authority, &expected_session_id)
            .await
        {
            session.close().await;
        }
        Ok(json!({
            "ok": true,
            "sessionId": expected_session_id,
            "reason": request
                .payload
                .get("reason")
                .or_else(|| request.payload.get("reasonCode"))
                .cloned()
                .unwrap_or_else(|| json!("closed")),
        }))
    }

    async fn take_preview_session_for_close(
        &self,
        authority: &ValidatedStreamAuthority,
        session_id: &str,
    ) -> Option<PreviewSessionHandle> {
        let mut sessions = self.sessions.lock().await;
        let session_key = session_key_for_authority(authority);
        if let Some(session) = sessions.remove(&session_key) {
            return Some(session);
        }
        if !session_id.trim().is_empty() {
            if let Some(key) = sessions
                .iter()
                .find_map(|(key, handle)| (handle.session_id == session_id).then(|| key.clone()))
            {
                return sessions.remove(&key);
            }
        }
        None
    }

    async fn take_stale_preview_sessions(
        &self,
        cfg: &Config,
        authority: &ValidatedStreamAuthority,
        source_ids: &[String],
        now: u64,
    ) -> Vec<PreviewSessionHandle> {
        let max_sessions = max_preview_sessions(cfg);
        let mut sessions = self.sessions.lock().await;
        let mut keys = sessions
            .iter()
            .filter_map(|(key, handle)| {
                let expired = handle.expires_at > 0 && handle.expires_at <= now;
                let same_session = key == &session_key_for_authority(authority)
                    || handle.session_id == session_id_for_claims(authority);
                let same_requester_source = handle.requester_ref == authority.device_pk.trim()
                    && preview_sources_overlap(&handle.source_ids, source_ids);
                (expired || same_session || same_requester_source).then(|| key.clone())
            })
            .collect::<Vec<_>>();

        if sessions.len().saturating_sub(keys.len()) >= max_sessions {
            let mut oldest = sessions
                .iter()
                .filter(|(key, _)| !keys.iter().any(|existing| existing == *key))
                .map(|(key, handle)| (key.clone(), handle.created_at))
                .collect::<Vec<_>>();
            oldest.sort_by_key(|(_, created_at)| *created_at);
            let remove_count = sessions
                .len()
                .saturating_sub(keys.len())
                .saturating_add(1)
                .saturating_sub(max_sessions);
            keys.extend(oldest.into_iter().take(remove_count).map(|(key, _)| key));
        }

        keys.sort();
        keys.dedup();
        keys.into_iter()
            .filter_map(|key| {
                let handle = sessions.remove(&key)?;
                warn!(
                    session_id = %handle.session_id,
                    sources = ?handle.source_ids,
                    "closing stale media transport preview lease"
                );
                Some(handle)
            })
            .collect()
    }

    pub async fn handle_candidate(
        &self,
        cfg: &Config,
        request: ManagedCandidateRequest,
    ) -> Result<Value> {
        let authority = validate_stream_authority(cfg, &request.authority)?;
        let session_key = session_key_for_authority(&authority);
        let session = self
            .sessions
            .lock()
            .await
            .get(&session_key)
            .cloned()
            .ok_or_else(|| anyhow!("stream session is not open for candidate"))?;
        let candidate = candidate_from_payload(&request.payload)?;
        validate_remote_candidate(&candidate)?;
        let endpoint = candidate_endpoint_value(&candidate);
        session
            .peer_connection
            .add_ice_candidate(candidate)
            .await
            .context("remote trickle candidate rejected")?;
        Ok(json!({
            "ok": true,
            "sessionId": format!("nvr-preview-{}", authority.nonce),
            "candidateApplied": true,
            "endpoint": endpoint,
        }))
    }
}

pub fn resolve_control_camera(
    cfg: &Config,
    request: &ManagedControlRequest,
) -> Result<CameraDeviceConfig> {
    let authority = validate_stream_authority(cfg, &request.authority)?;
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
    if !authority.owner
        && !authority
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
    let preview_mux = bind_preview_udp_mux(cfg)?;
    info!(
        port = preview_mux.local_addr.port(),
        configured_min = cfg.udp_port_min,
        configured_max = cfg.udp_port_max,
        "live preview media transport mux bound"
    );
    setting_engine.set_udp_network(preview_mux.network);
    setting_engine.set_lite(true);
    setting_engine.set_network_types(vec![NetworkType::Udp4]);
    let blocked_iface = camera_iface.trim().to_string();
    setting_engine.set_interface_filter(Box::new(move |iface| {
        let trimmed = iface.trim();
        !trimmed.eq_ignore_ascii_case("lo") && trimmed != blocked_iface
    }));
    Ok(setting_engine)
}

fn bind_preview_udp_mux(cfg: &LivePreviewConfig) -> Result<PreviewUdpMux> {
    if cfg.udp_port_max < cfg.udp_port_min {
        return Err(anyhow!(
            "invalid live preview udp port range: {}-{}",
            cfg.udp_port_min,
            cfg.udp_port_max
        ));
    }

    bind_preview_udp_mux_candidates(
        cfg.udp_port_min..=cfg.udp_port_max,
        cfg.udp_port_min,
        cfg.udp_port_max,
    )
}

fn bind_preview_udp_mux_candidates<I>(
    ports: I,
    configured_min: u16,
    configured_max: u16,
) -> Result<PreviewUdpMux>
where
    I: IntoIterator<Item = u16>,
{
    let mut last_err = None;
    for port in ports {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        match StdUdpSocket::bind(bind_addr) {
            Ok(socket) => {
                socket
                    .set_nonblocking(true)
                    .context("live preview udp mux socket nonblocking")?;
                let socket =
                    UdpSocket::from_std(socket).context("live preview udp mux socket adoption")?;
                let local_addr = socket
                    .local_addr()
                    .context("live preview udp mux local address")?;
                let mux = UDPMuxDefault::new(UDPMuxParams::new(socket));
                let mux = mux as Arc<dyn UDPMux + Send + Sync>;
                return Ok(PreviewUdpMux {
                    network: UDPNetwork::Muxed(mux),
                    local_addr,
                });
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    let detail = last_err
        .map(|err| err.to_string())
        .unwrap_or_else(|| "no ports attempted".to_string());
    Err(anyhow!(
        "no live preview udp mux port available in {}-{}: {}",
        configured_min,
        configured_max,
        detail
    ))
}

fn build_rtc_configuration(_hints: &ManagedIceServerHints) -> RTCConfiguration {
    // The NVR service is an ICE-lite answerer. It advertises routable host
    // candidates and lets the browser full ICE agent perform connectivity
    // checks; mixing STUN-derived service candidates into ICE-lite produces
    // unusable candidate-pair state in routed lab networks.
    RTCConfiguration {
        ice_servers: Vec::new(),
        ..Default::default()
    }
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
        validate_remote_candidate(candidate)?;
        pc.add_ice_candidate(candidate.clone())
            .await
            .context("remote ice candidate rejected")?;
    }
    Ok(())
}

pub(crate) fn validate_stream_authority(
    cfg: &Config,
    claims: &StreamAuthorityClaims,
) -> Result<ValidatedStreamAuthority> {
    let gateway_pk = cfg.gateway.host_gateway_pk.trim();
    if gateway_pk.is_empty() {
        return Err(anyhow!("host gateway pk is not configured"));
    }
    let payload = claims.clone();
    if payload.gateway_pk.trim() != gateway_pk {
        return Err(anyhow!("stream authority gateway mismatch"));
    }
    if payload.service.trim() != "nvr" {
        return Err(anyhow!("stream authority service mismatch"));
    }
    if payload.service_pk.trim() != cfg.nostr_pubkey.trim() {
        return Err(anyhow!("stream authority target service mismatch"));
    }
    if payload.identity_id.trim() != cfg.api.identity_id.trim() {
        return Err(anyhow!("stream authority identity mismatch"));
    }
    validate_resolved_member_ref(payload.device_pk.trim(), "stream authority devicePk")?;
    if payload.expires_at < crate::util::now_ms() {
        return Err(anyhow!("stream authority expired"));
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

fn candidate_from_payload(value: &Value) -> Result<RTCIceCandidateInit> {
    let candidate_value = value
        .get("candidate")
        .cloned()
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get("candidate"))
                .cloned()
        })
        .unwrap_or_else(|| value.clone());
    let candidate: RTCIceCandidateInit =
        serde_json::from_value(candidate_value).context("invalid stream candidate payload")?;
    if candidate.candidate.trim().is_empty() {
        return Err(anyhow!("stream candidate is empty"));
    }
    Ok(candidate)
}

fn validate_remote_candidate(candidate: &RTCIceCandidateInit) -> Result<()> {
    if candidate.candidate.trim().is_empty() {
        return Err(anyhow!("stream candidate is empty"));
    }
    parse_candidate_endpoint(&candidate.candidate)
        .ok_or_else(|| anyhow!("stream candidate missing actionable endpoint evidence"))?;
    Ok(())
}

fn candidate_endpoint_value(candidate: &RTCIceCandidateInit) -> Value {
    parse_candidate_endpoint(&candidate.candidate)
        .map(|endpoint| {
            json!({
                "protocol": endpoint.protocol,
                "address": endpoint.address,
                "port": endpoint.port,
                "candidateType": endpoint.candidate_type,
            })
        })
        .unwrap_or(Value::Null)
}

fn request_candidates(request: &ManagedOfferRequest) -> Result<Vec<RTCIceCandidateInit>> {
    let mut out = Vec::new();
    for candidate in &request.candidates {
        push_unique_ice_candidate(&mut out, candidate);
    }
    for candidate in collect_offer_candidates(&request.offer) {
        push_unique_ice_candidate(&mut out, &candidate);
    }
    for candidate in &out {
        validate_remote_candidate(candidate)?;
    }
    Ok(out)
}

fn offer_description_sdp(value: &Value) -> Option<&str> {
    value.get("sdp").and_then(|item| item.as_str()).or_else(|| {
        value
            .get("description")
            .and_then(|item| item.get("sdp"))
            .and_then(|item| item.as_str())
    })
}

fn select_preview_codec_for_camera(
    value: &Value,
    camera: &CameraDeviceConfig,
) -> Result<PreviewCodec> {
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

fn preview_source_ids_match_refresh(
    source_ids: &[String],
    previous_source_id: &str,
    current_source_id: &str,
) -> bool {
    let previous = previous_source_id.trim();
    let current = current_source_id.trim();
    source_ids.iter().any(|source| {
        (!previous.is_empty() && source == previous) || (!current.is_empty() && source == current)
    })
}

fn select_sources(
    cfg: &Config,
    requested: Vec<String>,
    token: &ValidatedStreamAuthority,
) -> Result<Vec<CameraDeviceConfig>> {
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

fn session_key_for_authority(authority: &ValidatedStreamAuthority) -> String {
    format!("{}:{}", authority.device_pk.trim(), authority.nonce.trim())
}

fn service_participant_ref(cfg: &Config) -> String {
    let service_pk = cfg.nostr_pubkey.trim();
    if service_pk.is_empty() {
        "service:nvr".to_string()
    } else {
        format!("service:{service_pk}")
    }
}

fn peer_connection_state_label(state: RTCPeerConnectionState) -> &'static str {
    match state {
        RTCPeerConnectionState::Unspecified => "unspecified",
        RTCPeerConnectionState::New => "new",
        RTCPeerConnectionState::Connecting => "connecting",
        RTCPeerConnectionState::Connected => "connected",
        RTCPeerConnectionState::Disconnected => "disconnected",
        RTCPeerConnectionState::Failed => "failed",
        RTCPeerConnectionState::Closed => "closed",
    }
}

fn media_observation_state_for_peer_state(state: RTCPeerConnectionState) -> &'static str {
    match state {
        RTCPeerConnectionState::Unspecified | RTCPeerConnectionState::New => "pending",
        RTCPeerConnectionState::Connecting => "connecting",
        RTCPeerConnectionState::Connected => "connected",
        RTCPeerConnectionState::Disconnected => "disconnected",
        RTCPeerConnectionState::Failed => "failed",
        RTCPeerConnectionState::Closed => "closed",
    }
}

fn media_observation_reason_for_peer_state(state: RTCPeerConnectionState) -> Option<&'static str> {
    match state {
        RTCPeerConnectionState::Disconnected => Some("peerConnectionDisconnected"),
        RTCPeerConnectionState::Failed => Some("peerConnectionFailed"),
        RTCPeerConnectionState::Closed => Some("peerConnectionClosed"),
        _ => None,
    }
}

fn selected_pair_state_for_peer_state(state: RTCPeerConnectionState) -> Option<&'static str> {
    match state {
        RTCPeerConnectionState::Unspecified => None,
        RTCPeerConnectionState::New | RTCPeerConnectionState::Connecting => Some("pending"),
        RTCPeerConnectionState::Connected | RTCPeerConnectionState::Disconnected => {
            Some("selected")
        }
        RTCPeerConnectionState::Failed => Some("failed"),
        RTCPeerConnectionState::Closed => Some("none"),
    }
}

fn requested_close_session_id(
    request: &ManagedCloseRequest,
    authority: &ValidatedStreamAuthority,
) -> String {
    let explicit = request.session_id.trim();
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    request
        .payload
        .get("sessionId")
        .or_else(|| request.payload.get("session_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| session_id_for_claims(authority))
}

fn preview_sources_overlap(left: &[String], right: &[String]) -> bool {
    left.iter()
        .any(|source| right.iter().any(|candidate| candidate == source))
}

fn max_preview_sessions(cfg: &Config) -> usize {
    let min = cfg.live_preview.udp_port_min;
    let max = cfg.live_preview.udp_port_max;
    let port_count = max.saturating_sub(min).saturating_add(1);
    usize::from((port_count / 4).max(2).min(16))
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
    let has_msid_semantic = sdp
        .lines()
        .any(|line| line.trim() == "a=msid-semantic:WMS *");
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

        if in_video_section
            && !saw_msid_in_section
            && line.starts_with("a=mid:")
            && let Some((stream_id, track_id)) =
                media_stream_tracks.get(video_index.saturating_sub(1))
        {
            out.push(format!("a=msid:{stream_id} {track_id}"));
            saw_msid_in_section = true;
        }
    }

    let mut normalized = out.join("\r\n");
    if !normalized.is_empty() {
        normalized.push_str("\r\n");
    }
    normalized
}

fn projection_codec_for_preview(codec: PreviewCodec) -> ProjectionCodec {
    match codec {
        PreviewCodec::H264 => ProjectionCodec::H264,
        PreviewCodec::Vp8 => ProjectionCodec::Vp8,
    }
}

fn service_media_transport_observation(
    context: &PreviewTransportObservationContext,
    state: &str,
    connection_state: &str,
    selected_pair_state: Option<&str>,
    inbound_rtp_state: Option<&str>,
    render_state: Option<&str>,
    blocked_reason: Option<&str>,
    reason: Option<&str>,
    grace_ms: Option<u64>,
) -> PreviewTransportObservationEvent {
    PreviewTransportObservationEvent {
        path_id: context.path_id.clone(),
        session_id: context.session_id.clone(),
        activation_id: context.activation_id.clone(),
        route_promise_id: context.route_promise_id.clone(),
        requester_ref: context.requester_ref.clone(),
        participant_ref: context.participant_ref.clone(),
        participant_role: "service".to_string(),
        state: state.to_string(),
        connection_state: connection_state.to_string(),
        ice_connection_state: None,
        selected_pair_state: selected_pair_state.map(str::to_string),
        inbound_rtp_state: inbound_rtp_state.map(str::to_string),
        render_state: render_state.map(str::to_string),
        blocked_reason: blocked_reason.map(str::to_string),
        reason: reason.map(str::to_string),
        source_ids: context.source_ids.clone(),
        grace_ms,
        observed_at: crate::util::now_ms(),
        expires_at: context.expires_at,
    }
}

fn emit_service_media_transport_observation(
    context: &PreviewTransportObservationContext,
    event: PreviewTransportObservationEvent,
) {
    let _ = context.transport_events.send(event);
}

async fn run_projection_subscriber(
    mut subscription: MediaProjectionSubscription,
    track: Arc<TrackLocalStaticRTP>,
    mut stop_rx: watch::Receiver<bool>,
    observation_context: PreviewTransportObservationContext,
) {
    let started_at = crate::util::now_ms();
    let mut first_packet_observed = false;
    let mut waiting_observed_at = 0;
    let mut blocked_observed = false;
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            packet = timeout(
                Duration::from_millis(SOURCE_RTP_OBSERVATION_INTERVAL_MS),
                subscription.receiver.recv()
            ) => {
                match packet {
                    Ok(Ok(packet)) => {
                        if let Err(err) = track.write_rtp(&packet).await {
                            emit_service_media_transport_observation(
                                &observation_context,
                                service_media_transport_observation(
                                    &observation_context,
                                    "blocked",
                                    "connected",
                                    Some("selected"),
                                    Some("blocked"),
                                    Some("pending"),
                                    Some("serviceTrackWriteFailed"),
                                    Some("serviceTrackWriteFailed"),
                                    Some(SOURCE_RTP_BLOCKED_GRACE_MS),
                                ),
                            );
                            warn!(
                                source = %subscription.source_id,
                                codec = subscription.codec.label(),
                                error = %err,
                                "media projection RTP write failed"
                            );
                            blocked_observed = true;
                            continue;
                        }
                        if !first_packet_observed {
                            first_packet_observed = true;
                            blocked_observed = false;
                            emit_service_media_transport_observation(
                                &observation_context,
                                service_media_transport_observation(
                                    &observation_context,
                                    "connected",
                                    "connected",
                                    Some("selected"),
                                    Some("flowing"),
                                    Some("pending"),
                                    None,
                                    Some("sourceRtpFlowing"),
                                    None,
                                ),
                            );
                        }
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                        warn!(
                            source = %subscription.source_id,
                            codec = subscription.codec.label(),
                            skipped,
                            "media projection subscriber lagged"
                        );
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => break,
                    Err(_) => {
                        if first_packet_observed {
                            continue;
                        }
                        let now = crate::util::now_ms();
                        let waiting_ms = now.saturating_sub(started_at);
                        if waiting_ms >= SOURCE_RTP_BLOCKED_GRACE_MS && !blocked_observed {
                            blocked_observed = true;
                            emit_service_media_transport_observation(
                                &observation_context,
                                service_media_transport_observation(
                                    &observation_context,
                                    "blocked",
                                    "connected",
                                    Some("selected"),
                                    Some("blocked"),
                                    Some("pending"),
                                    Some("sourceRtpUnavailable"),
                                    Some("sourceRtpUnavailable"),
                                    Some(SOURCE_RTP_BLOCKED_GRACE_MS),
                                ),
                            );
                        } else if waiting_ms >= SOURCE_RTP_WAITING_GRACE_MS
                            && now.saturating_sub(waiting_observed_at) >= SOURCE_RTP_OBSERVATION_INTERVAL_MS
                        {
                            waiting_observed_at = now;
                            emit_service_media_transport_observation(
                                &observation_context,
                                service_media_transport_observation(
                                    &observation_context,
                                    "pending",
                                    "connected",
                                    Some("selected"),
                                    Some("pending"),
                                    Some("pending"),
                                    None,
                                    Some("sourceRtpWaiting"),
                                    Some(SOURCE_RTP_BLOCKED_GRACE_MS),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    info!(
        source = %subscription.source_id,
        codec = subscription.codec.label(),
        "media projection subscriber stopped"
    );
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
        let (service_pk, service_sk) = constitute_protocol::generate_keypair();
        cfg.nostr_pubkey = service_pk;
        cfg.nostr_sk_hex = service_sk;
        cfg.camera_devices.push(CameraDeviceConfig {
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

    fn stream_authority(cfg: &mut Config, nonce: &str) -> StreamAuthorityClaims {
        let (gateway_pk, _) = constitute_protocol::generate_keypair();
        let (device_pk, _) = constitute_protocol::generate_keypair();
        cfg.gateway.host_gateway_pk = gateway_pk.clone();
        StreamAuthorityClaims {
            capability_id: "cap-test".to_string(),
            gateway_pk: gateway_pk.to_string(),
            service_pk: cfg.nostr_pubkey.clone(),
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk,
            capability: "nvr.view".to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            nonce: nonce.to_string(),
            issued_at: crate::util::now_ms(),
            expires_at: crate::util::now_ms() + 60_000,
        }
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
        let (device_pk, _) = constitute_protocol::generate_keypair();
        let token = StreamAuthorityClaims {
            capability_id: "cap-test".to_string(),
            gateway_pk: "gateway".to_string(),
            service_pk: cfg.nostr_pubkey.clone(),
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk,
            capability: "nvr.view".to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            nonce: "nonce".to_string(),
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
        let mut cfg = sample_config();
        let request = ManagedOfferRequest {
            authority: stream_authority(&mut cfg, "nonce-1"),
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

        let out = request_candidates(&request).expect("candidates");
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
    fn request_candidates_reject_missing_actionable_endpoint() {
        let mut cfg = sample_config();
        let request = ManagedOfferRequest {
            authority: stream_authority(&mut cfg, "nonce-1"),
            offer: json!({
                "description": {
                    "type": "offer",
                    "sdp": "v=0\r\n"
                }
            }),
            ice_servers: ManagedIceServerHints::default(),
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 2122260223 10.0.229.73 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
        };

        let err = request_candidates(&request).expect_err("invalid endpoint");
        assert!(
            err.to_string()
                .contains("stream candidate missing actionable endpoint evidence")
        );
    }

    #[test]
    fn close_session_id_prefers_explicit_payload_session() {
        let mut cfg = sample_config();
        let authority = stream_authority(&mut cfg, "new-close-nonce");
        let request = ManagedCloseRequest {
            authority: authority.clone(),
            session_id: String::new(),
            payload: json!({ "sessionId": "nvr-preview-original-nonce" }),
        };

        assert_eq!(
            requested_close_session_id(&request, &authority),
            "nvr-preview-original-nonce"
        );
    }

    #[test]
    fn media_transport_leases_overlap_by_source_and_bound_capacity() {
        let mut cfg = sample_config();
        cfg.live_preview.udp_port_min = 41000;
        cfg.live_preview.udp_port_max = 41031;

        assert!(preview_sources_overlap(
            &["cam-1".to_string()],
            &["cam-1".to_string(), "cam-2".to_string()]
        ));
        assert!(!preview_sources_overlap(
            &["cam-1".to_string()],
            &["cam-2".to_string()]
        ));
        assert_eq!(max_preview_sessions(&cfg), 8);
    }

    #[tokio::test]
    async fn live_preview_udp_mux_binds_one_owned_transport_port() {
        let mut cfg = sample_config();
        cfg.live_preview.udp_port_min = 0;
        cfg.live_preview.udp_port_max = 0;

        let mux = bind_preview_udp_mux(&cfg.live_preview).expect("preview udp mux");
        assert!(mux.local_addr.port() > 0);
        match mux.network {
            UDPNetwork::Muxed(udp_mux) => {
                udp_mux.close().await.expect("close mux");
            }
            UDPNetwork::Ephemeral(_) => panic!("preview should use muxed media transport"),
        }
    }

    #[tokio::test]
    async fn live_preview_udp_mux_skips_busy_port_in_range() {
        let busy = StdUdpSocket::bind("0.0.0.0:0").expect("busy socket");
        let busy_port = busy.local_addr().expect("busy addr").port();

        let mux =
            bind_preview_udp_mux_candidates([busy_port, 0], busy_port, 0).expect("preview udp mux");
        assert_ne!(mux.local_addr.port(), busy_port);
        assert!(mux.local_addr.port() > 0);
        match mux.network {
            UDPNetwork::Muxed(udp_mux) => {
                udp_mux.close().await.expect("close mux");
            }
            UDPNetwork::Ephemeral(_) => panic!("preview should use muxed media transport"),
        }
    }

    #[test]
    fn peer_state_maps_to_media_transport_witness_posture() {
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::New),
            Some("pending")
        );
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::Connecting),
            Some("pending")
        );
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::Connected),
            Some("selected")
        );
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::Disconnected),
            Some("selected")
        );
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::Failed),
            Some("failed")
        );
        assert_eq!(
            selected_pair_state_for_peer_state(RTCPeerConnectionState::Closed),
            Some("none")
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
    fn service_source_rtp_wait_observations_use_media_transport_contract() {
        let (transport_events, _rx) = broadcast::channel(4);
        let context = PreviewTransportObservationContext {
            path_id: "nvr-preview-1:path:browserWebRtc".to_string(),
            session_id: "nvr-preview-1".to_string(),
            activation_id: "activation-1".to_string(),
            route_promise_id: "route-promise-1".to_string(),
            requester_ref: "device:aux".to_string(),
            participant_ref: "service:nvr".to_string(),
            source_ids: vec!["camera-1".to_string()],
            expires_at: Some(1_700_060_000),
            transport_events,
        };

        let pending = service_media_transport_observation(
            &context,
            "pending",
            "connected",
            Some("selected"),
            Some("pending"),
            Some("pending"),
            None,
            Some("sourceRtpWaiting"),
            Some(SOURCE_RTP_BLOCKED_GRACE_MS),
        );
        assert_eq!(pending.session_id, "nvr-preview-1");
        assert_eq!(pending.participant_role, "service");
        assert_eq!(pending.state, "pending");
        assert_eq!(pending.inbound_rtp_state.as_deref(), Some("pending"));
        assert_eq!(pending.blocked_reason, None);

        let blocked = service_media_transport_observation(
            &context,
            "blocked",
            "connected",
            Some("selected"),
            Some("blocked"),
            Some("pending"),
            Some("sourceRtpUnavailable"),
            Some("sourceRtpUnavailable"),
            Some(SOURCE_RTP_BLOCKED_GRACE_MS),
        );
        assert_eq!(blocked.state, "blocked");
        assert_eq!(blocked.inbound_rtp_state.as_deref(), Some("blocked"));
        assert_eq!(
            blocked.blocked_reason.as_deref(),
            Some("sourceRtpUnavailable")
        );
        assert_eq!(blocked.grace_ms, Some(SOURCE_RTP_BLOCKED_GRACE_MS));
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
        let err =
            select_preview_codec_for_camera(&offer, &camera).expect_err("xm should require vp8");
        assert!(err.to_string().contains("required for XM live preview"));
    }

    #[test]
    fn preview_refresh_matches_previous_or_current_source() {
        let sources = vec!["reolink-ec-71-db-32-0a-8f".to_string()];

        assert!(preview_source_ids_match_refresh(
            &sources,
            "reolink-192-168-250-97",
            "reolink-ec-71-db-32-0a-8f"
        ));
        assert!(preview_source_ids_match_refresh(
            &sources,
            "reolink-ec-71-db-32-0a-8f",
            "reolink-ec-71-db-32-0a-8f"
        ));
        assert!(!preview_source_ids_match_refresh(
            &sources,
            "xm-192-168-0-201",
            "xm-192-168-0-201"
        ));
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
        let ff_idx = args
            .iter()
            .position(|arg| arg == "-fflags")
            .expect("fflags");
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
    fn validate_stream_authority_accepts_matching_gateway_and_service() {
        let mut cfg = sample_config();
        let authority = stream_authority(&mut cfg, "nonce-1");
        let payload = validate_stream_authority(&cfg, &authority).expect("authority");
        assert_eq!(payload.gateway_pk, cfg.gateway.host_gateway_pk);
        assert_eq!(payload.service_pk, cfg.nostr_pubkey);
    }

    #[test]
    fn ice_lite_service_ignores_browser_stun_hints() {
        let config = build_rtc_configuration(&ManagedIceServerHints {
            stun: vec!["stun:stun.l.google.com:19302".to_string()],
            turn: vec![],
        });
        assert!(
            config.ice_servers.is_empty(),
            "ICE-lite NVR service should advertise host candidates only"
        );
    }

    #[tokio::test]
    async fn answerer_advertises_ice_lite() {
        let cfg = sample_config();
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("register codecs");
        let offer_api = APIBuilder::new().with_media_engine(media_engine).build();
        let offerer = Arc::new(
            offer_api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("offerer"),
        );
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
        let offer = offerer.create_offer(None).await.expect("offer");
        offerer
            .set_local_description(offer)
            .await
            .expect("set local offer");

        let mut answer_media_engine = MediaEngine::default();
        answer_media_engine
            .register_default_codecs()
            .expect("register codecs");
        let answer_api = APIBuilder::new()
            .with_media_engine(answer_media_engine)
            .with_setting_engine(
                build_setting_engine(&cfg.live_preview, cfg.camera_network.interface.trim())
                    .expect("setting engine"),
            )
            .build();
        let answerer = Arc::new(
            answer_api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("answerer"),
        );
        answerer
            .set_remote_description(offerer.local_description().await.expect("local offer"))
            .await
            .expect("set remote offer");
        let answer = answerer.create_answer(None).await.expect("answer");
        answerer
            .set_local_description(answer)
            .await
            .expect("set local answer");

        let sdp = answerer
            .local_description()
            .await
            .expect("local answer")
            .sdp;
        assert!(sdp.contains("ice-lite"), "{sdp}");
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
        let sdp = answerer
            .local_description()
            .await
            .expect("local answer")
            .sdp;

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
