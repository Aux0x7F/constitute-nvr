//! Swarm-frame edge adapter for NVR stream/session records.

use crate::camera_device;
use crate::config::{CameraDeviceConfig, Config};
use crate::live::{
    ManagedCandidateRequest, ManagedCloseRequest, ManagedControlRequest, ManagedOfferRequest,
    ManagedOfferResponse, PreviewManager, PreviewTransportObservationEvent, StreamAuthorityClaims,
    StreamSessionOfferRecords, resolve_control_camera, stream_session_close_for_request,
    stream_session_control_for_request, validate_stream_authority,
};
use crate::util;
use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    CAPABILITY_MEDIA_STREAM_PREVIEW, CAPABILITY_PROJECTION_DELTA_APPLY,
    CAPABILITY_ROUTE_PROMISE_RESOLVE, CAPABILITY_STREAM_SESSION_CONTROL,
    CAPABILITY_STREAM_SESSION_OFFER, CaacEnvelope, MediaTransportObservation, ProjectionDeltaOp,
    ProjectionDeltaOpKind, ProjectionPathSegment, RECORD_CONTRIBUTION_LIFECYCLE,
    RECORD_MEDIA_TRANSPORT_OBSERVATION, RECORD_MEDIA_TRANSPORT_PATH, RECORD_ROUTE_OBSERVATION,
    RECORD_ROUTE_PROMISE, RECORD_STREAM_ROUTE_PLAN, ReplayCache, RouteObservation,
    RouteObservationState, STREAM_CANDIDATE_ACTIONABILITY_USABLE, STREAM_CANDIDATE_ROLE_BROWSER,
    StreamSessionClose, StreamSessionControl, StreamSessionHealth, SwarmAck, SwarmFrame,
    SwarmFrameBody, SwarmFrameKind, SwarmProjectionDelta, SwarmProjectionSnapshot, SwarmRecordRef,
    ZoneScope, open_envelope, seal_envelope, swarm_frame_id, validate_media_transport_observation,
    validate_projection_delta, validate_projection_snapshot, validate_route_observation,
    validate_stream_session_close, validate_stream_session_control, validate_stream_session_health,
    validate_swarm_frame,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

const STREAM_CHANNEL_ID: &str = "nvr.streams";
const STREAM_PROJECTION_ID: &str = "nvr.streams";
const STREAM_PROJECTION_POLICY_ID: &str = "nvr.streams.delta";
const RESPONSE_TTL_MS: u64 = 90_000;
const OFFER_FRAME_CAPABILITIES: &[&str] = &[
    CAPABILITY_MEDIA_STREAM_PREVIEW,
    CAPABILITY_STREAM_SESSION_OFFER,
];
const CONTROL_FRAME_CAPABILITIES: &[&str] = &[CAPABILITY_STREAM_SESSION_CONTROL];

#[derive(Clone)]
pub struct SwarmEdge {
    cfg: Arc<Mutex<Config>>,
    preview: PreviewManager,
    replay: Arc<Mutex<ReplayCache>>,
    stream_projection_revision: Arc<Mutex<u64>>,
    stream_projection_state: Arc<Mutex<Value>>,
}

#[derive(Clone, Debug)]
struct StreamProjectionBaseline {
    base_revision: u64,
    state: Value,
}

impl SwarmEdge {
    pub fn new(cfg: Arc<Mutex<Config>>, preview: PreviewManager) -> Self {
        Self {
            cfg,
            preview,
            replay: Arc::new(Mutex::new(ReplayCache::default())),
            stream_projection_revision: Arc::new(Mutex::new(0)),
            stream_projection_state: Arc::new(Mutex::new(json!({
                "streamSessions": {}
            }))),
        }
    }

    pub async fn handle_frame(&self, frame: SwarmFrame) -> Result<Vec<SwarmFrame>> {
        let now = util::now_ms();
        let reject_source = frame.clone();
        match self.handle_frame_inner(frame, now).await {
            Ok(frames) => Ok(frames),
            Err(err) => {
                let cfg = self.cfg.lock().await.clone();
                build_reject_response_frame(
                    &cfg,
                    &reject_source,
                    now,
                    "nvr_frame_rejected",
                    &err.to_string(),
                )
                .map(|frame| vec![frame])
            }
        }
    }

    pub async fn reject_frame(
        &self,
        frame: &SwarmFrame,
        reason_code: &str,
        detail: &str,
    ) -> Result<SwarmFrame> {
        let cfg = self.cfg.lock().await.clone();
        build_reject_response_frame(&cfg, frame, util::now_ms(), reason_code, detail)
    }

    pub async fn member_read_observation_frame(&self, frame: &SwarmFrame) -> Result<SwarmFrame> {
        let cfg = self.cfg.lock().await.clone();
        build_member_read_observation_frame(&cfg, frame, util::now_ms())
    }

    pub async fn gateway_frame_admission(&self, frame: &SwarmFrame) -> GatewayFrameAdmission {
        let cfg = self.cfg.lock().await.clone();
        gateway_frame_admission(&cfg, frame)
    }

    pub async fn service_admission_frames(&self, frame: &SwarmFrame) -> Result<Vec<SwarmFrame>> {
        let cfg = self.cfg.lock().await.clone();
        if !matches!(
            classify_stream_frame(&cfg, frame)?,
            Some(StreamFrameAction::Offer)
        ) {
            return Ok(Vec::new());
        }
        let now = util::now_ms();
        let claims = self.open_frame_claims_without_replay(&cfg, frame).await?;
        ensure_opened_route_promise(&claims)?;
        ensure_signal_type(&claims, &["offer"])?;
        let response_zone_scope = response_zone_scope_from_claims(&claims, frame);
        let request = managed_offer_from_claims(&cfg, &claims)?;
        let offer_records = self.preview.offer_admission_records(&cfg, &request, now)?;
        build_offer_admission_frames(&cfg, frame, &offer_records, now, response_zone_scope)
    }

    pub fn subscribe_transport_observations(
        &self,
    ) -> broadcast::Receiver<PreviewTransportObservationEvent> {
        self.preview.subscribe_transport_observations()
    }

    pub async fn transport_observation_frames(
        &self,
        event: PreviewTransportObservationEvent,
    ) -> Result<Vec<SwarmFrame>> {
        let cfg = self.cfg.lock().await.clone();
        build_transport_observation_frame(&cfg, &event, util::now_ms()).map(|frame| vec![frame])
    }

    async fn handle_frame_inner(&self, frame: SwarmFrame, now: u64) -> Result<Vec<SwarmFrame>> {
        validate_swarm_frame(&frame, now).context("invalid swarm frame")?;
        let cfg = self.cfg.lock().await.clone();
        if !frame_targets_nvr(&cfg, &frame) {
            return Ok(Vec::new());
        }

        match classify_stream_frame(&cfg, &frame)? {
            Some(StreamFrameAction::Offer) => self.handle_offer_frame(cfg, frame, now).await,
            Some(StreamFrameAction::Candidate) => {
                self.handle_candidate_frame(cfg, frame, now).await
            }
            Some(StreamFrameAction::Close) => self.handle_close_frame(cfg, frame, now).await,
            Some(StreamFrameAction::Control) => self.handle_control_frame(cfg, frame, now).await,
            None => Ok(Vec::new()),
        }
    }

    async fn handle_offer_frame(
        &self,
        cfg: Config,
        frame: SwarmFrame,
        now: u64,
    ) -> Result<Vec<SwarmFrame>> {
        let claims = self.open_frame_claims(&cfg, &frame).await?;
        ensure_opened_route_promise(&claims)?;
        ensure_signal_type(&claims, &["offer"])?;
        let response_zone_scope = response_zone_scope_from_claims(&claims, &frame);
        let request = managed_offer_from_claims(&cfg, &claims)?;
        let response = self.preview.handle_offer(&cfg, request).await?;
        let projection_value = offer_projection_value(&response)?;
        let baseline = self
            .next_stream_projection_baseline(&response.session_id, projection_value.clone())
            .await;
        build_offer_response_frames(
            &cfg,
            &frame,
            &response,
            now,
            &baseline,
            projection_value,
            response_zone_scope,
        )
    }

    async fn handle_control_frame(
        &self,
        cfg: Config,
        frame: SwarmFrame,
        now: u64,
    ) -> Result<Vec<SwarmFrame>> {
        let claims = self.open_frame_claims(&cfg, &frame).await?;
        ensure_opened_route_promise(&claims)?;
        ensure_signal_type(&claims, &["control"])?;
        let response_zone_scope = response_zone_scope_from_claims(&claims, &frame);
        let request = managed_control_from_claims(&cfg, &claims)?;
        let stream_control = stream_session_control_for_request(&cfg, &request, now)?;
        let camera = resolve_control_camera(&cfg, &request)?;
        let result = invoke_control(&camera, &request).await?;
        let projection_value = control_projection_value(&stream_control, &camera);
        let baseline = self
            .next_stream_projection_baseline(&stream_control.session_id, projection_value.clone())
            .await;
        build_control_response_frames(
            &cfg,
            &frame,
            &stream_control,
            result,
            now,
            &baseline,
            projection_value,
            response_zone_scope,
        )
    }

    async fn handle_candidate_frame(
        &self,
        cfg: Config,
        frame: SwarmFrame,
        now: u64,
    ) -> Result<Vec<SwarmFrame>> {
        let claims = self.open_frame_claims(&cfg, &frame).await?;
        ensure_opened_route_promise(&claims)?;
        ensure_signal_type(&claims, &["candidate"])?;
        let response_zone_scope = response_zone_scope_from_claims(&claims, &frame);
        let request = managed_candidate_from_claims(&cfg, &claims)?;
        let result = self.preview.handle_candidate(&cfg, request).await?;
        let (session_id, projection_value) = candidate_projection_value(&result)?;
        let baseline = self
            .next_stream_projection_baseline(&session_id, projection_value.clone())
            .await;
        build_candidate_response_frames(
            &cfg,
            &frame,
            result,
            now,
            &baseline,
            projection_value,
            response_zone_scope,
        )
    }

    async fn handle_close_frame(
        &self,
        cfg: Config,
        frame: SwarmFrame,
        now: u64,
    ) -> Result<Vec<SwarmFrame>> {
        let claims = self.open_frame_claims(&cfg, &frame).await?;
        ensure_opened_route_promise(&claims)?;
        ensure_signal_type(&claims, &["close", "session_close"])?;
        let response_zone_scope = response_zone_scope_from_claims(&claims, &frame);
        let request = managed_close_from_claims(&cfg, &claims)?;
        let stream_close = stream_session_close_for_request(&cfg, &request, now)?;
        let response = self.preview.handle_close(&cfg, request).await?;
        let projection_value = close_projection_value(&stream_close);
        let baseline = self
            .next_stream_projection_baseline(&stream_close.session_id, projection_value.clone())
            .await;
        build_close_response_frames(
            &cfg,
            &frame,
            &stream_close,
            response,
            now,
            &baseline,
            projection_value,
            response_zone_scope,
        )
    }

    async fn open_frame_claims(&self, cfg: &Config, frame: &SwarmFrame) -> Result<Value> {
        self.open_frame_claims_inner(cfg, frame, true).await
    }

    async fn open_frame_claims_without_replay(
        &self,
        cfg: &Config,
        frame: &SwarmFrame,
    ) -> Result<Value> {
        self.open_frame_claims_inner(cfg, frame, false).await
    }

    async fn open_frame_claims_inner(
        &self,
        cfg: &Config,
        frame: &SwarmFrame,
        consume_replay: bool,
    ) -> Result<Value> {
        if frame.body.encoding != "caac" {
            return Err(anyhow!("swarm stream frame body must be CAAC sealed"));
        }
        let envelope_value = frame
            .body
            .envelope
            .clone()
            .ok_or_else(|| anyhow!("swarm stream frame missing CAAC envelope"))?;
        let envelope: CaacEnvelope =
            serde_json::from_value(envelope_value).context("invalid swarm frame CAAC envelope")?;
        let claims = if consume_replay {
            let mut replay = self.replay.lock().await;
            open_envelope(
                &envelope,
                &cfg.nostr_sk_hex,
                util::now_ms(),
                Some(&mut replay),
            )
        } else {
            open_envelope(&envelope, &cfg.nostr_sk_hex, util::now_ms(), None)
        }
        .context("swarm stream frame CAAC open failed")?;
        ensure_runtime_issuer_matches_claims(&claims, &envelope.issuer_pk)?;
        Ok(claims)
    }

    async fn next_stream_projection_baseline(
        &self,
        session_id: &str,
        projection_value: Value,
    ) -> StreamProjectionBaseline {
        let mut revision_guard = self.stream_projection_revision.lock().await;
        let mut state_guard = self.stream_projection_state.lock().await;
        let base_revision = *revision_guard;
        let baseline = state_guard.clone();
        let mut next_state = baseline.clone();
        if !next_state.is_object() {
            next_state = json!({});
        }
        if let Some(root) = next_state.as_object_mut() {
            let sessions = root
                .entry("streamSessions".to_string())
                .or_insert_with(|| json!({}));
            if !sessions.is_object() {
                *sessions = json!({});
            }
            if let Some(map) = sessions.as_object_mut() {
                map.insert(session_id.to_string(), projection_value);
            }
        }
        *state_guard = next_state;
        *revision_guard = revision_guard.saturating_add(1);
        StreamProjectionBaseline {
            base_revision,
            state: baseline,
        }
    }
}

fn ensure_runtime_issuer_matches_claims(claims: &Value, issuer_pk: &str) -> Result<()> {
    let source = claims
        .get("authority")
        .or_else(|| claims.get("authorityClaims"))
        .or_else(|| claims.get("claims"))
        .unwrap_or(claims);
    let device_pk = source
        .get("devicePk")
        .or_else(|| source.get("device_pk"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if device_pk.is_empty() {
        return Err(anyhow!("swarm stream authority missing runtime device pk"));
    }
    if device_pk != issuer_pk.trim() {
        return Err(anyhow!(
            "swarm stream issuer does not match runtime authority"
        ));
    }
    Ok(())
}

async fn invoke_control(
    camera: &CameraDeviceConfig,
    request: &ManagedControlRequest,
) -> Result<Value> {
    let ptz_payload = request
        .payload
        .get("ptz")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !camera.ptz_capable {
        return Err(anyhow!("camera does not advertise PTZ control"));
    }
    let result = camera_device::control_camera_device(camera, &ptz_payload).await?;
    Ok(json!({
        "sourceId": camera.source_id,
        "preempted": request.preempted,
        "controlLease": request.control_lease,
        "ptz": ptz_payload,
        "currentPose": result.current_pose,
        "desiredPose": result.desired_pose,
        "poseStatus": result.pose_status,
        "managementPlane": result.management_plane,
        "ptzDiagnostics": result.ptz_diagnostics,
        "ok": true,
    }))
}

fn offer_projection_value(response: &ManagedOfferResponse) -> Result<Value> {
    let stream_session = response
        .stream_session
        .as_ref()
        .ok_or_else(|| anyhow!("preview response missing stream session records"))?;
    Ok(json!({
        "sessionId": response.session_id,
        "status": "answer_ready",
        "sourceIds": response.sources.iter().map(|source| source.source_id.clone()).collect::<Vec<_>>(),
        "routePromiseId": &stream_session.offer.route_promise.promise_id,
        "recordKinds": [RECORD_ROUTE_PROMISE, RECORD_STREAM_ROUTE_PLAN, "stream.session.admission", RECORD_CONTRIBUTION_LIFECYCLE, "stream.session.answer", "stream.session.candidate", RECORD_MEDIA_TRANSPORT_PATH, "stream.session.health"],
    }))
}

fn control_projection_value(control: &StreamSessionControl, camera: &CameraDeviceConfig) -> Value {
    json!({
        "sessionId": control.session_id,
        "status": "control_applied",
        "sourceId": camera.source_id,
        "recordKinds": ["stream.session.control", "stream.session.health"],
    })
}

fn candidate_projection_value(result: &Value) -> Result<(String, Value)> {
    let session_id = result
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("candidate response missing sessionId"))?
        .to_string();
    Ok((
        session_id.clone(),
        json!({
            "sessionId": session_id,
            "status": "candidate_applied",
            "recordKinds": ["stream.session.candidate", "stream.session.health"],
        }),
    ))
}

fn close_projection_value(close: &StreamSessionClose) -> Value {
    json!({
        "sessionId": close.session_id,
        "status": "closed",
        "recordKinds": ["stream.session.close", "stream.session.health"],
    })
}

fn build_offer_admission_frames(
    cfg: &Config,
    request_frame: &SwarmFrame,
    offer_records: &StreamSessionOfferRecords,
    now: u64,
    response_zone_scope: Option<ZoneScope>,
) -> Result<Vec<SwarmFrame>> {
    let mut frames = vec![
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::RoutePromise,
            RECORD_ROUTE_PROMISE,
            &offer_records.route_promise.promise_id,
            CAPABILITY_ROUTE_PROMISE_RESOLVE,
            json!({
                "recordKind": RECORD_ROUTE_PROMISE,
                "record": &offer_records.route_promise,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamRoutePlan,
            RECORD_STREAM_ROUTE_PLAN,
            &offer_records.route_plan.session_id,
            CAPABILITY_MEDIA_STREAM_PREVIEW,
            json!({
                "recordKind": RECORD_STREAM_ROUTE_PLAN,
                "record": &offer_records.route_plan,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.admission",
            &offer_records.admission.admission_id,
            CAPABILITY_STREAM_SESSION_OFFER,
            json!({
                "recordKind": "stream.session.admission",
                "record": &offer_records.admission,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
    ];
    for contribution in &offer_records.contribution_lifecycles {
        frames.push(seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::ContributionLifecycle,
            RECORD_CONTRIBUTION_LIFECYCLE,
            &contribution.contribution_id,
            CAPABILITY_MEDIA_STREAM_PREVIEW,
            json!({
                "recordKind": RECORD_CONTRIBUTION_LIFECYCLE,
                "record": contribution,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?);
    }
    Ok(frames)
}

fn build_offer_response_frames(
    cfg: &Config,
    request_frame: &SwarmFrame,
    response: &ManagedOfferResponse,
    now: u64,
    projection_baseline: &StreamProjectionBaseline,
    projection_value: Value,
    response_zone_scope: Option<ZoneScope>,
) -> Result<Vec<SwarmFrame>> {
    let stream_session = response
        .stream_session
        .as_ref()
        .ok_or_else(|| anyhow!("preview response missing stream session records"))?;
    let mut frames = Vec::new();
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::RoutePromise,
        RECORD_ROUTE_PROMISE,
        &stream_session.offer.route_promise.promise_id,
        CAPABILITY_ROUTE_PROMISE_RESOLVE,
        json!({
            "recordKind": RECORD_ROUTE_PROMISE,
            "record": &stream_session.offer.route_promise,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::StreamRoutePlan,
        RECORD_STREAM_ROUTE_PLAN,
        &stream_session.offer.route_plan.session_id,
        CAPABILITY_MEDIA_STREAM_PREVIEW,
        json!({
            "recordKind": RECORD_STREAM_ROUTE_PLAN,
            "record": &stream_session.offer.route_plan,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::StreamStatus,
        "stream.session.admission",
        &stream_session.offer.admission.admission_id,
        CAPABILITY_STREAM_SESSION_OFFER,
        json!({
            "recordKind": "stream.session.admission",
            "record": &stream_session.offer.admission,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    for contribution in &stream_session.offer.contribution_lifecycles {
        frames.push(seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::ContributionLifecycle,
            RECORD_CONTRIBUTION_LIFECYCLE,
            &contribution.contribution_id,
            CAPABILITY_MEDIA_STREAM_PREVIEW,
            json!({
                "recordKind": RECORD_CONTRIBUTION_LIFECYCLE,
                "record": contribution,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?);
    }
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::StreamStatus,
        "stream.session.answer",
        &stream_session.answer.answer.answer_id,
        CAPABILITY_STREAM_SESSION_OFFER,
        json!({
            "recordKind": "stream.session.answer",
            "record": stream_session.answer.answer,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    for candidate in &stream_session.answer.candidates {
        frames.push(seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.candidate",
            &candidate.candidate_id,
            CAPABILITY_STREAM_SESSION_OFFER,
            json!({
                "recordKind": "stream.session.candidate",
                "record": candidate,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?);
    }
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::StreamStatus,
        RECORD_MEDIA_TRANSPORT_PATH,
        &stream_session.answer.media_transport_path.path_id,
        CAPABILITY_MEDIA_STREAM_PREVIEW,
        json!({
            "recordKind": RECORD_MEDIA_TRANSPORT_PATH,
            "record": &stream_session.answer.media_transport_path,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    for contribution in &stream_session.answer.contribution_lifecycles {
        frames.push(seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::ContributionLifecycle,
            RECORD_CONTRIBUTION_LIFECYCLE,
            &contribution.contribution_id,
            CAPABILITY_MEDIA_STREAM_PREVIEW,
            json!({
                "recordKind": RECORD_CONTRIBUTION_LIFECYCLE,
                "record": contribution,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?);
    }
    let health = stream_session_health(&response.session_id, "answer_ready", now)?;
    frames.push(seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::StreamStatus,
        "stream.session.health",
        &health.health_id,
        CAPABILITY_MEDIA_STREAM_PREVIEW,
        json!({
            "recordKind": "stream.session.health",
            "record": health,
        }),
        now,
        None,
        response_zone_scope.as_ref(),
    )?);
    frames.push(stream_projection_snapshot_frame(
        cfg,
        request_frame,
        now,
        projection_baseline,
        response_zone_scope.as_ref(),
    )?);
    frames.push(stream_projection_delta_frame(
        cfg,
        request_frame,
        &response.session_id,
        "answer_ready",
        projection_value,
        now,
        projection_baseline.base_revision,
        response_zone_scope.as_ref(),
    )?);
    Ok(frames)
}

fn build_transport_observation_frame(
    cfg: &Config,
    event: &PreviewTransportObservationEvent,
    now: u64,
) -> Result<SwarmFrame> {
    let observation_expires_at = Some(
        event
            .observed_at
            .saturating_add(RESPONSE_TTL_MS)
            .max(now.saturating_add(RESPONSE_TTL_MS)),
    );
    let observation = MediaTransportObservation {
        kind: Some(RECORD_MEDIA_TRANSPORT_OBSERVATION.to_string()),
        observation_id: format!(
            "media-observation-{}-{}",
            event.session_id.trim(),
            event.observed_at
        ),
        path_id: event.path_id.clone(),
        session_id: event.session_id.clone(),
        activation_id: Some(event.activation_id.clone()),
        route_promise_id: Some(event.route_promise_id.clone()),
        participant_ref: event.participant_ref.clone(),
        participant_role: event.participant_role.clone(),
        state: event.state.clone(),
        connection_state: Some(event.connection_state.clone()),
        ice_connection_state: event.ice_connection_state.clone(),
        selected_pair_state: event.selected_pair_state.clone(),
        inbound_rtp_state: event.inbound_rtp_state.clone(),
        render_state: event.render_state.clone(),
        blocked_reason: event.blocked_reason.clone(),
        reason: event.reason.clone(),
        safe_facts: json!({
            "sourceCount": event.source_ids.len(),
            "graceMs": event.grace_ms,
            "pathExpiresAt": event.expires_at,
            "serviceConnectionState": event.connection_state,
            "selectedPairState": event.selected_pair_state,
        }),
        evidence_refs: vec![event.path_id.clone()],
        observed_at: event.observed_at,
        expires_at: observation_expires_at,
    };
    validate_media_transport_observation(&observation)?;
    let payload = json!({
        "recordKind": RECORD_MEDIA_TRANSPORT_OBSERVATION,
        "record": observation,
    });
    seal_service_record_frame(
        cfg,
        SwarmFrameKind::StreamStatus,
        RECORD_MEDIA_TRANSPORT_OBSERVATION,
        &format!(
            "media-observation-{}-{}",
            event.session_id.trim(),
            event.observed_at
        ),
        CAPABILITY_MEDIA_STREAM_PREVIEW,
        payload,
        now,
        event,
    )
}

fn build_control_response_frames(
    cfg: &Config,
    request_frame: &SwarmFrame,
    control: &StreamSessionControl,
    result: Value,
    now: u64,
    projection_baseline: &StreamProjectionBaseline,
    projection_value: Value,
    response_zone_scope: Option<ZoneScope>,
) -> Result<Vec<SwarmFrame>> {
    validate_stream_session_control(control)?;
    let health = stream_session_health(&control.session_id, "control_applied", now)?;
    Ok(vec![
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.control",
            &control.control_id,
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.control",
                "record": control,
                "result": result,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.health",
            &health.health_id,
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.health",
                "record": health,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_snapshot_frame(
            cfg,
            request_frame,
            now,
            projection_baseline,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_delta_frame(
            cfg,
            request_frame,
            &control.session_id,
            "control_applied",
            projection_value,
            now,
            projection_baseline.base_revision,
            response_zone_scope.as_ref(),
        )?,
    ])
}

fn build_candidate_response_frames(
    cfg: &Config,
    request_frame: &SwarmFrame,
    result: Value,
    now: u64,
    projection_baseline: &StreamProjectionBaseline,
    projection_value: Value,
    response_zone_scope: Option<ZoneScope>,
) -> Result<Vec<SwarmFrame>> {
    let session_id = result
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("candidate response missing sessionId"))?
        .to_string();
    let endpoint = result.get("endpoint").cloned().unwrap_or(Value::Null);
    let health = stream_session_health(&session_id, "candidate_applied", now)?;
    Ok(vec![
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.candidate",
            &format!("candidate-applied-{session_id}-{now}"),
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.candidate",
                "record": {
                    "candidateId": format!("candidate-applied-{session_id}-{now}"),
                    "sessionId": session_id,
                    "transport": "webrtc",
                    "candidateRole": STREAM_CANDIDATE_ROLE_BROWSER,
                    "actionability": STREAM_CANDIDATE_ACTIONABILITY_USABLE,
                    "endpoint": endpoint,
                    "payload": {
                        "direction": "remote",
                        "candidateApplied": true,
                    },
                    "issuedAt": now,
                },
                "result": result,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.health",
            &health.health_id,
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.health",
                "record": health,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_snapshot_frame(
            cfg,
            request_frame,
            now,
            projection_baseline,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_delta_frame(
            cfg,
            request_frame,
            &session_id,
            "candidate_applied",
            projection_value,
            now,
            projection_baseline.base_revision,
            response_zone_scope.as_ref(),
        )?,
    ])
}

fn build_close_response_frames(
    cfg: &Config,
    request_frame: &SwarmFrame,
    close: &StreamSessionClose,
    response: Value,
    now: u64,
    projection_baseline: &StreamProjectionBaseline,
    projection_value: Value,
    response_zone_scope: Option<ZoneScope>,
) -> Result<Vec<SwarmFrame>> {
    validate_stream_session_close(close)?;
    let health = stream_session_health(&close.session_id, "closed", now)?;
    Ok(vec![
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.close",
            &close.close_id,
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.close",
                "record": close,
                "result": response,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        seal_record_frame(
            cfg,
            request_frame,
            SwarmFrameKind::StreamStatus,
            "stream.session.health",
            &health.health_id,
            CAPABILITY_STREAM_SESSION_CONTROL,
            json!({
                "recordKind": "stream.session.health",
                "record": health,
            }),
            now,
            None,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_snapshot_frame(
            cfg,
            request_frame,
            now,
            projection_baseline,
            response_zone_scope.as_ref(),
        )?,
        stream_projection_delta_frame(
            cfg,
            request_frame,
            &close.session_id,
            "closed",
            projection_value,
            now,
            projection_baseline.base_revision,
            response_zone_scope.as_ref(),
        )?,
    ])
}

fn stream_session_health(session_id: &str, status: &str, now: u64) -> Result<StreamSessionHealth> {
    let health = StreamSessionHealth {
        health_id: format!("health-{session_id}-{now}"),
        session_id: session_id.to_string(),
        status: status.to_string(),
        recovery: json!({}),
        issued_at: now,
    };
    validate_stream_session_health(&health)?;
    Ok(health)
}

fn stream_projection_snapshot_frame(
    cfg: &Config,
    request_frame: &SwarmFrame,
    now: u64,
    baseline: &StreamProjectionBaseline,
    response_zone_scope: Option<&ZoneScope>,
) -> Result<SwarmFrame> {
    let snapshot =
        stream_projection_snapshot(cfg, now, baseline.base_revision, baseline.state.clone())?;
    seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::ProjectionSnapshot,
        "projection.snapshot",
        &format!("nvr.streams.snapshot.{}", snapshot.revision),
        CAPABILITY_PROJECTION_DELTA_APPLY,
        json!({
            "recordKind": "projection.snapshot",
            "snapshot": snapshot,
        }),
        now,
        Some(snapshot.revision),
        response_zone_scope,
    )
}

fn stream_projection_snapshot(
    cfg: &Config,
    now: u64,
    revision: u64,
    state: Value,
) -> Result<SwarmProjectionSnapshot> {
    let session_count = state
        .get("streamSessions")
        .and_then(Value::as_object)
        .map(|sessions| sessions.len())
        .unwrap_or(0);
    let snapshot = SwarmProjectionSnapshot {
        projection_id: STREAM_PROJECTION_ID.to_string(),
        policy_id: STREAM_PROJECTION_POLICY_ID.to_string(),
        revision,
        state,
        coverage: json!({
            "projectionId": STREAM_PROJECTION_ID,
            "materializedCount": session_count,
            "targetCount": session_count,
            "completionRatio": 1.0,
            "syncState": "baseline",
        }),
        freshness: json!({
            "state": "baseline",
            "updatedAt": now,
        }),
        source_refs: vec![format!("service:{}", cfg.nostr_pubkey.trim())],
        issued_at: now,
    };
    validate_projection_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn stream_projection_delta_frame(
    cfg: &Config,
    request_frame: &SwarmFrame,
    session_id: &str,
    status: &str,
    value: Value,
    now: u64,
    base_revision: u64,
    response_zone_scope: Option<&ZoneScope>,
) -> Result<SwarmFrame> {
    let delta = stream_projection_delta(cfg, session_id, status, value, now, base_revision)?;
    seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::ProjectionDelta,
        "projection.delta",
        &format!("nvr.streams.delta.{}", delta.revision),
        CAPABILITY_PROJECTION_DELTA_APPLY,
        json!({
            "recordKind": "projection.delta",
            "delta": delta,
        }),
        now,
        Some(delta.revision),
        response_zone_scope,
    )
}

fn stream_projection_delta(
    cfg: &Config,
    session_id: &str,
    status: &str,
    value: Value,
    now: u64,
    base_revision: u64,
) -> Result<SwarmProjectionDelta> {
    let delta = SwarmProjectionDelta {
        projection_id: STREAM_PROJECTION_ID.to_string(),
        policy_id: STREAM_PROJECTION_POLICY_ID.to_string(),
        base_revision,
        revision: base_revision.saturating_add(1),
        ops: vec![ProjectionDeltaOp {
            op: ProjectionDeltaOpKind::Set,
            path: vec![
                ProjectionPathSegment::Key("streamSessions".to_string()),
                ProjectionPathSegment::Key(session_id.to_string()),
            ],
            value: Some(value),
        }],
        affected_records: vec![json!({
            "kind": "stream.session.health",
            "id": format!("health-{session_id}-{now}"),
            "status": status,
        })],
        coverage: json!({
            "projectionId": STREAM_PROJECTION_ID,
            "status": status,
            "materializedCount": 1,
            "targetCount": 1,
            "completionRatio": 1.0,
            "syncState": "completeEnough",
        }),
        freshness: json!({
            "state": "fresh",
            "updatedAt": now,
        }),
        source_refs: vec![format!("service:{}", cfg.nostr_pubkey.trim())],
        issued_at: now,
    };
    validate_projection_delta(&delta, base_revision)?;
    Ok(delta)
}

fn seal_record_frame(
    cfg: &Config,
    request_frame: &SwarmFrame,
    kind: SwarmFrameKind,
    record_kind: &str,
    record_id: &str,
    capability: &str,
    payload: Value,
    now: u64,
    revision: Option<u64>,
    response_zone_scope: Option<&ZoneScope>,
) -> Result<SwarmFrame> {
    let recipients = response_recipients(cfg, request_frame)?;
    let envelope = seal_envelope(
        record_kind,
        &payload,
        &cfg.nostr_sk_hex,
        &recipients,
        now,
        now.saturating_add(RESPONSE_TTL_MS),
    )?;
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind,
        issuer: cfg.nostr_pubkey.trim().to_string(),
        audience: json!({
            "actorRef": request_frame.issuer,
            "serviceRef": service_ref(cfg),
        }),
        zone_scope: response_zone_scope
            .cloned()
            .or_else(|| fallback_response_zone_scope(request_frame)),
        issued_at: now,
        expires_at: Some(now.saturating_add(RESPONSE_TTL_MS)),
        nonce: format!(
            "nvr-{}-{}",
            record_kind.replace('.', "-"),
            Uuid::new_v4().simple()
        ),
        correlation_id: Some(request_frame.frame_id.clone()),
        channel_id: Some(
            request_frame
                .channel_id
                .clone()
                .unwrap_or_else(|| STREAM_CHANNEL_ID.to_string()),
        ),
        record_ref: Some(SwarmRecordRef {
            kind: record_kind.to_string(),
            id: record_id.to_string(),
            revision,
        }),
        capability: Some(capability.to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope)?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now)?;
    Ok(frame)
}

fn seal_service_record_frame(
    cfg: &Config,
    kind: SwarmFrameKind,
    record_kind: &str,
    record_id: &str,
    capability: &str,
    payload: Value,
    now: u64,
    event: &PreviewTransportObservationEvent,
) -> Result<SwarmFrame> {
    let mut recipients = Vec::new();
    push_recipient(&mut recipients, event.requester_ref.trim());
    push_recipient(&mut recipients, cfg.gateway.host_gateway_pk.trim());
    if recipients.is_empty() {
        return Err(anyhow!("no valid transport observation recipient"));
    }
    let envelope = seal_envelope(
        record_kind,
        &payload,
        &cfg.nostr_sk_hex,
        &recipients,
        now,
        now.saturating_add(RESPONSE_TTL_MS),
    )?;
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind,
        issuer: cfg.nostr_pubkey.trim().to_string(),
        audience: json!({
            "actorRef": event.requester_ref,
            "serviceRef": service_ref(cfg),
        }),
        zone_scope: Some(first_zone_scope(cfg)),
        issued_at: now,
        expires_at: Some(now.saturating_add(RESPONSE_TTL_MS)),
        nonce: format!(
            "nvr-{}-{}",
            record_kind.replace('.', "-"),
            Uuid::new_v4().simple()
        ),
        correlation_id: Some(event.session_id.clone()),
        channel_id: Some(STREAM_CHANNEL_ID.to_string()),
        record_ref: Some(SwarmRecordRef {
            kind: record_kind.to_string(),
            id: record_id.to_string(),
            revision: None,
        }),
        capability: Some(capability.to_string()),
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope)?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now)?;
    Ok(frame)
}

fn build_reject_response_frame(
    cfg: &Config,
    request_frame: &SwarmFrame,
    now: u64,
    reason_code: &str,
    detail: &str,
) -> Result<SwarmFrame> {
    let recipients = response_recipients(cfg, request_frame)?;
    let envelope = seal_envelope(
        "stream.session.reject",
        &json!({
            "reasonCode": reason_code,
            "detail": detail,
            "sourceFrameId": request_frame.frame_id,
        }),
        &cfg.nostr_sk_hex,
        &recipients,
        now,
        now.saturating_add(RESPONSE_TTL_MS),
    )?;
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::Reject,
        issuer: cfg.nostr_pubkey.trim().to_string(),
        audience: json!({
            "actorRef": request_frame.issuer,
            "serviceRef": service_ref(cfg),
        }),
        zone_scope: fallback_response_zone_scope(request_frame)
            .or_else(|| Some(first_zone_scope(cfg))),
        issued_at: now,
        expires_at: Some(now.saturating_add(RESPONSE_TTL_MS)),
        nonce: format!("nvr-reject-{}", Uuid::new_v4().simple()),
        correlation_id: Some(request_frame.frame_id.clone()),
        channel_id: request_frame.channel_id.clone(),
        record_ref: None,
        capability: None,
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope)?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: Some(SwarmAck {
            acked_frame_id: None,
            retry_after_ms: None,
            gap_after_frame_ids: vec![],
            reason_code: Some(reason_code.to_string()),
        }),
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now)?;
    Ok(frame)
}

fn build_member_read_observation_frame(
    cfg: &Config,
    request_frame: &SwarmFrame,
    now: u64,
) -> Result<SwarmFrame> {
    let observation = RouteObservation {
        kind: Some(RECORD_ROUTE_OBSERVATION.to_string()),
        observation_id: format!("route-member-read-{}-{now}", request_frame.frame_id),
        state: RouteObservationState::MemberRead,
        frame_id: Some(request_frame.frame_id.clone()),
        promise_id: None,
        activation_id: None,
        delivered_to: vec![cfg.nostr_pubkey.trim().to_string()],
        failed_predicates: vec![],
        release_reason: None,
        diagnostics: json!({
            "detail": "service member read frame from edge socket",
        }),
        issued_at: now,
    };
    validate_route_observation(&observation)?;
    seal_record_frame(
        cfg,
        request_frame,
        SwarmFrameKind::RouteObservation,
        RECORD_ROUTE_OBSERVATION,
        &observation.observation_id,
        "route.observation.publish",
        json!({
            "recordKind": RECORD_ROUTE_OBSERVATION,
            "record": observation,
        }),
        now,
        None,
        None,
    )
}

fn response_zone_scope_from_claims(
    claims: &Value,
    request_frame: &SwarmFrame,
) -> Option<ZoneScope> {
    let route_promise = claims
        .get("routePromise")
        .or_else(|| claims.get("route_promise"));
    for value in [
        route_promise.and_then(|promise| promise.get("returnZoneScope")),
        route_promise.and_then(|promise| promise.get("return_zone_scope")),
        route_promise.and_then(|promise| promise.get("requesterZoneScope")),
        route_promise.and_then(|promise| promise.get("requester_zone_scope")),
        route_promise.and_then(|promise| promise.get("responseZoneScope")),
        route_promise.and_then(|promise| promise.get("response_zone_scope")),
        claims.get("returnZoneScope"),
        claims.get("return_zone_scope"),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(scope) = serde_json::from_value::<ZoneScope>(value.clone())
            && validate_response_zone_scope(&scope).is_ok()
        {
            return Some(scope);
        }
    }
    fallback_response_zone_scope(request_frame)
}

fn first_zone_scope(cfg: &Config) -> ZoneScope {
    let zone_id = cfg
        .swarm
        .zones
        .first()
        .map(|zone| zone.key.trim())
        .filter(|zone| !zone.is_empty())
        .unwrap_or("local");
    ZoneScope {
        zone_id: zone_id.to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    }
}

fn fallback_response_zone_scope(request_frame: &SwarmFrame) -> Option<ZoneScope> {
    request_frame.zone_scope.clone()
}

fn validate_response_zone_scope(scope: &ZoneScope) -> Result<()> {
    if scope.zone_id.trim().is_empty() {
        return Err(anyhow!("response zone scope missing zoneId"));
    }
    Ok(())
}

fn response_recipients(cfg: &Config, request_frame: &SwarmFrame) -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    push_recipient(&mut recipients, request_frame.issuer.trim());
    push_recipient(&mut recipients, cfg.gateway.host_gateway_pk.trim());
    if recipients.is_empty() {
        return Err(anyhow!("no valid response recipient for swarm frame"));
    }
    Ok(recipients)
}

fn push_recipient(recipients: &mut Vec<String>, value: &str) {
    if is_hex_pubkey(value) && !recipients.iter().any(|item| item == value) {
        recipients.push(value.to_string());
    }
}

fn is_hex_pubkey(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamFrameAction {
    Offer,
    Candidate,
    Close,
    Control,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayFrameAdmission {
    Admit,
    Ignore,
    Reject { detail: String },
}

fn gateway_frame_admission(cfg: &Config, frame: &SwarmFrame) -> GatewayFrameAdmission {
    if !frame_targets_nvr(cfg, frame) {
        return GatewayFrameAdmission::Ignore;
    }
    match classify_stream_frame(cfg, frame) {
        Ok(Some(_)) => GatewayFrameAdmission::Admit,
        Ok(None) => GatewayFrameAdmission::Ignore,
        Err(err) => GatewayFrameAdmission::Reject {
            detail: err.to_string(),
        },
    }
}

fn classify_stream_frame(cfg: &Config, frame: &SwarmFrame) -> Result<Option<StreamFrameAction>> {
    let Some(kind) = record_kind(frame) else {
        return Ok(None);
    };
    let action = match (frame.kind.clone(), kind) {
        (SwarmFrameKind::StreamIntent, "stream.session.intent" | "stream.session.offer") => {
            StreamFrameAction::Offer
        }
        (SwarmFrameKind::StreamControl, "stream.session.candidate") => StreamFrameAction::Candidate,
        (SwarmFrameKind::StreamControl, "stream.session.close") => StreamFrameAction::Close,
        (SwarmFrameKind::StreamControl, "stream.session.control") => StreamFrameAction::Control,
        _ => return Ok(None),
    };
    ensure_stream_route_headers(cfg, frame, action)?;
    Ok(Some(action))
}

fn ensure_stream_route_headers(
    cfg: &Config,
    frame: &SwarmFrame,
    action: StreamFrameAction,
) -> Result<()> {
    if !frame_targets_nvr(cfg, frame) {
        return Err(anyhow!("stream frame audience does not target nvr service"));
    }
    if frame.channel_id.as_deref().map(str::trim) != Some(STREAM_CHANNEL_ID) {
        return Err(anyhow!("stream frame missing nvr stream channel"));
    }
    if frame.zone_scope.is_none() {
        return Err(anyhow!("stream frame missing route zone scope"));
    }
    let required = match action {
        StreamFrameAction::Offer => OFFER_FRAME_CAPABILITIES,
        StreamFrameAction::Candidate | StreamFrameAction::Close | StreamFrameAction::Control => {
            CONTROL_FRAME_CAPABILITIES
        }
    };
    let capability = frame
        .capability
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !required.iter().any(|allowed| *allowed == capability) {
        return Err(anyhow!("stream frame missing required route capability"));
    }
    Ok(())
}

fn frame_targets_nvr(cfg: &Config, frame: &SwarmFrame) -> bool {
    let service_pk = cfg.nostr_pubkey.trim();
    let service_ref = service_ref(cfg);
    let audience = &frame.audience;
    let declared = [
        audience_value(audience, "memberRef"),
        audience_value(audience, "serviceMemberRef"),
        audience_value(audience, "servicePk"),
        audience_value(audience, "recipientServicePk"),
        audience_value(audience, "serviceRef"),
        audience_value(audience, "service"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if declared.is_empty() {
        return false;
    }
    declared.iter().any(|value| {
        value == service_pk || value == &service_ref || value.eq_ignore_ascii_case("nvr")
    })
}

fn audience_value(audience: &Value, key: &str) -> Option<String> {
    audience
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn service_ref(cfg: &Config) -> String {
    let service_pk = cfg.nostr_pubkey.trim();
    if service_pk.is_empty() {
        "service:nvr".to_string()
    } else {
        format!("service:{service_pk}")
    }
}

fn is_stream_offer_frame(frame: &SwarmFrame) -> bool {
    matches!(frame.kind, SwarmFrameKind::StreamIntent)
        && record_kind(frame)
            .map(|kind| kind == "stream.session.intent" || kind == "stream.session.offer")
            .unwrap_or(false)
}

fn is_stream_control_frame(frame: &SwarmFrame) -> bool {
    matches!(frame.kind, SwarmFrameKind::StreamControl)
        && record_kind(frame)
            .map(|kind| kind == "stream.session.control")
            .unwrap_or(false)
}

fn is_stream_candidate_frame(frame: &SwarmFrame) -> bool {
    matches!(frame.kind, SwarmFrameKind::StreamControl)
        && record_kind(frame)
            .map(|kind| kind == "stream.session.candidate")
            .unwrap_or(false)
}

fn is_stream_close_frame(frame: &SwarmFrame) -> bool {
    matches!(frame.kind, SwarmFrameKind::StreamControl)
        && record_kind(frame)
            .map(|kind| kind == "stream.session.close")
            .unwrap_or(false)
}

fn record_kind(frame: &SwarmFrame) -> Option<&str> {
    frame
        .record_ref
        .as_ref()
        .map(|record| record.kind.trim())
        .filter(|kind| !kind.is_empty())
}

fn ensure_signal_type(claims: &Value, allowed: &[&str]) -> Result<()> {
    let signal_type = claims
        .get("signalType")
        .or_else(|| claims.get("signal_type"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(signal_type) = signal_type {
        let signal_type = signal_type.to_ascii_lowercase();
        if !allowed.iter().any(|allowed| *allowed == signal_type) {
            return Err(anyhow!("swarm stream signal type mismatch"));
        }
    }
    Ok(())
}

fn ensure_opened_route_promise(claims: &Value) -> Result<()> {
    let promise = claims
        .get("routePromise")
        .or_else(|| claims.get("route_promise"));
    if let Some(promise) = promise {
        if promise.is_object()
            && promise
                .get("promiseId")
                .or_else(|| promise.get("promise_id"))
                .and_then(Value::as_str)
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
        {
            return Ok(());
        }
        return Err(anyhow!("stream frame route promise is malformed"));
    }
    let promise_id = claims
        .get("routePromiseId")
        .or_else(|| claims.get("route_promise_id"))
        .or_else(|| claims.get("promiseId"))
        .or_else(|| claims.get("promise_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if promise_id.is_empty() {
        return Err(anyhow!("stream frame missing route promise"));
    }
    Ok(())
}

fn managed_offer_from_claims(cfg: &Config, claims: &Value) -> Result<ManagedOfferRequest> {
    let payload = object_or_empty(claims.get("payload"));
    let record_payload = claims
        .get("record")
        .and_then(|record| record.get("payload"))
        .cloned();
    let offer = claims
        .get("offer")
        .cloned()
        .or_else(|| payload.get("offer").cloned())
        .or_else(|| record_payload.clone())
        .or_else(|| {
            (payload.get("description").is_some()
                || payload.get("type").is_some()
                || payload.get("sdp").is_some())
            .then(|| payload.clone())
        })
        .ok_or_else(|| anyhow!("swarm stream offer missing offer payload"))?;
    let ice_servers = claims
        .get("iceServers")
        .or_else(|| payload.get("iceServers"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("invalid swarm stream iceServers")?
        .unwrap_or_default();
    let mut candidates = Vec::new();
    collect_candidates(claims.get("candidates"), &mut candidates)?;
    collect_candidates(payload.get("candidates"), &mut candidates)?;
    collect_candidates(offer.get("candidates"), &mut candidates)?;
    Ok(ManagedOfferRequest {
        authority: authority_from_claims(cfg, claims)?,
        offer,
        ice_servers,
        candidates,
    })
}

fn managed_control_from_claims(cfg: &Config, claims: &Value) -> Result<ManagedControlRequest> {
    let payload = object_or_empty(claims.get("payload"));
    let record_params = claims
        .get("record")
        .and_then(|record| record.get("params"))
        .cloned();
    let control_payload = if payload.is_object() && !payload.as_object().unwrap().is_empty() {
        payload.clone()
    } else {
        record_params.unwrap_or_else(|| json!({}))
    };
    Ok(ManagedControlRequest {
        authority: authority_from_claims(cfg, claims)?,
        control_lease: claims
            .get("controlLease")
            .or_else(|| control_payload.get("controlLease"))
            .cloned()
            .unwrap_or_else(|| json!({})),
        preempted: claims
            .get("preempted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        payload: control_payload,
    })
}

fn managed_candidate_from_claims(cfg: &Config, claims: &Value) -> Result<ManagedCandidateRequest> {
    let payload = object_or_empty(claims.get("payload"));
    let record_payload = claims
        .get("record")
        .and_then(|record| record.get("payload"))
        .cloned();
    let candidate_payload = if payload.is_object() && !payload.as_object().unwrap().is_empty() {
        payload.clone()
    } else {
        record_payload.unwrap_or_else(|| json!({}))
    };
    Ok(ManagedCandidateRequest {
        authority: authority_from_claims(cfg, claims)?,
        payload: candidate_payload,
    })
}

fn managed_close_from_claims(cfg: &Config, claims: &Value) -> Result<ManagedCloseRequest> {
    let payload = object_or_empty(claims.get("payload"));
    let close_payload = if payload.is_object() && !payload.as_object().unwrap().is_empty() {
        payload.clone()
    } else if let Some(record) = claims.get("record") {
        json!({
            "sessionId": record
                .get("sessionId")
                .or_else(|| record.get("session_id"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            "reason": record
                .get("reasonCode")
                .or_else(|| record.get("reason_code"))
                .and_then(Value::as_str)
                .unwrap_or("closed")
        })
    } else {
        json!({})
    };
    let session_id = close_payload
        .get("sessionId")
        .or_else(|| close_payload.get("session_id"))
        .or_else(|| {
            claims
                .get("record")
                .and_then(|record| record.get("sessionId").or_else(|| record.get("session_id")))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_string();
    Ok(ManagedCloseRequest {
        authority: authority_from_claims(cfg, claims)?,
        session_id,
        payload: close_payload,
    })
}

fn authority_from_claims(cfg: &Config, claims: &Value) -> Result<StreamAuthorityClaims> {
    let source = claims
        .get("authority")
        .or_else(|| claims.get("authorityClaims"))
        .or_else(|| claims.get("claims"))
        .unwrap_or(claims);
    let authority: StreamAuthorityClaims =
        serde_json::from_value(source.clone()).context("invalid swarm stream authority claims")?;
    validate_stream_authority(cfg, &authority)?;
    Ok(authority)
}

fn object_or_empty(value: Option<&Value>) -> Value {
    value
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn collect_candidates(value: Option<&Value>, out: &mut Vec<RTCIceCandidateInit>) -> Result<()> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Ok(());
    };
    for entry in entries {
        let candidate: RTCIceCandidateInit =
            serde_json::from_value(entry.clone()).context("invalid ICE candidate")?;
        if candidate.candidate.trim().is_empty() {
            continue;
        }
        if out.iter().any(|existing| {
            existing.candidate == candidate.candidate
                && existing.sdp_mid == candidate.sdp_mid
                && existing.sdp_mline_index == candidate.sdp_mline_index
                && existing.username_fragment == candidate.username_fragment
        }) {
            continue;
        }
        out.push(candidate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CameraDeviceDesiredConfig, Config};
    use crate::live::{
        ManagedSourceInfo, StreamSessionExchangeRecords, stream_session_records_for_answer,
        stream_session_records_for_offer,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

    static CONFIG_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-swarm-edge-test-{}-{}-{}.json",
            std::process::id(),
            crate::util::now_ms(),
            CONFIG_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let (mut cfg, _) = Config::load_or_create(&path).expect("config");
        let _ = std::fs::remove_file(&path);
        let (service_pk, service_sk) = constitute_protocol::generate_keypair();
        let (gateway_pk, _) = constitute_protocol::generate_keypair();
        cfg.nostr_pubkey = service_pk;
        cfg.nostr_sk_hex = service_sk;
        cfg.gateway.host_gateway_pk = gateway_pk;
        cfg.api.identity_id = "identity-1".to_string();
        cfg.camera_devices.push(CameraDeviceConfig {
            source_id: "cam-1".to_string(),
            name: "Front".to_string(),
            onvif_host: "192.0.2.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:pw@192.0.2.10:554/h264Preview_01_main".to_string(),
            username: "admin".to_string(),
            password: "pw".to_string(),
            driver_id: "reolink".to_string(),
            vendor: "Reolink".to_string(),
            model: "E1".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: true,
            enabled: true,
            segment_secs: 10,
            desired: CameraDeviceDesiredConfig::default(),
            credentials: Default::default(),
        });
        cfg
    }

    fn request_frame(
        cfg: &Config,
        kind: SwarmFrameKind,
        record_kind: &str,
        now: u64,
    ) -> SwarmFrame {
        let capability = if matches!(kind, SwarmFrameKind::StreamIntent) {
            CAPABILITY_MEDIA_STREAM_PREVIEW.to_string()
        } else {
            CAPABILITY_STREAM_SESSION_CONTROL.to_string()
        };
        let mut frame = SwarmFrame {
            version: constitute_protocol::SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind,
            issuer: cfg.gateway.host_gateway_pk.clone(),
            audience: json!({
                "servicePk": cfg.nostr_pubkey,
                "service": "nvr",
            }),
            zone_scope: Some(ZoneScope {
                zone_id: "zone-test".to_string(),
                privacy: Some("rawIds".to_string()),
                ttl: Some(30),
                max_hops: Some(2),
            }),
            issued_at: now,
            expires_at: Some(now + RESPONSE_TTL_MS),
            nonce: format!("nonce-{record_kind}"),
            correlation_id: Some("corr-1".to_string()),
            channel_id: Some(STREAM_CHANNEL_ID.to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: record_kind.to_string(),
                id: format!("{record_kind}-1"),
                revision: None,
            }),
            capability: Some(capability),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({ "envelopeId": "fixture" })),
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        frame
    }

    fn response(cfg: &Config) -> ManagedOfferResponse {
        let now = 1_700_000_001_000;
        let authority = authority_claims(cfg, "nonce-1");
        let offer_request = ManagedOfferRequest {
            authority: authority.clone(),
            offer: json!({
                "description": { "type": "offer", "sdp": "v=0\r\n" },
                "sourceIds": ["cam-1"]
            }),
            ice_servers: Default::default(),
            candidates: vec![],
        };
        let mut response = ManagedOfferResponse {
            signal_type: "answer".to_string(),
            answer: RTCSessionDescription::answer(
                "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n".to_string(),
            )
            .expect("answer"),
            session_id: "nvr-preview-nonce-1".to_string(),
            sources: vec![ManagedSourceInfo {
                source_id: "cam-1".to_string(),
                name: "Front".to_string(),
                rtsp_preview_url: "rtsp://should-not-enter-swarm-frame".to_string(),
            }],
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 1 192.0.2.5 5000 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
            stream_session: None,
        };
        let offer = stream_session_records_for_offer(cfg, &offer_request, &authority, now)
            .expect("offer records");
        let answer =
            stream_session_records_for_answer(&response, &offer, now).expect("answer records");
        response.stream_session = Some(StreamSessionExchangeRecords { offer, answer });
        response
    }

    fn baseline(revision: u64) -> StreamProjectionBaseline {
        StreamProjectionBaseline {
            base_revision: revision,
            state: json!({
                "streamSessions": {}
            }),
        }
    }

    fn authority_claims(cfg: &Config, nonce: &str) -> StreamAuthorityClaims {
        let (device_pk, _) = constitute_protocol::generate_keypair();
        StreamAuthorityClaims {
            capability_id: format!("cap-{nonce}"),
            gateway_pk: cfg.gateway.host_gateway_pk.clone(),
            service_pk: cfg.nostr_pubkey.clone(),
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk,
            capability: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            issued_at: crate::util::now_ms(),
            expires_at: crate::util::now_ms() + 60_000,
            nonce: nonce.to_string(),
        }
    }

    #[test]
    fn offer_response_emits_answer_candidate_status_and_projection_delta_frames() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let request = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );

        let response = response(&cfg);
        let projection_value = offer_projection_value(&response).expect("projection value");
        let frames = build_offer_response_frames(
            &cfg,
            &request,
            &response,
            now,
            &baseline(0),
            projection_value,
            None,
        )
        .expect("frames");
        let record_kinds = frames
            .iter()
            .filter_map(|frame| frame.record_ref.as_ref().map(|record| record.kind.as_str()))
            .collect::<Vec<_>>();

        assert!(record_kinds.contains(&RECORD_ROUTE_PROMISE));
        assert!(record_kinds.contains(&RECORD_STREAM_ROUTE_PLAN));
        assert!(record_kinds.contains(&"stream.session.admission"));
        assert!(record_kinds.contains(&RECORD_CONTRIBUTION_LIFECYCLE));
        assert!(record_kinds.contains(&"stream.session.answer"));
        assert!(record_kinds.contains(&"stream.session.candidate"));
        assert!(record_kinds.contains(&RECORD_MEDIA_TRANSPORT_PATH));
        assert!(record_kinds.contains(&"stream.session.health"));
        assert!(record_kinds.contains(&"projection.snapshot"));
        assert!(record_kinds.contains(&"projection.delta"));
        let snapshot_index = record_kinds
            .iter()
            .position(|kind| *kind == "projection.snapshot")
            .expect("snapshot frame");
        let delta_index = record_kinds
            .iter()
            .position(|kind| *kind == "projection.delta")
            .expect("delta frame");
        assert!(snapshot_index < delta_index);
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame.kind, SwarmFrameKind::ProjectionDelta))
        );
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame.kind, SwarmFrameKind::ProjectionSnapshot))
        );
        for frame in frames {
            validate_swarm_frame(&frame, now).expect("valid response frame");
        }
    }

    #[test]
    fn offer_admission_frames_emit_before_answer_materialization() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let request = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );

        let response = response(&cfg);
        let offer = &response
            .stream_session
            .as_ref()
            .expect("stream session")
            .offer;
        let frames =
            build_offer_admission_frames(&cfg, &request, offer, now, None).expect("frames");
        let record_kinds = frames
            .iter()
            .filter_map(|frame| frame.record_ref.as_ref().map(|record| record.kind.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            record_kinds,
            vec![
                RECORD_ROUTE_PROMISE,
                RECORD_STREAM_ROUTE_PLAN,
                "stream.session.admission",
                RECORD_CONTRIBUTION_LIFECYCLE,
                RECORD_CONTRIBUTION_LIFECYCLE,
            ]
        );
        assert!(!record_kinds.contains(&"stream.session.answer"));
        for frame in frames {
            validate_swarm_frame(&frame, now).expect("valid admission frame");
        }
    }

    #[test]
    fn member_read_observation_uses_shared_route_contract() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let request = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );

        let frame = build_member_read_observation_frame(&cfg, &request, now).expect("frame");

        assert!(matches!(frame.kind, SwarmFrameKind::RouteObservation));
        assert_eq!(
            frame.record_ref.as_ref().map(|record| record.kind.as_str()),
            Some(RECORD_ROUTE_OBSERVATION)
        );
        assert_eq!(
            frame.correlation_id.as_deref(),
            Some(request.frame_id.as_str())
        );
        validate_swarm_frame(&frame, now).expect("valid member-read observation frame");
    }

    #[test]
    fn gateway_frame_admission_ignores_non_executable_route_records() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let mut frame = request_frame(
            &cfg,
            SwarmFrameKind::RouteObservation,
            RECORD_ROUTE_OBSERVATION,
            now,
        );
        frame.zone_scope = None;
        frame.capability = Some("route.observation.publish".to_string());

        assert_eq!(
            gateway_frame_admission(&cfg, &frame),
            GatewayFrameAdmission::Ignore
        );
    }

    #[test]
    fn gateway_frame_admission_rejects_targeted_stream_without_zone_scope() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let mut frame = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );
        frame.zone_scope = None;

        let admission = gateway_frame_admission(&cfg, &frame);
        assert!(matches!(
            admission,
            GatewayFrameAdmission::Reject { ref detail } if detail.contains("missing route zone scope")
        ));

        let reject = build_reject_response_frame(
            &cfg,
            &frame,
            now,
            "nvr_edge_invalid_frame",
            "stream frame missing route zone scope",
        )
        .expect("reject frame");
        validate_swarm_frame(&reject, now).expect("valid reject frame with fallback service scope");
    }

    #[test]
    fn transport_observation_frame_uses_shared_media_contract() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let event = PreviewTransportObservationEvent {
            path_id: "nvr-preview-nonce-1:path:browserWebRtc".to_string(),
            session_id: "nvr-preview-nonce-1".to_string(),
            activation_id: "activation-1".to_string(),
            route_promise_id: "route-promise-nvr-preview-nonce-1".to_string(),
            requester_ref: cfg.gateway.host_gateway_pk.clone(),
            participant_ref: format!("service:{}", cfg.nostr_pubkey),
            participant_role: "service".to_string(),
            state: "disconnected".to_string(),
            connection_state: "disconnected".to_string(),
            ice_connection_state: None,
            selected_pair_state: Some("selected".to_string()),
            inbound_rtp_state: None,
            render_state: None,
            blocked_reason: Some("peerConnectionDisconnected".to_string()),
            reason: Some("peerConnectionDisconnected".to_string()),
            source_ids: vec!["cam-1".to_string()],
            grace_ms: Some(12_000),
            observed_at: now,
            expires_at: Some(now + RESPONSE_TTL_MS),
        };

        let frame =
            build_transport_observation_frame(&cfg, &event, now).expect("observation frame");

        validate_swarm_frame(&frame, now).expect("valid observation frame");
        assert!(matches!(frame.kind, SwarmFrameKind::StreamStatus));
        assert_eq!(
            frame.record_ref.as_ref().map(|record| record.kind.as_str()),
            Some(RECORD_MEDIA_TRANSPORT_OBSERVATION)
        );
        assert_eq!(frame.correlation_id.as_deref(), Some("nvr-preview-nonce-1"));
        assert_eq!(
            frame.capability.as_deref(),
            Some(CAPABILITY_MEDIA_STREAM_PREVIEW)
        );
    }

    #[test]
    fn transport_observation_frame_survives_parent_path_expiry() {
        let cfg = config();
        let now = 1_700_000_121_000;
        let event = PreviewTransportObservationEvent {
            path_id: "nvr-preview-nonce-1:path:browserWebRtc".to_string(),
            session_id: "nvr-preview-nonce-1".to_string(),
            activation_id: "activation-1".to_string(),
            route_promise_id: "route-promise-nvr-preview-nonce-1".to_string(),
            requester_ref: cfg.gateway.host_gateway_pk.clone(),
            participant_ref: format!("service:{}", cfg.nostr_pubkey),
            participant_role: "service".to_string(),
            state: "failed".to_string(),
            connection_state: "failed".to_string(),
            ice_connection_state: None,
            selected_pair_state: Some("failed".to_string()),
            inbound_rtp_state: None,
            render_state: None,
            blocked_reason: Some("peerConnectionFailed".to_string()),
            reason: Some("peerConnectionFailed".to_string()),
            source_ids: vec!["cam-1".to_string()],
            grace_ms: None,
            observed_at: now,
            expires_at: Some(now - 1),
        };

        let frame =
            build_transport_observation_frame(&cfg, &event, now).expect("post-expiry observation");

        validate_swarm_frame(&frame, now).expect("valid observation frame");
        assert_eq!(frame.correlation_id.as_deref(), Some("nvr-preview-nonce-1"));
    }

    #[test]
    fn offer_response_targets_runtime_return_zone_scope() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let request = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );
        let runtime_zone = ZoneScope {
            zone_id: "runtime-return-zone".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(30),
            max_hops: Some(2),
        };

        let response = response(&cfg);
        let projection_value = offer_projection_value(&response).expect("projection value");
        let frames = build_offer_response_frames(
            &cfg,
            &request,
            &response,
            now,
            &baseline(0),
            projection_value,
            Some(runtime_zone.clone()),
        )
        .expect("frames");

        assert!(!frames.is_empty());
        for frame in frames {
            assert_eq!(frame.zone_scope.as_ref(), Some(&runtime_zone));
            validate_swarm_frame(&frame, now).expect("valid response frame");
        }
    }

    #[test]
    fn control_and_close_emit_stream_status_and_projection_delta_frames() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let control_request = request_frame(
            &cfg,
            SwarmFrameKind::StreamControl,
            "stream.session.control",
            now,
        );
        let close_request = request_frame(
            &cfg,
            SwarmFrameKind::StreamControl,
            "stream.session.close",
            now,
        );
        let control = StreamSessionControl {
            control_id: "control-nvr-preview-nonce-1".to_string(),
            session_id: "nvr-preview-nonce-1".to_string(),
            command: "ptz".to_string(),
            params: json!({ "sourceId": "cam-1", "ptz": { "pan": 0.1 } }),
            issued_at: now,
        };
        let close = StreamSessionClose {
            close_id: "close-nvr-preview-nonce-1".to_string(),
            session_id: "nvr-preview-nonce-1".to_string(),
            reason_code: "closed".to_string(),
            issued_at: now,
        };

        let control_frames = build_control_response_frames(
            &cfg,
            &control_request,
            &control,
            json!({ "ok": true }),
            now,
            &baseline(0),
            control_projection_value(&control, &cfg.camera_devices[0]),
            None,
        )
        .expect("control frames");
        let close_frames = build_close_response_frames(
            &cfg,
            &close_request,
            &close,
            json!({ "ok": true }),
            now,
            &baseline(1),
            close_projection_value(&close),
            None,
        )
        .expect("close frames");

        assert!(control_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "stream.session.control")
        }));
        assert!(close_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "stream.session.close")
        }));
        assert!(control_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "projection.snapshot")
        }));
        assert!(control_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "projection.delta")
        }));
        assert!(close_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "projection.snapshot")
        }));
        assert!(close_frames.iter().any(|frame| {
            frame
                .record_ref
                .as_ref()
                .is_some_and(|record| record.kind == "projection.delta")
        }));
    }

    #[test]
    fn candidate_frames_are_routed_separately_from_control_frames() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let candidate = request_frame(
            &cfg,
            SwarmFrameKind::StreamControl,
            "stream.session.candidate",
            now,
        );
        let control = request_frame(
            &cfg,
            SwarmFrameKind::StreamControl,
            "stream.session.control",
            now,
        );

        assert!(is_stream_candidate_frame(&candidate));
        assert!(!is_stream_control_frame(&candidate));
        assert!(is_stream_control_frame(&control));
        assert!(!is_stream_candidate_frame(&control));
    }

    #[test]
    fn candidate_response_emits_candidate_health_and_projection_delta_frames() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let request = request_frame(
            &cfg,
            SwarmFrameKind::StreamControl,
            "stream.session.candidate",
            now,
        );

        let result = json!({
            "ok": true,
            "sessionId": "nvr-preview-nonce-1",
            "endpoint": {
                "protocol": "udp",
                "address": "192.0.2.10",
                "port": 5000,
                "candidateType": "host"
            }
        });
        let (_, projection_value) = candidate_projection_value(&result).expect("projection value");
        let frames = build_candidate_response_frames(
            &cfg,
            &request,
            result,
            now,
            &baseline(0),
            projection_value,
            None,
        )
        .expect("candidate frames");
        let record_kinds = frames
            .iter()
            .filter_map(|frame| frame.record_ref.as_ref().map(|record| record.kind.as_str()))
            .collect::<Vec<_>>();

        assert!(record_kinds.contains(&"stream.session.candidate"));
        assert!(record_kinds.contains(&"stream.session.health"));
        assert!(record_kinds.contains(&"projection.snapshot"));
        assert!(record_kinds.contains(&"projection.delta"));
        for frame in frames {
            validate_swarm_frame(&frame, now).expect("valid candidate response frame");
        }
    }

    #[test]
    fn stream_projection_delta_coverage_is_materializable_by_runtime() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let delta = stream_projection_delta(
            &cfg,
            "nvr-preview-nonce-1",
            "accepted",
            json!({ "status": "accepted" }),
            now,
            0,
        )
        .expect("projection delta");

        assert_eq!(delta.coverage["materializedCount"], json!(1));
        assert_eq!(delta.coverage["targetCount"], json!(1));
        assert_eq!(delta.coverage["completionRatio"], json!(1.0));
        assert_eq!(delta.coverage["syncState"], json!("completeEnough"));
    }

    #[test]
    fn non_targeted_frames_are_ignored() {
        let mut cfg = config();
        let (other_pk, _) = constitute_protocol::generate_keypair();
        let now = 1_700_000_001_000;
        let mut frame = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );
        frame.audience = json!({ "servicePk": other_pk });
        frame.frame_id = String::new();
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");

        assert!(!frame_targets_nvr(&cfg, &frame));
        cfg.nostr_pubkey = other_pk;
        assert!(frame_targets_nvr(&cfg, &frame));
    }

    #[test]
    fn stream_frame_headers_require_route_channel_and_capability() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let frame = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );
        assert_eq!(
            classify_stream_frame(&cfg, &frame).expect("classified"),
            Some(StreamFrameAction::Offer)
        );

        let mut missing_channel = frame.clone();
        missing_channel.channel_id = None;
        let err = classify_stream_frame(&cfg, &missing_channel).expect_err("missing channel");
        assert!(err.to_string().contains("channel"));

        let mut missing_capability = frame;
        missing_capability.capability = None;
        let err = classify_stream_frame(&cfg, &missing_capability).expect_err("missing capability");
        assert!(err.to_string().contains("capability"));
    }

    #[tokio::test]
    async fn targeted_invalid_stream_frame_returns_reject_without_dropping_edge_session() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let preview = PreviewManager::new(&cfg).expect("preview");
        let edge = SwarmEdge::new(
            std::sync::Arc::new(tokio::sync::Mutex::new(cfg.clone())),
            preview,
        );
        let frame = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );

        let responses = edge
            .handle_frame(frame.clone())
            .await
            .expect("invalid targeted frame is materialized as reject");

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].kind, SwarmFrameKind::Reject);
        assert_eq!(
            responses[0]
                .ack
                .as_ref()
                .and_then(|ack| ack.reason_code.as_deref()),
            Some("nvr_frame_rejected")
        );
        assert_eq!(
            responses[0].correlation_id.as_deref(),
            Some(frame.frame_id.as_str())
        );
        validate_swarm_frame(&responses[0], util::now_ms()).expect("valid reject frame");
    }

    #[test]
    fn opened_claims_require_route_promise_reference() {
        assert!(ensure_opened_route_promise(&json!({})).is_err());
        ensure_opened_route_promise(&json!({
            "routePromiseId": "route-promise-1"
        }))
        .expect("route promise id");
        ensure_opened_route_promise(&json!({
            "routePromise": { "promiseId": "route-promise-1" }
        }))
        .expect("route promise object");
    }

    #[test]
    fn claims_accept_embedded_authority() {
        let cfg = config();
        let claims = json!({
            "authority": authority_claims(&cfg, "nonce-claims"),
            "payload": {
                "description": { "type": "offer", "sdp": "v=0\r\n" }
            }
        });

        let request = managed_offer_from_claims(&cfg, &claims).expect("managed offer");
        assert_eq!(request.authority.nonce, "nonce-claims");
        assert_eq!(request.offer["description"]["type"], json!("offer"));
    }

    #[tokio::test]
    async fn opens_runtime_issued_caac_and_rejects_issuer_mismatch() {
        let cfg = config();
        let now = crate::util::now_ms();
        let preview = PreviewManager::new(&cfg).expect("preview");
        let edge = SwarmEdge::new(
            std::sync::Arc::new(tokio::sync::Mutex::new(cfg.clone())),
            preview,
        );
        let (device_pk, device_sk) = constitute_protocol::generate_keypair();
        let mut authority = authority_claims(&cfg, "runtime-issued");
        authority.device_pk = device_pk.clone();
        let claims = json!({
            "signalType": "offer",
            "authority": authority,
            "offer": {
                "description": { "type": "offer", "sdp": "v=0\r\n" },
                "sourceIds": ["cam-1"]
            }
        });
        let envelope = seal_envelope(
            "stream.session.offer",
            &claims,
            &device_sk,
            &[cfg.nostr_pubkey.clone()],
            now,
            now + 60_000,
        )
        .expect("seal");
        let mut frame = request_frame(
            &cfg,
            SwarmFrameKind::StreamIntent,
            "stream.session.offer",
            now,
        );
        frame.issuer = device_pk.clone();
        frame.body.envelope = Some(serde_json::to_value(envelope).expect("envelope"));
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");

        let opened = edge
            .open_frame_claims(&cfg, &frame)
            .await
            .expect("runtime issuer opens");
        assert_eq!(opened["authority"]["devicePk"], json!(device_pk));

        let (other_pk, other_sk) = constitute_protocol::generate_keypair();
        let envelope = seal_envelope(
            "stream.session.offer",
            &claims,
            &other_sk,
            &[cfg.nostr_pubkey.clone()],
            now,
            now + 60_000,
        )
        .expect("seal mismatch");
        frame.issuer = other_pk;
        frame.body.envelope = Some(serde_json::to_value(envelope).expect("envelope"));
        frame.nonce = "nonce-runtime-issued-mismatch".to_string();
        frame.frame_id = swarm_frame_id(&frame).expect("frame id");
        let err = edge
            .open_frame_claims(&cfg, &frame)
            .await
            .expect_err("issuer mismatch rejected");
        assert!(err.to_string().contains("issuer"));
    }
}
