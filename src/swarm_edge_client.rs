//! Gateway swarm-edge client for route-promised NVR stream control records.
//!
//! The stream carries only `swarm.edge.*` control records and generic
//! `SwarmFrame` records. Nostr remains a bootstrap/fallback carrier elsewhere.

use crate::config::Config;
use crate::swarm_edge::{GatewayFrameAdmission, SwarmEdge};
use crate::util;
use anyhow::{Context, Result, anyhow};
use constitute_fabric::{HostFabricMemberContributionSpec, build_host_fabric_member_contribution};
use constitute_protocol::{
    CAPABILITY_MEDIA_STREAM_PREVIEW, CAPABILITY_PROJECTION_DELTA_APPLY,
    CAPABILITY_PROJECTION_OBSERVE, CAPABILITY_STORAGE_PIN, CAPABILITY_STREAM_SESSION_CONTROL,
    CAPABILITY_STREAM_SESSION_OFFER, CAPABILITY_SWARM_EDGE_ATTACH, CARRIER_EDGE_ADAPTER_WEB_SOCKET,
    CARRIER_EDGE_BACKPRESSURE_CLEAR, CARRIER_EDGE_SESSION_OPEN, CarrierEdgeSessionEvidence,
    FABRIC_MEMBER_CONTRIBUTION_RUNNING, FABRIC_MEMBER_ROLE_DOMAIN_SERVICE,
    HostFabricMemberContribution, RECORD_CARRIER_EDGE_SESSION_EVIDENCE, SWARM_EDGE_WIRE_ACCEPT,
    SWARM_EDGE_WIRE_HELLO, SWARM_EDGE_WIRE_RESUME, SWARM_FRAME_VERSION, SWARM_WIRE_FRAME,
    SwarmEdgeAccept, SwarmEdgeHello, SwarmEdgeResume, SwarmFrame, SwarmFrameBody, ZoneScope,
    seal_envelope, validate_carrier_edge_session_evidence,
    validate_host_fabric_member_contribution, validate_swarm_edge_hello,
    validate_swarm_edge_resume,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::{Duration, Instant, sleep, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};
use uuid::Uuid;

const EDGE_RECONNECT_DELAY_SECS: u64 = 5;
const EDGE_FRAME_WORK_QUEUE: usize = 256;
const EDGE_RESPONSE_QUEUE: usize = 256;
const EDGE_WRITE_TIMEOUT_MS: u64 = 5_000;
const EDGE_FRAME_WORK_TIMEOUT_MS: u64 = 20_000;
const HELLO_TTL_MS: u64 = 90_000;
const EDGE_SESSION_RENEW_MS: u64 = 60_000;
const EDGE_SESSION_MAX_AGE_MS: u64 = 20 * 60 * 1000;
const STREAM_CHANNEL_ID: &str = "nvr.streams";
const SURFACE_CHANNEL_ID: &str = "nvr.surface";

#[derive(Clone)]
pub struct EdgeStreamHandle;

enum EdgeOutbound {
    Frame(SwarmFrame),
    Resume(SwarmEdgeResume),
}

impl EdgeOutbound {
    fn label(&self) -> String {
        match self {
            Self::Frame(frame) => frame.frame_id.clone(),
            Self::Resume(resume) => format!("resume:{}", resume.session_id),
        }
    }

    fn wire(&self) -> Value {
        match self {
            Self::Frame(frame) => edge_frame_wire(frame),
            Self::Resume(resume) => edge_resume_wire(resume),
        }
    }
}

pub fn start(cfg: Arc<Mutex<Config>>, edge: SwarmEdge) -> EdgeStreamHandle {
    tokio::spawn(async move {
        loop {
            let snapshot = cfg.lock().await.clone();
            let endpoint = snapshot.gateway.edge_stream_endpoint.trim().to_string();
            if endpoint.is_empty() {
                warn!("gateway edge stream endpoint empty; outbound swarm edge disabled");
                return;
            }

            match run_connection(endpoint.clone(), snapshot, edge.clone()).await {
                Ok(()) => info!(endpoint = %endpoint, "gateway edge stream closed"),
                Err(err) => warn!(endpoint = %endpoint, error = %err, "gateway edge stream failed"),
            }
            sleep(Duration::from_secs(EDGE_RECONNECT_DELAY_SECS)).await;
        }
    });
    EdgeStreamHandle
}

async fn run_connection(endpoint: String, cfg: Config, edge: SwarmEdge) -> Result<()> {
    let (ws, _) = connect_async(&endpoint)
        .await
        .with_context(|| format!("connect gateway edge stream: {endpoint}"))?;
    let (mut write, mut read) = ws.split();
    let hello = build_edge_hello(&cfg, util::now_ms())?;
    write
        .send(Message::Text(edge_hello_wire(&hello).to_string().into()))
        .await
        .context("send swarm edge hello")?;
    info!(endpoint = %endpoint, member_ref = %hello.member_ref, "nvr attached to gateway edge stream");
    let mut transport_events = edge.subscribe_transport_observations();
    let session_renew = sleep(Duration::from_millis(EDGE_SESSION_RENEW_MS));
    let session_max_age = sleep(Duration::from_millis(EDGE_SESSION_MAX_AGE_MS));
    tokio::pin!(session_renew);
    tokio::pin!(session_max_age);
    let mut accepted_session: Option<SwarmEdgeAccept> = None;
    let (frame_tx, mut frame_rx) = mpsc::channel::<SwarmFrame>(EDGE_FRAME_WORK_QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<EdgeOutbound>(EDGE_RESPONSE_QUEUE);
    let worker_edge = edge.clone();
    let worker_out = out_tx.clone();
    let (writer_done_tx, mut writer_done_rx) = oneshot::channel::<()>();
    let frame_worker = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let frame_id = frame.frame_id.clone();
            match worker_edge.service_admission_frames(&frame).await {
                Ok(frames) => {
                    for response in frames {
                        if worker_out
                            .send(EdgeOutbound::Frame(response))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        frame_id = %frame_id,
                        error = %err,
                        "nvr edge worker failed service admission preflight"
                    );
                    match worker_edge
                        .reject_frame(&frame, "nvr_edge_admission_failed", &err.to_string())
                        .await
                    {
                        Ok(response) => {
                            let _ = worker_out.send(EdgeOutbound::Frame(response)).await;
                        }
                        Err(reject_err) => {
                            warn!(
                                frame_id = %frame_id,
                                error = %reject_err,
                                "failed to build nvr edge admission reject"
                            );
                        }
                    }
                    continue;
                }
            }

            match timeout(
                Duration::from_millis(EDGE_FRAME_WORK_TIMEOUT_MS),
                worker_edge.handle_frame(frame.clone()),
            )
            .await
            {
                Ok(Ok(responses)) => {
                    for response in responses {
                        if worker_out
                            .send(EdgeOutbound::Frame(response))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        frame_id = %frame_id,
                        error = %err,
                        "nvr edge worker failed to handle gateway frame"
                    );
                }
                Err(_) => {
                    warn!(
                        frame_id = %frame_id,
                        timeout_ms = EDGE_FRAME_WORK_TIMEOUT_MS,
                        "nvr edge worker timed out before service answer"
                    );
                    match worker_edge
                        .reject_frame(
                            &frame,
                            "nvr_edge_answer_timeout",
                            "nvr edge worker timed out before service answer",
                        )
                        .await
                    {
                        Ok(response) => {
                            let _ = worker_out.send(EdgeOutbound::Frame(response)).await;
                        }
                        Err(err) => {
                            warn!(
                                frame_id = %frame_id,
                                error = %err,
                                "failed to build nvr edge timeout reject"
                            );
                        }
                    }
                }
            }
        }
    });
    let frame_writer = tokio::spawn(async move {
        while let Some(outbound) = out_rx.recv().await {
            let label = outbound.label();
            let text = outbound.wire().to_string();
            match timeout(
                Duration::from_millis(EDGE_WRITE_TIMEOUT_MS),
                write.send(Message::Text(text.into())),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!(
                        label = %label,
                        error = %err,
                        "failed to send nvr edge outbound record"
                    );
                    break;
                }
                Err(_) => {
                    warn!(
                        label = %label,
                        timeout_ms = EDGE_WRITE_TIMEOUT_MS,
                        "timed out sending nvr edge outbound record"
                    );
                    break;
                }
            }
        }
        let _ = writer_done_tx.send(());
    });

    loop {
        tokio::select! {
            _ = &mut session_max_age => {
                info!(
                    endpoint = %endpoint,
                    max_age_ms = EDGE_SESSION_MAX_AGE_MS,
                    "recycling nvr gateway edge session before read-witness lease can become stale"
                );
                break;
            }
            _ = &mut session_renew => {
                if let Some(accept) = accepted_session.as_ref() {
                    match build_edge_resume(&cfg, accept, util::now_ms()) {
                        Ok(resume) => {
                            if let Err(err) = out_tx.try_send(EdgeOutbound::Resume(resume)) {
                                warn!(
                                    error = %err,
                                    "nvr edge response queue saturated while sending session renewal"
                                );
                                break;
                            }
                            info!(
                                endpoint = %endpoint,
                                renew_ms = EDGE_SESSION_RENEW_MS,
                                "renewed nvr gateway edge session before attach lease expiry"
                            );
                        }
                        Err(err) => {
                            warn!(error = %err, "failed to build nvr gateway edge session renewal");
                            break;
                        }
                    }
                } else {
                    warn!("nvr gateway edge session renewal skipped before accept");
                    break;
                }
                session_renew
                    .as_mut()
                    .reset(Instant::now() + Duration::from_millis(EDGE_SESSION_RENEW_MS));
            }
            _ = &mut writer_done_rx => {
                break;
            }
            message = read.next() => {
                let Some(message) = message else {
                    break;
                };
                let message = message.context("read gateway edge stream")?;
                let Message::Text(text) = message else {
                    if matches!(message, Message::Close(_)) {
                        break;
                    }
                    continue;
                };
                match parse_edge_wire_text(&text) {
                    Ok(EdgeWireRecord::Accept(accept)) => {
                        let evidence =
                            nvr_carrier_edge_session_evidence(&accept, util::now_ms())?;
                        debug!(
                            session_id = %accept.session_id,
                            adapter_ref = %evidence.adapter_ref,
                            carrier_state = %evidence.state,
                            "gateway accepted nvr carrier edge session"
                        );
                        accepted_session = Some(accept);
                    }
                    Ok(EdgeWireRecord::Frame(frame)) => {
                        let frame_id = frame.frame_id.clone();
                        match edge.gateway_frame_admission(&frame).await {
                            GatewayFrameAdmission::Ignore => {
                                debug!(
                                    frame_id = %frame_id,
                                    "ignored non-executable nvr edge frame before service work queue"
                                );
                            }
                            GatewayFrameAdmission::Reject { detail } => {
                                warn!(
                                    frame_id = %frame_id,
                                    detail = %detail,
                                    "rejected invalid nvr edge frame before service admission"
                                );
                                match edge
                                    .reject_frame(&frame, "nvr_edge_invalid_frame", &detail)
                                    .await
                                {
                                    Ok(reject_frame) => {
                                        if let Err(err) =
                                            out_tx.try_send(EdgeOutbound::Frame(reject_frame))
                                        {
                                            warn!(
                                                frame_id = %frame_id,
                                                error = %err,
                                                "nvr edge response queue saturated while sending invalid-frame reject"
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            frame_id = %frame_id,
                                            error = %err,
                                            "failed to build nvr edge invalid-frame reject"
                                        );
                                    }
                                }
                            }
                            GatewayFrameAdmission::Admit => {
                                match edge.member_read_observation_frame(&frame).await {
                                    Ok(observation_frame) => {
                                        if let Err(err) =
                                            out_tx.try_send(EdgeOutbound::Frame(observation_frame))
                                        {
                                            warn!(
                                                frame_id = %frame_id,
                                                error = %err,
                                                "nvr edge response queue saturated while sending member-read observation"
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            frame_id = %frame_id,
                                            error = %err,
                                            "failed to build nvr edge member-read observation"
                                        );
                                    }
                                }
                                match frame_tx.try_send(frame) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(frame))
                                    | Err(mpsc::error::TrySendError::Closed(frame)) => {
                                warn!(
                                    frame_id = %frame_id,
                                    "nvr edge frame work queue saturated; rejecting gateway frame before service admission"
                                );
                                        match edge
                                            .reject_frame(
                                                &frame,
                                                "nvr_edge_overloaded",
                                                "nvr edge work queue saturated before service admission",
                                            )
                                            .await
                                        {
                                            Ok(reject_frame) => {
                                                if let Err(err) =
                                                    out_tx.try_send(EdgeOutbound::Frame(reject_frame))
                                                {
                                                    warn!(
                                                        frame_id = %frame_id,
                                                        error = %err,
                                                        "nvr edge response queue saturated while sending overload reject"
                                                    );
                                                }
                                            }
                                            Err(err) => {
                                                warn!(
                                                    frame_id = %frame_id,
                                                    error = %err,
                                                    "failed to build nvr edge overload reject"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(EdgeWireRecord::Reject(value)) => {
                        warn!(reject = %value, "gateway rejected nvr edge record");
                    }
                    Err(err) => {
                        warn!(error = %err, "ignored unsupported gateway edge message");
                    }
                }
            }
            event = transport_events.recv() => {
                match event {
                    Ok(event) => {
                        let frames = edge
                            .transport_observation_frames(event)
                            .await
                            .context("build media transport observation frame")?;
                        for frame in frames {
                            let frame_id = frame.frame_id.clone();
                            if let Err(err) = out_tx.try_send(EdgeOutbound::Frame(frame)) {
                                warn!(
                                    frame_id = %frame_id,
                                    error = %err,
                                    "nvr media transport observation queue saturated"
                                );
                            }
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(skipped, "media transport observation stream lagged");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }

    drop(frame_tx);
    drop(out_tx);
    frame_worker.abort();
    frame_writer.abort();
    Ok(())
}

fn build_edge_hello(cfg: &Config, now: u64) -> Result<SwarmEdgeHello> {
    let zone_scope = first_zone_scope(cfg);
    let member_ref = service_member_ref(cfg);
    let service_ref = service_ref(cfg);
    let capability_refs = nvr_edge_capabilities()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let channel_refs = vec![
        STREAM_CHANNEL_ID.to_string(),
        SURFACE_CHANNEL_ID.to_string(),
    ];
    let fabric_contribution = nvr_host_fabric_contribution(cfg, &member_ref, &service_ref, now)?;
    let fabric_contribution_ref = fabric_contribution.contribution_id.clone();
    validate_host_fabric_member_contribution(&fabric_contribution)?;
    let promise_refs = vec![
        service_ref.clone(),
        cfg.nostr_pubkey.trim().to_string(),
        fabric_contribution_ref.clone(),
    ];
    let recipients = if cfg.gateway.host_gateway_pk.trim().is_empty() {
        Vec::new()
    } else {
        vec![cfg.gateway.host_gateway_pk.trim().to_string()]
    };
    let claims = json!({
        "memberKind": "service",
        "memberRef": member_ref,
        "serviceRef": service_ref,
        "service": "nvr",
        "servicePk": cfg.nostr_pubkey.trim(),
        "identityId": cfg.api.identity_id.trim(),
        "hostFabricMemberContributionRef": fabric_contribution_ref,
        "hostFabricMemberContribution": fabric_contribution,
        "capabilityRefs": capability_refs,
        "channelRefs": channel_refs,
        "promiseRefs": promise_refs,
    });
    let envelope = seal_envelope(
        SWARM_EDGE_WIRE_HELLO,
        &claims,
        &cfg.nostr_sk_hex,
        &recipients,
        now,
        now.saturating_add(HELLO_TTL_MS),
    )?;
    let hello = SwarmEdgeHello {
        member_kind: "service".to_string(),
        member_ref,
        zone_scope,
        supported_versions: vec![SWARM_FRAME_VERSION as u32],
        last_acked_frame_id: None,
        last_projection_revisions: json!({}),
        capability_refs,
        channel_refs,
        promise_refs,
        nonce: format!("nvr-edge-{}", Uuid::new_v4().simple()),
        issued_at: now,
        expires_at: Some(now.saturating_add(HELLO_TTL_MS)),
        sealed_claims: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope)?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
    };
    validate_swarm_edge_hello(&hello)?;
    Ok(hello)
}

fn nvr_host_fabric_contribution(
    cfg: &Config,
    member_ref: &str,
    service_ref: &str,
    now: u64,
) -> Result<HostFabricMemberContribution> {
    let host_ref = if cfg.gateway.host_gateway_pk.trim().is_empty() {
        format!("discovery:{}", first_zone_scope(cfg).zone_id)
    } else {
        format!("gateway:{}", cfg.gateway.host_gateway_pk.trim())
    };
    let fabric_ref = format!("host-fabric:{host_ref}");
    let contribution = build_host_fabric_member_contribution(HostFabricMemberContributionSpec {
        contribution_id: format!("hostFabric:nvr:{}", cfg.nostr_pubkey.trim()),
        fabric_ref,
        host_ref,
        member_ref: member_ref.to_string(),
        participant_ref: member_ref.to_string(),
        role: FABRIC_MEMBER_ROLE_DOMAIN_SERVICE.to_string(),
        role_ref: format!("role:{FABRIC_MEMBER_ROLE_DOMAIN_SERVICE}"),
        state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
        contract_ref: service_ref.to_string(),
        subject_ref: service_ref.to_string(),
        module_refs: vec![
            "module:nvr-edge-client".to_string(),
            "module:nvr-service".to_string(),
            service_ref.to_string(),
        ],
        source_refs: vec![format!("source:nvr:{}", cfg.nostr_pubkey.trim())],
        capability_refs: nvr_edge_capabilities()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        grant_refs: Vec::new(),
        input_refs: vec![
            STREAM_CHANNEL_ID.to_string(),
            SURFACE_CHANNEL_ID.to_string(),
        ],
        output_refs: vec![
            "projection:nvr.streams".to_string(),
            "projection:nvr.surface".to_string(),
            service_ref.to_string(),
        ],
        evidence_refs: vec![format!("swarm.edge.hello:nvr:{now}")],
        lifecycle_plan_refs: Vec::new(),
        release_refs: Vec::new(),
        resource_posture: None,
        blocked_reasons: Vec::new(),
        safe_facts: json!({
            "service": "nvr",
            "role": FABRIC_MEMBER_ROLE_DOMAIN_SERVICE,
            "streamChannel": STREAM_CHANNEL_ID,
            "surfaceChannel": SURFACE_CHANNEL_ID,
        }),
        observed_at: now,
        expires_at: Some(now.saturating_add(HELLO_TTL_MS)),
    })?;
    validate_host_fabric_member_contribution(&contribution)?;
    Ok(contribution)
}

fn build_edge_resume(cfg: &Config, accept: &SwarmEdgeAccept, now: u64) -> Result<SwarmEdgeResume> {
    let recipients = if cfg.gateway.host_gateway_pk.trim().is_empty() {
        Vec::new()
    } else {
        vec![cfg.gateway.host_gateway_pk.trim().to_string()]
    };
    let claims = json!({
        "sessionId": accept.session_id.clone(),
        "memberKind": accept.member_kind.clone(),
        "memberRef": accept.member_ref.clone(),
        "capabilityRefs": accept.capability_refs.clone(),
        "channelRefs": accept.channel_refs.clone(),
        "promiseRefs": accept.promise_refs.clone(),
    });
    let envelope = seal_envelope(
        SWARM_EDGE_WIRE_RESUME,
        &claims,
        &cfg.nostr_sk_hex,
        &recipients,
        now,
        now.saturating_add(HELLO_TTL_MS),
    )?;
    let resume = SwarmEdgeResume {
        session_id: accept.session_id.clone(),
        member_kind: accept.member_kind.clone(),
        member_ref: accept.member_ref.clone(),
        zone_scope: accept.zone_scope.clone(),
        last_acked_frame_id: accept.last_acked_frame_id.clone(),
        last_projection_revisions: accept.last_projection_revisions.clone(),
        capability_refs: accept.capability_refs.clone(),
        channel_refs: accept.channel_refs.clone(),
        promise_refs: accept.promise_refs.clone(),
        nonce: format!("nvr-edge-resume-{}", Uuid::new_v4().simple()),
        issued_at: now,
        expires_at: Some(now.saturating_add(HELLO_TTL_MS)),
        sealed_claims: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope)?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
    };
    validate_swarm_edge_resume(&resume)?;
    Ok(resume)
}

fn first_zone_scope(cfg: &Config) -> ZoneScope {
    let zone_id = cfg
        .swarm
        .zones
        .first()
        .map(|zone| zone.key.trim())
        .filter(|zone| !zone.is_empty())
        .unwrap_or("default");
    ZoneScope {
        zone_id: zone_id.to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    }
}

fn nvr_edge_capabilities() -> Vec<&'static str> {
    vec![
        CAPABILITY_SWARM_EDGE_ATTACH,
        CAPABILITY_MEDIA_STREAM_PREVIEW,
        CAPABILITY_STREAM_SESSION_OFFER,
        CAPABILITY_STREAM_SESSION_CONTROL,
        CAPABILITY_PROJECTION_OBSERVE,
        CAPABILITY_PROJECTION_DELTA_APPLY,
        CAPABILITY_STORAGE_PIN,
    ]
}

fn service_member_ref(cfg: &Config) -> String {
    cfg.nostr_pubkey.trim().to_string()
}

fn service_ref(cfg: &Config) -> String {
    let service_pk = cfg.nostr_pubkey.trim();
    if service_pk.is_empty() {
        "service:nvr".to_string()
    } else {
        format!("service:{service_pk}")
    }
}

fn nvr_carrier_edge_session_evidence(
    accept: &SwarmEdgeAccept,
    now: u64,
) -> Result<CarrierEdgeSessionEvidence> {
    let member_ref = accept.member_ref.trim();
    let session_id = accept.session_id.trim();
    let service_ref = accept
        .promise_refs
        .iter()
        .map(|reference| reference.trim())
        .find(|reference| reference.starts_with("service:"))
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("service:nvr:{member_ref}"));
    let record = CarrierEdgeSessionEvidence {
        kind: Some(RECORD_CARRIER_EDGE_SESSION_EVIDENCE.to_string()),
        evidence_id: format!(
            "carrier-edge-evidence:nvr:{}:{}",
            slug(&service_ref),
            slug(session_id)
        ),
        selection_ref: format!("carrier-select:{}:gateway-edge", slug(&service_ref)),
        edge_session_ref: format!("edge-session:{session_id}"),
        adapter_ref: "adapter:gateway-association:websocket".to_string(),
        adapter_kind: CARRIER_EDGE_ADAPTER_WEB_SOCKET.to_string(),
        participant_ref: service_ref.clone(),
        peer_ref: None,
        state: CARRIER_EDGE_SESSION_OPEN.to_string(),
        connection_state: Some("connected".to_string()),
        backpressure_state: Some(CARRIER_EDGE_BACKPRESSURE_CLEAR.to_string()),
        retry_posture: json!({ "state": "notRequired", "retryAfterMs": null }),
        release_posture: json!({ "state": "held", "expiresAt": accept.expires_at }),
        safe_facts: json!({
            "service": "nvr",
            "memberKind": accept.member_kind,
            "capabilityCount": accept.capability_refs.len(),
            "channelCount": accept.channel_refs.len(),
            "promiseCount": accept.promise_refs.len(),
            "source": "swarmEdgeAccept"
        }),
        evidence_refs: vec![format!("session:{session_id}"), service_ref],
        blocked_reasons: vec![],
        observed_at: now,
        expires_at: accept.expires_at,
    };
    validate_carrier_edge_session_evidence(&record)?;
    Ok(record)
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn edge_hello_wire(hello: &SwarmEdgeHello) -> Value {
    json!({
        "type": SWARM_EDGE_WIRE_HELLO,
        "hello": hello,
    })
}

fn edge_resume_wire(resume: &SwarmEdgeResume) -> Value {
    json!({
        "type": SWARM_EDGE_WIRE_RESUME,
        "resume": resume,
    })
}

fn edge_frame_wire(frame: &SwarmFrame) -> Value {
    json!({
        "type": SWARM_WIRE_FRAME,
        "frame": frame,
    })
}

#[derive(Debug)]
enum EdgeWireRecord {
    Accept(SwarmEdgeAccept),
    Frame(SwarmFrame),
    Reject(Value),
}

fn parse_edge_wire_text(text: &str) -> Result<EdgeWireRecord> {
    let value: Value = serde_json::from_str(text).context("invalid gateway edge json")?;
    let record_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    match record_type {
        SWARM_EDGE_WIRE_ACCEPT => {
            if let Some(accept) = value
                .get("accept")
                .cloned()
                .or_else(|| value.get("session").cloned())
            {
                Ok(EdgeWireRecord::Accept(serde_json::from_value(accept)?))
            } else {
                Ok(EdgeWireRecord::Reject(value))
            }
        }
        SWARM_WIRE_FRAME => {
            let frame = value
                .get("frame")
                .cloned()
                .ok_or_else(|| anyhow!("swarm.frame wire message missing frame"))?;
            Ok(EdgeWireRecord::Frame(serde_json::from_value(frame)?))
        }
        constitute_protocol::SWARM_EDGE_WIRE_REJECT => Ok(EdgeWireRecord::Reject(value)),
        other => Err(anyhow!(
            "gateway edge stream accepts swarm.edge.* control and swarm.frame records only, got {other}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitute_protocol::{
        SwarmFrameKind, SwarmRecordRef, swarm_frame_id, validate_swarm_frame,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static CONFIG_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-edge-stream-test-{}-{}-{}.json",
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
        cfg.gateway.edge_stream_endpoint = "ws://127.0.0.1:7448".to_string();
        cfg.swarm.zones[0].key = "zone-test".to_string();
        cfg
    }

    #[test]
    fn builds_valid_swarm_edge_hello_wire_record() {
        let cfg = config();
        let hello = build_edge_hello(&cfg, 1_700_000_001_000).expect("hello");
        let wire = edge_hello_wire(&hello);
        let rendered = serde_json::to_string(&wire).expect("wire json");

        validate_swarm_edge_hello(&hello).expect("valid hello");
        assert_eq!(
            wire["type"],
            json!(constitute_protocol::SWARM_EDGE_WIRE_HELLO)
        );
        assert_eq!(hello.member_kind, "service");
        assert_eq!(hello.member_ref, cfg.nostr_pubkey);
        assert!(
            hello
                .capability_refs
                .contains(&CAPABILITY_SWARM_EDGE_ATTACH.to_string())
        );
        assert!(
            hello
                .promise_refs
                .contains(&format!("hostFabric:nvr:{}", cfg.nostr_pubkey))
        );
        assert!(!rendered.contains(&format!("/sess{}", "ion")));
        assert!(!rendered.contains(&format!("/{}{}", "swarm", "/edge")));
    }

    #[test]
    fn parses_only_generic_gateway_edge_stream_records() {
        let cfg = config();
        let now = 1_700_000_001_000;
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::StreamIntent,
            issuer: cfg.gateway.host_gateway_pk.clone(),
            audience: json!({ "serviceRef": format!("service:{}", cfg.nostr_pubkey) }),
            zone_scope: Some(first_zone_scope(&cfg)),
            issued_at: now,
            expires_at: Some(now + 60_000),
            nonce: "offer-nonce-1".to_string(),
            correlation_id: None,
            channel_id: Some(STREAM_CHANNEL_ID.to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: constitute_protocol::RECORD_STREAM_SESSION_OFFER.to_string(),
                id: "offer-1".to_string(),
                revision: None,
            }),
            capability: Some(CAPABILITY_STREAM_SESSION_OFFER.to_string()),
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
        validate_swarm_frame(&frame, now).expect("valid frame");

        let wire = edge_frame_wire(&frame).to_string();
        match parse_edge_wire_text(&wire).expect("parsed") {
            EdgeWireRecord::Frame(parsed) => assert_eq!(parsed.frame_id, frame.frame_id),
            other => panic!("unexpected record: {other:?}"),
        }

        let hello = build_edge_hello(&cfg, now).expect("hello");
        let accept = SwarmEdgeAccept {
            session_id: "edge-session-1".to_string(),
            member_kind: hello.member_kind.clone(),
            member_ref: hello.member_ref.clone(),
            zone_scope: hello.zone_scope.clone(),
            accepted_version: SWARM_FRAME_VERSION as u32,
            last_acked_frame_id: None,
            last_projection_revisions: hello.last_projection_revisions.clone(),
            capability_refs: hello.capability_refs.clone(),
            channel_refs: hello.channel_refs.clone(),
            promise_refs: hello.promise_refs.clone(),
            nonce: "accept-nonce-1".to_string(),
            issued_at: now,
            expires_at: Some(now + 60_000),
            sealed_claims: hello.sealed_claims.clone(),
        };
        let evidence =
            nvr_carrier_edge_session_evidence(&accept, now + 1).expect("carrier evidence");
        validate_carrier_edge_session_evidence(&evidence).expect("valid carrier evidence");
        assert_eq!(
            evidence.adapter_ref,
            "adapter:gateway-association:websocket"
        );
        assert_eq!(evidence.state, CARRIER_EDGE_SESSION_OPEN);
        match parse_edge_wire_text(
            &json!({ "type": SWARM_EDGE_WIRE_ACCEPT, "session": accept }).to_string(),
        )
        .expect("parsed legacy session accept")
        {
            EdgeWireRecord::Accept(parsed) => assert_eq!(parsed.session_id, "edge-session-1"),
            other => panic!("unexpected record: {other:?}"),
        }

        let nostr_event_shape = json!({
            "kind": 1,
            "tags": [["type", "swarm_frame"]],
            "content": serde_json::to_string(&frame).expect("frame json"),
        });
        assert!(parse_edge_wire_text(&nostr_event_shape.to_string()).is_err());
    }
}
