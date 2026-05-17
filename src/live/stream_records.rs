//! Route-plan and stream-record adapters for managed NVR live preview.

use crate::config::Config;
use anyhow::{Result, anyhow};
use constitute_protocol::{
    CAPABILITY_MEDIA_STREAM_PREVIEW, ContributionLifecycle, MediaTransportPath,
    RECORD_CONTRIBUTION_LIFECYCLE, RECORD_MEDIA_TRANSPORT_PATH, RECORD_ROUTE_PROMISE,
    RECORD_STREAM_ROUTE_PLAN, ReachabilityState, RoutePromise,
    STREAM_CANDIDATE_ACTIONABILITY_BLOCKED, STREAM_CANDIDATE_ACTIONABILITY_USABLE,
    STREAM_CANDIDATE_ROLE_BROWSER, STREAM_CANDIDATE_ROLE_SERVICE, StreamPathKind, StreamPathState,
    StreamRoutePath, StreamRoutePlan, StreamSessionAdmission, StreamSessionAnswer,
    StreamSessionCandidate, StreamSessionClose, StreamSessionControl, StreamSessionIntent,
    StreamSessionOffer, ZoneScope, validate_contribution_lifecycle, validate_media_transport_path,
    validate_route_promise, validate_stream_route_plan, validate_stream_session_admission,
    validate_stream_session_candidate, validate_stream_session_control,
    validate_stream_session_intent, validate_stream_session_offer,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use super::preview::{
    ManagedCloseRequest, ManagedControlRequest, ManagedOfferRequest, ManagedOfferResponse,
    StreamAuthorityClaims, validate_stream_authority,
};

const STREAM_CHANNEL_ID: &str = "nvr.streams";
const WEBRTC_TRANSPORT: &str = "webrtc";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionOfferRecords {
    pub route_promise: RoutePromise,
    pub route_plan: StreamRoutePlan,
    pub intent: StreamSessionIntent,
    pub admission: StreamSessionAdmission,
    pub offer: StreamSessionOffer,
    pub candidates: Vec<StreamSessionCandidate>,
    #[serde(rename = "contributionLifecycles")]
    pub contribution_lifecycles: Vec<ContributionLifecycle>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionAnswerRecords {
    pub answer: StreamSessionAnswer,
    pub candidates: Vec<StreamSessionCandidate>,
    #[serde(rename = "mediaTransportPath")]
    pub media_transport_path: MediaTransportPath,
    #[serde(rename = "contributionLifecycles")]
    pub contribution_lifecycles: Vec<ContributionLifecycle>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSessionExchangeRecords {
    pub offer: StreamSessionOfferRecords,
    pub answer: StreamSessionAnswerRecords,
}

pub fn session_id_for_claims(claims: &StreamAuthorityClaims) -> String {
    stream_session_id(&claims.nonce)
}

pub fn stream_session_records_for_offer(
    cfg: &Config,
    request: &ManagedOfferRequest,
    claims: &StreamAuthorityClaims,
    issued_at: u64,
) -> Result<StreamSessionOfferRecords> {
    let session_id = session_id_for_claims(claims);
    let service_ref = service_ref(cfg);
    let service_member_ref = service_member_ref(cfg);
    let source_ids = offer_source_ids(&request.offer);
    let source_refs = stream_source_refs(&source_ids, claims);
    let requester_ref = requester_ref(claims);
    let route_promise = stream_route_promise(
        cfg,
        claims,
        &session_id,
        &requester_ref,
        &service_member_ref,
        &service_ref,
        &source_refs,
        issued_at,
    )?;
    let route_plan = stream_route_plan_for_offer(
        claims,
        &session_id,
        &requester_ref,
        &service_member_ref,
        &source_refs,
        &route_promise,
    )?;
    let intent = StreamSessionIntent {
        session_id: session_id.clone(),
        capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
        requester_ref,
        channel_id: STREAM_CHANNEL_ID.to_string(),
        transport: WEBRTC_TRANSPORT.to_string(),
        issued_at,
        expires_at: Some(claims.expires_at),
    };
    validate_stream_session_intent(&intent)?;

    let admission = StreamSessionAdmission {
        admission_id: format!("admission-{session_id}"),
        session_id: session_id.clone(),
        capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
        admitted_by: service_member_ref,
        constraints: json!({
            "sourceIds": source_ids,
            "candidateCount": request.candidates.len(),
            "transport": WEBRTC_TRANSPORT,
            "routePromiseId": &route_promise.promise_id,
            "routePlanId": &route_plan.session_id,
        }),
        issued_at,
    };
    validate_stream_session_admission(&admission)?;

    let offer = StreamSessionOffer {
        offer_id: format!("offer-{session_id}"),
        session_id: session_id.clone(),
        transport: WEBRTC_TRANSPORT.to_string(),
        payload: offer_payload(request),
        issued_at,
    };
    validate_stream_session_offer(&offer)?;
    ensure_no_media_bytes("stream session offer", &offer.payload)?;

    let candidates = request
        .candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            stream_candidate(
                &session_id,
                "remote",
                idx,
                candidate_payload(candidate),
                issued_at,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let contribution_lifecycles =
        offer_contribution_lifecycles(&route_promise, &admission, issued_at)?;

    Ok(StreamSessionOfferRecords {
        route_promise,
        route_plan,
        intent,
        admission,
        offer,
        candidates,
        contribution_lifecycles,
    })
}

pub fn stream_session_records_for_answer(
    response: &ManagedOfferResponse,
    offer: &StreamSessionOfferRecords,
    issued_at: u64,
) -> Result<StreamSessionAnswerRecords> {
    let session_id = response.session_id.clone();
    let answer = StreamSessionAnswer {
        answer_id: format!("answer-{session_id}"),
        session_id: session_id.clone(),
        transport: WEBRTC_TRANSPORT.to_string(),
        payload: strip_media_byte_fields(json!({
            "description": response.answer,
            "sourceIds": response.sources.iter().map(|source| source.source_id.clone()).collect::<Vec<_>>(),
        })),
        issued_at,
    };
    validate_answer_record(&answer)?;

    let candidates = response
        .candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            stream_candidate(
                &session_id,
                "local",
                idx,
                candidate_payload(candidate),
                issued_at,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let media_transport_path =
        media_transport_path_for_answer(response, offer, &candidates, issued_at)?;
    let contribution_lifecycles =
        answer_contribution_lifecycles(response, offer, &answer, &media_transport_path, issued_at)?;

    Ok(StreamSessionAnswerRecords {
        answer,
        candidates,
        media_transport_path,
        contribution_lifecycles,
    })
}

fn media_transport_path_for_answer(
    response: &ManagedOfferResponse,
    offer: &StreamSessionOfferRecords,
    service_candidates: &[StreamSessionCandidate],
    issued_at: u64,
) -> Result<MediaTransportPath> {
    let browser_candidate_refs = offer
        .candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    let service_candidate_refs = service_candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    let blocked_reason = if browser_candidate_refs.is_empty() {
        Some("missingBrowserCandidate".to_string())
    } else if service_candidate_refs.is_empty() {
        Some("missingServiceCandidate".to_string())
    } else {
        None
    };
    let state = if blocked_reason.is_some() {
        "blocked"
    } else {
        "actionable"
    };
    let path = MediaTransportPath {
        kind: Some(RECORD_MEDIA_TRANSPORT_PATH.to_string()),
        path_id: browser_webrtc_path_id(&response.session_id),
        session_id: response.session_id.clone(),
        activation_id: Some(offer.route_promise.activation_id.clone()),
        route_promise_id: Some(offer.route_promise.promise_id.clone()),
        transport_profile_ref: "runtime.media.browser-webrtc.default".to_string(),
        browser_candidate_refs,
        service_candidate_refs,
        relay_participant_refs: vec![],
        turn_participant_refs: vec![],
        state: state.to_string(),
        selected_pair_state: "pending".to_string(),
        inbound_rtp_state: "pending".to_string(),
        render_state: "pending".to_string(),
        blocked_reason,
        safe_facts: json!({
            "transport": WEBRTC_TRANSPORT,
            "iceLite": true,
            "serviceCandidateCount": service_candidates.len(),
            "browserCandidateCount": offer.candidates.len(),
            "sourceCount": response.sources.len(),
        }),
        evidence_refs: vec![offer.admission.admission_id.clone()],
        issued_at,
        expires_at: Some(offer.route_promise.expires_at),
    };
    validate_media_transport_path(&path)?;
    Ok(path)
}

fn route_promise_contribution_id(route_promise_id: &str) -> String {
    format!("contribution:{route_promise_id}:promise")
}

fn admission_witness_contribution_id(admission_id: &str) -> String {
    format!("contribution:{admission_id}:witness")
}

fn answer_fulfillment_contribution_id(answer_id: &str) -> String {
    format!("contribution:{answer_id}:fulfillment")
}

fn contribution_scope(session_id: &str) -> Value {
    json!({
        "channelId": STREAM_CHANNEL_ID,
        "capabilityRef": CAPABILITY_MEDIA_STREAM_PREVIEW,
        "sessionId": session_id,
        "transport": WEBRTC_TRANSPORT,
    })
}

fn offer_contribution_lifecycles(
    route_promise: &RoutePromise,
    admission: &StreamSessionAdmission,
    issued_at: u64,
) -> Result<Vec<ContributionLifecycle>> {
    let promise_id = route_promise_contribution_id(&route_promise.promise_id);
    let promise = ContributionLifecycle {
        kind: Some(RECORD_CONTRIBUTION_LIFECYCLE.to_string()),
        contribution_id: promise_id.clone(),
        parent_ref: route_promise.activation_id.clone(),
        subject_ref: route_promise.promise_id.clone(),
        writer_ref: route_promise.service_member_ref.clone(),
        contribution_type: "promise".to_string(),
        state: "active".to_string(),
        role: "route-producer".to_string(),
        authority_refs: route_promise.authority_refs.clone(),
        scope: contribution_scope(&admission.session_id),
        target_contribution_ref: None,
        supersedes: vec![],
        witness_refs: vec![],
        evidence_refs: vec![route_promise.promise_id.clone()],
        blocked_reasons: vec![],
        issued_at,
        valid_until: Some(route_promise.expires_at),
        release_after: Some(route_promise.expires_at),
        retracted_at: None,
        observed_at: None,
    };
    validate_contribution_lifecycle(&promise)?;

    let witness = ContributionLifecycle {
        kind: Some(RECORD_CONTRIBUTION_LIFECYCLE.to_string()),
        contribution_id: admission_witness_contribution_id(&admission.admission_id),
        parent_ref: route_promise.activation_id.clone(),
        subject_ref: admission.session_id.clone(),
        writer_ref: admission.admitted_by.clone(),
        contribution_type: "witness".to_string(),
        state: "witnessed".to_string(),
        role: "executor".to_string(),
        authority_refs: route_promise.authority_refs.clone(),
        scope: contribution_scope(&admission.session_id),
        target_contribution_ref: Some(promise_id),
        supersedes: vec![],
        witness_refs: vec![admission.admission_id.clone()],
        evidence_refs: vec![
            admission.admission_id.clone(),
            route_promise.promise_id.clone(),
        ],
        blocked_reasons: vec![],
        issued_at,
        valid_until: Some(route_promise.expires_at),
        release_after: Some(route_promise.expires_at),
        retracted_at: None,
        observed_at: Some(issued_at),
    };
    validate_contribution_lifecycle(&witness)?;
    Ok(vec![promise, witness])
}

fn answer_contribution_lifecycles(
    response: &ManagedOfferResponse,
    offer: &StreamSessionOfferRecords,
    answer: &StreamSessionAnswer,
    media_transport_path: &MediaTransportPath,
    issued_at: u64,
) -> Result<Vec<ContributionLifecycle>> {
    let fulfillment = ContributionLifecycle {
        kind: Some(RECORD_CONTRIBUTION_LIFECYCLE.to_string()),
        contribution_id: answer_fulfillment_contribution_id(&answer.answer_id),
        parent_ref: offer.route_promise.activation_id.clone(),
        subject_ref: response.session_id.clone(),
        writer_ref: offer.route_promise.service_member_ref.clone(),
        contribution_type: "fulfillment".to_string(),
        state: "active".to_string(),
        role: "executor".to_string(),
        authority_refs: offer.route_promise.authority_refs.clone(),
        scope: contribution_scope(&response.session_id),
        target_contribution_ref: Some(admission_witness_contribution_id(
            &offer.admission.admission_id,
        )),
        supersedes: vec![],
        witness_refs: vec![],
        evidence_refs: vec![
            answer.answer_id.clone(),
            media_transport_path.path_id.clone(),
            offer.admission.admission_id.clone(),
        ],
        blocked_reasons: vec![],
        issued_at,
        valid_until: Some(offer.route_promise.expires_at),
        release_after: Some(offer.route_promise.expires_at),
        retracted_at: None,
        observed_at: None,
    };
    validate_contribution_lifecycle(&fulfillment)?;
    Ok(vec![fulfillment])
}

pub fn stream_session_control_for_request(
    cfg: &Config,
    request: &ManagedControlRequest,
    issued_at: u64,
) -> Result<StreamSessionControl> {
    let claims = validate_stream_authority(cfg, &request.authority)?;
    let session_id = session_id_for_claims(&claims);
    let params = strip_media_byte_fields(json!({
        "sourceId": request.payload.get("sourceId").or_else(|| request.payload.get("source_id")).cloned().unwrap_or(Value::Null),
        "ptz": request.payload.get("ptz").cloned().unwrap_or_else(|| json!({})),
        "controlLease": request.control_lease,
        "preempted": request.preempted,
    }));
    ensure_no_media_bytes("stream session control", &params)?;

    let control = StreamSessionControl {
        control_id: format!("control-{session_id}-{issued_at}"),
        session_id,
        command: "ptz".to_string(),
        params,
        issued_at,
    };
    validate_stream_session_control(&control)?;
    Ok(control)
}

pub fn stream_session_close_for_request(
    cfg: &Config,
    request: &ManagedCloseRequest,
    issued_at: u64,
) -> Result<StreamSessionClose> {
    let claims = validate_stream_authority(cfg, &request.authority)?;
    let session_id = close_session_id_for_request(request, &claims);
    let close = StreamSessionClose {
        close_id: format!("close-{session_id}-{issued_at}"),
        session_id,
        reason_code: request
            .payload
            .get("reason")
            .or_else(|| request.payload.get("reasonCode"))
            .or_else(|| request.payload.get("reason_code"))
            .and_then(Value::as_str)
            .filter(|reason| !reason.trim().is_empty())
            .unwrap_or("closed")
            .to_string(),
        issued_at,
    };
    validate_close_record(&close)?;
    Ok(close)
}

fn close_session_id_for_request(
    request: &ManagedCloseRequest,
    claims: &StreamAuthorityClaims,
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
        .unwrap_or_else(|| session_id_for_claims(claims))
}

fn stream_candidate(
    session_id: &str,
    direction: &str,
    idx: usize,
    payload: Value,
    issued_at: u64,
) -> Result<StreamSessionCandidate> {
    let role = match direction {
        "remote" => STREAM_CANDIDATE_ROLE_BROWSER,
        "local" => STREAM_CANDIDATE_ROLE_SERVICE,
        _ => STREAM_CANDIDATE_ROLE_BROWSER,
    };
    let endpoint = candidate_endpoint_evidence(&payload);
    let (actionability, blocked_reason) = if endpoint.is_object() {
        (STREAM_CANDIDATE_ACTIONABILITY_USABLE.to_string(), None)
    } else {
        (
            STREAM_CANDIDATE_ACTIONABILITY_BLOCKED.to_string(),
            Some("missingCandidateEndpoint".to_string()),
        )
    };
    let candidate = StreamSessionCandidate {
        candidate_id: format!("candidate-{session_id}-{direction}-{idx}"),
        session_id: session_id.to_string(),
        transport: WEBRTC_TRANSPORT.to_string(),
        candidate_role: role.to_string(),
        actionability,
        blocked_reason,
        endpoint,
        payload: strip_media_byte_fields(json!({
            "direction": direction,
            "candidate": payload,
        })),
        issued_at,
    };
    validate_candidate_record(&candidate)?;
    Ok(candidate)
}

fn offer_payload(request: &ManagedOfferRequest) -> Value {
    let mut payload = Map::new();
    if let Some(description) = request.offer.get("description") {
        payload.insert(
            "description".to_string(),
            strip_media_byte_fields(description.clone()),
        );
    } else {
        payload.insert(
            "description".to_string(),
            strip_media_byte_fields(request.offer.clone()),
        );
    }
    payload.insert(
        "sourceIds".to_string(),
        json!(offer_source_ids(&request.offer)),
    );
    payload.insert(
        "candidateCount".to_string(),
        json!(request.candidates.len()),
    );
    strip_media_byte_fields(Value::Object(payload))
}

fn offer_source_ids(offer: &Value) -> Vec<String> {
    offer
        .get("sourceIds")
        .or_else(|| offer.get("sources"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn stream_source_refs(source_ids: &[String], claims: &StreamAuthorityClaims) -> Vec<String> {
    let mut out = source_ids
        .iter()
        .map(|source| source.trim())
        .filter(|source| !source.is_empty())
        .map(|source| format!("camera:{source}"))
        .collect::<Vec<_>>();
    if out.is_empty() {
        out.extend(
            claims
                .view_sources
                .iter()
                .map(|source| source.trim())
                .filter(|source| !source.is_empty())
                .map(|source| format!("camera:{source}")),
        );
    }
    if out.is_empty() {
        out.push("camera:any-preview-source".to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn stream_route_promise(
    cfg: &Config,
    claims: &StreamAuthorityClaims,
    session_id: &str,
    requester_ref: &str,
    service_member_ref: &str,
    service_ref: &str,
    source_refs: &[String],
    issued_at: u64,
) -> Result<RoutePromise> {
    let selected_path_id = browser_webrtc_path_id(session_id);
    let mut audience_refs = vec![service_member_ref.to_string(), requester_ref.to_string()];
    push_unique_ref(&mut audience_refs, service_ref);
    push_unique_ref(&mut audience_refs, &claims.service_pk);
    let mut authority_refs = vec![requester_ref.to_string()];
    push_unique_ref(
        &mut authority_refs,
        &format!("identity:{}", claims.identity_id.trim()),
    );
    push_unique_ref(
        &mut authority_refs,
        &format!("gateway:{}", claims.gateway_pk.trim()),
    );

    let promise = RoutePromise {
        kind: Some(RECORD_ROUTE_PROMISE.to_string()),
        promise_id: route_promise_id(session_id),
        activation_id: activation_id_for_claims(claims),
        node_ref: node_ref_for_sources(source_refs),
        capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
        requester_ref: requester_ref.to_string(),
        service_member_ref: service_member_ref.to_string(),
        service_pk: cfg.nostr_pubkey.trim().to_string(),
        channel_id: STREAM_CHANNEL_ID.to_string(),
        zone_scope: route_zone_scope(cfg),
        return_zone_scope: None,
        audience_refs,
        authority_refs,
        route_policy: json!({
            "requiresCaacOpen": true,
            "requiresAudience": true,
            "requiresChannel": STREAM_CHANNEL_ID,
            "requiresCapability": CAPABILITY_MEDIA_STREAM_PREVIEW,
        }),
        path_refs: vec![selected_path_id],
        issued_at,
        expires_at: claims.expires_at,
        release_policy: json!({
            "onClose": "release",
            "onLeaseExpiry": "expire",
        }),
    };
    validate_route_promise(&promise)?;
    Ok(promise)
}

fn stream_route_plan_for_offer(
    claims: &StreamAuthorityClaims,
    session_id: &str,
    requester_ref: &str,
    service_member_ref: &str,
    source_refs: &[String],
    route_promise: &RoutePromise,
) -> Result<StreamRoutePlan> {
    let selected_path = StreamRoutePath {
        path_id: browser_webrtc_path_id(session_id),
        kind: StreamPathKind::BrowserWebRtc,
        state: Some(StreamPathState::Selected),
        refs: vec![
            route_promise.promise_id.clone(),
            service_member_ref.to_string(),
        ],
        diagnostics: json!({
            "adapter": "browser-webrtc",
            "mediaPlane": "webrtc-rtp",
        }),
    };
    let fallback_path = StreamRoutePath {
        path_id: format!("{session_id}:fallback:degradedProjectionOnly"),
        kind: StreamPathKind::DegradedProjectionOnly,
        state: Some(StreamPathState::Unavailable),
        refs: vec![route_promise.promise_id.clone()],
        diagnostics: json!({
            "reason": "no alternate NVR stream transport selected",
        }),
    };
    let plan = StreamRoutePlan {
        kind: Some(RECORD_STREAM_ROUTE_PLAN.to_string()),
        session_id: session_id.to_string(),
        source_refs: source_refs.to_vec(),
        requester_ref: requester_ref.to_string(),
        service_member_ref: service_member_ref.to_string(),
        capability_ref: CAPABILITY_MEDIA_STREAM_PREVIEW.to_string(),
        route_lease: json!({
            "promiseId": &route_promise.promise_id,
            "issuedAt": route_promise.issued_at,
            "expiresAt": route_promise.expires_at,
        }),
        candidate_paths: vec![selected_path.clone()],
        preferred_path: selected_path.clone(),
        fallback_paths: vec![fallback_path],
        selected_path,
        path_state: StreamPathState::Selected,
        reachability_state: ReachabilityState::Reachable,
        release_policy: json!({
            "onClose": "release",
            "onLeaseExpiry": "expire",
        }),
        diagnostics: json!({
            "routePromiseId": &route_promise.promise_id,
            "authorityNonce": claims.nonce,
        }),
        expires_at: route_promise.expires_at,
    };
    validate_stream_route_plan(&plan)?;
    Ok(plan)
}

pub fn browser_webrtc_path_id(session_id: &str) -> String {
    format!("{session_id}:path:browserWebRtc")
}

fn route_promise_id(session_id: &str) -> String {
    format!("route-promise-{session_id}")
}

fn activation_id_for_claims(claims: &StreamAuthorityClaims) -> String {
    if claims.capability_id.trim().is_empty() {
        format!("activation-{}", claims.nonce.trim())
    } else {
        format!("activation-{}", claims.capability_id.trim())
    }
}

fn node_ref_for_sources(source_refs: &[String]) -> String {
    source_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "camera:any-preview-source".to_string())
}

fn route_zone_scope(cfg: &Config) -> ZoneScope {
    ZoneScope {
        zone_id: cfg
            .swarm
            .zones
            .first()
            .map(|zone| zone.key.trim())
            .filter(|zone| !zone.is_empty())
            .unwrap_or("default")
            .to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    }
}

fn push_unique_ref(refs: &mut Vec<String>, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() && !refs.iter().any(|item| item == trimmed) {
        refs.push(trimmed.to_string());
    }
}

fn candidate_payload(candidate: &RTCIceCandidateInit) -> Value {
    strip_media_byte_fields(serde_json::to_value(candidate).unwrap_or_else(|_| json!({})))
}

fn candidate_endpoint_evidence(candidate: &Value) -> Value {
    let text = candidate
        .get("candidate")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let Some(endpoint) = parse_candidate_endpoint(text) else {
        return Value::Null;
    };
    json!({
        "protocol": endpoint.protocol,
        "address": endpoint.address,
        "port": endpoint.port,
        "candidateType": endpoint.candidate_type,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateEndpoint {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub candidate_type: String,
}

pub(crate) fn parse_candidate_endpoint(candidate: &str) -> Option<CandidateEndpoint> {
    let parts = candidate.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 8 {
        return None;
    }
    let protocol = parts.get(2)?.trim().to_ascii_lowercase();
    if protocol != "udp" && protocol != "tcp" {
        return None;
    }
    let address = parts.get(4)?.trim();
    if address.is_empty() {
        return None;
    }
    let port = parts.get(5)?.trim().parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    let typ_idx = parts.iter().position(|part| *part == "typ")?;
    let candidate_type = parts.get(typ_idx + 1)?.trim();
    if candidate_type.is_empty() {
        return None;
    }
    Some(CandidateEndpoint {
        protocol,
        address: address.to_string(),
        port,
        candidate_type: candidate_type.to_string(),
    })
}

fn strip_media_byte_fields(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(key, _)| !is_media_byte_key(key))
                .map(|(key, value)| (key, strip_media_byte_fields(value)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(strip_media_byte_fields).collect())
        }
        other => other,
    }
}

fn ensure_no_media_bytes(context: &str, value: &Value) -> Result<()> {
    if contains_media_byte_field(value) {
        Err(anyhow!("{context} contains media byte field"))
    } else {
        Ok(())
    }
}

fn contains_media_byte_field(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| is_media_byte_key(key) || contains_media_byte_field(value)),
        Value::Array(items) => items.iter().any(contains_media_byte_field),
        _ => false,
    }
}

fn is_media_byte_key(key: &str) -> bool {
    matches!(
        key,
        "mediaBytes" | "payloadBytes" | "mediaData" | "mediaChunk" | "encodedMediaBytes"
    )
}

fn validate_answer_record(answer: &StreamSessionAnswer) -> Result<()> {
    if answer.answer_id.trim().is_empty() {
        return Err(anyhow!("stream session answer missing answerId"));
    }
    if answer.session_id.trim().is_empty() {
        return Err(anyhow!("stream session answer missing sessionId"));
    }
    if answer.transport.trim().is_empty() {
        return Err(anyhow!("stream session answer missing transport"));
    }
    if !answer.payload.is_object() {
        return Err(anyhow!("stream session answer payload must be an object"));
    }
    if answer.issued_at == 0 {
        return Err(anyhow!("stream session answer missing issuedAt"));
    }
    ensure_no_media_bytes("stream session answer", &answer.payload)
}

fn validate_candidate_record(candidate: &StreamSessionCandidate) -> Result<()> {
    validate_stream_session_candidate(candidate)?;
    ensure_no_media_bytes("stream session candidate", &candidate.payload)
}

fn validate_close_record(close: &StreamSessionClose) -> Result<()> {
    if close.close_id.trim().is_empty() {
        return Err(anyhow!("stream session close missing closeId"));
    }
    if close.session_id.trim().is_empty() {
        return Err(anyhow!("stream session close missing sessionId"));
    }
    if close.reason_code.trim().is_empty() {
        return Err(anyhow!("stream session close missing reasonCode"));
    }
    if close.issued_at == 0 {
        return Err(anyhow!("stream session close missing issuedAt"));
    }
    Ok(())
}

fn stream_session_id(nonce: &str) -> String {
    let suffix = nonce
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("nvr-preview-{}", suffix.trim_matches('-'))
}

fn requester_ref(claims: &StreamAuthorityClaims) -> String {
    claims.device_pk.trim().to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const SERVICE_PK: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const GATEWAY_PK: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const BROWSER_PK: &str = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

    fn claims() -> StreamAuthorityClaims {
        StreamAuthorityClaims {
            capability_id: "cap-1".to_string(),
            gateway_pk: GATEWAY_PK.to_string(),
            service_pk: SERVICE_PK.to_string(),
            service: "nvr".to_string(),
            identity_id: "identity-1".to_string(),
            device_pk: BROWSER_PK.to_string(),
            capability: "nvr.view".to_string(),
            owner: false,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            nonce: "nonce-1".to_string(),
            issued_at: 1_700_000_000_000,
            expires_at: 1_700_000_060_000,
        }
    }

    fn config() -> Config {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-session-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (mut cfg, _) = Config::load_or_create(&path).expect("config");
        cfg.nostr_pubkey = SERVICE_PK.to_string();
        cfg
    }

    fn config_and_authority(nonce: &str) -> (Config, StreamAuthorityClaims) {
        let path = std::env::temp_dir().join(format!(
            "constitute-nvr-session-capability-test-{}-{}.json",
            std::process::id(),
            crate::util::now_ms()
        ));
        let (mut cfg, _) = Config::load_or_create(&path).expect("config");
        let _ = std::fs::remove_file(&path);
        let (service_pk, service_sk) = constitute_protocol::generate_keypair();
        let (gateway_pk, _) = constitute_protocol::generate_keypair();
        cfg.nostr_pubkey = service_pk.clone();
        cfg.nostr_sk_hex = service_sk;
        cfg.gateway.host_gateway_pk = gateway_pk.clone();
        cfg.api.identity_id = "identity-1".to_string();
        let payload = StreamAuthorityClaims {
            capability_id: "cap-control".to_string(),
            gateway_pk: gateway_pk.clone(),
            service_pk,
            service: "nvr".to_string(),
            identity_id: cfg.api.identity_id.clone(),
            device_pk: BROWSER_PK.to_string(),
            capability: "nvr.control".to_string(),
            owner: true,
            view_sources: vec!["cam-1".to_string()],
            control_sources: vec!["cam-1".to_string()],
            nonce: nonce.to_string(),
            issued_at: crate::util::now_ms(),
            expires_at: crate::util::now_ms() + 60_000,
        };
        (cfg, payload)
    }

    #[test]
    fn maps_webrtc_offer_and_candidates_to_valid_stream_records() {
        let request = ManagedOfferRequest {
            authority: claims(),
            offer: json!({
                "description": {
                    "type": "offer",
                    "sdp": "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
                },
                "sourceIds": ["cam-1"],
                "mediaBytes": "must-not-survive"
            }),
            ice_servers: Default::default(),
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 1 192.0.2.5 5000 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
        };

        let records =
            stream_session_records_for_offer(&config(), &request, &claims(), 1_700_000_001_000)
                .expect("records");

        assert_eq!(records.intent.session_id, "nvr-preview-nonce-1");
        validate_route_promise(&records.route_promise).expect("route promise");
        validate_stream_route_plan(&records.route_plan).expect("route plan");
        assert_eq!(
            records.route_plan.capability_ref,
            CAPABILITY_MEDIA_STREAM_PREVIEW
        );
        assert!(!records.route_plan.fallback_paths.is_empty());
        validate_stream_session_intent(&records.intent).expect("intent");
        validate_stream_session_admission(&records.admission).expect("admission");
        validate_stream_session_offer(&records.offer).expect("offer");
        assert_eq!(records.contribution_lifecycles.len(), 2);
        for contribution in &records.contribution_lifecycles {
            validate_contribution_lifecycle(contribution).expect("contribution lifecycle");
        }
        assert_eq!(records.candidates.len(), 1);
        assert_eq!(
            records.candidates[0].candidate_role,
            STREAM_CANDIDATE_ROLE_BROWSER
        );
        assert_eq!(
            records.candidates[0].actionability,
            STREAM_CANDIDATE_ACTIONABILITY_USABLE
        );
        assert_eq!(records.candidates[0].endpoint["port"], json!(5000));
        assert!(
            !serde_json::to_string(&records)
                .unwrap()
                .contains("must-not-survive")
        );
    }

    #[test]
    fn maps_webrtc_answer_to_stream_record_without_media_bytes() {
        let request = ManagedOfferRequest {
            authority: claims(),
            offer: json!({
                "description": {
                    "type": "offer",
                    "sdp": "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
                },
                "sourceIds": ["cam-1"]
            }),
            ice_servers: Default::default(),
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 1 192.0.2.10 6000 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
        };
        let offer =
            stream_session_records_for_offer(&config(), &request, &claims(), 1_700_000_001_000)
                .expect("offer records");
        let response = ManagedOfferResponse {
            signal_type: "answer".to_string(),
            answer: RTCSessionDescription::answer(
                "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n".to_string(),
            )
            .expect("answer"),
            session_id: "nvr-preview-nonce-1".to_string(),
            sources: vec![super::super::preview::ManagedSourceInfo {
                source_id: "cam-1".to_string(),
                name: "Front".to_string(),
                rtsp_preview_url: "rtsp://secret.invalid/preview".to_string(),
            }],
            candidates: vec![RTCIceCandidateInit {
                candidate: "candidate:1 1 udp 1 192.0.2.5 5001 typ host".to_string(),
                sdp_mid: Some("0".to_string()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            }],
            stream_session: None,
        };

        let records = stream_session_records_for_answer(&response, &offer, 1_700_000_001_001)
            .expect("records");

        assert_eq!(records.answer.session_id, "nvr-preview-nonce-1");
        validate_answer_record(&records.answer).expect("answer");
        assert_eq!(records.candidates.len(), 1);
        validate_candidate_record(&records.candidates[0]).expect("candidate");
        assert_eq!(
            records.candidates[0].candidate_role,
            STREAM_CANDIDATE_ROLE_SERVICE
        );
        assert_eq!(
            records.candidates[0].actionability,
            STREAM_CANDIDATE_ACTIONABILITY_USABLE
        );
        validate_media_transport_path(&records.media_transport_path).expect("media path");
        assert_eq!(records.media_transport_path.state, "actionable");
        assert_eq!(records.media_transport_path.service_candidate_refs.len(), 1);
        assert_eq!(records.media_transport_path.browser_candidate_refs.len(), 1);
        assert_eq!(records.contribution_lifecycles.len(), 1);
        validate_contribution_lifecycle(&records.contribution_lifecycles[0])
            .expect("answer contribution lifecycle");
        let rendered = serde_json::to_string(&records).expect("json");
        assert!(!rendered.contains("rtsp://"));
        assert!(!rendered.contains("mediaBytes"));
    }

    #[test]
    fn parses_candidate_endpoint_evidence() {
        let endpoint =
            parse_candidate_endpoint("candidate:1 1 udp 2122260223 10.0.229.73 54547 typ host")
                .expect("endpoint");

        assert_eq!(endpoint.protocol, "udp");
        assert_eq!(endpoint.address, "10.0.229.73");
        assert_eq!(endpoint.port, 54547);
        assert_eq!(endpoint.candidate_type, "host");
        assert!(
            parse_candidate_endpoint("candidate:1 1 udp 2122260223 10.0.229.73 typ host").is_none()
        );
    }

    #[test]
    fn maps_control_record_without_media_byte_fields() {
        let (cfg, authority) = config_and_authority("control-nonce-1");
        let request = ManagedControlRequest {
            authority,
            payload: json!({
                "sourceId": "cam-1",
                "ptz": { "pan": 0.25 },
                "mediaBytes": "raw-video-must-not-survive",
                "nested": {
                    "payloadBytes": "raw-video-must-not-survive"
                }
            }),
            control_lease: json!({ "leaseId": "lease-1" }),
            preempted: false,
        };

        let record =
            stream_session_control_for_request(&cfg, &request, 1_700_000_001_000).expect("record");
        let rendered = serde_json::to_string(&record).expect("json");

        validate_stream_session_control(&record).expect("valid control record");
        assert_eq!(record.command, "ptz");
        assert_eq!(record.params["sourceId"], json!("cam-1"));
        assert!(!rendered.contains("mediaBytes"));
        assert!(!rendered.contains("payloadBytes"));
        assert!(!rendered.contains("raw-video-must-not-survive"));
    }

    #[test]
    fn close_record_uses_explicit_session_id_over_fresh_authority_nonce() {
        let (cfg, authority) = config_and_authority("close-nonce-new");
        let request = ManagedCloseRequest {
            authority,
            session_id: "nvr-preview-original-nonce".to_string(),
            payload: json!({ "reason": "adapter_failed" }),
        };

        let record = stream_session_close_for_request(&cfg, &request, 1_700_000_001_000)
            .expect("close record");

        validate_close_record(&record).expect("valid close");
        assert_eq!(record.session_id, "nvr-preview-original-nonce");
        assert_eq!(record.reason_code, "adapter_failed");
    }
}
