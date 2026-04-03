use crate::camera;
use crate::camera::RecorderManager;
use crate::config::{CameraConfig, Config};
use crate::crypto;
use crate::live::{ManagedCloseRequest, ManagedOfferRequest, PreviewManager};
use crate::reolink;
use crate::storage::StorageManager;
use crate::util;
use anyhow::{Result, anyhow};
use axum::http::StatusCode;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const INSECURE_HELLO_SECRET_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
pub struct ApiState {
    pub cfg: Arc<Mutex<Config>>,
    pub cfg_path: PathBuf,
    pub storage: StorageManager,
    pub recorder: RecorderManager,
    pub preview: PreviewManager,
}

pub async fn run(
    cfg: Config,
    cfg_path: PathBuf,
    storage: StorageManager,
    recorder: RecorderManager,
) -> Result<()> {
    let bind = cfg.api.bind.clone();
    let state = Arc::new(ApiState {
        cfg: Arc::new(Mutex::new(cfg)),
        cfg_path,
        storage,
        recorder,
        preview: PreviewManager::new()?,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/session", get(ws_session))
        .route("/managed/offer", post(managed_offer))
        .route("/managed/close", post(managed_close))
        .with_state(state);

    let listener = TcpListener::bind(&bind).await?;
    info!(bind = %bind, "api listener ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<Arc<ApiState>>) -> Json<Value> {
    let sources = state.storage.list_sources().await.unwrap_or_default();
    let runtime = state.recorder.list_states().await;
    let cfg = state.cfg.lock().await.clone();
    Json(json!({
        "ok": true,
        "service": "nvr",
        "deviceKind": "service",
        "version": cfg.service_version,
        "nodeRole": cfg.node_role,
        "identityId": cfg.api.identity_id,
        "devicePk": cfg.nostr_pubkey,
        "hostGatewayPk": cfg.gateway.host_gateway_pk,
        "sources": sources,
        "cameras": cfg.cameras,
        "sourceRuntime": runtime,
        "configuredSources": cfg.cameras.len(),
    }))
}

async fn ws_session(ws: WebSocketUpgrade, State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn managed_offer(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<ManagedOfferRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.lock().await.clone();
    match state.preview.handle_offer(&cfg, request).await {
        Ok(response) => Json(json!({
            "signalType": response.signal_type,
            "payload": response.answer,
            "answer": response.answer,
            "sessionId": response.session_id,
            "sources": response.sources,
        }))
        .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn managed_close(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<ManagedCloseRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.lock().await.clone();
    match state.preview.handle_close(&cfg, request).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err.to_string(),
            })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct HelloReq {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "identityId")]
    identity_id: String,
    #[serde(rename = "devicePk")]
    device_pk: String,
    #[serde(rename = "clientKey")]
    client_key: String,
    ts: u64,
    proof: String,
}

#[derive(Debug, Serialize)]
struct HelloAck {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "serverKey")]
    server_key: String,
    ts: u64,
}

#[derive(Debug, Deserialize)]
struct CipherEnvelope {
    #[serde(rename = "type")]
    kind: String,
    nonce: String,
    data: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum ClientCommand {
    ListSources,
    ListSourceStates,
    DiscoverOnvif,
    DiscoverReolink,
    ProbeReolink {
        ip: String,
    },
    ReadReolinkState {
        request: reolink::ReolinkConnectRequest,
    },
    ApplyReolinkState {
        request: reolink::ReolinkStateApplyRequest,
    },
    SetupReolink {
        request: reolink::ReolinkSetupRequest,
    },
    BootstrapReolink {
        request: reolink::ReolinkBootstrapRequest,
    },
    UpsertSource {
        source: SourceUpsert,
    },
    RemoveSource {
        #[serde(rename = "sourceId")]
        source_id: String,
    },
    ListSegments {
        #[serde(rename = "sourceId")]
        source_id: String,
        limit: Option<usize>,
    },
    GetSegment {
        #[serde(rename = "sourceId")]
        source_id: String,
        name: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceUpsert {
    source_id: String,
    name: String,
    onvif_host: String,
    #[serde(default = "default_onvif_port")]
    onvif_port: u16,
    rtsp_url: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default = "default_segment_secs")]
    segment_secs: u64,
}

impl SourceUpsert {
    fn into_camera(self) -> Result<CameraConfig> {
        if self.source_id.trim().is_empty() {
            return Err(anyhow!("sourceId is required"));
        }
        if self.rtsp_url.trim().is_empty() {
            return Err(anyhow!("rtsp_url is required"));
        }
        if self.onvif_host.trim().is_empty() {
            return Err(anyhow!("onvif_host is required"));
        }
        Ok(CameraConfig {
            source_id: self.source_id.trim().to_string(),
            name: if self.name.trim().is_empty() {
                self.source_id.trim().to_string()
            } else {
                self.name.trim().to_string()
            },
            onvif_host: self.onvif_host.trim().to_string(),
            onvif_port: self.onvif_port,
            rtsp_url: self.rtsp_url.trim().to_string(),
            username: self.username,
            password: self.password,
            enabled: self.enabled,
            segment_secs: self.segment_secs.max(2),
        })
    }
}

async fn handle_ws(mut socket: WebSocket, state: Arc<ApiState>) {
    let hello_msg = match socket.next().await {
        Some(Ok(Message::Text(text))) => text,
        _ => {
            let _ = socket.close().await;
            return;
        }
    };

    let hello: HelloReq = match serde_json::from_str(&hello_msg) {
        Ok(v) => v,
        Err(_) => {
            let _ = socket
                .send(Message::Text(error_json("invalid hello payload").into()))
                .await;
            let _ = socket.close().await;
            return;
        }
    };

    if hello.kind != "hello" {
        let _ = socket
            .send(Message::Text(error_json("expected hello frame").into()))
            .await;
        let _ = socket.close().await;
        return;
    }

    let cfg_snapshot = state.cfg.lock().await.clone();

    if let Err(err) = validate_hello(&cfg_snapshot, &hello) {
        let _ = socket
            .send(Message::Text(error_json(&err.to_string()).into()))
            .await;
        let _ = socket.close().await;
        return;
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let context = format!(
        "constitute-nvr:{}:{}",
        cfg_snapshot.api.identity_id, session_id
    );

    let (session_key, server_key) = match crypto::derive_session_key(
        &cfg_snapshot.api.server_secret_hex,
        session_identity_secret_hex(&cfg_snapshot),
        &hello.client_key,
        &context,
    ) {
        Ok(v) => v,
        Err(err) => {
            let _ = socket
                .send(Message::Text(
                    error_json(&format!("key derivation failed: {}", err)).into(),
                ))
                .await;
            let _ = socket.close().await;
            return;
        }
    };

    let ack = HelloAck {
        kind: "hello_ack",
        session_id: session_id.clone(),
        server_key,
        ts: util::now_ms(),
    };
    let _ = socket
        .send(Message::Text(
            serde_json::to_string(&ack)
                .unwrap_or_else(|_| "{}".to_string())
                .into(),
        ))
        .await;

    debug!(session_id = %session_id, device = %hello.device_pk, "session established");

    while let Some(frame) = socket.next().await {
        let text = match frame {
            Ok(Message::Text(t)) => t,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        };

        let env: CipherEnvelope = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                let _ =
                    send_cipher_error(&mut socket, &session_key, "invalid cipher envelope").await;
                continue;
            }
        };

        if env.kind != "cipher" {
            let _ = send_cipher_error(&mut socket, &session_key, "expected cipher envelope").await;
            continue;
        }

        let nonce_bytes = match base64::engine::general_purpose::STANDARD.decode(&env.nonce) {
            Ok(v) => v,
            Err(_) => {
                let _ =
                    send_cipher_error(&mut socket, &session_key, "invalid nonce encoding").await;
                continue;
            }
        };

        let nonce: [u8; 24] = match nonce_bytes.try_into() {
            Ok(v) => v,
            Err(_) => {
                let _ = send_cipher_error(&mut socket, &session_key, "invalid nonce length").await;
                continue;
            }
        };

        let cipher = match base64::engine::general_purpose::STANDARD.decode(&env.data) {
            Ok(v) => v,
            Err(_) => {
                let _ = send_cipher_error(&mut socket, &session_key, "invalid cipher data").await;
                continue;
            }
        };

        let plain = match crypto::decrypt_payload(&session_key, &nonce, &cipher) {
            Ok(v) => v,
            Err(_) => {
                let _ = send_cipher_error(&mut socket, &session_key, "decrypt failed").await;
                continue;
            }
        };

        let cmd: ClientCommand = match serde_json::from_slice(&plain) {
            Ok(v) => v,
            Err(_) => {
                let _ =
                    send_cipher_error(&mut socket, &session_key, "invalid command payload").await;
                continue;
            }
        };

        if let Err(err) = handle_command(cmd, &mut socket, &session_key, &state).await {
            warn!(session_id = %session_id, error = %err, "command handling failed");
            let _ = send_cipher_error(&mut socket, &session_key, &err.to_string()).await;
        }
    }
}

fn validate_hello(cfg: &Config, hello: &HelloReq) -> Result<()> {
    if hello.identity_id != cfg.api.identity_id {
        return Err(anyhow!("identity mismatch"));
    }

    if !cfg.api.authorized_device_pks.is_empty()
        && !cfg
            .api
            .authorized_device_pks
            .iter()
            .any(|pk| pk == &hello.device_pk)
    {
        return Err(anyhow!("device is not authorized for this identity"));
    }

    let now = util::now_unix_seconds();
    let ts = hello.ts;
    let skew = now.abs_diff(ts);
    if skew > 300 {
        return Err(anyhow!("hello timestamp outside allowed skew"));
    }

    if cfg.api.allow_unsigned_hello_mvp {
        return Ok(());
    }

    let proof_ok = crypto::verify_hello_proof(
        &cfg.api.identity_secret_hex,
        &hello.identity_id,
        &hello.device_pk,
        &hello.client_key,
        hello.ts,
        &hello.proof,
    )?;

    if !proof_ok {
        return Err(anyhow!("invalid hello proof"));
    }

    Ok(())
}

fn session_identity_secret_hex(cfg: &Config) -> &str {
    if cfg.api.allow_unsigned_hello_mvp {
        INSECURE_HELLO_SECRET_HEX
    } else {
        &cfg.api.identity_secret_hex
    }
}

async fn handle_command(
    cmd: ClientCommand,
    socket: &mut WebSocket,
    key: &[u8],
    state: &ApiState,
) -> Result<()> {
    match cmd {
        ClientCommand::ListSources => {
            let sources = state.storage.list_sources().await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "list_sources",
                    "sources": sources,
                }),
            )
            .await?;
        }
        ClientCommand::ListSourceStates => {
            let runtime = state.recorder.list_states().await;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "list_source_states",
                    "states": runtime,
                }),
            )
            .await?;
        }
        ClientCommand::DiscoverOnvif => {
            let found = camera::discover_onvif(3).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "discover_onvif",
                    "cameras": found,
                }),
            )
            .await?;
        }
        ClientCommand::DiscoverReolink => {
            let found = reolink::discover(3).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "discover_reolink",
                    "devices": found,
                }),
            )
            .await?;
        }
        ClientCommand::ProbeReolink { ip } => {
            let result = reolink::probe(&ip, 3).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "probe_reolink",
                    "result": result,
                }),
            )
            .await?;
        }
        ClientCommand::ReadReolinkState { request } => {
            let result = reolink::read_state(request).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "read_reolink_state",
                    "result": result,
                }),
            )
            .await?;
        }
        ClientCommand::ApplyReolinkState { request } => {
            let result = reolink::apply_state(request).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "apply_reolink_state",
                    "result": result,
                }),
            )
            .await?;
        }
        ClientCommand::SetupReolink { request } => {
            let request = request.normalized()?;
            let result = reolink::setup(request.clone()).await?;

            let effective_password = if !result.generated_password.trim().is_empty() {
                result.generated_password.clone()
            } else if !request.desired_password.trim().is_empty() {
                request.desired_password.clone()
            } else {
                request.password.clone()
            };

            let onvif_port = if result.bridge.after_advanced.i_onvif_port_enable != 0 {
                result.bridge.after_advanced.i_onvif_port.max(1) as u16
            } else if result.probe.onvif_port_open {
                8000
            } else {
                8000
            };

            let rtsp_port = if result.bridge.after_advanced.i_rtsp_port_enable != 0 {
                result.bridge.after_advanced.i_rtsp_port.max(1) as u16
            } else if result.probe.rtsp_port_open {
                554
            } else {
                554
            };

            let discovered = reolink::discover_with_hint(&request.ip, 2)
                .await
                .unwrap_or_default();
            let discovered_entry = discovered
                .into_iter()
                .find(|d| d.ip.trim() == request.ip.trim());
            let uid = discovered_entry
                .as_ref()
                .map(|d| d.uid.clone())
                .unwrap_or_default();
            let model = discovered_entry
                .as_ref()
                .map(|d| d.model.clone())
                .unwrap_or_default();

            let source_id = build_reolink_source_id(&uid, &request.ip);
            let source_name = if model.trim().is_empty() {
                format!("Reolink {}", request.ip)
            } else {
                model
            };
            let camera_cfg = CameraConfig {
                source_id: source_id.clone(),
                name: source_name,
                onvif_host: request.ip.clone(),
                onvif_port,
                rtsp_url: format!(
                    "rtsp://{}:{}@{}:{}/h264Preview_01_main",
                    request.username, effective_password, request.ip, rtsp_port
                ),
                username: request.username.clone(),
                password: effective_password,
                enabled: true,
                segment_secs: 10,
            };

            persist_camera_source(state, camera_cfg.clone()).await?;

            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "setup_reolink",
                    "result": result,
                    "source": camera_cfg,
                }),
            )
            .await?;
        }
        ClientCommand::BootstrapReolink { request } => {
            let result = reolink::bootstrap(request).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "bootstrap_reolink",
                    "result": result,
                }),
            )
            .await?;
        }
        ClientCommand::UpsertSource { source } => {
            let camera_cfg = source.into_camera()?;
            persist_camera_source(state, camera_cfg.clone()).await?;

            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "upsert_source",
                    "source": camera_cfg,
                }),
            )
            .await?;
        }
        ClientCommand::RemoveSource { source_id } => {
            let removed = {
                let mut guard = state.cfg.lock().await;
                let before = guard.cameras.len();
                guard.cameras.retain(|c| c.source_id != source_id);
                let changed = guard.cameras.len() != before;
                if changed {
                    let snapshot = guard.clone();
                    snapshot.persist(&state.cfg_path)?;
                }
                changed
            };

            let runtime_removed = state.recorder.remove_camera(&source_id).await;

            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "remove_source",
                    "sourceId": source_id,
                    "removed": removed || runtime_removed,
                }),
            )
            .await?;
        }
        ClientCommand::ListSegments { source_id, limit } => {
            let segments = state
                .storage
                .list_segments(&source_id, limit.unwrap_or(30))
                .await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "list_segments",
                    "sourceId": source_id,
                    "segments": segments,
                }),
            )
            .await?;
        }
        ClientCommand::GetSegment { source_id, name } => {
            let data = state.storage.read_segment(&source_id, &name).await?;
            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "segment_start",
                    "sourceId": source_id,
                    "name": name,
                    "bytes": data.len(),
                }),
            )
            .await?;

            for (idx, chunk) in data.chunks(48 * 1024).enumerate() {
                send_cipher_json(
                    socket,
                    key,
                    &json!({
                        "ok": true,
                        "cmd": "segment_chunk",
                        "seq": idx,
                        "data": base64::engine::general_purpose::STANDARD.encode(chunk),
                    }),
                )
                .await?;
            }

            send_cipher_json(
                socket,
                key,
                &json!({
                    "ok": true,
                    "cmd": "segment_end",
                    "name": name,
                }),
            )
            .await?;
        }
    }
    Ok(())
}

async fn persist_camera_source(state: &ApiState, camera_cfg: CameraConfig) -> Result<()> {
    let storage_root = {
        let mut guard = state.cfg.lock().await;
        if let Some(existing) = guard
            .cameras
            .iter_mut()
            .find(|c| c.source_id == camera_cfg.source_id || c.onvif_host == camera_cfg.onvif_host)
        {
            *existing = camera_cfg.clone();
        } else {
            guard.cameras.push(camera_cfg.clone());
        }
        let snapshot = guard.clone();
        snapshot.persist(&state.cfg_path)?;
        snapshot.storage_root()
    };

    state
        .recorder
        .upsert_camera(storage_root, camera_cfg)
        .await;

    Ok(())
}

fn build_reolink_source_id(uid: &str, ip: &str) -> String {
    let key = if uid.trim().is_empty() { ip.trim() } else { uid.trim() };
    let sanitized = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("reolink-{}", sanitized.trim_matches('-'))
}

async fn send_cipher_error(socket: &mut WebSocket, key: &[u8], message: &str) -> Result<()> {
    send_cipher_json(socket, key, &json!({"ok": false, "error": message})).await
}

async fn send_cipher_json(socket: &mut WebSocket, key: &[u8], value: &Value) -> Result<()> {
    let plain = serde_json::to_vec(value)?;
    let nonce = crypto::random_nonce_24();
    let cipher = crypto::encrypt_payload(key, &nonce, &plain)?;
    let frame = json!({
        "type": "cipher",
        "nonce": base64::engine::general_purpose::STANDARD.encode(nonce),
        "data": base64::engine::general_purpose::STANDARD.encode(cipher),
    });
    socket.send(Message::Text(frame.to_string().into())).await?;
    Ok(())
}

fn error_json(message: &str) -> String {
    json!({"ok": false, "error": message}).to_string()
}

fn default_onvif_port() -> u16 {
    80
}

fn default_enabled() -> bool {
    true
}

fn default_segment_secs() -> u64 {
    10
}
