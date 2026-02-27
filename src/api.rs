use crate::camera;
use crate::camera::RecorderManager;
use crate::config::{CameraConfig, Config};
use crate::crypto;
use crate::storage::StorageManager;
use crate::util;
use anyhow::{Result, anyhow};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
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

#[derive(Clone)]
pub struct ApiState {
    pub cfg: Arc<Mutex<Config>>,
    pub cfg_path: PathBuf,
    pub storage: StorageManager,
    pub recorder: RecorderManager,
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
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/session", get(ws_session))
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
        "version": cfg.service_version,
        "nodeRole": cfg.node_role,
        "identityId": cfg.api.identity_id,
        "sources": sources,
        "sourceRuntime": runtime,
        "configuredSources": cfg.cameras.len(),
    }))
}

async fn ws_session(ws: WebSocketUpgrade, State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
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
        &cfg_snapshot.api.identity_secret_hex,
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
        ClientCommand::UpsertSource { source } => {
            let camera_cfg = source.into_camera()?;
            let storage_root = {
                let mut guard = state.cfg.lock().await;
                if let Some(existing) = guard
                    .cameras
                    .iter_mut()
                    .find(|c| c.source_id == camera_cfg.source_id)
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
                .upsert_camera(storage_root, camera_cfg.clone())
                .await;

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
