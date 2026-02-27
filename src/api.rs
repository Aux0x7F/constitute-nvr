use crate::camera;
use crate::config::Config;
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
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct ApiState {
    pub cfg: Config,
    pub storage: StorageManager,
}

pub async fn run(cfg: Config, storage: StorageManager) -> Result<()> {
    let bind = cfg.api.bind.clone();
    let state = Arc::new(ApiState { cfg, storage });

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
    Json(json!({
        "ok": true,
        "service": "nvr",
        "version": state.cfg.service_version,
        "nodeRole": state.cfg.node_role,
        "identityId": state.cfg.api.identity_id,
        "sources": sources,
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
    DiscoverOnvif,
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

    if let Err(err) = validate_hello(&state.cfg, &hello) {
        let _ = socket
            .send(Message::Text(error_json(&err.to_string()).into()))
            .await;
        let _ = socket.close().await;
        return;
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let context = format!(
        "constitute-nvr:{}:{}",
        state.cfg.api.identity_id, session_id
    );

    let (session_key, server_key) = match crypto::derive_session_key(
        &state.cfg.api.server_secret_hex,
        &state.cfg.api.identity_secret_hex,
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
