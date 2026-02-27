use crate::config::Config;
use crate::nostr::{self, NostrEvent};
use crate::util;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant, interval};
use tracing::{debug, info, warn};

const PROTOCOL_VERSION: u8 = 1;
const RECORD_KIND: u32 = 30078;
const APP_KIND: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum UdpMessage {
    Hello {
        v: u8,
        node_id: String,
        device_pk: String,
        zones: Vec<String>,
        ts: u64,
    },
    Ack {
        v: u8,
        node_id: String,
        device_pk: String,
        zones: Vec<String>,
        ts: u64,
    },
    Record {
        v: u8,
        zone: String,
        record_type: String,
        event: NostrEvent,
        ts: u64,
    },
}

#[derive(Clone, Debug)]
struct PeerState {
    last_seen: Instant,
    confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRecordPayload {
    device_pk: String,
    identity_id: String,
    device_label: String,
    updated_at: u64,
    expires_at: u64,
    role: String,
    service: String,
    service_version: String,
    ingest_protocols: Vec<String>,
    capabilities: Vec<String>,
    ui_repo: String,
    #[serde(rename = "uiRef")]
    ui_ref: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ui_manifest_url: String,
    ui_entry: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_ws_url: String,
    metrics: DeviceMetricsPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceMetricsPayload {
    uptime_sec: u64,
    peers_known: u64,
    peers_confirmed: u64,
    cameras_total: u64,
    cameras_enabled: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZonePresencePayload {
    #[serde(rename = "type")]
    kind: String,
    zone: String,
    device_pk: String,
    swarm: String,
    role: String,
    service: String,
    service_version: String,
    ts: u64,
    ttl: u64,
}

#[derive(Clone)]
pub struct SwarmHandle {
    peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
}

impl SwarmHandle {
    pub async fn confirmed_peers(&self) -> usize {
        let guard = self.peers.lock().await;
        guard.values().filter(|p| p.confirmed).count()
    }
}

pub async fn start(cfg: Config) -> Result<SwarmHandle> {
    let bind: SocketAddr = cfg
        .swarm
        .bind
        .parse()
        .with_context(|| format!("invalid swarm.bind: {}", cfg.swarm.bind))?;

    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let peers = Arc::new(Mutex::new(resolve_peers(&cfg.swarm.peers).await));
    let table = Arc::new(Mutex::new(HashMap::<SocketAddr, PeerState>::new()));

    let recv_socket = Arc::clone(&socket);
    let recv_peers = Arc::clone(&peers);
    let recv_table = Arc::clone(&table);
    let recv_cfg = cfg.clone();

    tokio::spawn(async move {
        if let Err(err) = recv_loop(recv_socket, recv_peers, recv_table, recv_cfg).await {
            warn!(error = %err, "swarm recv loop exited");
        }
    });

    let tx_socket = Arc::clone(&socket);
    let tx_peers = Arc::clone(&peers);
    let tx_table = Arc::clone(&table);
    let tx_cfg = cfg.clone();

    tokio::spawn(async move {
        if let Err(err) = announce_loop(tx_socket, tx_peers, tx_table, tx_cfg).await {
            warn!(error = %err, "swarm announce loop exited");
        }
    });

    info!(bind = %bind, "swarm udp runtime started");

    Ok(SwarmHandle { peers: table })
}

async fn resolve_peers(raw: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for peer in raw {
        match lookup_host(peer).await {
            Ok(addrs) => out.extend(addrs),
            Err(err) => warn!(peer = %peer, error = %err, "failed resolving swarm peer"),
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

async fn announce_loop(
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    table: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    cfg: Config,
) -> Result<()> {
    let started_at = Instant::now();
    let mut hello_tick = interval(Duration::from_secs(5));
    let mut announce_tick = interval(Duration::from_secs(cfg.swarm.announce_interval_secs.max(5)));
    let zones = cfg
        .swarm
        .zones
        .iter()
        .map(|z| z.key.clone())
        .collect::<Vec<_>>();

    loop {
        tokio::select! {
            _ = hello_tick.tick() => {
                let hello = UdpMessage::Hello {
                    v: PROTOCOL_VERSION,
                    node_id: cfg.node_id.clone(),
                    device_pk: cfg.nostr_pubkey.clone(),
                    zones: zones.clone(),
                    ts: util::now_ms(),
                };
                broadcast_json(&socket, &peers, &hello).await;
            }
            _ = announce_tick.tick() => {
                let peers_known = peers.lock().await.len() as u64;
                let peers_confirmed = table.lock().await.values().filter(|p| p.confirmed).count() as u64;
                let cameras_total = cfg.cameras.len() as u64;
                let cameras_enabled = cfg.cameras.iter().filter(|c| c.enabled).count() as u64;
                let metrics = DeviceMetricsPayload {
                    uptime_sec: started_at.elapsed().as_secs(),
                    peers_known,
                    peers_confirmed,
                    cameras_total,
                    cameras_enabled,
                };

                for zone in &zones {
                    if let Ok(ev) = build_device_record(&cfg, &metrics) {
                        let msg = UdpMessage::Record {
                            v: PROTOCOL_VERSION,
                            zone: zone.clone(),
                            record_type: "device".to_string(),
                            event: ev,
                            ts: util::now_ms(),
                        };
                        broadcast_json(&socket, &peers, &msg).await;
                    }
                    if let Ok(ev) = build_zone_presence(&cfg, zone) {
                        let msg = UdpMessage::Record {
                            v: PROTOCOL_VERSION,
                            zone: zone.clone(),
                            record_type: "zone_presence".to_string(),
                            event: ev,
                            ts: util::now_ms(),
                        };
                        broadcast_json(&socket, &peers, &msg).await;
                    }
                }
            }
        }
    }
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    table: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    cfg: Config,
) -> Result<()> {
    let mut buf = vec![0u8; 65_535];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await?;
        let raw = &buf[..len];
        let msg: UdpMessage = match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match msg {
            UdpMessage::Hello {
                v,
                node_id,
                device_pk,
                zones,
                ..
            } => {
                if v != PROTOCOL_VERSION {
                    continue;
                }
                {
                    let mut guard = table.lock().await;
                    guard.insert(
                        from,
                        PeerState {
                            last_seen: Instant::now(),
                            confirmed: true,
                        },
                    );
                }

                let ack = UdpMessage::Ack {
                    v: PROTOCOL_VERSION,
                    node_id: cfg.node_id.clone(),
                    device_pk: cfg.nostr_pubkey.clone(),
                    zones: cfg.swarm.zones.iter().map(|z| z.key.clone()).collect(),
                    ts: util::now_ms(),
                };
                send_json(&socket, from, &ack).await;

                add_peer(peers.clone(), from).await;
                debug!(from = %from, node_id = %node_id, device_pk = %device_pk, zones = ?zones, "swarm hello received");
            }
            UdpMessage::Ack {
                v,
                device_pk,
                zones,
                ..
            } => {
                if v != PROTOCOL_VERSION {
                    continue;
                }
                {
                    let mut guard = table.lock().await;
                    guard.insert(
                        from,
                        PeerState {
                            last_seen: Instant::now(),
                            confirmed: true,
                        },
                    );
                }
                add_peer(peers.clone(), from).await;
                debug!(from = %from, device_pk = %device_pk, zones = ?zones, "swarm ack received");
            }
            UdpMessage::Record {
                v,
                zone,
                record_type,
                event,
                ..
            } => {
                if v != PROTOCOL_VERSION {
                    continue;
                }
                match nostr::verify_event(&event) {
                    Ok(true) => {
                        debug!(from = %from, zone = %zone, record_type = %record_type, "swarm record received");
                        let mut guard = table.lock().await;
                        if let Some(entry) = guard.get_mut(&from) {
                            entry.last_seen = Instant::now();
                        }
                    }
                    Ok(false) => {
                        debug!(from = %from, "swarm record rejected: invalid signature");
                    }
                    Err(err) => {
                        debug!(from = %from, error = %err, "swarm record rejected: verify error");
                    }
                }
            }
        }
    }
}

async fn add_peer(peers: Arc<Mutex<Vec<SocketAddr>>>, addr: SocketAddr) {
    let mut guard = peers.lock().await;
    if !guard.contains(&addr) {
        guard.push(addr);
    }
}

async fn broadcast_json(socket: &UdpSocket, peers: &Arc<Mutex<Vec<SocketAddr>>>, msg: &UdpMessage) {
    let payload = match serde_json::to_vec(msg) {
        Ok(v) => v,
        Err(_) => return,
    };
    let list = peers.lock().await.clone();
    for peer in list {
        let _ = socket.send_to(&payload, peer).await;
    }
}

async fn send_json(socket: &UdpSocket, to: SocketAddr, msg: &UdpMessage) {
    if let Ok(payload) = serde_json::to_vec(msg) {
        let _ = socket.send_to(&payload, to).await;
    }
}

fn build_device_record(cfg: &Config, metrics: &DeviceMetricsPayload) -> Result<NostrEvent> {
    let now = util::now_ms();
    let payload = DeviceRecordPayload {
        device_pk: cfg.nostr_pubkey.clone(),
        identity_id: cfg.api.identity_id.clone(),
        device_label: cfg.device_label.clone(),
        updated_at: now,
        expires_at: now + 24 * 60 * 60 * 1000,
        role: cfg.node_role.clone(),
        service: "nvr".to_string(),
        service_version: cfg.service_version.clone(),
        ingest_protocols: vec!["onvif".to_string(), "rtsp".to_string()],
        capabilities: vec!["camera".to_string()],
        ui_repo: cfg.ui.repo.clone(),
        ui_ref: cfg.ui.repo_ref.clone(),
        ui_manifest_url: cfg.ui.manifest_url.clone(),
        ui_entry: cfg.ui.entry.clone(),
        session_ws_url: cfg.api.public_ws_url.clone(),
        metrics: metrics.clone(),
    };
    let content = serde_json::to_string(&payload)?;
    let tags = vec![
        vec!["t".to_string(), "swarm_discovery".to_string()],
        vec!["type".to_string(), "device".to_string()],
        vec!["role".to_string(), cfg.node_role.clone()],
        vec!["service".to_string(), "nvr".to_string()],
        vec!["cap".to_string(), "camera".to_string()],
    ];
    let unsigned = nostr::build_unsigned_event(
        &cfg.nostr_pubkey,
        RECORD_KIND,
        tags,
        content,
        util::now_unix_seconds(),
    );
    nostr::sign_event(&unsigned, &cfg.nostr_sk_hex)
}

fn build_zone_presence(cfg: &Config, zone: &str) -> Result<NostrEvent> {
    let payload = ZonePresencePayload {
        kind: "zone_presence".to_string(),
        zone: zone.to_string(),
        device_pk: cfg.nostr_pubkey.clone(),
        swarm: cfg.swarm.endpoint_hint.clone(),
        role: cfg.node_role.clone(),
        service: "nvr".to_string(),
        service_version: cfg.service_version.clone(),
        ts: util::now_ms(),
        ttl: 120,
    };

    let content = serde_json::to_string(&payload)?;
    let tags = vec![
        vec!["t".to_string(), "constitute".to_string()],
        vec!["z".to_string(), zone.to_string()],
    ];

    let unsigned = nostr::build_unsigned_event(
        &cfg.nostr_pubkey,
        APP_KIND,
        tags,
        content,
        util::now_unix_seconds(),
    );
    nostr::sign_event(&unsigned, &cfg.nostr_sk_hex)
}
