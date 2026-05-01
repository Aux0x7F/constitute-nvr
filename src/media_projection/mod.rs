use crate::camera_device::registry::driver_is_xm;
use crate::config::{CameraDeviceConfig, Config};
use crate::media::{ffmpeg, planner, types::OutputCodec};
use crate::recording::runtime::backoff_secs;
use rtp::packet::Packet as RtpPacket;
use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::{Mutex, broadcast, watch};
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, info, warn};
use util::marshal::Unmarshal;

const PROJECTION_RTP_BUFFER: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProjectionCodec {
    H264,
    Vp8,
}

impl ProjectionCodec {
    pub fn label(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Vp8 => "vp8",
        }
    }

    fn output_codec(self) -> OutputCodec {
        match self {
            Self::H264 => OutputCodec::H264,
            Self::Vp8 => OutputCodec::Vp8,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaProjectionSourceHealth {
    pub source_id: String,
    pub state: String,
    pub policy: String,
    pub codec: String,
    pub selected_stream: String,
    pub subscriber_count: usize,
    pub restart_attempt: u64,
    pub last_packet_timestamp: Option<u64>,
    pub last_error: Option<String>,
    pub warmed_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaProjectionHealth {
    pub state: String,
    pub sources: Vec<MediaProjectionSourceHealth>,
}

#[derive(Clone)]
pub struct MediaProjectionRuntime {
    inner: Arc<Mutex<HashMap<ProjectionKey, Arc<ProjectionHandle>>>>,
}

impl MediaProjectionRuntime {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn warm_enabled_previews(&self, cfg: &Config) {
        for camera in cfg.camera_devices.iter().filter(|camera| camera.enabled) {
            let codec = preferred_projection_codec(camera);
            self.ensure_projection(camera.clone(), codec).await;
        }
    }

    pub async fn subscribe_preview(
        &self,
        camera: CameraDeviceConfig,
        codec: ProjectionCodec,
    ) -> MediaProjectionSubscription {
        let handle = self.ensure_projection(camera, codec).await;
        MediaProjectionSubscription {
            source_id: handle.key.source_id.clone(),
            codec,
            receiver: handle.sender.subscribe(),
        }
    }

    pub async fn health(&self, cfg: &Config) -> MediaProjectionHealth {
        self.warm_enabled_previews(cfg).await;
        let handles = self.inner.lock().await;
        let mut sources = Vec::new();
        for camera in cfg.camera_devices.iter().filter(|camera| camera.enabled) {
            let codec = preferred_projection_codec(camera);
            let key = ProjectionKey::new(&camera.source_id, codec);
            if let Some(handle) = handles.get(&key) {
                let state = handle
                    .state
                    .lock()
                    .await
                    .snapshot(handle.sender.receiver_count());
                sources.push(state);
            } else {
                sources.push(MediaProjectionSourceHealth {
                    source_id: camera.source_id.clone(),
                    state: "warming".to_string(),
                    policy: "preview-projection".to_string(),
                    codec: codec.label().to_string(),
                    selected_stream: "preview".to_string(),
                    subscriber_count: 0,
                    restart_attempt: 0,
                    last_packet_timestamp: None,
                    last_error: None,
                    warmed_at: None,
                });
            }
        }
        MediaProjectionHealth {
            state: aggregate_projection_state(&sources),
            sources,
        }
    }

    async fn ensure_projection(
        &self,
        camera: CameraDeviceConfig,
        codec: ProjectionCodec,
    ) -> Arc<ProjectionHandle> {
        let key = ProjectionKey::new(&camera.source_id, codec);
        let mut handles = self.inner.lock().await;
        if let Some(existing) = handles.get(&key) {
            return Arc::clone(existing);
        }

        let (sender, _) = broadcast::channel(PROJECTION_RTP_BUFFER);
        let (stop_tx, stop_rx) = watch::channel(false);
        let state = Arc::new(Mutex::new(ProjectionState::new(&camera.source_id, codec)));
        let handle = Arc::new(ProjectionHandle {
            key: key.clone(),
            sender: sender.clone(),
            _stop: stop_tx,
            state: Arc::clone(&state),
        });
        handles.insert(key.clone(), Arc::clone(&handle));
        tokio::spawn(run_projection_worker(camera, codec, sender, state, stop_rx));
        handle
    }
}

impl Default for MediaProjectionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MediaProjectionSubscription {
    pub source_id: String,
    pub codec: ProjectionCodec,
    pub receiver: broadcast::Receiver<RtpPacket>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProjectionKey {
    source_id: String,
    codec: ProjectionCodec,
}

impl ProjectionKey {
    fn new(source_id: &str, codec: ProjectionCodec) -> Self {
        Self {
            source_id: source_id.trim().to_string(),
            codec,
        }
    }
}

struct ProjectionHandle {
    key: ProjectionKey,
    sender: broadcast::Sender<RtpPacket>,
    _stop: watch::Sender<bool>,
    state: Arc<Mutex<ProjectionState>>,
}

#[derive(Debug)]
struct ProjectionState {
    source_id: String,
    state: String,
    codec: ProjectionCodec,
    restart_attempt: u64,
    last_packet_timestamp: Option<u64>,
    last_error: Option<String>,
    warmed_at: Option<u64>,
}

impl ProjectionState {
    fn new(source_id: &str, codec: ProjectionCodec) -> Self {
        Self {
            source_id: source_id.to_string(),
            state: "warming".to_string(),
            codec,
            restart_attempt: 0,
            last_packet_timestamp: None,
            last_error: None,
            warmed_at: Some(crate::util::now_ms()),
        }
    }

    fn snapshot(&self, subscriber_count: usize) -> MediaProjectionSourceHealth {
        let state = if self.state == "ready" && subscriber_count > 0 {
            "active".to_string()
        } else if self.state == "ready" && self.last_packet_timestamp.is_some() {
            "warm".to_string()
        } else {
            self.state.clone()
        };
        MediaProjectionSourceHealth {
            source_id: self.source_id.clone(),
            state,
            policy: "preview-projection".to_string(),
            codec: self.codec.label().to_string(),
            selected_stream: "preview".to_string(),
            subscriber_count,
            restart_attempt: self.restart_attempt,
            last_packet_timestamp: self.last_packet_timestamp,
            last_error: self.last_error.clone(),
            warmed_at: self.warmed_at,
        }
    }
}

pub fn preferred_projection_codec(camera: &CameraDeviceConfig) -> ProjectionCodec {
    if driver_is_xm(camera.driver_id.trim()) {
        ProjectionCodec::Vp8
    } else {
        ProjectionCodec::H264
    }
}

fn aggregate_projection_state(sources: &[MediaProjectionSourceHealth]) -> String {
    if sources.is_empty() {
        return "idle".to_string();
    }
    if sources
        .iter()
        .any(|source| source.state == "error" || source.state == "backoff")
    {
        return "degraded".to_string();
    }
    if sources.iter().any(|source| source.state == "active") {
        return "active".to_string();
    }
    if sources
        .iter()
        .any(|source| source.state == "warming" || source.state == "starting")
    {
        return "warming".to_string();
    }
    "ready".to_string()
}

async fn run_projection_worker(
    camera: CameraDeviceConfig,
    codec: ProjectionCodec,
    sender: broadcast::Sender<RtpPacket>,
    state: Arc<Mutex<ProjectionState>>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let plan = planner::preview_pipeline_plan_for_codec(&camera, codec.output_codec());
    let std_socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(err) => {
            set_projection_error(&state, format!("udp bind failed: {err}")).await;
            warn!(source = %camera.source_id, error = %err, "media projection UDP bind failed");
            return;
        }
    };
    if let Err(err) = std_socket.set_nonblocking(true) {
        set_projection_error(&state, format!("udp nonblocking setup failed: {err}")).await;
        warn!(source = %camera.source_id, error = %err, "media projection UDP nonblocking setup failed");
        return;
    }
    let local_addr = match std_socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            set_projection_error(&state, format!("udp local addr failed: {err}")).await;
            warn!(source = %camera.source_id, error = %err, "media projection UDP local addr failed");
            return;
        }
    };
    let socket = match UdpSocket::from_std(std_socket) {
        Ok(socket) => socket,
        Err(err) => {
            set_projection_error(&state, format!("udp socket init failed: {err}")).await;
            warn!(source = %camera.source_id, error = %err, "media projection UDP socket init failed");
            return;
        }
    };

    let mut buf = vec![0u8; 1600];
    let mut continuity = ProjectionRtpContinuity::default();

    loop {
        if *stop_rx.borrow() {
            break;
        }

        {
            let mut current = state.lock().await;
            current.state = "starting".to_string();
            current.last_error = None;
        }

        let mut ffmpeg = Command::new("ffmpeg");
        ffmpeg.args(ffmpeg::build_live_preview_ffmpeg_args(
            &plan,
            local_addr.port(),
        ));

        let mut child = match ffmpeg.stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            Ok(child) => child,
            Err(err) => {
                let backoff =
                    note_projection_backoff(&state, format!("ffmpeg start failed: {err}")).await;
                warn!(
                    source = %camera.source_id,
                    codec = codec.label(),
                    error = %err,
                    backoff_secs = backoff,
                    "media projection worker failed to start; will retry"
                );
                wait_or_stop(Duration::from_secs(backoff), &mut stop_rx).await;
                continue;
            }
        };

        info!(
            source = %camera.source_id,
            codec = codec.label(),
            "media projection worker started"
        );

        let exit_reason = loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    break ProjectionExitReason::Stopped;
                }
                status = child.wait() => {
                    break match status {
                        Ok(status) => ProjectionExitReason::ChildExited(format!("ffmpeg exited with status {}", status)),
                        Err(err) => ProjectionExitReason::ChildWaitFailed(err.to_string()),
                    };
                }
                recv = timeout(Duration::from_secs(projection_no_packet_timeout_secs()), socket.recv_from(&mut buf)) => {
                    match recv {
                        Ok(Ok((len, _))) => {
                            let mut slice = &buf[..len];
                            let mut packet = match RtpPacket::unmarshal(&mut slice) {
                                Ok(packet) => packet,
                                Err(err) => {
                                    warn!(source = %camera.source_id, error = %err, "media projection RTP unmarshal failed");
                                    continue;
                                }
                            };
                            continuity.rewrite(&mut packet);
                            {
                                let mut current = state.lock().await;
                                current.state = "ready".to_string();
                                current.restart_attempt = 0;
                                current.last_packet_timestamp = Some(crate::util::now_ms());
                                current.last_error = None;
                            }
                            let _ = sender.send(packet);
                        }
                        Ok(Err(err)) => {
                            break ProjectionExitReason::SocketRecvFailed(err.to_string());
                        }
                        Err(_) => {
                            break ProjectionExitReason::NoPackets(projection_no_packet_timeout_secs());
                        }
                    }
                }
            }
        };

        let _ = child.kill().await;
        let _ = child.wait().await;

        match exit_reason {
            ProjectionExitReason::Stopped => break,
            ProjectionExitReason::ChildExited(message)
            | ProjectionExitReason::ChildWaitFailed(message)
            | ProjectionExitReason::SocketRecvFailed(message) => {
                let backoff = note_projection_backoff(&state, message.clone()).await;
                warn!(
                    source = %camera.source_id,
                    codec = codec.label(),
                    message,
                    backoff_secs = backoff,
                    "media projection worker exited; restarting"
                );
                wait_or_stop(Duration::from_secs(backoff), &mut stop_rx).await;
            }
            ProjectionExitReason::NoPackets(timeout_secs) => {
                let message = format!("no RTP packets for {timeout_secs}s");
                let backoff = note_projection_backoff(&state, message).await;
                warn!(
                    source = %camera.source_id,
                    codec = codec.label(),
                    idle_timeout_secs = timeout_secs,
                    backoff_secs = backoff,
                    "media projection worker stalled; restarting"
                );
                wait_or_stop(Duration::from_secs(backoff), &mut stop_rx).await;
            }
        }
    }

    {
        let mut current = state.lock().await;
        current.state = "stopped".to_string();
    }
    debug!(source = %camera.source_id, codec = codec.label(), "media projection worker stopped");
}

async fn wait_or_stop(duration: Duration, stop_rx: &mut watch::Receiver<bool>) {
    tokio::select! {
        _ = stop_rx.changed() => {}
        _ = sleep(duration) => {}
    }
}

async fn set_projection_error(state: &Arc<Mutex<ProjectionState>>, message: String) {
    let mut current = state.lock().await;
    current.state = "error".to_string();
    current.last_error = Some(message);
}

async fn note_projection_backoff(state: &Arc<Mutex<ProjectionState>>, message: String) -> u64 {
    let mut current = state.lock().await;
    current.restart_attempt = current.restart_attempt.saturating_add(1);
    current.state = "backoff".to_string();
    current.last_error = Some(message);
    backoff_secs(current.restart_attempt)
}

fn projection_no_packet_timeout_secs() -> u64 {
    8
}

#[derive(Debug)]
enum ProjectionExitReason {
    Stopped,
    ChildExited(String),
    ChildWaitFailed(String),
    SocketRecvFailed(String),
    NoPackets(u64),
}

#[derive(Debug, Default)]
struct ProjectionRtpContinuity {
    last_source_sequence: Option<u16>,
    last_source_timestamp: Option<u32>,
    last_output_sequence: Option<u16>,
    last_output_timestamp: Option<u32>,
    last_timestamp_step: u32,
}

impl ProjectionRtpContinuity {
    fn rewrite(&mut self, packet: &mut RtpPacket) {
        let source_sequence = packet.header.sequence_number;
        let source_timestamp = packet.header.timestamp;

        match (
            self.last_source_sequence,
            self.last_source_timestamp,
            self.last_output_sequence,
            self.last_output_timestamp,
        ) {
            (Some(prev_src_seq), Some(prev_src_ts), Some(prev_out_seq), Some(prev_out_ts)) => {
                let sequence_step = continuity_sequence_step(prev_src_seq, source_sequence);
                let timestamp_step = continuity_timestamp_step(
                    prev_src_ts,
                    source_timestamp,
                    self.last_timestamp_step,
                );
                let output_sequence = prev_out_seq.wrapping_add(sequence_step);
                let output_timestamp = prev_out_ts.wrapping_add(timestamp_step);
                packet.header.sequence_number = output_sequence;
                packet.header.timestamp = output_timestamp;
                self.last_output_sequence = Some(output_sequence);
                self.last_output_timestamp = Some(output_timestamp);
                self.last_timestamp_step = timestamp_step.max(1);
            }
            _ => {
                packet.header.sequence_number = source_sequence;
                packet.header.timestamp = source_timestamp;
                self.last_output_sequence = Some(source_sequence);
                self.last_output_timestamp = Some(source_timestamp);
                self.last_timestamp_step = default_projection_timestamp_step();
            }
        }

        self.last_source_sequence = Some(source_sequence);
        self.last_source_timestamp = Some(source_timestamp);
    }
}

fn continuity_sequence_step(previous: u16, current: u16) -> u16 {
    let delta = current.wrapping_sub(previous);
    if delta == 0 || delta > 4096 { 1 } else { delta }
}

fn continuity_timestamp_step(previous: u32, current: u32, last_step: u32) -> u32 {
    let delta = current.wrapping_sub(previous);
    if delta == 0 {
        0
    } else if delta > continuity_restart_timestamp_threshold() {
        last_step.max(default_projection_timestamp_step())
    } else {
        delta
    }
}

fn default_projection_timestamp_step() -> u32 {
    3000
}

fn continuity_restart_timestamp_threshold() -> u32 {
    90_000 * 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_projection_codec_uses_vp8_for_xm_only() {
        let xm = test_camera("xm", "xm_40e");
        let generic = test_camera("generic", "generic_onvif_rtsp");
        assert_eq!(preferred_projection_codec(&xm), ProjectionCodec::Vp8);
        assert_eq!(preferred_projection_codec(&generic), ProjectionCodec::H264);
    }

    #[test]
    fn aggregate_projection_state_prefers_degraded_then_active() {
        let mut source = MediaProjectionSourceHealth {
            source_id: "cam".to_string(),
            state: "active".to_string(),
            policy: "preview-projection".to_string(),
            codec: "h264".to_string(),
            selected_stream: "preview".to_string(),
            subscriber_count: 1,
            restart_attempt: 0,
            last_packet_timestamp: Some(1),
            last_error: None,
            warmed_at: Some(1),
        };
        assert_eq!(aggregate_projection_state(&[source.clone()]), "active");
        source.state = "backoff".to_string();
        assert_eq!(aggregate_projection_state(&[source]), "degraded");
    }

    #[test]
    fn projection_no_packet_timeout_stays_short() {
        assert_eq!(projection_no_packet_timeout_secs(), 8);
    }

    #[test]
    fn projection_rtp_continuity_rewrites_large_restart_jumps() {
        let mut continuity = ProjectionRtpContinuity::default();
        let mut first = RtpPacket::default();
        first.header.sequence_number = 40_000;
        first.header.timestamp = 120_000;
        continuity.rewrite(&mut first);
        assert_eq!(first.header.sequence_number, 40_000);
        assert_eq!(first.header.timestamp, 120_000);

        let mut second = RtpPacket::default();
        second.header.sequence_number = 40_003;
        second.header.timestamp = 123_000;
        continuity.rewrite(&mut second);
        assert_eq!(second.header.sequence_number, 40_003);
        assert_eq!(second.header.timestamp, 123_000);

        let mut restarted = RtpPacket::default();
        restarted.header.sequence_number = 7;
        restarted.header.timestamp = 9_000;
        continuity.rewrite(&mut restarted);
        assert_eq!(restarted.header.sequence_number, 40_004);
        assert_eq!(restarted.header.timestamp, 126_000);
    }

    fn test_camera(source_id: &str, driver_id: &str) -> CameraDeviceConfig {
        CameraDeviceConfig {
            source_id: source_id.to_string(),
            name: source_id.to_string(),
            onvif_host: "10.0.0.10".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://example.invalid/preview".to_string(),
            username: String::new(),
            password: String::new(),
            driver_id: driver_id.to_string(),
            vendor: String::new(),
            model: String::new(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        }
    }
}
