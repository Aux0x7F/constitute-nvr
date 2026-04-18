use crate::config::{CameraConfig, Config};
use crate::drivers::driver_is_xm;
use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep, timeout};
use tracing::{info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredCamera {
    pub endpoint: String,
    pub from: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRuntimeState {
    pub source_id: String,
    pub state: String,
    pub restart_attempt: u64,
    pub backoff_secs: u64,
    pub last_error: String,
    pub updated_at: u64,
}

struct RuntimeEntry {
    state: Arc<Mutex<SourceRuntimeState>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
pub struct RecorderManager {
    inner: Arc<Mutex<HashMap<String, RuntimeEntry>>>,
}

impl RecorderManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn ensure_started(&self, cfg: &Config) {
        let storage_root = cfg.storage_root();
        for cam in &cfg.cameras {
            self.upsert_camera(storage_root.clone(), cam.clone()).await;
        }
    }

    pub async fn upsert_camera(&self, storage_root: PathBuf, cam: CameraConfig) {
        self.remove_camera(&cam.source_id).await;

        let state = Arc::new(Mutex::new(SourceRuntimeState {
            source_id: cam.source_id.clone(),
            state: if cam.enabled {
                "starting".to_string()
            } else {
                "stopped".to_string()
            },
            restart_attempt: 0,
            backoff_secs: 0,
            last_error: String::new(),
            updated_at: now_ms(),
        }));

        let handle = if cam.enabled {
            let source_id = cam.source_id.clone();
            let camera = cam.clone();
            let state_ref = Arc::clone(&state);
            Some(tokio::spawn(async move {
                if let Err(err) = record_loop(storage_root, camera, Arc::clone(&state_ref)).await {
                    warn!(error = %err, source = %source_id, "camera recorder exited");
                    update_state(&state_ref, "failed", 0, String::from(err.to_string()), None)
                        .await;
                }
            }))
        } else {
            None
        };

        let mut guard = self.inner.lock().await;
        guard.insert(cam.source_id.clone(), RuntimeEntry { state, handle });
    }

    pub async fn remove_camera(&self, source_id: &str) -> bool {
        let source = String::from(source_id);
        let entry = {
            let mut guard = self.inner.lock().await;
            guard.remove(&source)
        };

        if let Some(mut entry) = entry {
            if let Some(handle) = entry.handle.take() {
                handle.abort();
            }
            update_state(&entry.state, "stopped", 0, String::new(), None).await;
            return true;
        }
        false
    }

    pub async fn list_states(&self) -> Vec<SourceRuntimeState> {
        let entries: Vec<Arc<Mutex<SourceRuntimeState>>> = {
            let guard = self.inner.lock().await;
            guard.values().map(|e| Arc::clone(&e.state)).collect()
        };

        let mut out = Vec::with_capacity(entries.len());
        for state in entries {
            out.push(state.lock().await.clone());
        }
        out.sort_by(|a, b| a.source_id.cmp(&b.source_id));
        out
    }
}

async fn record_loop(
    storage_root: PathBuf,
    cam: CameraConfig,
    state: Arc<Mutex<SourceRuntimeState>>,
) -> Result<()> {
    let out_dir = storage_root.join("segments").join(sanitize(&cam.source_id));
    tokio::fs::create_dir_all(&out_dir).await?;

    let output_pattern = out_dir.join("%Y%m%dT%H%M%S.mp4");
    let mut restart_attempt: u64 = 0;

    loop {
        update_state(&state, "starting", restart_attempt, String::new(), Some(0)).await;
        let baseline_segments = count_segment_files(&out_dir).await?;

        let mut cmd = Command::new("ffmpeg");
        cmd.args(build_ffmpeg_record_args(&cam, &output_pattern))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        info!(
            source = %cam.source_id,
            onvif_host = %cam.onvif_host,
            segment_secs = cam.segment_secs,
            "starting ffmpeg recorder"
        );
        update_state(
            &state,
            "connecting",
            restart_attempt,
            String::new(),
            Some(0),
        )
        .await;

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Err(anyhow!("ffmpeg not found in PATH"));
                }

                let message = format!("failed to launch ffmpeg: {}", err);
                warn!(source = %cam.source_id, error = %err, "failed to launch ffmpeg; retrying");
                restart_attempt = restart_attempt.saturating_add(1);
                let backoff = backoff_secs(restart_attempt);
                update_state(&state, "backoff", restart_attempt, message, Some(backoff)).await;
                sleep(Duration::from_secs(backoff)).await;
                continue;
            }
        };

        let mut marked_running = false;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let message = format!("ffmpeg exited with code {:?}", status.code());
                    warn!(source = %cam.source_id, code = ?status.code(), "ffmpeg exited; restarting");
                    restart_attempt = restart_attempt.saturating_add(1);
                    let backoff = backoff_secs(restart_attempt);
                    update_state(&state, "backoff", restart_attempt, message, Some(backoff)).await;
                    sleep(Duration::from_secs(backoff)).await;
                    break;
                }
                Ok(None) => {
                    if !marked_running {
                        let current_segments = count_segment_files(&out_dir)
                            .await
                            .unwrap_or(baseline_segments);
                        if current_segments > baseline_segments {
                            marked_running = true;
                            update_state(
                                &state,
                                "running",
                                restart_attempt,
                                String::new(),
                                Some(0),
                            )
                            .await;
                        }
                    }
                    sleep(Duration::from_secs(1)).await;
                }
                Err(err) => {
                    let message = format!("ffmpeg status check failed: {}", err);
                    warn!(source = %cam.source_id, error = %err, "failed to inspect ffmpeg status; retrying");
                    restart_attempt = restart_attempt.saturating_add(1);
                    let backoff = backoff_secs(restart_attempt);
                    update_state(&state, "backoff", restart_attempt, message, Some(backoff)).await;
                    sleep(Duration::from_secs(backoff)).await;
                    break;
                }
            }
        }
    }
}

async fn count_segment_files(out_dir: &PathBuf) -> Result<u64> {
    let mut count = 0u64;
    let mut reader = tokio::fs::read_dir(out_dir).await?;
    while let Some(entry) = reader.next_entry().await? {
        if entry
            .path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("mp4"))
            .unwrap_or(false)
        {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn backoff_secs(attempt: u64) -> u64 {
    let p = attempt.clamp(1, 6);
    let secs = 2_u64.pow(p as u32);
    secs.min(30)
}

fn build_ffmpeg_record_args(cam: &CameraConfig, output_pattern: &std::path::Path) -> Vec<String> {
    let mut args = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "warning".to_string(),
        "-rtsp_transport".to_string(),
        "tcp".to_string(),
        "-i".to_string(),
        cam.rtsp_url.clone(),
    ];
    if driver_is_xm(&cam.driver_id) {
        args.extend([
            "-map".to_string(),
            "0:v:0".to_string(),
            "-c:v".to_string(),
            "copy".to_string(),
        ]);
    } else {
        args.extend(["-c".to_string(), "copy".to_string()]);
    }
    args.extend([
        "-f".to_string(),
        "segment".to_string(),
        "-segment_time".to_string(),
        cam.segment_secs.to_string(),
        "-reset_timestamps".to_string(),
        "1".to_string(),
        "-strftime".to_string(),
        "1".to_string(),
        output_pattern.to_string_lossy().to_string(),
    ]);
    args
}

async fn update_state(
    state: &Arc<Mutex<SourceRuntimeState>>,
    status: &str,
    restart_attempt: u64,
    last_error: String,
    backoff_secs: Option<u64>,
) {
    let mut guard = state.lock().await;
    guard.state = status.to_string();
    guard.restart_attempt = restart_attempt;
    guard.backoff_secs = backoff_secs.unwrap_or(guard.backoff_secs);
    guard.last_error = last_error;
    guard.updated_at = now_ms();
}

pub async fn discover_onvif(timeout_secs: u64) -> Result<Vec<DiscoveredCamera>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let probe = build_probe_xml();

    socket
        .send_to(probe.as_bytes(), "239.255.255.250:3702")
        .await?;

    let mut seen = HashMap::<String, String>::new();
    let deadline = Duration::from_secs(timeout_secs.max(1));
    let mut buf = vec![0u8; 16 * 1024];

    while let Ok(recv) = timeout(deadline, socket.recv_from(&mut buf)).await {
        match recv {
            Ok((len, from)) => {
                let payload = String::from_utf8_lossy(&buf[..len]);
                for xaddr in extract_xaddrs(&payload) {
                    seen.entry(xaddr).or_insert_with(|| from.to_string());
                }
            }
            Err(_) => break,
        }
    }

    let out = seen
        .into_iter()
        .map(|(endpoint, from)| DiscoveredCamera { endpoint, from })
        .collect::<Vec<_>>();

    Ok(out)
}

fn build_probe_xml() -> String {
    format!(
        r#"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\"
            xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"
            xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"
            xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">
  <e:Header>
    <w:MessageID>uuid:{}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"#,
        uuid::Uuid::new_v4()
    )
}

fn extract_xaddrs(xml: &str) -> Vec<String> {
    let re = Regex::new(r"<[^>]*XAddrs[^>]*>([^<]+)</[^>]*XAddrs>").expect("regex");
    let mut out = Vec::new();
    for cap in re.captures_iter(xml) {
        if let Some(m) = cap.get(1) {
            for entry in m.as_str().split_whitespace() {
                if entry.starts_with("http://") || entry.starts_with("https://") {
                    out.push(entry.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xaddr() {
        let xml = "<XAddrs>http://10.0.0.2/onvif/device_service https://10.0.0.2/ws</XAddrs>";
        let out = extract_xaddrs(xml);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn backoff_bounds() {
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(8), 30);
    }

    #[test]
    fn xm_record_args_use_video_only_copy() {
        let camera = CameraConfig {
            source_id: "xm-1".to_string(),
            name: "XM".to_string(),
            onvif_host: "192.168.0.201".to_string(),
            onvif_port: 8000,
            rtsp_url: "rtsp://admin:123456@192.168.0.201:554/user=admin_password=123456_channel=1_stream=0.sdp?real_stream".to_string(),
            username: "admin".to_string(),
            password: "123456".to_string(),
            driver_id: "xm_40e".to_string(),
            vendor: "XM/NetSurveillance".to_string(),
            model: "XM RTSP camera".to_string(),
            mac_address: String::new(),
            rtsp_port: 554,
            ptz_capable: false,
            enabled: true,
            segment_secs: 10,
            desired: Default::default(),
            credentials: Default::default(),
        };
        let args = build_ffmpeg_record_args(&camera, &PathBuf::from("/tmp/out-%Y%m%dT%H%M%S.mp4"));
        assert!(args.windows(2).any(|pair| pair == ["-map", "0:v:0"]));
        assert!(args.windows(2).any(|pair| pair == ["-c:v", "copy"]));
        assert!(!args.windows(2).any(|pair| pair == ["-c", "copy"]));
    }
}
