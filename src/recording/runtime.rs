use crate::config::{CameraDeviceConfig, Config};
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

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
        for cam in &cfg.camera_devices {
            self.upsert_camera(storage_root.clone(), cam.clone()).await;
        }
    }

    pub async fn upsert_camera(&self, storage_root: PathBuf, cam: CameraDeviceConfig) {
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
                if let Err(err) =
                    super::worker::record_loop(storage_root, camera, Arc::clone(&state_ref)).await
                {
                    tracing::warn!(error = %err, source = %source_id, "camera recorder exited");
                    update_state(&state_ref, "failed", 0, err.to_string(), None).await;
                }
            }))
        } else {
            None
        };

        let mut guard = self.inner.lock().await;
        guard.insert(cam.source_id.clone(), RuntimeEntry { state, handle });
    }

    pub async fn remove_camera(&self, source_id: &str) -> bool {
        let source = source_id.to_string();
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
            guard
                .values()
                .map(|entry| Arc::clone(&entry.state))
                .collect()
        };

        let mut out = Vec::with_capacity(entries.len());
        for state in entries {
            out.push(state.lock().await.clone());
        }
        out.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        out
    }
}

pub(crate) async fn update_state(
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

pub(crate) fn backoff_secs(attempt: u64) -> u64 {
    let p = attempt.clamp(1, 6);
    let secs = 2_u64.pow(p as u32);
    secs.min(30)
}

pub(crate) fn sanitize(value: &str) -> String {
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

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

    Ok(seen
        .into_iter()
        .map(|(endpoint, from)| DiscoveredCamera { endpoint, from })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::{ffmpeg, planner};

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
        let camera = CameraDeviceConfig {
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
        let plan = planner::recording_pipeline_plan(&camera);
        let args = ffmpeg::build_recording_ffmpeg_args(
            &plan,
            &PathBuf::from("/tmp/out-%Y%m%dT%H%M%S.mp4"),
        );
        assert!(args.windows(2).any(|pair| pair == ["-map", "0:v:0"]));
        assert!(args.windows(2).any(|pair| pair == ["-c:v", "copy"]));
        assert!(!args.windows(2).any(|pair| pair == ["-c", "copy"]));
    }
}
