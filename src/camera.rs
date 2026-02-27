use crate::config::{CameraConfig, Config};
use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
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

#[derive(Clone)]
pub struct RecorderManager {
    inner: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl RecorderManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn ensure_started(&self, cfg: &Config) {
        for cam in &cfg.cameras {
            if !cam.enabled {
                continue;
            }
            self.start_camera(cfg, cam).await;
        }
    }

    async fn start_camera(&self, cfg: &Config, cam: &CameraConfig) {
        let mut guard = self.inner.lock().await;
        if guard.contains_key(&cam.source_id) {
            return;
        }

        let source_id = cam.source_id.clone();
        let camera = cam.clone();
        let storage_root = cfg.storage_root();

        let handle = tokio::spawn(async move {
            if let Err(err) = record_loop(storage_root, camera).await {
                warn!(error = %err, source = %source_id, "camera recorder exited");
            }
        });

        guard.insert(cam.source_id.clone(), handle);
    }
}

async fn record_loop(storage_root: PathBuf, cam: CameraConfig) -> Result<()> {
    let out_dir = storage_root.join("segments").join(sanitize(&cam.source_id));
    tokio::fs::create_dir_all(&out_dir).await?;

    let output_pattern = out_dir.join("%Y%m%dT%H%M%S.mp4");

    loop {
        let mut cmd = Command::new("ffmpeg");
        cmd.arg("-hide_banner")
            .arg("-loglevel")
            .arg("warning")
            .arg("-rtsp_transport")
            .arg("tcp")
            .arg("-i")
            .arg(&cam.rtsp_url)
            .arg("-c")
            .arg("copy")
            .arg("-f")
            .arg("segment")
            .arg("-segment_time")
            .arg(cam.segment_secs.to_string())
            .arg("-reset_timestamps")
            .arg("1")
            .arg("-strftime")
            .arg("1")
            .arg(output_pattern.to_string_lossy().to_string());

        info!(source = %cam.source_id, rtsp = %cam.rtsp_url, "starting ffmpeg recorder");
        match cmd.status().await {
            Ok(status) => {
                warn!(source = %cam.source_id, code = ?status.code(), "ffmpeg exited; restarting");
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Err(anyhow!("ffmpeg not found in PATH"));
                }
                warn!(source = %cam.source_id, error = %err, "failed to launch ffmpeg; retrying");
            }
        }

        sleep(Duration::from_secs(3)).await;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xaddr() {
        let xml = "<XAddrs>http://10.0.0.2/onvif/device_service https://10.0.0.2/ws</XAddrs>";
        let out = extract_xaddrs(xml);
        assert_eq!(out.len(), 2);
    }
}
