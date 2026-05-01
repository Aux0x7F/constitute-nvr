use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use crate::config::CameraDeviceConfig;
use crate::media::{ffmpeg, planner};

use super::runtime::{SourceRuntimeState, backoff_secs, update_state};
use super::segments::count_segment_files;

pub async fn record_loop(
    storage_root: PathBuf,
    cam: CameraDeviceConfig,
    state: Arc<Mutex<SourceRuntimeState>>,
) -> Result<()> {
    let out_dir = storage_root
        .join("segments")
        .join(super::runtime::sanitize(&cam.source_id));
    tokio::fs::create_dir_all(&out_dir).await?;

    let output_pattern = out_dir.join("%Y%m%dT%H%M%S.mp4");
    let mut restart_attempt: u64 = 0;

    loop {
        update_state(&state, "starting", restart_attempt, String::new(), Some(0)).await;
        let baseline_segments = count_segment_files(&out_dir).await?;
        let plan = planner::recording_pipeline_plan(&cam);

        let mut cmd = Command::new("ffmpeg");
        cmd.args(ffmpeg::build_recording_ffmpeg_args(&plan, &output_pattern))
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
                let message = format!("failed to start ffmpeg: {}", err);
                warn!(source = %cam.source_id, error = %err, "failed to start ffmpeg; retrying");
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
