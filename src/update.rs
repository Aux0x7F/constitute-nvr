use crate::config::Config;
use tokio::process::Command;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub fn spawn_update_poller(cfg: Config) {
    if !cfg.update.enabled {
        info!("update poller disabled by config");
        return;
    }

    tokio::spawn(async move {
        let script = cfg.update.script_path.clone();
        let mut tick = interval(Duration::from_secs(cfg.update.interval_secs.max(60)));
        info!(
            interval_secs = cfg.update.interval_secs,
            script = %script,
            "update poller started"
        );

        loop {
            tick.tick().await;
            let mut cmd = Command::new(&script);
            cmd.arg("--source-dir")
                .arg(&cfg.update.source_dir)
                .arg("--branch")
                .arg(&cfg.update.branch)
                .arg("--service-name")
                .arg("constitute-nvr")
                .arg("--try-restart");

            match cmd.status().await {
                Ok(status) if status.success() => {
                    debug!("update poll executed successfully");
                }
                Ok(status) => {
                    warn!(code = ?status.code(), "update poll script returned non-zero");
                }
                Err(err) => {
                    warn!(error = %err, script = %script, "update poll failed to launch");
                }
            }
        }
    });
}
