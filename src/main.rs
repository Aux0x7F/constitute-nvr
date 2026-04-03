mod api;
mod camera;
mod config;
mod crypto;
mod live;
mod nostr;
mod reolink;
mod reolink_cgi;
#[allow(dead_code)]
mod reolink_proto;
mod storage;
mod swarm;
mod update;
mod util;

use anyhow::Result;
use clap::Parser;
use config::{CameraConfig, Config};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "constitute-nvr",
    version,
    about = "Constitute NVR service (ONVIF ingest + swarm-native presence)"
)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long)]
    once: bool,
    #[arg(long)]
    discover_onvif: bool,
    #[arg(long)]
    discover_reolink: bool,
    #[arg(long)]
    discover_reolink_hint_ip: Option<String>,
    #[arg(long)]
    probe_reolink_ip: Option<String>,
    #[arg(long)]
    setup_reolink_ip: Option<String>,
    #[arg(long, default_value = "admin")]
    setup_reolink_username: String,
    #[arg(long)]
    setup_reolink_password: Option<String>,
    #[arg(long)]
    setup_reolink_desired_password: Option<String>,
    #[arg(long)]
    setup_reolink_generate_password: bool,
    #[arg(long)]
    bootstrap_reolink_server_ip: Option<String>,
    #[arg(long, default_value = "192.168.1.20")]
    bootstrap_reolink_lease_ip: String,
    #[arg(long)]
    bootstrap_reolink_target_mac: Option<String>,
    #[arg(long, default_value_t = 20)]
    bootstrap_reolink_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

    if args.discover_onvif {
        let discovered = camera::discover_onvif(3).await?;
        println!("{}", serde_json::to_string_pretty(&discovered)?);
        return Ok(());
    }

    if args.discover_reolink {
        let discovered = if let Some(hint) = &args.discover_reolink_hint_ip {
            reolink::discover_with_hint(hint, 3).await?
        } else {
            reolink::discover(3).await?
        };
        println!("{}", serde_json::to_string_pretty(&discovered)?);
        return Ok(());
    }

    if let Some(ip) = &args.probe_reolink_ip {
        let probe = reolink::probe(ip, 3).await?;
        println!("{}", serde_json::to_string_pretty(&probe)?);
        return Ok(());
    }

    if let Some(ip) = &args.setup_reolink_ip {
        let result = reolink::setup(reolink::ReolinkSetupRequest {
            ip: ip.clone(),
            username: args.setup_reolink_username.clone(),
            password: args.setup_reolink_password.clone().unwrap_or_default(),
            desired_password: args
                .setup_reolink_desired_password
                .clone()
                .unwrap_or_default(),
            generate_password: args.setup_reolink_generate_password,
            normal: None,
            advanced: None,
            p2p: None,
        })
        .await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    if let Some(server_ip) = &args.bootstrap_reolink_server_ip {
        let bootstrap = reolink::bootstrap(reolink::ReolinkBootstrapRequest {
            server_ip: server_ip.clone(),
            lease_ip: args.bootstrap_reolink_lease_ip.clone(),
            target_mac: args
                .bootstrap_reolink_target_mac
                .clone()
                .unwrap_or_default(),
            timeout_secs: args.bootstrap_reolink_timeout_secs,
            subnet_mask: "255.255.255.0".to_string(),
            router_ip: String::new(),
            dns_ip: String::new(),
        })
        .await?;

        let should_setup = args.setup_reolink_password.is_some()
            || args.setup_reolink_desired_password.is_some()
            || args.setup_reolink_generate_password;
        if should_setup {
            let setup = reolink::setup(reolink::ReolinkSetupRequest {
                ip: bootstrap.assigned_ip.clone(),
                username: args.setup_reolink_username.clone(),
                password: args.setup_reolink_password.clone().unwrap_or_default(),
                desired_password: args
                    .setup_reolink_desired_password
                    .clone()
                    .unwrap_or_default(),
                generate_password: args.setup_reolink_generate_password,
                normal: None,
                advanced: None,
                p2p: None,
            })
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "bootstrap": bootstrap,
                    "setup": setup,
                }))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&bootstrap)?);
        }
        return Ok(());
    }

    let cfg_path = args
        .config
        .unwrap_or_else(|| PathBuf::from("/etc/constitute-nvr/config.json"));
    let (mut cfg, created) = Config::load_or_create(&cfg_path)?;

    if created {
        warn!(path = %cfg_path.display(), "created new config file; update placeholders before production use");
    }

    if cfg.storage.root == config::DEFAULT_STORAGE_PLACEHOLDER {
        warn!(
            placeholder = %config::DEFAULT_STORAGE_PLACEHOLDER,
            "storage root is still placeholder; set a dedicated mount path"
        );
    }

    warn_if_camera_network_not_ready(&cfg);
    warn_if_template_cameras(&cfg);

    if let Err(err) = run_reolink_autoprovision(&mut cfg, &cfg_path).await {
        warn!(error = %err, "reolink auto-provision failed");
    }

    let storage =
        storage::StorageManager::new(cfg.storage_root(), &cfg.storage.encryption_key_hex)?;
    storage.ensure_dirs().await?;
    storage.start_encryptor(cfg.storage.encrypt_interval_secs);

    let recorder = camera::RecorderManager::new();
    recorder.ensure_started(&cfg).await;

    let swarm_handle = swarm::start(cfg.clone()).await?;

    if args.once {
        let sources = storage.list_sources().await.unwrap_or_default();
        println!("constitute-nvr: startup check complete");
        println!("node_id: {}", cfg.node_id);
        println!("role: {}", cfg.node_role);
        println!("identity_id: {}", cfg.api.identity_id);
        println!("storage_root: {}", cfg.storage.root);
        println!("sources: {}", sources.len());
        println!(
            "swarm_confirmed_peers: {}",
            swarm_handle.confirmed_peers().await
        );
        return Ok(());
    }

    update::spawn_update_poller(cfg.clone());

    info!(
        node_id = %cfg.node_id,
        role = %cfg.node_role,
        identity_id = %cfg.api.identity_id,
        storage = %cfg.storage.root,
        camera_count = cfg.cameras.len(),
        "constitute-nvr starting"
    );

    api::run(cfg, cfg_path, storage, recorder).await
}

fn warn_if_camera_network_not_ready(cfg: &Config) {
    if !cfg.camera_network.managed {
        return;
    }

    let iface = cfg.camera_network.interface.trim();
    if iface.is_empty() {
        warn!("camera_network is managed but interface is not configured");
        return;
    }

    let link = Command::new("ip").args(["link", "show", iface]).output();
    match link {
        Ok(output) if output.status.success() => {}
        Ok(_) => {
            warn!(interface = iface, "configured camera interface not present");
            return;
        }
        Err(err) => {
            warn!(interface = iface, error = %err, "failed inspecting camera interface");
            return;
        }
    }

    let host_ip = cfg.camera_network.host_ip.trim();
    if host_ip.is_empty() {
        warn!(
            interface = iface,
            "camera_network host_ip is not configured"
        );
        return;
    }

    let addr = Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output();
    match addr {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            if !text.contains(host_ip) {
                warn!(
                    interface = iface,
                    host_ip = host_ip,
                    subnet = %cfg.camera_network.subnet_cidr,
                    "camera network address is not present on configured interface"
                );
            }
        }
        Ok(_) => {
            warn!(
                interface = iface,
                "failed reading configured camera interface addresses"
            );
        }
        Err(err) => {
            warn!(interface = iface, error = %err, "failed reading configured camera interface addresses");
        }
    }
}

fn warn_if_template_cameras(cfg: &Config) {
    for cam in &cfg.cameras {
        if looks_like_template_camera(cam) {
            warn!(
                source = %cam.source_id,
                onvif_host = %cam.onvif_host,
                "camera source still matches template defaults; replace it with discovered camera config"
            );
        }
    }
}

fn looks_like_template_camera(cam: &CameraConfig) -> bool {
    cam.onvif_host.trim() == "10.60.0.11"
        || cam.rtsp_url.contains("@10.60.0.11:")
        || (cam.source_id.trim() == "cam-reolink-e1"
            && cam.username.trim() == "user"
            && cam.password.trim() == "pass")
}

async fn run_reolink_autoprovision(cfg: &mut Config, cfg_path: &Path) -> Result<()> {
    if !cfg.autoprovision.reolink_enabled {
        return Ok(());
    }

    let username = cfg.autoprovision.reolink_username.trim().to_string();
    if username.is_empty() {
        warn!("reolink auto-provision skipped: username is empty");
        return Ok(());
    }

    if cfg.autoprovision.reolink_password.trim().is_empty()
        && cfg.autoprovision.reolink_desired_password.trim().is_empty()
        && !cfg.autoprovision.reolink_generate_password
    {
        warn!("reolink auto-provision skipped: no password material configured");
        return Ok(());
    }

    let timeout = cfg.autoprovision.reolink_discover_timeout_secs.max(1);
    let hint_ip = cfg.autoprovision.reolink_hint_ip.trim().to_string();
    let discovered = if hint_ip.is_empty() {
        reolink::discover(timeout).await?
    } else {
        reolink::discover_with_hint(&hint_ip, timeout).await?
    };

    if discovered.is_empty() {
        info!("reolink auto-provision: no cameras discovered");
        return Ok(());
    }

    let mut changed = false;
    for device in discovered {
        let ip = device.ip.trim().to_string();
        if ip.is_empty() {
            continue;
        }

        let setup_req = reolink::ReolinkSetupRequest {
            ip: ip.clone(),
            username: username.clone(),
            password: cfg.autoprovision.reolink_password.clone(),
            desired_password: cfg.autoprovision.reolink_desired_password.clone(),
            generate_password: cfg.autoprovision.reolink_generate_password,
            normal: None,
            advanced: None,
            p2p: None,
        };

        let setup = match reolink::setup(setup_req).await {
            Ok(result) => result,
            Err(err) => {
                warn!(ip = %ip, error = %err, "reolink auto-provision setup failed");
                continue;
            }
        };

        let effective_password = if !setup.generated_password.is_empty() {
            setup.generated_password.clone()
        } else if !cfg.autoprovision.reolink_desired_password.trim().is_empty() {
            cfg.autoprovision.reolink_desired_password.clone()
        } else {
            cfg.autoprovision.reolink_password.clone()
        };

        let onvif_port = if setup.bridge.after_advanced.i_onvif_port_enable != 0 {
            setup.bridge.after_advanced.i_onvif_port.max(1)
        } else if setup.probe.onvif_port_open {
            8000
        } else {
            8000
        };
        let rtsp_port = if setup.bridge.after_advanced.i_rtsp_port_enable != 0 {
            setup.bridge.after_advanced.i_rtsp_port.max(1)
        } else if setup.probe.rtsp_port_open {
            554
        } else {
            554
        };

        let source_id = reolink_source_id(&device.uid, &ip);
        let source_name = if device.model.trim().is_empty() {
            format!("Reolink {}", ip)
        } else {
            device.model.clone()
        };
        let rtsp_url = format!(
            "rtsp://{}:{}@{}:{}/h264Preview_01_main",
            username, effective_password, ip, rtsp_port
        );

        let mut found = false;
        for cam in &mut cfg.cameras {
            if cam.source_id == source_id || cam.onvif_host == ip {
                cam.source_id = source_id.clone();
                cam.name = source_name.clone();
                cam.onvif_host = ip.clone();
                cam.onvif_port = onvif_port as u16;
                cam.rtsp_url = rtsp_url.clone();
                cam.username = username.clone();
                cam.password = effective_password.clone();
                cam.enabled = true;
                found = true;
                changed = true;
                break;
            }
        }

        if !found {
            cfg.cameras.push(CameraConfig {
                source_id: source_id.clone(),
                name: source_name.clone(),
                onvif_host: ip.clone(),
                onvif_port: onvif_port as u16,
                rtsp_url: rtsp_url.clone(),
                username: username.clone(),
                password: effective_password.clone(),
                enabled: true,
                segment_secs: 10,
            });
            changed = true;
        }

        info!(source_id = %source_id, ip = %ip, onvif_port, rtsp_port, "reolink auto-provisioned camera source");
    }

    if changed {
        cfg.persist(cfg_path)?;
        info!(path = %cfg_path.display(), camera_count = cfg.cameras.len(), "persisted auto-provisioned camera config");
    }

    Ok(())
}

fn reolink_source_id(uid: &str, ip: &str) -> String {
    let key = if uid.trim().is_empty() {
        ip.trim()
    } else {
        uid.trim()
    };
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

fn init_logging(level: &str) {
    let env = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_target(false)
        .compact()
        .init();
}
