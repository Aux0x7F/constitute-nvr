mod api;
mod camera;
mod config;
mod crypto;
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
use config::Config;
use std::path::PathBuf;
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
    let (cfg, created) = Config::load_or_create(&cfg_path)?;

    if created {
        warn!(path = %cfg_path.display(), "created new config file; update placeholders before production use");
    }

    if cfg.storage.root == config::DEFAULT_STORAGE_PLACEHOLDER {
        warn!(
            placeholder = %config::DEFAULT_STORAGE_PLACEHOLDER,
            "storage root is still placeholder; set a dedicated mount path"
        );
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
