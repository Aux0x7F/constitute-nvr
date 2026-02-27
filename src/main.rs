mod api;
mod camera;
mod config;
mod crypto;
mod nostr;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

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

    if args.discover_onvif {
        let discovered = camera::discover_onvif(3).await?;
        println!("{}", serde_json::to_string_pretty(&discovered)?);
        return Ok(());
    }

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

