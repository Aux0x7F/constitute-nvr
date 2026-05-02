use std::time::Duration;

use rand::RngCore;
use serde_json::{Value, json};
use tracing::debug;

use crate::util;

pub async fn submit_safe_event(
    default_container_id: &str,
    record_type: &str,
    subject: &str,
    priority: &str,
    tags: &[&str],
    facts: Value,
) {
    let base_url = match storage_url() {
        Some(url) => url,
        None => return,
    };
    let now = util::now_unix_seconds();
    let entry = json!({
        "entryId": format!("{}-{}", record_type.replace('.', "-"), random_hex(8)),
        "containerId": storage_container_id(default_container_id),
        "recordType": record_type,
        "subject": subject,
        "priority": priority,
        "tags": tags,
        "facts": facts,
        "createdAt": now,
    });
    let request = json!({ "entries": [entry] });
    let url = format!(
        "{}/v1/local-index/materialize",
        base_url.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    match tokio::time::timeout(
        Duration::from_secs(2),
        client.post(url).json(&request).send(),
    )
    .await
    {
        Ok(Ok(resp)) if resp.status().is_success() => {
            debug!(record_type, "storage proof event submitted");
        }
        _ => {}
    }
}

fn storage_url() -> Option<String> {
    std::env::var("CONSTITUTE_STORAGE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn storage_container_id(default_container_id: &str) -> String {
    std::env::var("CONSTITUTE_STORAGE_CONTAINER_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_container_id.to_string())
}

fn random_hex(bytes: usize) -> String {
    let mut out = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut out);
    out.iter().map(|byte| format!("{byte:02x}")).collect()
}
