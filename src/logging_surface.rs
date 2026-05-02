use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration;

use constitute_protocol::{
    LOG_SCHEMA_VERSION, LogCategory, LogCorrelationRef, LogEventEnvelope, LogOutcome,
    LogProducerRef, LogRedactionClass, LogSeverity, LogSubjectRef, log_event_id,
    validate_log_event,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::debug;

use crate::util;

#[derive(Debug, Deserialize)]
pub struct LoggingEventsQuery {
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerEventsResponse {
    pub producer_id: String,
    pub next_cursor: String,
    pub events: Vec<LogEventEnvelope>,
}

pub async fn submit_safe_event(
    component: &str,
    category: LogCategory,
    severity: LogSeverity,
    outcome: LogOutcome,
    subject: LogSubjectRef,
    tags: &[&str],
    safe_facts: Value,
) {
    let mut event = LogEventEnvelope {
        schema_version: LOG_SCHEMA_VERSION,
        event_id: String::new(),
        occurred_at: util::now_unix_seconds(),
        received_at: None,
        producer: LogProducerRef {
            service: "nvr".to_string(),
            component: component.to_string(),
            instance_id: None,
            gateway_pk: None,
            service_pk: None,
        },
        category,
        severity,
        outcome,
        subject: Some(subject),
        resource: None,
        correlation: Some(LogCorrelationRef {
            correlation_id: format!("nvr-{}", util::now_unix_seconds()),
            causation_id: None,
            trace_id: None,
        }),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        safe_facts,
        detail_ref: None,
        redaction: vec![LogRedactionClass::Safe],
    };
    event.event_id = match log_event_id(&event) {
        Ok(id) => id,
        Err(_) => return,
    };
    if validate_log_event(&event).is_err() {
        return;
    }
    append_outbox(&event);
    submit_to_logging(&event).await;
}

pub fn read_events(query: LoggingEventsQuery) -> ProducerEventsResponse {
    let limit = query.limit.unwrap_or(250).clamp(1, 1000);
    let mut seen_after = query.after.trim().is_empty();
    let mut events = Vec::new();
    let mut next_cursor = query.after;
    let Some(path) = outbox_path() else {
        return ProducerEventsResponse {
            producer_id: "nvr".to_string(),
            next_cursor,
            events,
        };
    };
    let Ok(file) = std::fs::File::open(path) else {
        return ProducerEventsResponse {
            producer_id: "nvr".to_string(),
            next_cursor,
            events,
        };
    };
    for line in BufReader::new(file).lines().map_while(|line| line.ok()) {
        let Ok(event) = serde_json::from_str::<LogEventEnvelope>(&line) else {
            continue;
        };
        if !seen_after {
            if event.event_id == next_cursor {
                seen_after = true;
            }
            continue;
        }
        next_cursor = event.event_id.clone();
        events.push(event);
        if events.len() >= limit {
            break;
        }
    }
    ProducerEventsResponse {
        producer_id: "nvr".to_string(),
        next_cursor,
        events,
    }
}

async fn submit_to_logging(event: &LogEventEnvelope) {
    let Some(base_url) = logging_url() else {
        return;
    };
    let client = reqwest::Client::new();
    let request = json!({
        "cursor": event.event_id,
        "events": [event],
    });
    let url = format!("{}/v1/producers/nvr/events", base_url.trim_end_matches('/'));
    match tokio::time::timeout(
        Duration::from_secs(2),
        client.post(url).json(&request).send(),
    )
    .await
    {
        Ok(Ok(resp)) if resp.status().is_success() => {
            debug!(event_id = %event.event_id, "logging event submitted");
        }
        _ => {}
    }
}

fn append_outbox(event: &LogEventEnvelope) {
    let Some(path) = outbox_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        if let Ok(line) = serde_json::to_string(event) {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn logging_url() -> Option<String> {
    std::env::var("CONSTITUTE_LOGGING_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn outbox_path() -> Option<PathBuf> {
    let override_path = std::env::var("CONSTITUTE_NVR_LOG_OUTBOX")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    Some(
        override_path
            .map(PathBuf::from)
            .unwrap_or_else(default_outbox_path),
    )
}

fn default_outbox_path() -> PathBuf {
    if std::path::Path::new("/data").is_dir() {
        PathBuf::from("/data/constitute-nvr/log-events.jsonl")
    } else {
        PathBuf::from("/var/lib/constitute-nvr/log-events.jsonl")
    }
}
