#![allow(dead_code)]

use anyhow::Result;

use super::{CameraNetworkSummary, DiscoveredCameraCandidate};
use crate::config::Config;
use crate::recording::runtime::DiscoveredCamera;

pub async fn discover_camera_device_candidates(
    cfg: &Config,
) -> Result<Vec<DiscoveredCameraCandidate>> {
    super::discover_candidates(cfg).await
}

pub fn summarize_camera_network(cfg: &Config) -> CameraNetworkSummary {
    super::camera_network_summary(cfg)
}

pub async fn discover_onvif(timeout_secs: u64) -> Result<Vec<DiscoveredCamera>> {
    crate::recording::runtime::discover_onvif(timeout_secs).await
}
