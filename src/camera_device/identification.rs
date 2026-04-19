#![allow(dead_code)]

use super::{DiscoveredCameraCandidate, DriverMatch};

pub fn identify_camera_device_candidate(
    candidate: &DiscoveredCameraCandidate,
) -> Option<DriverMatch> {
    Some(super::match_candidate(candidate))
}
