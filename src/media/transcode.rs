#![allow(dead_code)]

use super::types::{AudioPlanMode, VideoPlanMode};

pub fn xm_preview_requires_transcode(driver_id: &str) -> bool {
    driver_id.trim() == "xm_40e"
}

pub fn xm_recording_audio_mode(driver_id: &str) -> AudioPlanMode {
    if driver_id.trim() == "xm_40e" {
        AudioPlanMode::Drop
    } else {
        AudioPlanMode::Copy
    }
}

pub fn preview_video_mode(driver_id: &str) -> VideoPlanMode {
    if xm_preview_requires_transcode(driver_id) {
        VideoPlanMode::Transcode
    } else {
        VideoPlanMode::Copy
    }
}
