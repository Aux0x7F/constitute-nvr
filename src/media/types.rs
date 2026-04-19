#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStreamDescriptor {
    pub role: String,
    pub url: String,
    pub video_codec: String,
    pub audio_codec: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub fps: Option<f32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamCatalog {
    pub streams: Vec<DeviceStreamDescriptor>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMediaCapabilities {
    pub preview_prefers_substream: bool,
    pub recording_prefers_mainstream: bool,
    pub direct_h264_preview: bool,
    pub recording_copy_safe: bool,
    pub drop_audio_for_mp4: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoPlanMode {
    Copy,
    Transcode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioPlanMode {
    Copy,
    Transcode,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputCodec {
    H264,
    Vp8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputContainer {
    Rtp,
    Mp4,
    SegmentMp4,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoPlan {
    pub mode: VideoPlanMode,
    pub output_codec: OutputCodec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioPlan {
    pub mode: AudioPlanMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewPipelinePlan {
    pub input_url: String,
    pub video: VideoPlan,
    pub audio: AudioPlan,
    pub container: OutputContainer,
    pub generate_pts: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingPipelinePlan {
    pub input_url: String,
    pub video: VideoPlan,
    pub audio: AudioPlan,
    pub container: OutputContainer,
    pub segment_secs: u64,
    pub reason: String,
}
