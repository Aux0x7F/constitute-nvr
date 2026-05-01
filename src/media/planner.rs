#![allow(dead_code)]

use anyhow::{Result, anyhow};

use crate::config::CameraDeviceConfig;

use super::transcode::{preview_video_mode, xm_recording_audio_mode};
use super::types::{
    AudioPlan, AudioPlanMode, OutputCodec, OutputContainer, PreviewPipelinePlan,
    RecordingPipelinePlan, VideoPlan, VideoPlanMode,
};

pub fn preview_pipeline_plan(
    camera: &CameraDeviceConfig,
    offer_sdp: &str,
) -> Result<PreviewPipelinePlan> {
    let video_mode = preview_video_mode(&camera.driver_id);
    let input_url = preview_rtsp_url(camera);
    let output_codec = match video_mode {
        VideoPlanMode::Copy => OutputCodec::H264,
        VideoPlanMode::Transcode => {
            if !offer_sdp.contains("VP8/90000") {
                return Err(anyhow!(
                    "browser offer does not advertise VP8, which is required for XM live preview"
                ));
            }
            OutputCodec::Vp8
        }
    };
    if matches!(video_mode, VideoPlanMode::Copy) && !offer_sdp.contains("H264/90000") {
        if offer_sdp.contains("VP8/90000") {
            return Ok(PreviewPipelinePlan {
                input_url,
                video: VideoPlan {
                    mode: VideoPlanMode::Transcode,
                    output_codec: OutputCodec::Vp8,
                },
                audio: AudioPlan {
                    mode: AudioPlanMode::Drop,
                },
                container: OutputContainer::Rtp,
                generate_pts: true,
                reason: "browser offer omitted H.264; fallback to VP8 preview transcode"
                    .to_string(),
            });
        }
        return Err(anyhow!(
            "browser offer does not advertise a supported preview codec"
        ));
    }
    Ok(preview_pipeline_plan_for_codec(camera, output_codec))
}

pub fn preview_pipeline_plan_for_codec(
    camera: &CameraDeviceConfig,
    output_codec: OutputCodec,
) -> PreviewPipelinePlan {
    let is_xm = camera.driver_id.trim() == "xm_40e";
    let video_mode = match output_codec {
        OutputCodec::H264 => VideoPlanMode::Copy,
        OutputCodec::Vp8 => VideoPlanMode::Transcode,
    };
    PreviewPipelinePlan {
        input_url: preview_rtsp_url(camera),
        video: VideoPlan {
            mode: video_mode.clone(),
            output_codec,
        },
        audio: AudioPlan {
            mode: AudioPlanMode::Drop,
        },
        container: OutputContainer::Rtp,
        generate_pts: is_xm || matches!(video_mode, VideoPlanMode::Transcode),
        reason: if is_xm {
            "XM 40E preview uses HEVC decode plus browser-safe preview transcode".to_string()
        } else {
            "Reolink/generic preview remains direct H.264 copy when browser supports it".to_string()
        },
    }
}

pub fn recording_pipeline_plan(camera: &CameraDeviceConfig) -> RecordingPipelinePlan {
    let audio_mode = xm_recording_audio_mode(&camera.driver_id);
    RecordingPipelinePlan {
        input_url: camera.rtsp_url.clone(),
        video: VideoPlan {
            mode: VideoPlanMode::Copy,
            output_codec: OutputCodec::H264,
        },
        audio: AudioPlan { mode: audio_mode },
        container: OutputContainer::SegmentMp4,
        segment_secs: camera.segment_secs,
        reason: if camera.driver_id.trim() == "xm_40e" {
            "XM 40E recording keeps video-only MP4 because validated audio is not safe for direct MP4 copy".to_string()
        } else {
            "Default recording path keeps direct copy into MP4 segments".to_string()
        },
    }
}

pub fn preview_rtsp_url(camera: &CameraDeviceConfig) -> String {
    let mut url = camera.rtsp_url.clone();
    if url.contains("h264Preview_01_main") {
        url = url.replace("h264Preview_01_main", "h264Preview_01_sub");
    } else if url.contains("h265Preview_01_main") {
        url = url.replace("h265Preview_01_main", "h265Preview_01_sub");
    } else if camera.driver_id.trim() == "xm_40e" {
        url = url
            .replace("_stream=0.sdp?real_stream", "_stream=1.sdp?real_stream")
            .replace("_stream=0.sdp", "_stream=1.sdp");
    }
    url
}
