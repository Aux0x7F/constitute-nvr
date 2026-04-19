use std::path::Path;

use super::types::{
    AudioPlanMode, OutputCodec, PreviewPipelinePlan, RecordingPipelinePlan, VideoPlanMode,
};

pub fn build_live_preview_ffmpeg_args(
    plan: &PreviewPipelinePlan,
    udp_port: u16,
) -> Vec<String> {
    let mut args = vec![
        "-nostdin".to_string(),
        "-loglevel".to_string(),
        "error".to_string(),
        "-rtsp_transport".to_string(),
        "tcp".to_string(),
    ];
    if plan.generate_pts {
        args.push("-fflags".to_string());
        args.push("+genpts".to_string());
    }
    args.push("-i".to_string());
    args.push(plan.input_url.clone());
    args.push("-an".to_string());

    match (&plan.video.mode, &plan.video.output_codec) {
        (VideoPlanMode::Copy, _) => {
            args.push("-c:v".to_string());
            args.push("copy".to_string());
        }
        (VideoPlanMode::Transcode, OutputCodec::Vp8) => {
            args.extend([
                "-c:v".to_string(),
                "libvpx".to_string(),
                "-deadline".to_string(),
                "realtime".to_string(),
                "-cpu-used".to_string(),
                "8".to_string(),
                "-pix_fmt".to_string(),
                "yuv420p".to_string(),
                "-g".to_string(),
                "30".to_string(),
                "-keyint_min".to_string(),
                "30".to_string(),
                "-b:v".to_string(),
                "1M".to_string(),
                "-maxrate".to_string(),
                "1M".to_string(),
                "-bufsize".to_string(),
                "2M".to_string(),
            ]);
        }
        (VideoPlanMode::Transcode, OutputCodec::H264) => {
            args.extend(["-c:v".to_string(), "libx264".to_string()]);
        }
    }

    args.extend([
        "-f".to_string(),
        "rtp".to_string(),
        "-payload_type".to_string(),
        "96".to_string(),
        format!("rtp://127.0.0.1:{udp_port}?pkt_size=1200"),
    ]);
    args
}

pub fn build_recording_ffmpeg_args(
    plan: &RecordingPipelinePlan,
    output_pattern: &Path,
) -> Vec<String> {
    let mut args = vec![
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "warning".to_string(),
        "-rtsp_transport".to_string(),
        "tcp".to_string(),
        "-i".to_string(),
        plan.input_url.clone(),
    ];

    match plan.audio.mode {
        AudioPlanMode::Drop => {
            args.extend([
                "-map".to_string(),
                "0:v:0".to_string(),
                "-c:v".to_string(),
                "copy".to_string(),
            ]);
        }
        _ => {
            args.extend(["-c".to_string(), "copy".to_string()]);
        }
    }

    args.extend([
        "-f".to_string(),
        "segment".to_string(),
        "-segment_time".to_string(),
        plan.segment_secs.to_string(),
        "-reset_timestamps".to_string(),
        "1".to_string(),
        "-strftime".to_string(),
        "1".to_string(),
        output_pattern.to_string_lossy().to_string(),
    ]);
    args
}
