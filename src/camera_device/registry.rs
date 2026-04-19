pub const DRIVER_ID_REOLINK: &str = "reolink";
pub const DRIVER_ID_XM_40E: &str = "xm_40e";
pub const DRIVER_ID_GENERIC_ONVIF_RTSP: &str = "generic_onvif_rtsp";

pub fn driver_is_xm(driver_id: &str) -> bool {
    driver_id.trim() == DRIVER_ID_XM_40E
}
