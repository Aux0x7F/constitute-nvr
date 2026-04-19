#![allow(dead_code)]

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest, Md5};

type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReolinkFrameHeader {
    Short {
        op: u32,
        payload_len: u32,
        field_c: u32,
        field_d: u32,
        header_len: usize,
        total_len: usize,
    },
    Extended {
        op: u32,
        payload_len: u32,
        field_c: u32,
        field_d: u32,
        field_e: u32,
        header_len: usize,
        total_len: usize,
    },
}

pub const MAGIC: [u8; 4] = [0xf0, 0xde, 0xbc, 0x0a];
pub const BC_XML_KEY: [u8; 8] = [0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF];
pub const OBSERVED_HANDSHAKE_REQUEST_FIELD_D: u32 = 0x6514_dc12;
pub const OBSERVED_HANDSHAKE_RESPONSE_FIELD_D: u32 = 0x6614_dd12;
pub const OBSERVED_CLIENT_FIELD_D: u32 = 0x6414_0000;
pub const OBSERVED_SERVER_OK: u32 = 200;
pub const LOGIN_FRAME_LEN: usize = 316;
pub const LOGIN_MESSAGE_STRUCT_LEN: usize = 0x60c;
pub const LOGIN_MESSAGE_AUTH_MODE_OFFSET: usize = 0x00;
pub const LOGIN_MESSAGE_PORT_OFFSET: usize = 0x04;
pub const LOGIN_MESSAGE_UID_PORT_OFFSET: usize = 0x08;
pub const LOGIN_MESSAGE_NAME_OFFSET: usize = 0x0c;
pub const LOGIN_MESSAGE_NAME_FIELD_LEN: usize = 0x100;
pub const LOGIN_MESSAGE_HOST_OFFSET: usize = 0x10c;
pub const LOGIN_MESSAGE_HOST_FIELD_LEN: usize = 0x400;
pub const LOGIN_MESSAGE_UID_OFFSET: usize = 0x50c;
pub const LOGIN_MESSAGE_UID_FIELD_LEN: usize = 0x80;
pub const LOGIN_MESSAGE_USERNAME_OFFSET: usize = 0x58c;
pub const LOGIN_MESSAGE_USERNAME_FIELD_LEN: usize = 0x20;
pub const LOGIN_MESSAGE_PASSWORD_OFFSET: usize = 0x5ac;
pub const LOGIN_MESSAGE_PASSWORD_FIELD_LEN: usize = 0x20;
pub const LOGIN_MESSAGE_AUTH_CODE_OFFSET: usize = 0x5cc;
pub const LOGIN_MESSAGE_AUTH_CODE_FIELD_LEN: usize = 0x40;
pub const AUTH_CODE_STRUCT_LEN: usize = 4;
pub const AUTH_CODE_VALUE_OFFSET: usize = 0;
pub const AUTH_INFO_STRUCT_LEN: usize = 152;
pub const AUTH_INFO_NOTES_OFFSET: usize = 0;
pub const AUTH_INFO_NOTES_FIELD_LEN: usize = 128;
pub const AUTH_INFO_VALID_HOURS_OFFSET: usize = 128;
pub const AUTH_INFO_USER_LEVEL_OFFSET: usize = 132;
pub const AUTH_INFO_ABILITY_OFFSET: usize = 136;
pub const AUTH_INFO_ABILITY_FIELD_LEN: usize = 4;
pub const AUTH_INFO_CHANNEL_ABILITY_OFFSET: usize = 144;
pub const BOOT_PWD_STATE_STRUCT_LEN: usize = 1;
pub const BOOT_PWD_STATE_VALUE_OFFSET: usize = 0;
pub const NET_NORMAL_PORT_STRUCT_LEN: usize = 24;
pub const NET_NORMAL_PORT_SURV_ENABLE_OFFSET: usize = 0;
pub const NET_NORMAL_PORT_SURV_OFFSET: usize = 4;
pub const NET_NORMAL_PORT_HTTP_ENABLE_OFFSET: usize = 8;
pub const NET_NORMAL_PORT_HTTP_OFFSET: usize = 12;
pub const NET_NORMAL_PORT_HTTPS_ENABLE_OFFSET: usize = 16;
pub const NET_NORMAL_PORT_HTTPS_OFFSET: usize = 20;
pub const NET_ADVANCED_PORT_STRUCT_LEN: usize = 24;
pub const NET_ADVANCED_PORT_ONVIF_ENABLE_OFFSET: usize = 0;
pub const NET_ADVANCED_PORT_ONVIF_OFFSET: usize = 4;
pub const NET_ADVANCED_PORT_RTSP_ENABLE_OFFSET: usize = 8;
pub const NET_ADVANCED_PORT_RTSP_OFFSET: usize = 12;
pub const NET_ADVANCED_PORT_RTMP_ENABLE_OFFSET: usize = 16;
pub const NET_ADVANCED_PORT_RTMP_OFFSET: usize = 20;
pub const P2P_CFG_STRUCT_LEN: usize = 40;
pub const P2P_CFG_ENABLE_OFFSET: usize = 0;
pub const P2P_CFG_PORT_OFFSET: usize = 4;
pub const P2P_CFG_SERVER_DOMAIN_OFFSET: usize = 8;
pub const P2P_CFG_SERVER_DOMAIN_FIELD_LEN: usize = 32;
pub const FORCE_PASSWORD_STRUCT_LEN: usize = 96;
pub const FORCE_PASSWORD_USERNAME_OFFSET: usize = 0;
pub const FORCE_PASSWORD_USERNAME_FIELD_LEN: usize = 32;
pub const FORCE_PASSWORD_PASSWORD_OFFSET: usize = 32;
pub const FORCE_PASSWORD_PASSWORD_FIELD_LEN: usize = 32;
pub const FORCE_PASSWORD_NICKNAME_OFFSET: usize = 64;
pub const FORCE_PASSWORD_NICKNAME_FIELD_LEN: usize = 32;
pub const PTZ_DECODER_STRUCT_LEN: usize = 800;
pub const PTZ_DECODER_DATABIT_OFFSET: usize = 0;
pub const PTZ_DECODER_STOPBIT_OFFSET: usize = 4;
pub const PTZ_DECODER_ADDRESS_OFFSET: usize = 8;
pub const PTZ_DECODER_BAUDRATE_OFFSET: usize = 12;
pub const PTZ_DECODER_PARITY_OFFSET: usize = 16;
pub const PTZ_DECODER_FLOWCONTROL_OFFSET: usize = 20;
pub const PTZ_DECODER_TYPE_OFFSET: usize = 24;
pub const PTZ_DECODER_SUPPORT_PELCO_C_OFFSET: usize = 28;
pub const PTZ_DECODER_PRESET_OFFSET: usize = 32;
pub const PTZ_DECODER_PRESET_FIELD_LEN: usize = 256;
pub const PTZ_DECODER_CRUISE_OFFSET: usize = 288;
pub const PTZ_DECODER_CRUISE_FIELD_LEN: usize = 256;
pub const PTZ_DECODER_TRACK_OFFSET: usize = 544;
pub const PTZ_DECODER_TRACK_FIELD_LEN: usize = 256;
pub const PTZ_POSITION_STRUCT_LEN: usize = 12;
pub const PTZ_POSITION_P_OFFSET: usize = 0;
pub const PTZ_POSITION_T_OFFSET: usize = 4;
pub const PTZ_POSITION_Z_OFFSET: usize = 8;
pub const PTZ_3D_LOCATION_STRUCT_LEN: usize = 24;
pub const PTZ_3D_LOCATION_TOP_LEFT_X_OFFSET: usize = 0;
pub const PTZ_3D_LOCATION_TOP_LEFT_Y_OFFSET: usize = 4;
pub const PTZ_3D_LOCATION_WIDTH_OFFSET: usize = 8;
pub const PTZ_3D_LOCATION_HEIGHT_OFFSET: usize = 12;
pub const PTZ_3D_LOCATION_STREAM_TYPE_OFFSET: usize = 16;
pub const PTZ_3D_LOCATION_SPEED_OFFSET: usize = 20;
pub const SMART_TRACK_TASK_STRUCT_LEN: usize = 672;
pub const SMART_TRACK_TASK_TIMETABLE_LEN: usize = 168;
pub const SMART_TRACK_LIMIT_POINT_STRUCT_LEN: usize = 36;
pub const SMART_TRACK_LIMIT_POINT_LIMIT_OFFSET: usize = 0;
pub const SMART_TRACK_LIMIT_POINT_IMAGE_NAME_OFFSET: usize = 4;
pub const SMART_TRACK_LIMIT_POINT_IMAGE_NAME_FIELD_LEN: usize = 32;
pub const SMART_TRACK_LIMIT_STRUCT_LEN: usize = 72;
pub const SMART_TRACK_LIMIT_LEFT_OFFSET: usize = 0;
pub const SMART_TRACK_LIMIT_RIGHT_OFFSET: usize = 36;
pub const USER_RECORD_STRUCT_LEN: usize = 336;
pub const USER_RECORD_USERNAME_OFFSET: usize = 0;
pub const USER_RECORD_USERNAME_FIELD_LEN: usize = 32;
pub const USER_RECORD_NICKNAME_OFFSET: usize = 32;
pub const USER_RECORD_NICKNAME_FIELD_LEN: usize = 32;
pub const USER_RECORD_PASSWORD_OFFSET: usize = 64;
pub const USER_RECORD_PASSWORD_FIELD_LEN: usize = 32;
pub const USER_RECORD_LOCAL_RIGHT_OFFSET: usize = 96;
pub const USER_RECORD_LOCAL_RIGHT_FIELD_LEN: usize = 32;
pub const USER_RECORD_OLD_IPC_RIGHT_OFFSET: usize = 128;
pub const USER_RECORD_OLD_IPC_RIGHT_FIELD_LEN: usize = 32;
pub const USER_RECORD_MAGIC_NUM_OFFSET: usize = 160;
pub const USER_RECORD_USER_IP_OFFSET: usize = 164;
pub const USER_RECORD_USER_IP_FIELD_LEN: usize = 128;
pub const USER_RECORD_MAC_OFFSET: usize = 292;
pub const USER_RECORD_MAC_FIELD_LEN: usize = 8;
pub const USER_RECORD_LEVEL_OFFSET: usize = 300;
pub const USER_RECORD_LOGIN_STATE_OFFSET: usize = 304;
pub const USER_RECORD_VALID_PASSWORD_OFFSET: usize = 308;
pub const USER_RECORD_USER_SET_STATE_OFFSET: usize = 312;
pub const USER_RECORD_BOOT_PASSWORD_OFFSET: usize = 316;
pub const USER_RECORD_VALID_HOURS_OFFSET: usize = 320;
pub const USER_RECORD_CHANNEL_ABILITY_OFFSET: usize = 328;
pub const USER_CFG_STRUCT_LEN: usize = 10792;
pub const USER_CFG_CURRENT_USERNAME_OFFSET: usize = 0;
pub const USER_CFG_CURRENT_USERNAME_FIELD_LEN: usize = 32;
pub const USER_CFG_USERNUM_OFFSET: usize = 32;
pub const USER_CFG_USERS_OFFSET: usize = 40;
pub const USER_CFG_USERS_MAX: usize = 32;
pub const SIGNATURE_LOGIN_CFG_STRUCT_LEN: usize = 20;
pub const SIGNATURE_LOGIN_CFG_IS_OPENED_OFFSET: usize = 0;
pub const SIGNATURE_LOGIN_CFG_VERSION_OFFSET: usize = 4;
pub const SIGNATURE_LOGIN_CFG_V1_OFFSET: usize = 8;
pub const SIGNATURE_LOGIN_CFG_V2_OFFSET: usize = 12;
pub const SIGNATURE_LOGIN_CFG_V3_OFFSET: usize = 16;
pub const LOGIN_LEADING_ZERO_LEN: usize = 4;
pub const LOGIN_REFLECTED_SERVER_PREFIX_LEN: usize = 48;
pub const LOGIN_REFLECTED_SERVER_PREFIX_WINDOW: std::ops::Range<usize> =
    24..(24 + LOGIN_REFLECTED_SERVER_PREFIX_LEN);
pub const SERVER_HANDSHAKE_CREDENTIAL_SALT_INDICES: [usize; 21] = [
    105, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
    125, 126,
];
pub const LOGIN_CREDENTIAL_WINDOW: std::ops::Range<usize> = 107..191;
pub const LOGIN_USERNAME_WINDOW: std::ops::Range<usize> = 107..138;
pub const LOGIN_MIDDLE_WINDOW: std::ops::Range<usize> = 138..160;
pub const LOGIN_PASSWORD_WINDOW: std::ops::Range<usize> = 160..191;
pub const BAICHUAN_KEY: [u8; 16] = *b"!shenzhenbaichua";
pub const BAICHUAN_IV: [u8; 16] = *b"0123456789abcdef";

pub const LOGIN_STATIC_MIDDLE: [u8; 22] = [
    0x00, 0x64, 0x2f, 0x1a, 0x1d, 0x8d, 0x51, 0x4c, 0x51, 0x2e, 0x64, 0x63, 0x44, 0x8f, 0x7e, 0x5e,
    0x4f, 0x3c, 0x35, 0x1b, 0x1c, 0xc1,
];

pub const SDK_CMD_GET_NORMAL_PORT: u32 = 2041;
pub const SDK_CMD_SET_NORMAL_PORT: u32 = 2042;
pub const SDK_CMD_GET_PTZCFG: u32 = 2057;
pub const SDK_CMD_SET_PTZCFG: u32 = 2058;
pub const SDK_CMD_GET_AUTOREBOOT_CFG: u32 = 2061;
pub const SDK_CMD_SET_AUTOREBOOT_CFG: u32 = 2062;
pub const SDK_CMD_GET_USERCFG: u32 = 2068;
pub const SDK_CMD_SET_USERCFG: u32 = 2069;
pub const SDK_CMD_GET_BOOTPWD_STATE: u32 = 2079;
pub const SDK_CMD_SET_BOOTPWD_STATE: u32 = 2080;
pub const SDK_CMD_LOGIN: u32 = 2087;
pub const SDK_CMD_REBOOT: u32 = 2101;
pub const SDK_CMD_PTZ_CONTROL: u32 = 2108;
pub const SDK_CMD_GET_ADVANCED_PORTS: u32 = 2120;
pub const SDK_CMD_GET_PRESET: u32 = 2126;
pub const SDK_CMD_SET_PRESET: u32 = 2127;
pub const SDK_CMD_GET_CRUISE: u32 = 2128;
pub const SDK_CMD_SET_CRUISE: u32 = 2129;
pub const SDK_CMD_SET_ADVANCED_PORTS: u32 = 2121;
pub const SDK_CMD_FORCE_PASSWORD: u32 = 2124;
pub const SDK_CMD_GET_PTOP_CFG: u32 = 2153;
pub const SDK_CMD_SET_PTOP_CFG: u32 = 2154;
pub const SDK_CMD_GET_SIGNATURE_LOGIN_CFG: u32 = 2227;
pub const SDK_CMD_SET_SIGNATURE_LOGIN_CFG: u32 = 2228;
pub const SDK_CMD_GET_SMART_TRACK_LIMIT_CFG: u32 = 2364;
pub const SDK_CMD_SET_SMART_TRACK_LIMIT_CFG: u32 = 2365;
pub const SDK_CMD_GET_PTZ_CUR_POS: u32 = 2367;
pub const SDK_CMD_GET_SMART_TRACK_TASK_CFG: u32 = 2368;
pub const SDK_CMD_SET_SMART_TRACK_TASK_CFG: u32 = 2369;
pub const SDK_CMD_PTZ_3DLOCATION: u32 = 2374;
pub const SDK_CMD_GET_LOGIN_AUTH_CODE: u32 = 2432;
pub const SDK_CMD_SET_PTZ_POS: u32 = 2453;
pub const NATIVE_OP_GET_PTZ_CUR_POS: u32 = 0x1b1;
pub const NATIVE_OP_SET_PTZ_POS: u32 = 0x1d4;
pub const NATIVE_SESSION_LOGIN_TOKEN: &str = "system, network, alarm, record, video, image";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReolinkRemoteCommand {
    GetNetAdvancedPort,
    SetNetAdvancedPort,
    GetNetNormalPort,
    SetNetNormalPort,
    GetP2PCfg,
    SetP2PCfg,
    GetBootPwdState,
    SetBootPwdState,
    ForceUserPassword,
    GetLoginAuthCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReolinkDispatchKind {
    HeaderOnly,
    Payload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkObservedDispatch {
    pub kind: ReolinkDispatchKind,
    pub request_id: u32,
    pub payload_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkObservedTransportRequest {
    pub op: ReolinkTransportOp,
    pub payload_len: u32,
}

impl ReolinkRemoteCommand {
    pub fn request_id(self) -> u32 {
        match self {
            Self::GetNetAdvancedPort => 0x848,
            Self::SetNetAdvancedPort => 0x849,
            Self::GetNetNormalPort => 0x7f9,
            Self::SetNetNormalPort => 0x7fa,
            Self::GetP2PCfg | Self::SetP2PCfg => 0x869,
            Self::GetBootPwdState => 0x81f,
            Self::SetBootPwdState => 0x820,
            Self::ForceUserPassword => 0x84c,
            Self::GetLoginAuthCode => 0x980,
        }
    }

    pub fn payload_len(self) -> u32 {
        match self {
            Self::GetNetAdvancedPort
            | Self::GetNetNormalPort
            | Self::GetP2PCfg
            | Self::GetBootPwdState => 0,
            Self::SetBootPwdState => 0x01,
            Self::SetNetAdvancedPort | Self::SetNetNormalPort => 0x18,
            Self::SetP2PCfg => 0x28,
            Self::ForceUserPassword => 0x60,
            Self::GetLoginAuthCode => 0x98,
        }
    }

    pub fn observed_dispatch(self) -> Option<ReolinkObservedDispatch> {
        Some(match self {
            Self::GetNetAdvancedPort => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::HeaderOnly,
                request_id: 0x848,
                payload_len: 0,
            },
            Self::SetNetAdvancedPort => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x849,
                payload_len: 0x18,
            },
            Self::GetP2PCfg => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::HeaderOnly,
                request_id: 0x8a4,
                payload_len: 0,
            },
            Self::SetP2PCfg => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x86a,
                payload_len: 0x28,
            },
            Self::GetBootPwdState => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::HeaderOnly,
                request_id: 0x81f,
                payload_len: 0,
            },
            Self::SetBootPwdState => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x820,
                payload_len: 0x01,
            },
            Self::GetLoginAuthCode => ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x980,
                payload_len: 0x98,
            },
            // These still fan out through multiple helper IDs in the native wrapper.
            Self::GetNetNormalPort | Self::SetNetNormalPort | Self::ForceUserPassword => {
                return None;
            }
        })
    }

    pub fn observed_primary_transport(self) -> Option<ReolinkObservedTransportRequest> {
        Some(match self {
            Self::GetNetAdvancedPort => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadPortBundle,
                payload_len: 0,
            },
            Self::SetNetAdvancedPort => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WritePortBundle,
                payload_len: 222,
            },
            Self::GetNetNormalPort => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadPortBundle,
                payload_len: 0,
            },
            Self::SetNetNormalPort => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WritePortBundle,
                payload_len: 307,
            },
            Self::GetP2PCfg => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadP2P,
                payload_len: 0,
            },
            Self::SetP2PCfg => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WriteP2P,
                payload_len: 144,
            },
            Self::GetBootPwdState => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadBootPwdState,
                payload_len: 0,
            },
            Self::SetBootPwdState => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WriteBootPwdState,
                payload_len: 123,
            },
            Self::ForceUserPassword => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ForceUserPassword,
                payload_len: 328,
            },
            Self::GetLoginAuthCode => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadLoginAuthCode,
                payload_len: 218,
            },
        })
    }

    pub fn observed_apply_transport(self) -> Option<ReolinkObservedTransportRequest> {
        Some(match self {
            Self::SetNetAdvancedPort
            | Self::SetNetNormalPort
            | Self::SetP2PCfg
            | Self::ForceUserPassword => ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ApplyConfig,
                payload_len: 125,
            },
            _ => return None,
        })
    }

    pub fn observed_transport_ops(self) -> Option<&'static [ReolinkTransportOp]> {
        Some(match self {
            Self::GetNetAdvancedPort => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadPortBundle,
            ],
            Self::SetNetAdvancedPort => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadPortBundle,
                ReolinkTransportOp::WritePortBundle,
            ],
            Self::GetNetNormalPort => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadPortBundle,
            ],
            Self::SetNetNormalPort => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadPortBundle,
                ReolinkTransportOp::WritePortBundle,
            ],
            Self::ForceUserPassword => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ForceUserPassword,
            ],
            Self::GetP2PCfg => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadP2P,
            ],
            Self::GetBootPwdState => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadBootPwdState,
                ReolinkTransportOp::AsyncStatus,
            ],
            Self::SetBootPwdState => &[
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::WriteBootPwdState,
                ReolinkTransportOp::Telemetry,
            ],
            Self::SetP2PCfg => &[
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Handshake,
                ReolinkTransportOp::Login,
                ReolinkTransportOp::SessionBind,
                ReolinkTransportOp::ChannelReady,
                ReolinkTransportOp::CommonAck,
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::Telemetry,
                ReolinkTransportOp::ApplyConfig,
                ReolinkTransportOp::ReadP2P,
                ReolinkTransportOp::WriteP2P,
            ],
            Self::GetLoginAuthCode => &[
                ReolinkTransportOp::CommonReadA,
                ReolinkTransportOp::CommonReadB,
                ReolinkTransportOp::CommonReadC,
                ReolinkTransportOp::ReadLoginAuthCode,
                ReolinkTransportOp::Telemetry,
            ],
        })
    }

    #[allow(dead_code)]
    pub fn observed_verify_transport_ops(self) -> Option<&'static [ReolinkTransportOp]> {
        Some(match self {
            Self::SetNetNormalPort => &[ReolinkTransportOp::ReadPortBundle],
            Self::SetP2PCfg => &[ReolinkTransportOp::ReadP2P],
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReolinkTransportOp {
    Handshake = 0x01,
    AsyncStatus = 0x02,
    Login = 0x97,
    ReadLoginAuthCode = 0x1fd,
    SessionBind = 0x3a,
    ChannelReady = 0x92,
    CommonAck = 0xc0,
    CommonReadA = 0x66,
    CommonReadB = 0x50,
    CommonReadC = 0x72,
    ReadPortBundle = 0x25,
    ReadP2P = 0xd2,
    ReadBootPwdState = 0x76,
    WriteBootPwdState = 0x77,
    WritePortBundle = 0x24,
    WriteP2P = 0xd3,
    ForceUserPassword = 0x3b,
    ApplyConfig = 0x0a,
    Telemetry = 0xc7,
}

impl ReolinkTransportOp {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x01 => Self::Handshake,
            0x02 => Self::AsyncStatus,
            0x97 => Self::Login,
            0x1fd => Self::ReadLoginAuthCode,
            0x3a => Self::SessionBind,
            0x92 => Self::ChannelReady,
            0xc0 => Self::CommonAck,
            0x66 => Self::CommonReadA,
            0x50 => Self::CommonReadB,
            0x72 => Self::CommonReadC,
            0x25 => Self::ReadPortBundle,
            0xd2 => Self::ReadP2P,
            0x76 => Self::ReadBootPwdState,
            0x77 => Self::WriteBootPwdState,
            0x24 => Self::WritePortBundle,
            0xd3 => Self::WriteP2P,
            0x3b => Self::ForceUserPassword,
            0x0a => Self::ApplyConfig,
            0xc7 => Self::Telemetry,
            _ => return None,
        })
    }
}

impl ReolinkFrameHeader {
    pub fn op(&self) -> u32 {
        match self {
            Self::Short { op, .. } | Self::Extended { op, .. } => *op,
        }
    }

    pub fn payload_len(&self) -> u32 {
        match self {
            Self::Short { payload_len, .. } | Self::Extended { payload_len, .. } => *payload_len,
        }
    }

    pub fn field_c(&self) -> u32 {
        match self {
            Self::Short { field_c, .. } | Self::Extended { field_c, .. } => *field_c,
        }
    }

    pub fn field_d(&self) -> u32 {
        match self {
            Self::Short { field_d, .. } | Self::Extended { field_d, .. } => *field_d,
        }
    }

    pub fn field_e(&self) -> Option<u32> {
        match self {
            Self::Short { .. } => None,
            Self::Extended { field_e, .. } => Some(*field_e),
        }
    }

    pub fn header_len(&self) -> usize {
        match self {
            Self::Short { header_len, .. } | Self::Extended { header_len, .. } => *header_len,
        }
    }

    pub fn total_len(&self) -> usize {
        match self {
            Self::Short { total_len, .. } | Self::Extended { total_len, .. } => *total_len,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReolinkSegment<'a> {
    Frame {
        header: ReolinkFrameHeader,
        body: &'a [u8],
    },
    Opaque(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkAuthCode {
    pub auth_code: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkBootPwdState {
    pub has_boot_password: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkAuthInfo {
    pub notes: Vec<u8>,
    pub valid_hours: i32,
    pub user_level: i32,
    pub ability: u32,
    pub channel_ability: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkNetNormalPort {
    pub surv_enabled: bool,
    pub surv_port: u32,
    pub http_enabled: bool,
    pub http_port: u32,
    pub https_enabled: bool,
    pub https_port: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkNetAdvancedPort {
    pub onvif_enabled: bool,
    pub onvif_port: u32,
    pub rtsp_enabled: bool,
    pub rtsp_port: u32,
    pub rtmp_enabled: bool,
    pub rtmp_port: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkP2PCfg {
    pub enabled: bool,
    pub port: u32,
    pub server_domain: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkForcePassword {
    pub username: String,
    pub password: String,
    pub nickname: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkPtzDecoder {
    pub data_bit: i32,
    pub stop_bit: i32,
    pub decoder_address: i32,
    pub baud_rate: i32,
    pub parity: i32,
    pub flow_control: i32,
    pub decoder_type: i32,
    pub support_pelco_c: i32,
    pub preset: Vec<u8>,
    pub cruise: Vec<u8>,
    pub track: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReolinkPtzPosition {
    pub pan: i32,
    pub tilt: i32,
    pub zoom: i32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReolinkPtz3DLocation {
    pub top_left_x: f32,
    pub top_left_y: f32,
    pub width: f32,
    pub height: f32,
    pub stream_type: i32,
    pub speed: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkSmartTrackTask {
    pub timetable: [i32; SMART_TRACK_TASK_TIMETABLE_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkSmartTrackLimitPoint {
    pub limit: i32,
    pub image_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkSmartTrackLimit {
    pub left: ReolinkSmartTrackLimitPoint,
    pub right: ReolinkSmartTrackLimitPoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkUserRecord {
    pub username: String,
    pub nickname: String,
    pub password: String,
    pub local_right: String,
    pub old_ipc_right: String,
    pub magic_num: i32,
    pub user_ip: String,
    pub mac_address: Vec<u8>,
    pub user_level: i32,
    pub login_state: i32,
    pub valid_password: i32,
    pub user_set_state: i32,
    pub boot_password: i32,
    pub valid_hours: i32,
    pub channel_ability: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkUserConfig {
    pub current_username: String,
    pub user_count: i32,
    pub users: Vec<ReolinkUserRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReolinkSignatureLoginCfg {
    pub is_opened: i32,
    pub version: i32,
    pub supported_versions: [i32; 3],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReolinkLoginMessage {
    pub auth_mode: u32,
    pub port: u32,
    pub uid_port: u32,
    pub name: String,
    pub host: String,
    pub uid: String,
    pub username: String,
    pub password: String,
    pub auth_code: String,
}

pub fn parse_frame_header(buf: &[u8]) -> Option<ReolinkFrameHeader> {
    if buf.len() < 20 || buf[..4] != MAGIC {
        return None;
    }

    let op = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let payload_len = u32::from_le_bytes(buf[8..12].try_into().ok()?);
    let field_c = u32::from_le_bytes(buf[12..16].try_into().ok()?);
    let field_d = u32::from_le_bytes(buf[16..20].try_into().ok()?);

    if op == ReolinkTransportOp::Handshake as u32 {
        let short_total = 20usize.saturating_add(payload_len as usize);
        if buf.len() >= short_total && (buf.len() == short_total || buf.len() < short_total + 4) {
            return Some(ReolinkFrameHeader::Short {
                op,
                payload_len,
                field_c,
                field_d,
                header_len: 20,
                total_len: short_total,
            });
        }
    }

    if buf.len() < 24 {
        return None;
    }

    let field_e = u32::from_le_bytes(buf[20..24].try_into().ok()?);
    let total_len = 24usize.saturating_add(payload_len as usize);
    if buf.len() < total_len {
        return None;
    }

    Some(ReolinkFrameHeader::Extended {
        op,
        payload_len,
        field_c,
        field_d,
        field_e,
        header_len: 24,
        total_len,
    })
}

pub fn split_segments(mut buf: &[u8]) -> Vec<ReolinkSegment<'_>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            out.push(ReolinkSegment::Opaque(buf));
            break;
        }
        if buf[..4] != MAGIC {
            if let Some(next) = buf.windows(4).position(|window| window == MAGIC) {
                if next > 0 {
                    out.push(ReolinkSegment::Opaque(&buf[..next]));
                    buf = &buf[next..];
                    continue;
                }
            }
            out.push(ReolinkSegment::Opaque(buf));
            break;
        }

        if let Some(header) = parse_frame_header(buf) {
            let header_len = header.header_len();
            let total_len = header.total_len();
            let body = &buf[header_len..total_len];
            out.push(ReolinkSegment::Frame { header, body });
            buf = &buf[total_len..];
            continue;
        }

        out.push(ReolinkSegment::Opaque(buf));
        break;
    }
    out
}

fn trim_trailing_nul(buf: &[u8]) -> Vec<u8> {
    let used = buf
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
        .unwrap_or(0);
    buf[..used].to_vec()
}

fn read_fixed_c_string(buf: &[u8], offset: usize, field_len: usize) -> Option<String> {
    let field = buf.get(offset..offset.checked_add(field_len)?)?;
    let used = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    Some(String::from_utf8_lossy(&field[..used]).to_string())
}

fn write_fixed_c_string(
    out: &mut [u8],
    offset: usize,
    field_len: usize,
    value: &str,
) -> Option<()> {
    let field = out.get_mut(offset..offset.checked_add(field_len)?)?;
    field.fill(0);
    let bytes = value.as_bytes();
    if bytes.len() >= field_len {
        return None;
    }
    field[..bytes.len()].copy_from_slice(bytes);
    Some(())
}

pub fn parse_login_message(buf: &[u8]) -> Option<ReolinkLoginMessage> {
    if buf.len() < LOGIN_MESSAGE_STRUCT_LEN {
        return None;
    }

    Some(ReolinkLoginMessage {
        auth_mode: u32::from_le_bytes(
            buf.get(LOGIN_MESSAGE_AUTH_MODE_OFFSET..LOGIN_MESSAGE_AUTH_MODE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        port: u32::from_le_bytes(
            buf.get(LOGIN_MESSAGE_PORT_OFFSET..LOGIN_MESSAGE_PORT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        uid_port: u32::from_le_bytes(
            buf.get(LOGIN_MESSAGE_UID_PORT_OFFSET..LOGIN_MESSAGE_UID_PORT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        name: read_fixed_c_string(buf, LOGIN_MESSAGE_NAME_OFFSET, LOGIN_MESSAGE_NAME_FIELD_LEN)?,
        host: read_fixed_c_string(buf, LOGIN_MESSAGE_HOST_OFFSET, LOGIN_MESSAGE_HOST_FIELD_LEN)?,
        uid: read_fixed_c_string(buf, LOGIN_MESSAGE_UID_OFFSET, LOGIN_MESSAGE_UID_FIELD_LEN)?,
        username: read_fixed_c_string(
            buf,
            LOGIN_MESSAGE_USERNAME_OFFSET,
            LOGIN_MESSAGE_USERNAME_FIELD_LEN,
        )?,
        password: read_fixed_c_string(
            buf,
            LOGIN_MESSAGE_PASSWORD_OFFSET,
            LOGIN_MESSAGE_PASSWORD_FIELD_LEN,
        )?,
        auth_code: read_fixed_c_string(
            buf,
            LOGIN_MESSAGE_AUTH_CODE_OFFSET,
            LOGIN_MESSAGE_AUTH_CODE_FIELD_LEN,
        )?,
    })
}

pub fn parse_auth_code(buf: &[u8]) -> Option<ReolinkAuthCode> {
    if buf.len() < AUTH_CODE_STRUCT_LEN {
        return None;
    }

    Some(ReolinkAuthCode {
        auth_code: i32::from_le_bytes(
            buf.get(AUTH_CODE_VALUE_OFFSET..AUTH_CODE_VALUE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_auth_code(value: ReolinkAuthCode) -> Vec<u8> {
    value.auth_code.to_le_bytes().to_vec()
}

pub fn parse_boot_pwd_state(buf: &[u8]) -> Option<ReolinkBootPwdState> {
    let value = *buf.get(BOOT_PWD_STATE_VALUE_OFFSET)?;
    Some(ReolinkBootPwdState {
        has_boot_password: value != 0,
    })
}

pub fn build_boot_pwd_state(value: ReolinkBootPwdState) -> Vec<u8> {
    vec![u8::from(value.has_boot_password)]
}

pub fn parse_auth_info(buf: &[u8]) -> Option<ReolinkAuthInfo> {
    if buf.len() < AUTH_INFO_STRUCT_LEN {
        return None;
    }

    Some(ReolinkAuthInfo {
        notes: trim_trailing_nul(
            &buf[AUTH_INFO_NOTES_OFFSET..AUTH_INFO_NOTES_OFFSET + AUTH_INFO_NOTES_FIELD_LEN],
        ),
        valid_hours: i32::from_le_bytes(
            buf.get(AUTH_INFO_VALID_HOURS_OFFSET..AUTH_INFO_VALID_HOURS_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        user_level: i32::from_le_bytes(
            buf.get(AUTH_INFO_USER_LEVEL_OFFSET..AUTH_INFO_USER_LEVEL_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        ability: u32::from_le_bytes(
            buf.get(
                AUTH_INFO_ABILITY_OFFSET..AUTH_INFO_ABILITY_OFFSET + AUTH_INFO_ABILITY_FIELD_LEN,
            )?
            .try_into()
            .ok()?,
        ),
        channel_ability: u64::from_le_bytes(
            buf.get(AUTH_INFO_CHANNEL_ABILITY_OFFSET..AUTH_INFO_CHANNEL_ABILITY_OFFSET + 8)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_auth_info(info: &ReolinkAuthInfo) -> Vec<u8> {
    let mut out = vec![0u8; AUTH_INFO_STRUCT_LEN];
    let notes_len = info.notes.len().min(AUTH_INFO_NOTES_FIELD_LEN);
    out[AUTH_INFO_NOTES_OFFSET..AUTH_INFO_NOTES_OFFSET + notes_len]
        .copy_from_slice(&info.notes[..notes_len]);
    out[AUTH_INFO_VALID_HOURS_OFFSET..AUTH_INFO_VALID_HOURS_OFFSET + 4]
        .copy_from_slice(&info.valid_hours.to_le_bytes());
    out[AUTH_INFO_USER_LEVEL_OFFSET..AUTH_INFO_USER_LEVEL_OFFSET + 4]
        .copy_from_slice(&info.user_level.to_le_bytes());
    out[AUTH_INFO_ABILITY_OFFSET..AUTH_INFO_ABILITY_OFFSET + AUTH_INFO_ABILITY_FIELD_LEN]
        .copy_from_slice(&info.ability.to_le_bytes());
    out[AUTH_INFO_CHANNEL_ABILITY_OFFSET..AUTH_INFO_CHANNEL_ABILITY_OFFSET + 8]
        .copy_from_slice(&info.channel_ability.to_le_bytes());
    out
}

pub fn parse_net_normal_port(buf: &[u8]) -> Option<ReolinkNetNormalPort> {
    if buf.len() < NET_NORMAL_PORT_STRUCT_LEN {
        return None;
    }

    Some(ReolinkNetNormalPort {
        surv_enabled: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_SURV_ENABLE_OFFSET..NET_NORMAL_PORT_SURV_ENABLE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ) != 0,
        surv_port: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_SURV_OFFSET..NET_NORMAL_PORT_SURV_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        http_enabled: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_HTTP_ENABLE_OFFSET..NET_NORMAL_PORT_HTTP_ENABLE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ) != 0,
        http_port: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_HTTP_OFFSET..NET_NORMAL_PORT_HTTP_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        https_enabled: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_HTTPS_ENABLE_OFFSET..NET_NORMAL_PORT_HTTPS_ENABLE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ) != 0,
        https_port: u32::from_le_bytes(
            buf.get(NET_NORMAL_PORT_HTTPS_OFFSET..NET_NORMAL_PORT_HTTPS_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_net_normal_port(value: ReolinkNetNormalPort) -> Vec<u8> {
    let mut out = vec![0u8; NET_NORMAL_PORT_STRUCT_LEN];
    out[NET_NORMAL_PORT_SURV_ENABLE_OFFSET..NET_NORMAL_PORT_SURV_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.surv_enabled)).to_le_bytes());
    out[NET_NORMAL_PORT_SURV_OFFSET..NET_NORMAL_PORT_SURV_OFFSET + 4]
        .copy_from_slice(&value.surv_port.to_le_bytes());
    out[NET_NORMAL_PORT_HTTP_ENABLE_OFFSET..NET_NORMAL_PORT_HTTP_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.http_enabled)).to_le_bytes());
    out[NET_NORMAL_PORT_HTTP_OFFSET..NET_NORMAL_PORT_HTTP_OFFSET + 4]
        .copy_from_slice(&value.http_port.to_le_bytes());
    out[NET_NORMAL_PORT_HTTPS_ENABLE_OFFSET..NET_NORMAL_PORT_HTTPS_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.https_enabled)).to_le_bytes());
    out[NET_NORMAL_PORT_HTTPS_OFFSET..NET_NORMAL_PORT_HTTPS_OFFSET + 4]
        .copy_from_slice(&value.https_port.to_le_bytes());
    out
}

pub fn parse_net_advanced_port(buf: &[u8]) -> Option<ReolinkNetAdvancedPort> {
    if buf.len() < NET_ADVANCED_PORT_STRUCT_LEN {
        return None;
    }

    Some(ReolinkNetAdvancedPort {
        onvif_enabled: u32::from_le_bytes(
            buf.get(
                NET_ADVANCED_PORT_ONVIF_ENABLE_OFFSET..NET_ADVANCED_PORT_ONVIF_ENABLE_OFFSET + 4,
            )?
            .try_into()
            .ok()?,
        ) != 0,
        onvif_port: u32::from_le_bytes(
            buf.get(NET_ADVANCED_PORT_ONVIF_OFFSET..NET_ADVANCED_PORT_ONVIF_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        rtsp_enabled: u32::from_le_bytes(
            buf.get(
                NET_ADVANCED_PORT_RTSP_ENABLE_OFFSET..NET_ADVANCED_PORT_RTSP_ENABLE_OFFSET + 4,
            )?
            .try_into()
            .ok()?,
        ) != 0,
        rtsp_port: u32::from_le_bytes(
            buf.get(NET_ADVANCED_PORT_RTSP_OFFSET..NET_ADVANCED_PORT_RTSP_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        rtmp_enabled: u32::from_le_bytes(
            buf.get(
                NET_ADVANCED_PORT_RTMP_ENABLE_OFFSET..NET_ADVANCED_PORT_RTMP_ENABLE_OFFSET + 4,
            )?
            .try_into()
            .ok()?,
        ) != 0,
        rtmp_port: u32::from_le_bytes(
            buf.get(NET_ADVANCED_PORT_RTMP_OFFSET..NET_ADVANCED_PORT_RTMP_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_net_advanced_port(value: ReolinkNetAdvancedPort) -> Vec<u8> {
    let mut out = vec![0u8; NET_ADVANCED_PORT_STRUCT_LEN];
    out[NET_ADVANCED_PORT_ONVIF_ENABLE_OFFSET..NET_ADVANCED_PORT_ONVIF_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.onvif_enabled)).to_le_bytes());
    out[NET_ADVANCED_PORT_ONVIF_OFFSET..NET_ADVANCED_PORT_ONVIF_OFFSET + 4]
        .copy_from_slice(&value.onvif_port.to_le_bytes());
    out[NET_ADVANCED_PORT_RTSP_ENABLE_OFFSET..NET_ADVANCED_PORT_RTSP_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.rtsp_enabled)).to_le_bytes());
    out[NET_ADVANCED_PORT_RTSP_OFFSET..NET_ADVANCED_PORT_RTSP_OFFSET + 4]
        .copy_from_slice(&value.rtsp_port.to_le_bytes());
    out[NET_ADVANCED_PORT_RTMP_ENABLE_OFFSET..NET_ADVANCED_PORT_RTMP_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.rtmp_enabled)).to_le_bytes());
    out[NET_ADVANCED_PORT_RTMP_OFFSET..NET_ADVANCED_PORT_RTMP_OFFSET + 4]
        .copy_from_slice(&value.rtmp_port.to_le_bytes());
    out
}

pub fn parse_p2p_cfg(buf: &[u8]) -> Option<ReolinkP2PCfg> {
    if buf.len() < P2P_CFG_STRUCT_LEN {
        return None;
    }

    Some(ReolinkP2PCfg {
        enabled: u32::from_le_bytes(
            buf.get(P2P_CFG_ENABLE_OFFSET..P2P_CFG_ENABLE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ) != 0,
        port: u32::from_le_bytes(
            buf.get(P2P_CFG_PORT_OFFSET..P2P_CFG_PORT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        server_domain: read_fixed_c_string(
            buf,
            P2P_CFG_SERVER_DOMAIN_OFFSET,
            P2P_CFG_SERVER_DOMAIN_FIELD_LEN,
        )?,
    })
}

pub fn build_p2p_cfg(value: &ReolinkP2PCfg) -> Option<Vec<u8>> {
    let mut out = vec![0u8; P2P_CFG_STRUCT_LEN];
    out[P2P_CFG_ENABLE_OFFSET..P2P_CFG_ENABLE_OFFSET + 4]
        .copy_from_slice(&(u32::from(value.enabled)).to_le_bytes());
    out[P2P_CFG_PORT_OFFSET..P2P_CFG_PORT_OFFSET + 4].copy_from_slice(&value.port.to_le_bytes());
    write_fixed_c_string(
        &mut out,
        P2P_CFG_SERVER_DOMAIN_OFFSET,
        P2P_CFG_SERVER_DOMAIN_FIELD_LEN,
        &value.server_domain,
    )?;
    Some(out)
}

pub fn parse_force_password(buf: &[u8]) -> Option<ReolinkForcePassword> {
    if buf.len() < FORCE_PASSWORD_STRUCT_LEN {
        return None;
    }

    Some(ReolinkForcePassword {
        username: read_fixed_c_string(
            buf,
            FORCE_PASSWORD_USERNAME_OFFSET,
            FORCE_PASSWORD_USERNAME_FIELD_LEN,
        )?,
        password: read_fixed_c_string(
            buf,
            FORCE_PASSWORD_PASSWORD_OFFSET,
            FORCE_PASSWORD_PASSWORD_FIELD_LEN,
        )?,
        nickname: read_fixed_c_string(
            buf,
            FORCE_PASSWORD_NICKNAME_OFFSET,
            FORCE_PASSWORD_NICKNAME_FIELD_LEN,
        )?,
    })
}

pub fn build_force_password(value: &ReolinkForcePassword) -> Option<Vec<u8>> {
    let mut out = vec![0u8; FORCE_PASSWORD_STRUCT_LEN];
    write_fixed_c_string(
        &mut out,
        FORCE_PASSWORD_USERNAME_OFFSET,
        FORCE_PASSWORD_USERNAME_FIELD_LEN,
        &value.username,
    )?;
    write_fixed_c_string(
        &mut out,
        FORCE_PASSWORD_PASSWORD_OFFSET,
        FORCE_PASSWORD_PASSWORD_FIELD_LEN,
        &value.password,
    )?;
    write_fixed_c_string(
        &mut out,
        FORCE_PASSWORD_NICKNAME_OFFSET,
        FORCE_PASSWORD_NICKNAME_FIELD_LEN,
        &value.nickname,
    )?;
    Some(out)
}

pub fn parse_ptz_decoder(buf: &[u8]) -> Option<ReolinkPtzDecoder> {
    if buf.len() < PTZ_DECODER_STRUCT_LEN {
        return None;
    }

    Some(ReolinkPtzDecoder {
        data_bit: i32::from_le_bytes(
            buf.get(PTZ_DECODER_DATABIT_OFFSET..PTZ_DECODER_DATABIT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        stop_bit: i32::from_le_bytes(
            buf.get(PTZ_DECODER_STOPBIT_OFFSET..PTZ_DECODER_STOPBIT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        decoder_address: i32::from_le_bytes(
            buf.get(PTZ_DECODER_ADDRESS_OFFSET..PTZ_DECODER_ADDRESS_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        baud_rate: i32::from_le_bytes(
            buf.get(PTZ_DECODER_BAUDRATE_OFFSET..PTZ_DECODER_BAUDRATE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        parity: i32::from_le_bytes(
            buf.get(PTZ_DECODER_PARITY_OFFSET..PTZ_DECODER_PARITY_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        flow_control: i32::from_le_bytes(
            buf.get(PTZ_DECODER_FLOWCONTROL_OFFSET..PTZ_DECODER_FLOWCONTROL_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        decoder_type: i32::from_le_bytes(
            buf.get(PTZ_DECODER_TYPE_OFFSET..PTZ_DECODER_TYPE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        support_pelco_c: i32::from_le_bytes(
            buf.get(PTZ_DECODER_SUPPORT_PELCO_C_OFFSET..PTZ_DECODER_SUPPORT_PELCO_C_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        preset: trim_trailing_nul(buf.get(
            PTZ_DECODER_PRESET_OFFSET..PTZ_DECODER_PRESET_OFFSET + PTZ_DECODER_PRESET_FIELD_LEN,
        )?),
        cruise: trim_trailing_nul(buf.get(
            PTZ_DECODER_CRUISE_OFFSET..PTZ_DECODER_CRUISE_OFFSET + PTZ_DECODER_CRUISE_FIELD_LEN,
        )?),
        track: trim_trailing_nul(buf.get(
            PTZ_DECODER_TRACK_OFFSET..PTZ_DECODER_TRACK_OFFSET + PTZ_DECODER_TRACK_FIELD_LEN,
        )?),
    })
}

pub fn build_ptz_decoder(value: &ReolinkPtzDecoder) -> Option<Vec<u8>> {
    let mut out = vec![0u8; PTZ_DECODER_STRUCT_LEN];
    out[PTZ_DECODER_DATABIT_OFFSET..PTZ_DECODER_DATABIT_OFFSET + 4]
        .copy_from_slice(&value.data_bit.to_le_bytes());
    out[PTZ_DECODER_STOPBIT_OFFSET..PTZ_DECODER_STOPBIT_OFFSET + 4]
        .copy_from_slice(&value.stop_bit.to_le_bytes());
    out[PTZ_DECODER_ADDRESS_OFFSET..PTZ_DECODER_ADDRESS_OFFSET + 4]
        .copy_from_slice(&value.decoder_address.to_le_bytes());
    out[PTZ_DECODER_BAUDRATE_OFFSET..PTZ_DECODER_BAUDRATE_OFFSET + 4]
        .copy_from_slice(&value.baud_rate.to_le_bytes());
    out[PTZ_DECODER_PARITY_OFFSET..PTZ_DECODER_PARITY_OFFSET + 4]
        .copy_from_slice(&value.parity.to_le_bytes());
    out[PTZ_DECODER_FLOWCONTROL_OFFSET..PTZ_DECODER_FLOWCONTROL_OFFSET + 4]
        .copy_from_slice(&value.flow_control.to_le_bytes());
    out[PTZ_DECODER_TYPE_OFFSET..PTZ_DECODER_TYPE_OFFSET + 4]
        .copy_from_slice(&value.decoder_type.to_le_bytes());
    out[PTZ_DECODER_SUPPORT_PELCO_C_OFFSET..PTZ_DECODER_SUPPORT_PELCO_C_OFFSET + 4]
        .copy_from_slice(&value.support_pelco_c.to_le_bytes());
    if value.preset.len() > PTZ_DECODER_PRESET_FIELD_LEN
        || value.cruise.len() > PTZ_DECODER_CRUISE_FIELD_LEN
        || value.track.len() > PTZ_DECODER_TRACK_FIELD_LEN
    {
        return None;
    }
    out[PTZ_DECODER_PRESET_OFFSET..PTZ_DECODER_PRESET_OFFSET + value.preset.len()]
        .copy_from_slice(&value.preset);
    out[PTZ_DECODER_CRUISE_OFFSET..PTZ_DECODER_CRUISE_OFFSET + value.cruise.len()]
        .copy_from_slice(&value.cruise);
    out[PTZ_DECODER_TRACK_OFFSET..PTZ_DECODER_TRACK_OFFSET + value.track.len()]
        .copy_from_slice(&value.track);
    Some(out)
}

pub fn parse_ptz_position(buf: &[u8]) -> Option<ReolinkPtzPosition> {
    if buf.len() < PTZ_POSITION_STRUCT_LEN {
        return None;
    }
    Some(ReolinkPtzPosition {
        pan: i32::from_le_bytes(
            buf.get(PTZ_POSITION_P_OFFSET..PTZ_POSITION_P_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        tilt: i32::from_le_bytes(
            buf.get(PTZ_POSITION_T_OFFSET..PTZ_POSITION_T_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        zoom: i32::from_le_bytes(
            buf.get(PTZ_POSITION_Z_OFFSET..PTZ_POSITION_Z_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_ptz_position(value: &ReolinkPtzPosition) -> Vec<u8> {
    let mut out = vec![0u8; PTZ_POSITION_STRUCT_LEN];
    out[PTZ_POSITION_P_OFFSET..PTZ_POSITION_P_OFFSET + 4].copy_from_slice(&value.pan.to_le_bytes());
    out[PTZ_POSITION_T_OFFSET..PTZ_POSITION_T_OFFSET + 4]
        .copy_from_slice(&value.tilt.to_le_bytes());
    out[PTZ_POSITION_Z_OFFSET..PTZ_POSITION_Z_OFFSET + 4]
        .copy_from_slice(&value.zoom.to_le_bytes());
    out
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn build_native_extension_xml(channel_id: u32, include_chn_type: bool) -> String {
    if include_chn_type {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<Extension version=\"1.1\">\n\
<channelId>{channel_id}</channelId>\n\
<chnType>0</chnType>\n\
</Extension>\n"
        )
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<Extension version=\"1.1\">\n\
<channelId>{channel_id}</channelId>\n\
</Extension>\n"
        )
    }
}

pub fn build_native_user_extension_xml(username: &str, token: Option<&str>) -> String {
    let user = xml_escape(username);
    if let Some(token) = token {
        let token = xml_escape(token);
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<Extension version=\"1.1\">\n\
<userName>{user}</userName>\n\
<token>{token}</token>\n\
</Extension>\n"
        )
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<Extension version=\"1.1\">\n\
<userName>{user}</userName>\n\
</Extension>\n"
        )
    }
}

pub fn build_native_ptz_position_xml(value: ReolinkPtzPosition) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<body>\n\
<ptzCurPos version=\"1.1\">\n\
<pPos>{}</pPos>\n\
<tPos>{}</tPos>\n\
<zPos>{}</zPos>\n\
</ptzCurPos>\n\
</body>\n",
        value.pan, value.tilt, value.zoom
    )
}

pub fn derive_native_aes_key(nonce: &str, password: &str) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(format!("{nonce}-{password}").as_bytes());
    let digest = hasher.finalize();
    let mut material = hex::encode_upper(digest).into_bytes();
    material.push(0);
    let mut key = [0u8; 16];
    key.copy_from_slice(&material[..16]);
    key
}

pub fn encrypt_native_payload(key: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    let cipher = Aes128CfbEnc::new(key.as_slice().into(), BAICHUAN_IV.as_slice().into());
    cipher.encrypt(&mut out);
    out
}

pub fn decrypt_native_payload(key: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    let cipher = Aes128CfbDec::new(key.as_slice().into(), BAICHUAN_IV.as_slice().into());
    cipher.decrypt(&mut out);
    out
}

pub fn build_native_header_only_frame(op: u32, request_id: u32) -> Vec<u8> {
    build_extended_frame(op, request_id, OBSERVED_CLIENT_FIELD_D, 0, &[])
}

pub fn build_native_extension_frame(
    op: u32,
    request_id: u32,
    xml: &str,
    key: &[u8; 16],
) -> Vec<u8> {
    let payload = encrypt_native_payload(key, xml.as_bytes());
    build_extended_frame(
        op,
        request_id,
        OBSERVED_CLIENT_FIELD_D,
        payload.len() as u32,
        &payload,
    )
}

pub fn build_native_session_login_frame(
    request_id: u32,
    username: &str,
    key: &[u8; 16],
) -> Vec<u8> {
    build_native_extension_frame(
        ReolinkTransportOp::Login as u32,
        request_id,
        &build_native_user_extension_xml(username, Some(NATIVE_SESSION_LOGIN_TOKEN)),
        key,
    )
}

pub fn build_native_session_bind_frame(request_id: u32, username: &str, key: &[u8; 16]) -> Vec<u8> {
    build_native_extension_frame(
        ReolinkTransportOp::SessionBind as u32,
        request_id,
        &build_native_user_extension_xml(username, None),
        key,
    )
}

pub fn build_native_prepare_ptz_frame(request_id: u32, channel_id: u32, key: &[u8; 16]) -> Vec<u8> {
    build_native_extension_frame(
        ReolinkTransportOp::ApplyConfig as u32,
        request_id,
        &build_native_extension_xml(channel_id, true),
        key,
    )
}

pub fn build_native_ptz_get_frame(request_id: u32, channel_id: u32, key: &[u8; 16]) -> Vec<u8> {
    let extension =
        encrypt_native_payload(key, build_native_extension_xml(channel_id, true).as_bytes());
    build_extended_frame(
        NATIVE_OP_GET_PTZ_CUR_POS,
        request_id,
        OBSERVED_CLIENT_FIELD_D,
        extension.len() as u32,
        &extension,
    )
}

pub fn build_native_ptz_set_frame(
    request_id: u32,
    channel_id: u32,
    position: ReolinkPtzPosition,
    key: &[u8; 16],
) -> Vec<u8> {
    let extension = encrypt_native_payload(
        key,
        build_native_extension_xml(channel_id, false).as_bytes(),
    );
    let body = encrypt_native_payload(key, build_native_ptz_position_xml(position).as_bytes());
    let mut payload = Vec::with_capacity(extension.len() + body.len());
    payload.extend_from_slice(&extension);
    payload.extend_from_slice(&body);
    build_extended_frame(
        NATIVE_OP_SET_PTZ_POS,
        request_id,
        OBSERVED_CLIENT_FIELD_D,
        extension.len() as u32,
        &payload,
    )
}

fn parse_xml_tag_i32(xml: &str, tag: &str) -> Option<i32> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    xml[start..end].trim().parse().ok()
}

pub fn parse_native_ptz_position_xml(xml: &str) -> Option<ReolinkPtzPosition> {
    Some(ReolinkPtzPosition {
        pan: parse_xml_tag_i32(xml, "pPos")?,
        tilt: parse_xml_tag_i32(xml, "tPos")?,
        zoom: parse_xml_tag_i32(xml, "zPos")?,
    })
}

pub fn parse_ptz_3d_location(buf: &[u8]) -> Option<ReolinkPtz3DLocation> {
    if buf.len() < PTZ_3D_LOCATION_STRUCT_LEN {
        return None;
    }
    Some(ReolinkPtz3DLocation {
        top_left_x: f32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_TOP_LEFT_X_OFFSET..PTZ_3D_LOCATION_TOP_LEFT_X_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        top_left_y: f32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_TOP_LEFT_Y_OFFSET..PTZ_3D_LOCATION_TOP_LEFT_Y_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        width: f32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_WIDTH_OFFSET..PTZ_3D_LOCATION_WIDTH_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        height: f32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_HEIGHT_OFFSET..PTZ_3D_LOCATION_HEIGHT_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        stream_type: i32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_STREAM_TYPE_OFFSET..PTZ_3D_LOCATION_STREAM_TYPE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        speed: i32::from_le_bytes(
            buf.get(PTZ_3D_LOCATION_SPEED_OFFSET..PTZ_3D_LOCATION_SPEED_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
    })
}

pub fn build_ptz_3d_location(value: &ReolinkPtz3DLocation) -> Vec<u8> {
    let mut out = vec![0u8; PTZ_3D_LOCATION_STRUCT_LEN];
    out[PTZ_3D_LOCATION_TOP_LEFT_X_OFFSET..PTZ_3D_LOCATION_TOP_LEFT_X_OFFSET + 4]
        .copy_from_slice(&value.top_left_x.to_le_bytes());
    out[PTZ_3D_LOCATION_TOP_LEFT_Y_OFFSET..PTZ_3D_LOCATION_TOP_LEFT_Y_OFFSET + 4]
        .copy_from_slice(&value.top_left_y.to_le_bytes());
    out[PTZ_3D_LOCATION_WIDTH_OFFSET..PTZ_3D_LOCATION_WIDTH_OFFSET + 4]
        .copy_from_slice(&value.width.to_le_bytes());
    out[PTZ_3D_LOCATION_HEIGHT_OFFSET..PTZ_3D_LOCATION_HEIGHT_OFFSET + 4]
        .copy_from_slice(&value.height.to_le_bytes());
    out[PTZ_3D_LOCATION_STREAM_TYPE_OFFSET..PTZ_3D_LOCATION_STREAM_TYPE_OFFSET + 4]
        .copy_from_slice(&value.stream_type.to_le_bytes());
    out[PTZ_3D_LOCATION_SPEED_OFFSET..PTZ_3D_LOCATION_SPEED_OFFSET + 4]
        .copy_from_slice(&value.speed.to_le_bytes());
    out
}

pub fn parse_smart_track_task(buf: &[u8]) -> Option<ReolinkSmartTrackTask> {
    if buf.len() < SMART_TRACK_TASK_STRUCT_LEN {
        return None;
    }
    let mut timetable = [0i32; SMART_TRACK_TASK_TIMETABLE_LEN];
    for (index, slot) in timetable.iter_mut().enumerate() {
        let offset = index * 4;
        *slot = i32::from_le_bytes(buf.get(offset..offset + 4)?.try_into().ok()?);
    }
    Some(ReolinkSmartTrackTask { timetable })
}

pub fn build_smart_track_task(value: &ReolinkSmartTrackTask) -> Vec<u8> {
    let mut out = vec![0u8; SMART_TRACK_TASK_STRUCT_LEN];
    for (index, item) in value.timetable.iter().enumerate() {
        let offset = index * 4;
        out[offset..offset + 4].copy_from_slice(&item.to_le_bytes());
    }
    out
}

fn parse_smart_track_limit_point(buf: &[u8]) -> Option<ReolinkSmartTrackLimitPoint> {
    if buf.len() < SMART_TRACK_LIMIT_POINT_STRUCT_LEN {
        return None;
    }
    Some(ReolinkSmartTrackLimitPoint {
        limit: i32::from_le_bytes(
            buf.get(
                SMART_TRACK_LIMIT_POINT_LIMIT_OFFSET..SMART_TRACK_LIMIT_POINT_LIMIT_OFFSET + 4,
            )?
            .try_into()
            .ok()?,
        ),
        image_name: read_fixed_c_string(
            buf,
            SMART_TRACK_LIMIT_POINT_IMAGE_NAME_OFFSET,
            SMART_TRACK_LIMIT_POINT_IMAGE_NAME_FIELD_LEN,
        )?,
    })
}

fn build_smart_track_limit_point(value: &ReolinkSmartTrackLimitPoint) -> Option<Vec<u8>> {
    let mut out = vec![0u8; SMART_TRACK_LIMIT_POINT_STRUCT_LEN];
    out[SMART_TRACK_LIMIT_POINT_LIMIT_OFFSET..SMART_TRACK_LIMIT_POINT_LIMIT_OFFSET + 4]
        .copy_from_slice(&value.limit.to_le_bytes());
    write_fixed_c_string(
        &mut out,
        SMART_TRACK_LIMIT_POINT_IMAGE_NAME_OFFSET,
        SMART_TRACK_LIMIT_POINT_IMAGE_NAME_FIELD_LEN,
        &value.image_name,
    )?;
    Some(out)
}

pub fn parse_smart_track_limit(buf: &[u8]) -> Option<ReolinkSmartTrackLimit> {
    if buf.len() < SMART_TRACK_LIMIT_STRUCT_LEN {
        return None;
    }
    Some(ReolinkSmartTrackLimit {
        left: parse_smart_track_limit_point(buf.get(
            SMART_TRACK_LIMIT_LEFT_OFFSET
                ..SMART_TRACK_LIMIT_LEFT_OFFSET + SMART_TRACK_LIMIT_POINT_STRUCT_LEN,
        )?)?,
        right: parse_smart_track_limit_point(buf.get(
            SMART_TRACK_LIMIT_RIGHT_OFFSET
                ..SMART_TRACK_LIMIT_RIGHT_OFFSET + SMART_TRACK_LIMIT_POINT_STRUCT_LEN,
        )?)?,
    })
}

pub fn build_smart_track_limit(value: &ReolinkSmartTrackLimit) -> Option<Vec<u8>> {
    let mut out = vec![0u8; SMART_TRACK_LIMIT_STRUCT_LEN];
    let left = build_smart_track_limit_point(&value.left)?;
    let right = build_smart_track_limit_point(&value.right)?;
    out[SMART_TRACK_LIMIT_LEFT_OFFSET
        ..SMART_TRACK_LIMIT_LEFT_OFFSET + SMART_TRACK_LIMIT_POINT_STRUCT_LEN]
        .copy_from_slice(&left);
    out[SMART_TRACK_LIMIT_RIGHT_OFFSET
        ..SMART_TRACK_LIMIT_RIGHT_OFFSET + SMART_TRACK_LIMIT_POINT_STRUCT_LEN]
        .copy_from_slice(&right);
    Some(out)
}

fn parse_user_record(buf: &[u8]) -> Option<ReolinkUserRecord> {
    if buf.len() < USER_RECORD_STRUCT_LEN {
        return None;
    }
    Some(ReolinkUserRecord {
        username: read_fixed_c_string(
            buf,
            USER_RECORD_USERNAME_OFFSET,
            USER_RECORD_USERNAME_FIELD_LEN,
        )?,
        nickname: read_fixed_c_string(
            buf,
            USER_RECORD_NICKNAME_OFFSET,
            USER_RECORD_NICKNAME_FIELD_LEN,
        )?,
        password: read_fixed_c_string(
            buf,
            USER_RECORD_PASSWORD_OFFSET,
            USER_RECORD_PASSWORD_FIELD_LEN,
        )?,
        local_right: read_fixed_c_string(
            buf,
            USER_RECORD_LOCAL_RIGHT_OFFSET,
            USER_RECORD_LOCAL_RIGHT_FIELD_LEN,
        )?,
        old_ipc_right: read_fixed_c_string(
            buf,
            USER_RECORD_OLD_IPC_RIGHT_OFFSET,
            USER_RECORD_OLD_IPC_RIGHT_FIELD_LEN,
        )?,
        magic_num: i32::from_le_bytes(
            buf.get(USER_RECORD_MAGIC_NUM_OFFSET..USER_RECORD_MAGIC_NUM_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        user_ip: read_fixed_c_string(
            buf,
            USER_RECORD_USER_IP_OFFSET,
            USER_RECORD_USER_IP_FIELD_LEN,
        )?,
        mac_address: buf
            .get(USER_RECORD_MAC_OFFSET..USER_RECORD_MAC_OFFSET + USER_RECORD_MAC_FIELD_LEN)?
            .to_vec(),
        user_level: i32::from_le_bytes(
            buf.get(USER_RECORD_LEVEL_OFFSET..USER_RECORD_LEVEL_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        login_state: i32::from_le_bytes(
            buf.get(USER_RECORD_LOGIN_STATE_OFFSET..USER_RECORD_LOGIN_STATE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        valid_password: i32::from_le_bytes(
            buf.get(USER_RECORD_VALID_PASSWORD_OFFSET..USER_RECORD_VALID_PASSWORD_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        user_set_state: i32::from_le_bytes(
            buf.get(USER_RECORD_USER_SET_STATE_OFFSET..USER_RECORD_USER_SET_STATE_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        boot_password: i32::from_le_bytes(
            buf.get(USER_RECORD_BOOT_PASSWORD_OFFSET..USER_RECORD_BOOT_PASSWORD_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        valid_hours: i32::from_le_bytes(
            buf.get(USER_RECORD_VALID_HOURS_OFFSET..USER_RECORD_VALID_HOURS_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        channel_ability: u64::from_le_bytes(
            buf.get(USER_RECORD_CHANNEL_ABILITY_OFFSET..USER_RECORD_CHANNEL_ABILITY_OFFSET + 8)?
                .try_into()
                .ok()?,
        ),
    })
}

fn build_user_record(value: &ReolinkUserRecord) -> Option<Vec<u8>> {
    let mut out = vec![0u8; USER_RECORD_STRUCT_LEN];
    write_fixed_c_string(
        &mut out,
        USER_RECORD_USERNAME_OFFSET,
        USER_RECORD_USERNAME_FIELD_LEN,
        &value.username,
    )?;
    write_fixed_c_string(
        &mut out,
        USER_RECORD_NICKNAME_OFFSET,
        USER_RECORD_NICKNAME_FIELD_LEN,
        &value.nickname,
    )?;
    write_fixed_c_string(
        &mut out,
        USER_RECORD_PASSWORD_OFFSET,
        USER_RECORD_PASSWORD_FIELD_LEN,
        &value.password,
    )?;
    write_fixed_c_string(
        &mut out,
        USER_RECORD_LOCAL_RIGHT_OFFSET,
        USER_RECORD_LOCAL_RIGHT_FIELD_LEN,
        &value.local_right,
    )?;
    write_fixed_c_string(
        &mut out,
        USER_RECORD_OLD_IPC_RIGHT_OFFSET,
        USER_RECORD_OLD_IPC_RIGHT_FIELD_LEN,
        &value.old_ipc_right,
    )?;
    write_fixed_c_string(
        &mut out,
        USER_RECORD_USER_IP_OFFSET,
        USER_RECORD_USER_IP_FIELD_LEN,
        &value.user_ip,
    )?;
    if value.mac_address.len() > USER_RECORD_MAC_FIELD_LEN {
        return None;
    }
    out[USER_RECORD_MAGIC_NUM_OFFSET..USER_RECORD_MAGIC_NUM_OFFSET + 4]
        .copy_from_slice(&value.magic_num.to_le_bytes());
    out[USER_RECORD_MAC_OFFSET..USER_RECORD_MAC_OFFSET + value.mac_address.len()]
        .copy_from_slice(&value.mac_address);
    out[USER_RECORD_LEVEL_OFFSET..USER_RECORD_LEVEL_OFFSET + 4]
        .copy_from_slice(&value.user_level.to_le_bytes());
    out[USER_RECORD_LOGIN_STATE_OFFSET..USER_RECORD_LOGIN_STATE_OFFSET + 4]
        .copy_from_slice(&value.login_state.to_le_bytes());
    out[USER_RECORD_VALID_PASSWORD_OFFSET..USER_RECORD_VALID_PASSWORD_OFFSET + 4]
        .copy_from_slice(&value.valid_password.to_le_bytes());
    out[USER_RECORD_USER_SET_STATE_OFFSET..USER_RECORD_USER_SET_STATE_OFFSET + 4]
        .copy_from_slice(&value.user_set_state.to_le_bytes());
    out[USER_RECORD_BOOT_PASSWORD_OFFSET..USER_RECORD_BOOT_PASSWORD_OFFSET + 4]
        .copy_from_slice(&value.boot_password.to_le_bytes());
    out[USER_RECORD_VALID_HOURS_OFFSET..USER_RECORD_VALID_HOURS_OFFSET + 4]
        .copy_from_slice(&value.valid_hours.to_le_bytes());
    out[USER_RECORD_CHANNEL_ABILITY_OFFSET..USER_RECORD_CHANNEL_ABILITY_OFFSET + 8]
        .copy_from_slice(&value.channel_ability.to_le_bytes());
    Some(out)
}

pub fn parse_user_config(buf: &[u8]) -> Option<ReolinkUserConfig> {
    if buf.len() < USER_CFG_STRUCT_LEN {
        return None;
    }
    let user_count = i32::from_le_bytes(
        buf.get(USER_CFG_USERNUM_OFFSET..USER_CFG_USERNUM_OFFSET + 4)?
            .try_into()
            .ok()?,
    );
    let clamped_count = user_count.clamp(0, USER_CFG_USERS_MAX as i32) as usize;
    let mut users = Vec::with_capacity(clamped_count);
    for index in 0..clamped_count {
        let offset = USER_CFG_USERS_OFFSET + index * USER_RECORD_STRUCT_LEN;
        users.push(parse_user_record(
            buf.get(offset..offset + USER_RECORD_STRUCT_LEN)?,
        )?);
    }
    Some(ReolinkUserConfig {
        current_username: read_fixed_c_string(
            buf,
            USER_CFG_CURRENT_USERNAME_OFFSET,
            USER_CFG_CURRENT_USERNAME_FIELD_LEN,
        )?,
        user_count,
        users,
    })
}

pub fn build_user_config(value: &ReolinkUserConfig) -> Option<Vec<u8>> {
    if value.users.len() > USER_CFG_USERS_MAX {
        return None;
    }
    let mut out = vec![0u8; USER_CFG_STRUCT_LEN];
    write_fixed_c_string(
        &mut out,
        USER_CFG_CURRENT_USERNAME_OFFSET,
        USER_CFG_CURRENT_USERNAME_FIELD_LEN,
        &value.current_username,
    )?;
    out[USER_CFG_USERNUM_OFFSET..USER_CFG_USERNUM_OFFSET + 4]
        .copy_from_slice(&value.user_count.to_le_bytes());
    for (index, user) in value.users.iter().enumerate() {
        let offset = USER_CFG_USERS_OFFSET + index * USER_RECORD_STRUCT_LEN;
        let encoded = build_user_record(user)?;
        out[offset..offset + USER_RECORD_STRUCT_LEN].copy_from_slice(&encoded);
    }
    Some(out)
}

pub fn parse_signature_login_cfg(buf: &[u8]) -> Option<ReolinkSignatureLoginCfg> {
    if buf.len() < SIGNATURE_LOGIN_CFG_STRUCT_LEN {
        return None;
    }
    Some(ReolinkSignatureLoginCfg {
        is_opened: i32::from_le_bytes(
            buf.get(
                SIGNATURE_LOGIN_CFG_IS_OPENED_OFFSET..SIGNATURE_LOGIN_CFG_IS_OPENED_OFFSET + 4,
            )?
            .try_into()
            .ok()?,
        ),
        version: i32::from_le_bytes(
            buf.get(SIGNATURE_LOGIN_CFG_VERSION_OFFSET..SIGNATURE_LOGIN_CFG_VERSION_OFFSET + 4)?
                .try_into()
                .ok()?,
        ),
        supported_versions: [
            i32::from_le_bytes(
                buf.get(SIGNATURE_LOGIN_CFG_V1_OFFSET..SIGNATURE_LOGIN_CFG_V1_OFFSET + 4)?
                    .try_into()
                    .ok()?,
            ),
            i32::from_le_bytes(
                buf.get(SIGNATURE_LOGIN_CFG_V2_OFFSET..SIGNATURE_LOGIN_CFG_V2_OFFSET + 4)?
                    .try_into()
                    .ok()?,
            ),
            i32::from_le_bytes(
                buf.get(SIGNATURE_LOGIN_CFG_V3_OFFSET..SIGNATURE_LOGIN_CFG_V3_OFFSET + 4)?
                    .try_into()
                    .ok()?,
            ),
        ],
    })
}

pub fn build_signature_login_cfg(value: &ReolinkSignatureLoginCfg) -> Vec<u8> {
    let mut out = vec![0u8; SIGNATURE_LOGIN_CFG_STRUCT_LEN];
    out[SIGNATURE_LOGIN_CFG_IS_OPENED_OFFSET..SIGNATURE_LOGIN_CFG_IS_OPENED_OFFSET + 4]
        .copy_from_slice(&value.is_opened.to_le_bytes());
    out[SIGNATURE_LOGIN_CFG_VERSION_OFFSET..SIGNATURE_LOGIN_CFG_VERSION_OFFSET + 4]
        .copy_from_slice(&value.version.to_le_bytes());
    out[SIGNATURE_LOGIN_CFG_V1_OFFSET..SIGNATURE_LOGIN_CFG_V1_OFFSET + 4]
        .copy_from_slice(&value.supported_versions[0].to_le_bytes());
    out[SIGNATURE_LOGIN_CFG_V2_OFFSET..SIGNATURE_LOGIN_CFG_V2_OFFSET + 4]
        .copy_from_slice(&value.supported_versions[1].to_le_bytes());
    out[SIGNATURE_LOGIN_CFG_V3_OFFSET..SIGNATURE_LOGIN_CFG_V3_OFFSET + 4]
        .copy_from_slice(&value.supported_versions[2].to_le_bytes());
    out
}

pub fn build_login_message(msg: &ReolinkLoginMessage) -> Option<Vec<u8>> {
    let mut out = vec![0u8; LOGIN_MESSAGE_STRUCT_LEN];
    out[LOGIN_MESSAGE_AUTH_MODE_OFFSET..LOGIN_MESSAGE_AUTH_MODE_OFFSET + 4]
        .copy_from_slice(&msg.auth_mode.to_le_bytes());
    out[LOGIN_MESSAGE_PORT_OFFSET..LOGIN_MESSAGE_PORT_OFFSET + 4]
        .copy_from_slice(&msg.port.to_le_bytes());
    out[LOGIN_MESSAGE_UID_PORT_OFFSET..LOGIN_MESSAGE_UID_PORT_OFFSET + 4]
        .copy_from_slice(&msg.uid_port.to_le_bytes());
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_NAME_OFFSET,
        LOGIN_MESSAGE_NAME_FIELD_LEN,
        &msg.name,
    )?;
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_HOST_OFFSET,
        LOGIN_MESSAGE_HOST_FIELD_LEN,
        &msg.host,
    )?;
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_UID_OFFSET,
        LOGIN_MESSAGE_UID_FIELD_LEN,
        &msg.uid,
    )?;
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_USERNAME_OFFSET,
        LOGIN_MESSAGE_USERNAME_FIELD_LEN,
        &msg.username,
    )?;
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_PASSWORD_OFFSET,
        LOGIN_MESSAGE_PASSWORD_FIELD_LEN,
        &msg.password,
    )?;
    write_fixed_c_string(
        &mut out,
        LOGIN_MESSAGE_AUTH_CODE_OFFSET,
        LOGIN_MESSAGE_AUTH_CODE_FIELD_LEN,
        &msg.auth_code,
    )?;
    Some(out)
}

pub fn build_short_frame(op: u32, field_c: u32, field_d: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&field_c.to_le_bytes());
    out.extend_from_slice(&field_d.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn bcencrypt(offset: u8, payload: &[u8]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            let key = BC_XML_KEY[(index + (offset as usize)) % BC_XML_KEY.len()];
            byte ^ key ^ offset
        })
        .collect()
}

pub fn bcdecrypt(offset: u8, payload: &[u8]) -> Vec<u8> {
    // BCEncrypt is a XOR stream, so decrypt == encrypt.
    bcencrypt(offset, payload)
}

pub fn build_handshake_probe_frame() -> Vec<u8> {
    build_short_frame(
        ReolinkTransportOp::Handshake as u32,
        0,
        OBSERVED_HANDSHAKE_REQUEST_FIELD_D,
        &[],
    )
}

fn parse_nonce_from_xml(xml: &str) -> Option<String> {
    let start = xml.find("<nonce>")?;
    let value_start = start + "<nonce>".len();
    let end = xml[value_start..].find("</nonce>")?;
    Some(xml[value_start..(value_start + end)].to_string())
}

pub fn decrypt_handshake_xml(body: &[u8]) -> Option<String> {
    let plaintext = bcdecrypt(0, body);
    String::from_utf8(plaintext).ok()
}

pub fn extract_nonce_from_handshake_body(body: &[u8]) -> Option<String> {
    let xml = decrypt_handshake_xml(body)?;
    parse_nonce_from_xml(&xml)
}

pub fn md5_upper_31(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let upper = hex::encode_upper(digest);
    upper[..31].to_string()
}

pub fn build_login_xml(username: &str, password: &str, nonce: &str) -> String {
    let username_md5 = md5_upper_31(&format!("{username}{nonce}"));
    let password_md5 = md5_upper_31(&format!("{password}{nonce}"));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
<body>\n\
<LoginUser version=\"1.1\">\n\
<userName>{username_md5}</userName>\n\
<password>{password_md5}</password>\n\
<userVer>1</userVer>\n\
</LoginUser>\n\
<LoginNet version=\"1.1\">\n\
<type>LAN</type>\n\
<udpPort>0</udpPort>\n\
</LoginNet>\n\
</body>\n"
    )
}

pub fn build_login_frame(username: &str, password: &str, nonce: &str) -> Vec<u8> {
    let xml = build_login_xml(username, password, nonce);
    let encrypted = bcencrypt(0, xml.as_bytes());
    build_extended_frame(
        ReolinkTransportOp::Handshake as u32,
        0,
        OBSERVED_CLIENT_FIELD_D,
        0,
        &encrypted,
    )
}

pub fn build_extended_frame(
    op: u32,
    field_c: u32,
    field_d: u32,
    field_e: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&field_c.to_le_bytes());
    out.extend_from_slice(&field_d.to_le_bytes());
    out.extend_from_slice(&field_e.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn login_credential_window(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < LOGIN_FRAME_LEN {
        return None;
    }
    let header = parse_frame_header(frame)?;
    match header {
        ReolinkFrameHeader::Short { op, .. } if op == ReolinkTransportOp::Handshake as u32 => {
            Some(&frame[LOGIN_CREDENTIAL_WINDOW.clone()])
        }
        _ => None,
    }
}

pub fn handshake_frame_body(frame: &[u8]) -> Option<&[u8]> {
    let header = parse_frame_header(frame)?;
    match header {
        ReolinkFrameHeader::Short { op, .. } if op == ReolinkTransportOp::Handshake as u32 => {
            Some(&frame[header.header_len()..header.total_len()])
        }
        _ => None,
    }
}

pub fn login_reflected_server_prefix(frame: &[u8]) -> Option<&[u8]> {
    let _ = login_credential_window(frame)?;
    Some(&frame[LOGIN_REFLECTED_SERVER_PREFIX_WINDOW.clone()])
}

pub fn handshake_reflected_prefix(frame: &[u8]) -> Option<&[u8]> {
    let body = handshake_frame_body(frame)?;
    body.get(..LOGIN_REFLECTED_SERVER_PREFIX_LEN)
}

pub fn handshake_observed_credential_salt(frame: &[u8]) -> Option<[u8; 21]> {
    let body = handshake_frame_body(frame)?;
    let mut out = [0u8; SERVER_HANDSHAKE_CREDENTIAL_SALT_INDICES.len()];
    for (slot, index) in out
        .iter_mut()
        .zip(SERVER_HANDSHAKE_CREDENTIAL_SALT_INDICES.iter().copied())
    {
        *slot = *body.get(index)?;
    }
    Some(out)
}

pub fn login_has_expected_zero_lead(frame: &[u8]) -> bool {
    matches!(login_credential_window(frame), Some(_)
        if frame[20..(20 + LOGIN_LEADING_ZERO_LEN)].iter().all(|byte| *byte == 0))
}

pub fn login_matches_server_prefix(login_frame: &[u8], server_handshake_frame: &[u8]) -> bool {
    let reflected = match login_reflected_server_prefix(login_frame) {
        Some(value) => value,
        None => return false,
    };
    let server_prefix = match handshake_reflected_prefix(server_handshake_frame) {
        Some(value) => value,
        None => return false,
    };
    server_prefix == reflected
}

pub fn login_username_block(frame: &[u8]) -> Option<&[u8]> {
    let _ = login_credential_window(frame)?;
    Some(&frame[LOGIN_USERNAME_WINDOW.clone()])
}

pub fn login_middle_block(frame: &[u8]) -> Option<&[u8]> {
    let _ = login_credential_window(frame)?;
    Some(&frame[LOGIN_MIDDLE_WINDOW.clone()])
}

pub fn login_password_block(frame: &[u8]) -> Option<&[u8]> {
    let _ = login_credential_window(frame)?;
    Some(&frame[LOGIN_PASSWORD_WINDOW.clone()])
}

pub fn login_has_observed_static_middle(frame: &[u8]) -> bool {
    matches!(login_middle_block(frame), Some(block) if block == LOGIN_STATIC_MIDDLE)
}

pub fn login_frames_differ_only_in_credential_blocks(left: &[u8], right: &[u8]) -> bool {
    if login_credential_window(left).is_none() || login_credential_window(right).is_none() {
        return false;
    }
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .enumerate()
        .all(|(index, (lhs, rhs))| {
            lhs == rhs
                || LOGIN_USERNAME_WINDOW.contains(&index)
                || LOGIN_PASSWORD_WINDOW.contains(&index)
        })
}

pub fn replace_login_blocks(
    frame: &[u8],
    username_block: &[u8],
    password_block: &[u8],
) -> Option<Vec<u8>> {
    if username_block.len() != LOGIN_USERNAME_WINDOW.len()
        || password_block.len() != LOGIN_PASSWORD_WINDOW.len()
    {
        return None;
    }
    let _ = login_credential_window(frame)?;
    let mut out = frame.to_vec();
    out[LOGIN_USERNAME_WINDOW.clone()].copy_from_slice(username_block);
    out[LOGIN_MIDDLE_WINDOW.clone()].copy_from_slice(&LOGIN_STATIC_MIDDLE);
    out[LOGIN_PASSWORD_WINDOW.clone()].copy_from_slice(password_block);
    Some(out)
}

pub fn encode_password_secret(secret: &[u8]) -> Option<String> {
    if secret.len() > 0x3ff {
        return None;
    }

    let padded_len = (secret.len() + 1).next_multiple_of(16);
    let mut buffer = vec![0u8; padded_len];
    buffer[0] = secret.len() as u8;
    buffer[1..=secret.len()].copy_from_slice(secret);

    let cipher = Aes128::new_from_slice(&BAICHUAN_KEY).ok()?;
    let mut previous = BAICHUAN_IV;
    for chunk in buffer.chunks_exact_mut(16) {
        for (slot, iv) in chunk.iter_mut().zip(previous) {
            *slot ^= iv;
        }
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
        previous.copy_from_slice(chunk);
    }

    Some(BASE64_STANDARD.encode(buffer))
}

pub fn decode_password_secret(secret: &str) -> Option<Vec<u8>> {
    let mut buffer = BASE64_STANDARD.decode(secret).ok()?;
    if buffer.is_empty() || buffer.len() % 16 != 0 {
        return None;
    }

    let cipher = Aes128::new_from_slice(&BAICHUAN_KEY).ok()?;
    let mut previous = BAICHUAN_IV;
    for chunk in buffer.chunks_exact_mut(16) {
        let current = <[u8; 16]>::try_from(&*chunk).ok()?;
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
        for (slot, iv) in chunk.iter_mut().zip(previous) {
            *slot ^= iv;
        }
        previous = current;
    }

    let declared_len = buffer[0] as usize;
    let end = 1usize.checked_add(declared_len)?;
    if end > buffer.len() {
        return None;
    }
    Some(buffer[1..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED_USERNAME_BLOCK: [u8; 31] = [
        0x79, 0x62, 0x50, 0x3a, 0xb9, 0x2a, 0x1e, 0x0e, 0x7a, 0x6f, 0x5b, 0x4c, 0xbb, 0x5c, 0x1c,
        0x7a, 0x79, 0x1f, 0x5a, 0x3d, 0xbc, 0x5d, 0x15, 0x7a, 0x08, 0x6d, 0x58, 0x3e, 0xcc, 0x2c,
        0x18,
    ];

    const OBSERVED_PASSWORD_BLOCK: [u8; 31] = [
        0x29, 0x1f, 0x0d, 0x73, 0x1b, 0x2d, 0x4e, 0xbb, 0x59, 0x1e, 0x7d, 0x72, 0x1e, 0x2c, 0x3a,
        0xce, 0x2b, 0x18, 0x7a, 0x0d, 0x6e, 0x5c, 0x48, 0xc9, 0x2f, 0x14, 0x04, 0x09, 0x69, 0x2d,
        0x39,
    ];
    const OBSERVED_SERVER_HANDSHAKE_BODY: [u8; 273] = [
        0x23, 0x12, 0x44, 0x26, 0x36, 0x49, 0x0e, 0x9a, 0x6d, 0x5e, 0x55, 0x24, 0x34, 0x54, 0x5a,
        0xce, 0x31, 0x1d, 0x1e, 0x6b, 0x3f, 0x07, 0x1b, 0x90, 0x7b, 0x44, 0x52, 0x2c, 0x67, 0x4b,
        0x2d, 0xab, 0x59, 0x00, 0x04, 0x69, 0x7a, 0x56, 0x46, 0xf5, 0x23, 0x4f, 0x53, 0x2f, 0x23,
        0x57, 0x72, 0xc3, 0x5a, 0x43, 0x5f, 0x39, 0x23, 0x19, 0x0c, 0x96, 0x70, 0x43, 0x1c, 0x3d,
        0x3f, 0x1b, 0x0b, 0x96, 0x70, 0x43, 0x01, 0x69, 0x6b, 0x47, 0x49, 0xdd, 0x21, 0x27, 0x00,
        0x3f, 0x23, 0x19, 0x1d, 0xc1, 0x72, 0x49, 0x09, 0x77, 0x75, 0x1d, 0x01, 0x8f, 0x7a, 0x13,
        0x36, 0x77, 0x34, 0x06, 0x16, 0x9c, 0x7a, 0x13, 0x0a, 0x72, 0x3b, 0x5f, 0x4d, 0x99, 0x79,
        0x1d, 0x11, 0x2a, 0x23, 0x0c, 0x3b, 0x9c, 0x50, 0x7c, 0x7e, 0x2e, 0x17, 0x59, 0x2e, 0xb5,
        0x6d, 0x43, 0x72, 0x7d, 0x30, 0x3c, 0x4b, 0xc3, 0x30, 0x43, 0x53, 0x25, 0x39, 0x0c, 0x46,
        0xf5, 0x23, 0x4c, 0x49, 0x3f, 0x32, 0x3d, 0x01, 0x8f, 0x7a, 0x61, 0x55, 0x38, 0x2e, 0x57,
        0x72, 0xc3, 0x7e, 0x58, 0x48, 0x23, 0x0e, 0x10, 0x08, 0x9a, 0x21, 0x5d, 0x5d, 0x38, 0x29,
        0x1e, 0x17, 0x8d, 0x7b, 0x11, 0x13, 0x2a, 0x2f, 0x1d, 0x10, 0xab, 0x66, 0x5d, 0x59, 0x75,
        0x50, 0x55, 0x19, 0x8a, 0x6b, 0x45, 0x68, 0x32, 0x2a, 0x0c, 0x46, 0x8c, 0x76, 0x4a, 0x6a,
        0x7a, 0x66, 0x46, 0x19, 0x8a, 0x6b, 0x45, 0x68, 0x32, 0x2a, 0x0c, 0x46, 0xf5, 0x23, 0x4c,
        0x49, 0x3f, 0x32, 0x3d, 0x01, 0x8f, 0x7a, 0x13, 0x4f, 0x22, 0x3d, 0x3f, 0x4b, 0xc3, 0x30,
        0x4c, 0x49, 0x3f, 0x32, 0x3d, 0x01, 0x8f, 0x7a, 0x13, 0x36, 0x77, 0x75, 0x08, 0x0d, 0x8b,
        0x77, 0x79, 0x45, 0x3b, 0x3f, 0x25, 0x11, 0x8c, 0x6b, 0x13, 0x36, 0x77, 0x75, 0x2c, 0x16,
        0x9c, 0x6d, 0x54, 0x4c, 0x3f, 0x33, 0x06, 0x16, 0xc1, 0x15, 0x11, 0x13, 0x29, 0x35, 0x0d,
        0x01, 0xc1, 0x15,
    ];

    fn observed_server_handshake_frame() -> Vec<u8> {
        let mut frame = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0xdd, 0x14, 0x66,
        ];
        frame.extend_from_slice(&OBSERVED_SERVER_HANDSHAKE_BODY);
        frame
    }

    fn observed_login_frame() -> Vec<u8> {
        let mut frame = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x28, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0xdc, 0x14, 0x65,
        ];
        frame.extend(std::iter::repeat_n(0u8, 296));
        frame[LOGIN_REFLECTED_SERVER_PREFIX_WINDOW.clone()]
            .copy_from_slice(&OBSERVED_SERVER_HANDSHAKE_BODY[..LOGIN_REFLECTED_SERVER_PREFIX_LEN]);
        frame[LOGIN_USERNAME_WINDOW.clone()].copy_from_slice(&OBSERVED_USERNAME_BLOCK);
        frame[LOGIN_MIDDLE_WINDOW.clone()].copy_from_slice(&LOGIN_STATIC_MIDDLE);
        frame[LOGIN_PASSWORD_WINDOW.clone()].copy_from_slice(&OBSERVED_PASSWORD_BLOCK);
        frame
    }

    #[test]
    fn parses_login_message_layout() {
        let mut buf = vec![0u8; LOGIN_MESSAGE_STRUCT_LEN];
        buf[LOGIN_MESSAGE_AUTH_MODE_OFFSET..LOGIN_MESSAGE_AUTH_MODE_OFFSET + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        buf[LOGIN_MESSAGE_PORT_OFFSET..LOGIN_MESSAGE_PORT_OFFSET + 4]
            .copy_from_slice(&9000u32.to_le_bytes());
        buf[LOGIN_MESSAGE_UID_PORT_OFFSET..LOGIN_MESSAGE_UID_PORT_OFFSET + 4]
            .copy_from_slice(&1234u32.to_le_bytes());
        write_fixed_c_string(
            &mut buf,
            LOGIN_MESSAGE_HOST_OFFSET,
            LOGIN_MESSAGE_HOST_FIELD_LEN,
            "192.168.1.20",
        )
        .expect("host");
        write_fixed_c_string(
            &mut buf,
            LOGIN_MESSAGE_UID_OFFSET,
            LOGIN_MESSAGE_UID_FIELD_LEN,
            "UIDTEST123",
        )
        .expect("uid");
        write_fixed_c_string(
            &mut buf,
            LOGIN_MESSAGE_USERNAME_OFFSET,
            LOGIN_MESSAGE_USERNAME_FIELD_LEN,
            "admin",
        )
        .expect("username");
        write_fixed_c_string(
            &mut buf,
            LOGIN_MESSAGE_PASSWORD_OFFSET,
            LOGIN_MESSAGE_PASSWORD_FIELD_LEN,
            "test1234",
        )
        .expect("password");
        write_fixed_c_string(
            &mut buf,
            LOGIN_MESSAGE_AUTH_CODE_OFFSET,
            LOGIN_MESSAGE_AUTH_CODE_FIELD_LEN,
            "AUTH-CODE-XYZ",
        )
        .expect("auth code");

        let parsed = parse_login_message(&buf).expect("parsed");
        assert_eq!(
            parsed,
            ReolinkLoginMessage {
                auth_mode: 3,
                port: 9000,
                uid_port: 1234,
                host: "192.168.1.20".into(),
                name: String::new(),
                uid: "UIDTEST123".into(),
                username: "admin".into(),
                password: "test1234".into(),
                auth_code: "AUTH-CODE-XYZ".into(),
            }
        );
    }

    #[test]
    fn parses_and_builds_auth_code_layout() {
        let expected = ReolinkAuthCode { auth_code: 7 };
        let raw = build_auth_code(expected);
        assert_eq!(raw.len(), AUTH_CODE_STRUCT_LEN);
        assert_eq!(parse_auth_code(&raw), Some(expected));
    }

    #[test]
    fn parses_and_builds_boot_pwd_state_layout() {
        let expected = ReolinkBootPwdState {
            has_boot_password: true,
        };
        let raw = build_boot_pwd_state(expected);
        assert_eq!(raw.len(), BOOT_PWD_STATE_STRUCT_LEN);
        assert_eq!(parse_boot_pwd_state(&raw), Some(expected));
    }

    #[test]
    fn parses_and_builds_auth_info_layout() {
        let expected = ReolinkAuthInfo {
            notes: b"alpha-note".to_vec(),
            valid_hours: 72,
            user_level: 3,
            ability: 0x1122_3344,
            channel_ability: 0x8877_6655_4433_2211,
        };
        let raw = build_auth_info(&expected);
        assert_eq!(raw.len(), AUTH_INFO_STRUCT_LEN);
        assert_eq!(parse_auth_info(&raw), Some(expected));
    }

    #[test]
    fn builds_login_message_layout_roundtrip() {
        let msg = ReolinkLoginMessage {
            auth_mode: 0,
            port: 9000,
            uid_port: 0,
            host: "192.168.1.20".into(),
            name: "lab-e1".into(),
            uid: String::new(),
            username: "admin".into(),
            password: "test1234".into(),
            auth_code: String::new(),
        };

        let bytes = build_login_message(&msg).expect("bytes");
        assert_eq!(bytes.len(), LOGIN_MESSAGE_STRUCT_LEN);
        assert_eq!(parse_login_message(&bytes), Some(msg));
    }

    #[test]
    fn parses_and_builds_net_normal_port_layout() {
        let expected = ReolinkNetNormalPort {
            surv_enabled: true,
            surv_port: 9000,
            http_enabled: false,
            http_port: 80,
            https_enabled: true,
            https_port: 443,
        };
        let raw = build_net_normal_port(expected);
        assert_eq!(raw.len(), NET_NORMAL_PORT_STRUCT_LEN);
        assert_eq!(parse_net_normal_port(&raw), Some(expected));
    }

    #[test]
    fn parses_and_builds_net_advanced_port_layout() {
        let expected = ReolinkNetAdvancedPort {
            onvif_enabled: true,
            onvif_port: 8000,
            rtsp_enabled: true,
            rtsp_port: 554,
            rtmp_enabled: false,
            rtmp_port: 1935,
        };
        let raw = build_net_advanced_port(expected);
        assert_eq!(raw.len(), NET_ADVANCED_PORT_STRUCT_LEN);
        assert_eq!(parse_net_advanced_port(&raw), Some(expected));
    }

    #[test]
    fn parses_and_builds_p2p_cfg_layout() {
        let expected = ReolinkP2PCfg {
            enabled: false,
            port: 0,
            server_domain: "p2p.reolink.com".into(),
        };
        let raw = build_p2p_cfg(&expected).expect("raw");
        assert_eq!(raw.len(), P2P_CFG_STRUCT_LEN);
        assert_eq!(parse_p2p_cfg(&raw), Some(expected));
    }

    #[test]
    fn parses_and_builds_force_password_layout() {
        let expected = ReolinkForcePassword {
            username: "admin".into(),
            password: "test1234".into(),
            nickname: "Camera A".into(),
        };
        let raw = build_force_password(&expected).expect("raw");
        assert_eq!(raw.len(), FORCE_PASSWORD_STRUCT_LEN);
        assert_eq!(parse_force_password(&raw), Some(expected));
    }

    #[test]
    fn exposes_public_wrapper_metadata() {
        assert_eq!(ReolinkRemoteCommand::SetNetAdvancedPort.request_id(), 0x849);
        assert_eq!(ReolinkRemoteCommand::SetNetAdvancedPort.payload_len(), 0x18);
        assert_eq!(ReolinkRemoteCommand::SetP2PCfg.request_id(), 0x869);
        assert_eq!(ReolinkRemoteCommand::SetP2PCfg.payload_len(), 0x28);
        assert_eq!(ReolinkRemoteCommand::ForceUserPassword.payload_len(), 0x60);
    }

    #[test]
    fn parses_short_handshake_header() {
        let buf = [
            0xf0, 0xde, 0xbc, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0xdc, 0x14, 0x65,
        ];
        let header = parse_frame_header(&buf).expect("header");
        assert_eq!(
            header,
            ReolinkFrameHeader::Short {
                op: 1,
                payload_len: 0,
                field_c: 0,
                field_d: 0x6514dc12,
                header_len: 20,
                total_len: 20,
            }
        );
    }

    #[test]
    fn parses_extended_request_header() {
        let mut buf = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x97, 0x00, 0x00, 0x00, 0xa6, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x14, 0x64, 0xa6, 0x00, 0x00, 0x00,
        ];
        buf.extend(std::iter::repeat_n(0u8, 0xa6));
        let header = parse_frame_header(&buf).expect("header");
        assert_eq!(
            header,
            ReolinkFrameHeader::Extended {
                op: 0x97,
                payload_len: 0xa6,
                field_c: 1,
                field_d: 0x6414_0000,
                field_e: 0xa6,
                header_len: 24,
                total_len: 190,
            }
        );
    }

    #[test]
    fn splits_multiple_extended_frames() {
        let mut first = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x97, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc,
        ];
        let mut second = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x92, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xee,
        ];
        first.append(&mut second);
        let segments = split_segments(&first);
        assert_eq!(segments.len(), 2);
        match &segments[0] {
            ReolinkSegment::Frame { header, body } => {
                assert_eq!(header.op(), 0x97);
                assert_eq!(*body, [0xaa, 0xbb, 0xcc]);
            }
            _ => panic!("expected frame"),
        }
        match &segments[1] {
            ReolinkSegment::Frame { header, body } => {
                assert_eq!(header.op(), 0x92);
                assert_eq!(*body, [0xdd, 0xee]);
            }
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn observes_server_ok_code() {
        assert_eq!(OBSERVED_SERVER_OK, 200);
    }

    #[test]
    fn identifies_known_transport_ops() {
        assert_eq!(
            ReolinkTransportOp::from_u32(0x3b),
            Some(ReolinkTransportOp::ForceUserPassword)
        );
        assert_eq!(
            ReolinkTransportOp::from_u32(0x76),
            Some(ReolinkTransportOp::ReadBootPwdState)
        );
        assert_eq!(ReolinkTransportOp::from_u32(0xffff), None);
    }

    #[test]
    fn builds_short_frame_roundtrip() {
        let frame = build_short_frame(0x01, 0, 0x6514_dc12, &[]);
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(
            header,
            ReolinkFrameHeader::Short {
                op: 0x01,
                payload_len: 0,
                field_c: 0,
                field_d: 0x6514_dc12,
                header_len: 20,
                total_len: 20,
            }
        );
    }

    #[test]
    fn builds_extended_frame_roundtrip() {
        let frame = build_extended_frame(0x24, 8, OBSERVED_CLIENT_FIELD_D, 0, &[0xaa, 0xbb]);
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(
            header,
            ReolinkFrameHeader::Extended {
                op: 0x24,
                payload_len: 2,
                field_c: 8,
                field_d: OBSERVED_CLIENT_FIELD_D,
                field_e: 0,
                header_len: 24,
                total_len: 26,
            }
        );
    }

    #[test]
    fn extracts_login_credential_window() {
        let mut frame = vec![
            0xf0, 0xde, 0xbc, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0xdc, 0x14, 0x65,
        ];
        frame.extend(std::iter::repeat_n(0u8, 300));
        frame[LOGIN_CREDENTIAL_WINDOW.start] = 0xaa;
        frame[LOGIN_CREDENTIAL_WINDOW.end - 1] = 0xbb;
        let window = login_credential_window(&frame).expect("window");
        assert_eq!(window.len(), LOGIN_CREDENTIAL_WINDOW.len());
        assert_eq!(window[0], 0xaa);
        assert_eq!(window[window.len() - 1], 0xbb);
    }

    #[test]
    fn observed_login_frame_matches_declared_length() {
        let frame = observed_login_frame();
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(header.total_len(), LOGIN_FRAME_LEN);
        assert_eq!(frame.len(), LOGIN_FRAME_LEN);
    }

    #[test]
    fn splits_observed_login_blocks() {
        let frame = observed_login_frame();
        assert!(login_has_expected_zero_lead(&frame));
        assert_eq!(
            login_reflected_server_prefix(&frame).expect("prefix"),
            &OBSERVED_SERVER_HANDSHAKE_BODY[..LOGIN_REFLECTED_SERVER_PREFIX_LEN]
        );
        assert_eq!(
            login_username_block(&frame).expect("username"),
            OBSERVED_USERNAME_BLOCK
        );
        assert_eq!(
            login_middle_block(&frame).expect("middle"),
            LOGIN_STATIC_MIDDLE
        );
        assert_eq!(
            login_password_block(&frame).expect("password"),
            OBSERVED_PASSWORD_BLOCK
        );
        assert!(login_has_observed_static_middle(&frame));
    }

    #[test]
    fn extracts_server_handshake_body() {
        let frame = observed_server_handshake_frame();
        let body = handshake_frame_body(&frame).expect("body");
        assert_eq!(body, OBSERVED_SERVER_HANDSHAKE_BODY);
    }

    #[test]
    fn login_matches_observed_server_prefix() {
        let login = observed_login_frame();
        let server = observed_server_handshake_frame();
        assert!(login_matches_server_prefix(&login, &server));
    }

    #[test]
    fn extracts_observed_handshake_windows() {
        let payload: Vec<u8> = (0..OBSERVED_SERVER_HANDSHAKE_BODY.len())
            .map(|index| index as u8)
            .collect();
        let frame = build_short_frame(
            ReolinkTransportOp::Handshake as u32,
            0,
            0x6514_dc12,
            &payload,
        );

        assert_eq!(
            handshake_reflected_prefix(&frame).expect("prefix"),
            &payload[..LOGIN_REFLECTED_SERVER_PREFIX_LEN]
        );
        assert_eq!(
            handshake_observed_credential_salt(&frame).expect("salt"),
            SERVER_HANDSHAKE_CREDENTIAL_SALT_INDICES.map(|index| payload[index])
        );
    }

    #[test]
    fn detects_diffs_confined_to_credential_blocks() {
        let left = observed_login_frame();
        let mut right = left.clone();
        right[LOGIN_USERNAME_WINDOW.start] ^= 0xff;
        right[LOGIN_PASSWORD_WINDOW.end - 1] ^= 0xff;
        assert!(login_frames_differ_only_in_credential_blocks(&left, &right));

        right[LOGIN_MIDDLE_WINDOW.start] ^= 0xff;
        assert!(!login_frames_differ_only_in_credential_blocks(
            &left, &right
        ));
    }

    #[test]
    fn encodes_observed_password_secret() {
        assert_eq!(
            encode_password_secret(b"test1234").as_deref(),
            Some("sYvw14rJMSHhNsRJlaApLA==")
        );
    }

    #[test]
    fn decodes_observed_password_secret() {
        assert_eq!(
            decode_password_secret("sYvw14rJMSHhNsRJlaApLA==").as_deref(),
            Some(b"test1234".as_slice())
        );
    }

    #[test]
    fn maps_confirmed_observed_dispatches() {
        assert_eq!(
            ReolinkRemoteCommand::GetNetAdvancedPort.observed_dispatch(),
            Some(ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::HeaderOnly,
                request_id: 0x848,
                payload_len: 0,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetNetAdvancedPort.observed_dispatch(),
            Some(ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x849,
                payload_len: 0x18,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetP2PCfg.observed_dispatch(),
            Some(ReolinkObservedDispatch {
                kind: ReolinkDispatchKind::Payload,
                request_id: 0x86a,
                payload_len: 0x28,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::GetNetNormalPort.observed_dispatch(),
            None
        );
        assert_eq!(
            ReolinkRemoteCommand::ForceUserPassword.observed_dispatch(),
            None
        );
    }

    #[test]
    fn maps_confirmed_observed_primary_transport() {
        assert_eq!(
            ReolinkRemoteCommand::GetNetAdvancedPort.observed_primary_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadPortBundle,
                payload_len: 0,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetNetAdvancedPort.observed_primary_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WritePortBundle,
                payload_len: 222,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetNetNormalPort.observed_primary_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WritePortBundle,
                payload_len: 307,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetP2PCfg.observed_primary_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::WriteP2P,
                payload_len: 144,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::SetP2PCfg.observed_apply_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ApplyConfig,
                payload_len: 125,
            })
        );
        assert_eq!(
            ReolinkRemoteCommand::GetLoginAuthCode.observed_primary_transport(),
            Some(ReolinkObservedTransportRequest {
                op: ReolinkTransportOp::ReadLoginAuthCode,
                payload_len: 218,
            })
        );
    }

    #[test]
    fn maps_confirmed_observed_transport_ops() {
        assert_eq!(
            ReolinkRemoteCommand::GetNetAdvancedPort.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadPortBundle,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::SetNetAdvancedPort.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadPortBundle,
                    ReolinkTransportOp::WritePortBundle,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::GetNetNormalPort.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadPortBundle,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::SetNetNormalPort.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadPortBundle,
                    ReolinkTransportOp::WritePortBundle,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::ForceUserPassword.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ForceUserPassword,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::GetP2PCfg.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadP2P,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::GetBootPwdState.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadBootPwdState,
                    ReolinkTransportOp::AsyncStatus,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::SetBootPwdState.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::WriteBootPwdState,
                    ReolinkTransportOp::Telemetry,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::SetP2PCfg.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Handshake,
                    ReolinkTransportOp::Login,
                    ReolinkTransportOp::SessionBind,
                    ReolinkTransportOp::ChannelReady,
                    ReolinkTransportOp::CommonAck,
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::Telemetry,
                    ReolinkTransportOp::ApplyConfig,
                    ReolinkTransportOp::ReadP2P,
                    ReolinkTransportOp::WriteP2P,
                ][..]
            )
        );
        assert_eq!(
            ReolinkRemoteCommand::GetLoginAuthCode.observed_transport_ops(),
            Some(
                &[
                    ReolinkTransportOp::CommonReadA,
                    ReolinkTransportOp::CommonReadB,
                    ReolinkTransportOp::CommonReadC,
                    ReolinkTransportOp::ReadLoginAuthCode,
                    ReolinkTransportOp::Telemetry,
                ][..]
            )
        );
    }

    #[test]
    fn replaces_login_blocks_and_preserves_observed_middle() {
        let frame = observed_login_frame();
        let username = [0x11; 31];
        let password = [0x22; 31];
        let replaced = replace_login_blocks(&frame, &username, &password).expect("replaced");
        assert_eq!(login_username_block(&replaced).expect("username"), username);
        assert_eq!(
            login_middle_block(&replaced).expect("middle"),
            LOGIN_STATIC_MIDDLE
        );
        assert_eq!(login_password_block(&replaced).expect("password"), password);
    }

    #[test]
    fn bcencrypt_roundtrip() {
        let payload = b"constitute-reolink-bcencrypt";
        let encrypted = bcencrypt(0, payload);
        assert_ne!(encrypted, payload);
        let decrypted = bcdecrypt(0, &encrypted);
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn decrypts_observed_handshake_and_extracts_nonce() {
        let frame = observed_server_handshake_frame();
        let body = handshake_frame_body(&frame).expect("handshake body");
        let xml = decrypt_handshake_xml(body).expect("handshake xml");
        assert!(xml.contains("<Encryption version=\"1.1\">"));
        assert!(xml.contains("<nonce>"));
        let nonce = extract_nonce_from_handshake_body(body).expect("nonce");
        assert!(!nonce.is_empty());
    }

    #[test]
    fn computes_expected_modern_login_hashes() {
        let nonce = "69a886e7-e6zQYHd61yUQBte6rV0F";
        assert_eq!(
            md5_upper_31(&format!("{}{}", "admin", nonce)),
            "ED31EBDF0CB67A665AE471BF2A75BA7"
        );
        assert_eq!(
            md5_upper_31(&format!("{}{}", "Test1234", nonce)),
            "E400F51521344AC76EFCBF85C5A869C"
        );
    }

    #[test]
    fn builds_expected_login_xml_and_frame_shape() {
        let nonce = "69a886e7-e6zQYHd61yUQBte6rV0F";
        let xml = build_login_xml("admin", "Test1234", nonce);
        assert!(xml.contains("<userName>ED31EBDF0CB67A665AE471BF2A75BA7</userName>"));
        assert!(xml.contains("<password>E400F51521344AC76EFCBF85C5A869C</password>"));

        let frame = build_login_frame("admin", "Test1234", nonce);
        let header = parse_frame_header(&frame).expect("frame header");
        assert_eq!(header.op(), ReolinkTransportOp::Handshake as u32);
        assert_eq!(frame.len(), 24 + xml.len());

        let encrypted = match header {
            ReolinkFrameHeader::Extended { .. } => &frame[24..],
            ReolinkFrameHeader::Short { .. } => panic!("expected extended login frame"),
        };
        let decrypted = String::from_utf8(bcdecrypt(0, encrypted)).expect("login xml utf8");
        assert_eq!(decrypted, xml);
    }

    #[test]
    fn builds_expected_handshake_probe_frame() {
        let frame = build_handshake_probe_frame();
        assert_eq!(
            frame,
            vec![
                0xf0, 0xde, 0xbc, 0x0a, // magic
                0x01, 0x00, 0x00, 0x00, // op
                0x00, 0x00, 0x00, 0x00, // payload len
                0x00, 0x00, 0x00, 0x00, // field c
                0x12, 0xdc, 0x14, 0x65, // field d
            ]
        );
    }

    #[test]
    fn derives_expected_native_aes_key() {
        let key = derive_native_aes_key("69e00658-r6VKbALDLgV79bIJbVCw", "Test1234");
        assert_eq!(hex::encode_upper(key), "33464638353135443233444146454137");
    }

    #[test]
    fn native_ptz_position_xml_roundtrips() {
        let position = ReolinkPtzPosition {
            pan: 1200,
            tilt: 150,
            zoom: 20,
        };
        let xml = build_native_ptz_position_xml(position);
        assert_eq!(parse_native_ptz_position_xml(&xml), Some(position));
    }

    #[test]
    fn builds_observed_native_ptz_get_frame() {
        let key = derive_native_aes_key("69e00658-r6VKbALDLgV79bIJbVCw", "Test1234");
        let frame = build_native_ptz_get_frame(13, 0, &key);
        assert_eq!(
            hex::encode(frame),
            "f0debc0ab10100007d0000000d000000000014647d000000e7e49bf3a5aa96dc8f3ba2b0d9f5d8a3bd2392e2485648b2f524f0197ed5ff5426083d95249947c5effc643e719781780af8a599f4ab4f811683be06433d476f58fb30e2ff0241d7dd4772d15a3a6f7b0244664e18c124724fa762b3414f574dd96478788843311a1587e236cab7e6607e49f1d9f69732f347e5f3e442"
        );
    }

    #[test]
    fn builds_observed_native_ptz_set_frame() {
        let key = derive_native_aes_key("69e00658-r6VKbALDLgV79bIJbVCw", "Test1234");
        let frame = build_native_ptz_set_frame(
            14,
            0,
            ReolinkPtzPosition {
                pan: 600,
                tilt: 50,
                zoom: 0,
            },
            &key,
        );
        assert_eq!(
            hex::encode(frame),
            "f0debc0ad4010000f60000000e0000000000146468000000e7e49bf3a5aa96dc8f3ba2b0d9f5d8a3bd2392e2485648b2f524f0197ed5ff5426083d95249947c5effc643e719781780af8a599f4ab4f811683be06433d476f58fb30e2ff0241d7dd4772d15a3a6f7b0244664e18c124724fa762b30d62416d239fde3a752d9227e7e49bf3a5aa96dc8f3ba2b0d9f5d8a3bd2392e2485648b2f524f0197ed5ff5426083d95249947c5efdb732e6dc7f82d9d9d1ed82a595ccfb868fff4e382b81958ce5dfaafeadbc389b4de7b7ae608dafff93ad4dd3f6e1fea31338ac90949ae5f6acfa4bbd2ef02caa119c823643d756253c238a4f368631a9ed20ee1fafb222b2adb1a977b44df8f98c531ea52"
        );
    }

    #[test]
    fn builds_observed_native_session_login_frame() {
        let key = derive_native_aes_key("69e005cb-Bg1MR1hzCrHeb0WxIQKN", "Test1234");
        let frame = build_native_session_login_frame(1, "admin", &key);
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(header.op(), ReolinkTransportOp::Login as u32);
        assert_eq!(header.field_c(), 1);
        let body = decrypt_native_payload(&key, &frame[header.header_len()..header.total_len()]);
        let xml = String::from_utf8(body).expect("utf8");
        assert!(xml.contains("<userName>admin</userName>"));
        assert!(xml.contains(NATIVE_SESSION_LOGIN_TOKEN));
    }

    #[test]
    fn builds_observed_native_session_bind_frame() {
        let key = derive_native_aes_key("69e005cb-Bg1MR1hzCrHeb0WxIQKN", "Test1234");
        let frame = build_native_session_bind_frame(2, "admin", &key);
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(header.op(), ReolinkTransportOp::SessionBind as u32);
        assert_eq!(header.field_c(), 2);
        let body = decrypt_native_payload(&key, &frame[header.header_len()..header.total_len()]);
        let xml = String::from_utf8(body).expect("utf8");
        assert!(xml.contains("<userName>admin</userName>"));
        assert!(!xml.contains("<token>"));
    }

    #[test]
    fn builds_observed_native_prepare_ptz_frame() {
        let key = derive_native_aes_key("69e005cb-Bg1MR1hzCrHeb0WxIQKN", "Test1234");
        let frame = build_native_prepare_ptz_frame(9, 0, &key);
        let header = parse_frame_header(&frame).expect("header");
        assert_eq!(header.op(), ReolinkTransportOp::ApplyConfig as u32);
        assert_eq!(header.field_c(), 9);
        let body = decrypt_native_payload(&key, &frame[header.header_len()..header.total_len()]);
        let xml = String::from_utf8(body).expect("utf8");
        assert!(xml.contains("<channelId>0</channelId>"));
        assert!(xml.contains("<chnType>0</chnType>"));
    }

    #[test]
    fn decrypts_observed_native_ptz_get_response() {
        let key = derive_native_aes_key("69e00658-r6VKbALDLgV79bIJbVCw", "Test1234");
        let frame = hex::decode("f0debc0ab10100008e0000000d000000c800000000000000e7e49bf3a5aa96dc8f3ba2b0d9f5d8a3bd2392e2485648b2f524f0197ed5ff5426083d95249947c5efdb732e6dc7f82d9d9d1ed82a595ccfb868fff4e382b81958ce5dfaafeadbc389b4de7b7ae608d994308caa82f95b2df126707b1e4d5bfc9f69d1c10628e7c69d0949bd5297092010272f93a11079fb14a2dc06a5ded089eb0725912d9b5f8e4646a11dd6d8").expect("frame");
        let header = parse_frame_header(&frame).expect("header");
        let body = &frame[header.header_len()..header.total_len()];
        let xml = String::from_utf8(decrypt_native_payload(&key, body)).expect("xml");
        assert_eq!(
            parse_native_ptz_position_xml(&xml),
            Some(ReolinkPtzPosition {
                pan: 561,
                tilt: 51,
                zoom: 0,
            })
        );
    }
}
