use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use reqwest::Client;
use roxmltree::{Document, Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

use crate::config::{CameraDesiredConfig, CameraTimeMode};

const DEVICE_WSDL: &str = "http://www.onvif.org/ver10/device/wsdl";
const MEDIA_WSDL: &str = "http://www.onvif.org/ver10/media/wsdl";
const PTZ_WSDL: &str = "http://www.onvif.org/ver20/ptz/wsdl";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnvifNetworkProtocol {
    pub name: String,
    pub enabled: bool,
    pub port: u16,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnvifState {
    pub manufacturer: String,
    pub model: String,
    pub firmware_version: String,
    pub serial_number: String,
    pub hardware_id: String,
    pub device_service_url: String,
    pub media_service_url: String,
    pub ptz_service_url: String,
    pub profile_token: String,
    pub time_mode: String,
    pub timezone: String,
    pub ntp_server: String,
    pub manual_time: String,
    pub ptz_capable: bool,
    pub current_pose: Option<OnvifPtzPose>,
    pub pose_status: String,
    pub network_protocols: Vec<OnvifNetworkProtocol>,
    pub network_protocols_writable: bool,
    pub raw: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnvifPtzPose {
    pub pan: Option<f32>,
    pub tilt: Option<f32>,
    pub zoom: Option<f32>,
}

pub async fn read_state(ip: &str, port: u16, username: &str, password: &str) -> Result<OnvifState> {
    let client = http_client()?;
    let device_service_url = format!("http://{}:{}/onvif/device_service", ip.trim(), port.max(1));
    let device_info_xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetDeviceInformation"),
        "<tds:GetDeviceInformation/>",
    )
    .await
    .context("ONVIF GetDeviceInformation failed")?;
    let capabilities_xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetCapabilities"),
        "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
    )
    .await
    .context("ONVIF GetCapabilities failed")?;
    let date_time_xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetSystemDateAndTime"),
        "<tds:GetSystemDateAndTime/>",
    )
    .await
    .context("ONVIF GetSystemDateAndTime failed")?;
    let ntp_xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetNTP"),
        "<tds:GetNTP/>",
    )
    .await
    .unwrap_or_default();
    let network_protocols_xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetNetworkProtocols"),
        "<tds:GetNetworkProtocols/>",
    )
    .await
    .unwrap_or_default();

    let info_doc = parse_doc(&device_info_xml)?;
    let caps_doc = parse_doc(&capabilities_xml)?;
    let time_doc = parse_doc(&date_time_xml)?;
    let ntp_doc = if ntp_xml.trim().is_empty() {
        None
    } else {
        Some(parse_doc(&ntp_xml).context("invalid ONVIF GetNTP response")?)
    };
    let network_protocols_doc = if network_protocols_xml.trim().is_empty() {
        None
    } else {
        Some(
            parse_doc(&network_protocols_xml)
                .context("invalid ONVIF GetNetworkProtocols response")?,
        )
    };
    let network_protocols = network_protocols_doc
        .as_ref()
        .map(parse_network_protocols)
        .unwrap_or_default();

    let media_service_url = capability_xaddr(&caps_doc, "Media")
        .unwrap_or_else(|| format!("http://{}:{}/onvif/media_service", ip.trim(), port.max(1)));
    let ptz_service_url = capability_xaddr(&caps_doc, "PTZ")
        .unwrap_or_else(|| format!("http://{}:{}/onvif/ptz_service", ip.trim(), port.max(1)));

    let profiles_xml = soap_call(
        &client,
        &media_service_url,
        username,
        password,
        &format!("{MEDIA_WSDL}/GetProfiles"),
        "<trt:GetProfiles/>",
    )
    .await
    .context("ONVIF GetProfiles failed")?;
    let profiles_doc = parse_doc(&profiles_xml)?;
    let profile_token = preferred_profile_token(&profiles_doc).unwrap_or_default();

    let ptz_status_xml = if profile_token.is_empty() {
        None
    } else {
        soap_call(
            &client,
            &ptz_service_url,
            username,
            password,
            &format!("{PTZ_WSDL}/GetStatus"),
            &format!(
                "<tptz:GetStatus><tptz:ProfileToken>{}</tptz:ProfileToken></tptz:GetStatus>",
                escape_xml(&profile_token)
            ),
        )
        .await
        .ok()
    };
    let ptz_capable = ptz_status_xml.is_some();
    let (current_pose, pose_status) = ptz_status_xml
        .as_deref()
        .and_then(|xml| parse_doc(xml).ok())
        .map(|doc| (parse_ptz_pose(&doc), parse_ptz_move_status(&doc)))
        .unwrap_or((None, String::new()));

    Ok(OnvifState {
        manufacturer: descendant_text(&info_doc, "Manufacturer"),
        model: descendant_text(&info_doc, "Model"),
        firmware_version: descendant_text(&info_doc, "FirmwareVersion"),
        serial_number: descendant_text(&info_doc, "SerialNumber"),
        hardware_id: descendant_text(&info_doc, "HardwareId"),
        device_service_url,
        media_service_url,
        ptz_service_url,
        profile_token: profile_token.clone(),
        time_mode: descendant_text(&time_doc, "DateTimeType").to_ascii_lowercase(),
        timezone: descendant_text(&time_doc, "TZ"),
        ntp_server: ntp_doc.as_ref().map(first_ntp_server).unwrap_or_default(),
        manual_time: local_datetime_value(&time_doc),
        ptz_capable,
        current_pose: current_pose.clone(),
        pose_status: pose_status.clone(),
        network_protocols: network_protocols.clone(),
        network_protocols_writable: network_protocols_doc.is_some(),
        raw: json!({
            "deviceInformation": {
                "manufacturer": descendant_text(&info_doc, "Manufacturer"),
                "model": descendant_text(&info_doc, "Model"),
                "firmwareVersion": descendant_text(&info_doc, "FirmwareVersion"),
                "serialNumber": descendant_text(&info_doc, "SerialNumber"),
                "hardwareId": descendant_text(&info_doc, "HardwareId"),
            },
            "services": {
                "device": capability_xaddr(&caps_doc, "Device").unwrap_or_default(),
                "media": capability_xaddr(&caps_doc, "Media").unwrap_or_default(),
                "ptz": capability_xaddr(&caps_doc, "PTZ").unwrap_or_default(),
                "events": capability_xaddr(&caps_doc, "Events").unwrap_or_default(),
            },
            "time": {
                "mode": descendant_text(&time_doc, "DateTimeType"),
                "timezone": descendant_text(&time_doc, "TZ"),
                "localDateTime": local_datetime_value(&time_doc),
                "ntpServer": ntp_doc.as_ref().map(first_ntp_server).unwrap_or_default(),
            },
            "ptz": {
                "currentPose": current_pose,
                "status": pose_status,
            },
            "networkProtocols": network_protocols,
            "networkProtocolsSupported": network_protocols_doc.is_some(),
            "profileToken": profile_token,
        }),
    })
}

pub async fn read_network_protocols(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<Vec<OnvifNetworkProtocol>> {
    let client = http_client()?;
    let device_service_url = format!("http://{}:{}/onvif/device_service", ip.trim(), port.max(1));
    let xml = soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/GetNetworkProtocols"),
        "<tds:GetNetworkProtocols/>",
    )
    .await
    .context("ONVIF GetNetworkProtocols failed")?;
    let doc = parse_doc(&xml)?;
    Ok(parse_network_protocols(&doc))
}

pub async fn set_network_protocol(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    protocol_name: &str,
    enabled: bool,
    protocol_port: u16,
) -> Result<()> {
    let client = http_client()?;
    let device_service_url = format!("http://{}:{}/onvif/device_service", ip.trim(), port.max(1));
    soap_call(
        &client,
        &device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/SetNetworkProtocols"),
        &format!(
            "<tds:SetNetworkProtocols><tds:NetworkProtocols><tt:Name>{}</tt:Name><tt:Enabled>{}</tt:Enabled><tt:Port>{}</tt:Port></tds:NetworkProtocols></tds:SetNetworkProtocols>",
            escape_xml(protocol_name.trim()),
            if enabled { "true" } else { "false" },
            protocol_port.max(1),
        ),
    )
    .await
    .with_context(|| format!("ONVIF SetNetworkProtocols failed for {}", protocol_name.trim()))
    .map(|_| ())
}

pub async fn apply_time_settings(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    desired: &CameraDesiredConfig,
) -> Result<()> {
    let state = read_state(ip, port, username, password).await?;
    let client = http_client()?;
    let timezone = if desired.timezone.trim().is_empty() {
        state.timezone.trim().to_string()
    } else {
        desired.timezone.trim().to_string()
    };

    if matches!(desired.time_mode, CameraTimeMode::Ntp) {
        let ntp_server = desired.ntp_server.trim();
        if !ntp_server.is_empty() {
            soap_call(
                &client,
                &state.device_service_url,
                username,
                password,
                &format!("{DEVICE_WSDL}/SetNTP"),
                &format!(
                    "<tds:SetNTP><tds:FromDHCP>false</tds:FromDHCP>{}</tds:SetNTP>",
                    ntp_manual_entry(ntp_server)
                ),
            )
            .await
            .context("ONVIF SetNTP failed")?;
        }

        let timezone_xml = if timezone.is_empty() {
            String::new()
        } else {
            format!(
                "<tds:TimeZone><tt:TZ>{}</tt:TZ></tds:TimeZone>",
                escape_xml(&timezone)
            )
        };
        soap_call(
            &client,
            &state.device_service_url,
            username,
            password,
            &format!("{DEVICE_WSDL}/SetSystemDateAndTime"),
            &format!(
                "<tds:SetSystemDateAndTime><tds:DateTimeType>NTP</tds:DateTimeType><tds:DaylightSavings>false</tds:DaylightSavings>{timezone_xml}</tds:SetSystemDateAndTime>"
            ),
        )
        .await
        .context("ONVIF SetSystemDateAndTime (NTP) failed")?;
        return Ok(());
    }

    let manual_time = desired.manual_time.trim();
    if manual_time.is_empty() {
        return Err(anyhow!("manual_time is required when time_mode is manual"));
    }
    let manual_xml = build_manual_datetime_xml(manual_time)?;
    let timezone_xml = if timezone.is_empty() {
        String::new()
    } else {
        format!(
            "<tds:TimeZone><tt:TZ>{}</tt:TZ></tds:TimeZone>",
            escape_xml(&timezone)
        )
    };
    soap_call(
        &client,
        &state.device_service_url,
        username,
        password,
        &format!("{DEVICE_WSDL}/SetSystemDateAndTime"),
        &format!(
            "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType><tds:DaylightSavings>false</tds:DaylightSavings>{timezone_xml}<tds:UTCDateTime>{manual_xml}</tds:UTCDateTime></tds:SetSystemDateAndTime>"
        ),
    )
    .await
    .context("ONVIF SetSystemDateAndTime (manual) failed")?;
    Ok(())
}

pub async fn ptz_control(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    direction: &str,
    active: bool,
) -> Result<()> {
    let state = read_state(ip, port, username, password).await?;
    if state.profile_token.trim().is_empty() || state.ptz_service_url.trim().is_empty() {
        return Err(anyhow!(
            "ONVIF PTZ service is not available for this camera"
        ));
    }
    let client = http_client()?;
    if !active || direction.eq_ignore_ascii_case("stop") {
        soap_call(
            &client,
            &state.ptz_service_url,
            username,
            password,
            &format!("{PTZ_WSDL}/Stop"),
            &format!(
                "<tptz:Stop><tptz:ProfileToken>{}</tptz:ProfileToken><tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>",
                escape_xml(&state.profile_token)
            ),
        )
        .await
        .context("ONVIF PTZ stop failed")?;
        return Ok(());
    }

    let (x, y) = match direction.trim().to_ascii_lowercase().as_str() {
        "left" => (-0.2f32, 0.0f32),
        "right" => (0.2f32, 0.0f32),
        "up" => (0.0f32, 0.2f32),
        "down" => (0.0f32, -0.2f32),
        other => return Err(anyhow!("unsupported ONVIF PTZ direction: {other}")),
    };
    soap_call(
        &client,
        &state.ptz_service_url,
        username,
        password,
        &format!("{PTZ_WSDL}/ContinuousMove"),
        &format!(
            "<tptz:ContinuousMove><tptz:ProfileToken>{}</tptz:ProfileToken><tptz:Velocity><tt:PanTilt x=\"{}\" y=\"{}\"/></tptz:Velocity><tptz:Timeout>PT2S</tptz:Timeout></tptz:ContinuousMove>",
            escape_xml(&state.profile_token),
            x,
            y,
        ),
    )
    .await
    .context("ONVIF PTZ move failed")?;
    Ok(())
}

pub async fn ptz_set_pose(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    pan: Option<f32>,
    tilt: Option<f32>,
    zoom: Option<f32>,
) -> Result<OnvifPtzPose> {
    let state = read_state(ip, port, username, password).await?;
    if state.profile_token.trim().is_empty() || state.ptz_service_url.trim().is_empty() {
        return Err(anyhow!(
            "ONVIF PTZ service is not available for this camera"
        ));
    }
    let client = http_client()?;
    let previous_pose = state.current_pose.clone();
    let target_pan = pan
        .or(state.current_pose.as_ref().and_then(|pose| pose.pan))
        .unwrap_or(0.0);
    let target_tilt = tilt
        .or(state.current_pose.as_ref().and_then(|pose| pose.tilt))
        .unwrap_or(0.0);
    let target_zoom = zoom.or(state.current_pose.as_ref().and_then(|pose| pose.zoom));
    let zoom_xml = target_zoom
        .map(|value| format!("<tt:Zoom x=\"{}\"/>", clamp_pose(value)))
        .unwrap_or_default();
    soap_call(
        &client,
        &state.ptz_service_url,
        username,
        password,
        &format!("{PTZ_WSDL}/AbsoluteMove"),
        &format!(
            "<tptz:AbsoluteMove><tptz:ProfileToken>{}</tptz:ProfileToken><tptz:Position><tt:PanTilt x=\"{}\" y=\"{}\"/>{}</tptz:Position></tptz:AbsoluteMove>",
            escape_xml(&state.profile_token),
            clamp_pose(target_pan),
            clamp_pose(target_tilt),
            zoom_xml,
        ),
    )
    .await
    .context("ONVIF PTZ absolute move failed")?;
    let expected = OnvifPtzPose {
        pan: Some(clamp_pose(target_pan)),
        tilt: Some(clamp_pose(target_tilt)),
        zoom: target_zoom.map(clamp_pose),
    };
    for _ in 0..5 {
        sleep(Duration::from_millis(450)).await;
        let refreshed = read_state(ip, port, username, password).await?;
        if let Some(pose) = refreshed.current_pose {
            if pose_looks_updated(previous_pose.as_ref(), &pose)
                || pose_matches_target(&pose, &expected)
            {
                return Ok(pose);
            }
        }
    }
    Err(anyhow!(
        "ONVIF PTZ absolute move was accepted but no updated pose was observed from GetStatus"
    ))
}

pub async fn ptz_step_pose(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    pan_delta: f32,
    tilt_delta: f32,
    zoom_delta: f32,
) -> Result<OnvifPtzPose> {
    let state = read_state(ip, port, username, password).await?;
    let current = state.current_pose.clone().unwrap_or_default();
    let next_pan = Some(clamp_pose(current.pan.unwrap_or(0.0) + pan_delta));
    let next_tilt = Some(clamp_pose(current.tilt.unwrap_or(0.0) + tilt_delta));
    let next_zoom = if zoom_delta == 0.0 {
        current.zoom
    } else {
        Some(clamp_pose(current.zoom.unwrap_or(0.0) + zoom_delta))
    };
    ptz_set_pose(ip, port, username, password, next_pan, next_tilt, next_zoom).await
}

fn http_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed building ONVIF http client")
}

async fn soap_call(
    client: &Client,
    url: &str,
    username: &str,
    password: &str,
    action: &str,
    body_xml: &str,
) -> Result<String> {
    let body = build_envelope(username, password, body_xml);
    let response = client
        .post(url.trim())
        .header(
            "Content-Type",
            format!(
                "application/soap+xml; charset=utf-8; action=\"{}\"",
                action.trim()
            ),
        )
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed posting ONVIF action {} to {}", action, url))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .context("failed reading ONVIF response body")?;
    if !status.is_success() {
        return Err(anyhow!(
            "ONVIF action {} failed with {}: {}",
            action,
            status,
            text
        ));
    }
    Ok(text)
}

fn build_envelope(username: &str, password: &str, body_xml: &str) -> String {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let created = iso8601_now_utc();
    let mut digest = Sha1::new();
    digest.update(nonce);
    digest.update(created.as_bytes());
    digest.update(password.trim().as_bytes());
    let password_digest = BASE64.encode(digest.finalize());
    let nonce_b64 = BASE64.encode(nonce);
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" ",
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" ",
            "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" ",
            "xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" ",
            "xmlns:tt=\"http://www.onvif.org/ver10/schema\" ",
            "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" ",
            "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">",
            "<soap:Header><wsse:Security soap:mustUnderstand=\"true\"><wsse:UsernameToken>",
            "<wsse:Username>{}</wsse:Username>",
            "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">{}</wsse:Password>",
            "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">{}</wsse:Nonce>",
            "<wsu:Created>{}</wsu:Created>",
            "</wsse:UsernameToken></wsse:Security></soap:Header>",
            "<soap:Body>{}</soap:Body></soap:Envelope>"
        ),
        escape_xml(username.trim()),
        password_digest,
        nonce_b64,
        created,
        body_xml,
    )
}

fn parse_doc(xml: &str) -> Result<Document<'_>> {
    Document::parse(xml).context("invalid ONVIF XML payload")
}

fn descendant_text(doc: &Document<'_>, name: &str) -> String {
    doc.descendants()
        .find(|node| node.is_element() && node.tag_name().name() == name)
        .and_then(|node| node.text())
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

fn parse_network_protocols(doc: &Document<'_>) -> Vec<OnvifNetworkProtocol> {
    let mut out = Vec::new();
    for node in doc
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "NetworkProtocols")
    {
        let name = node
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Name")
            .and_then(|child| child.text())
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let enabled = node
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Enabled")
            .and_then(|child| child.text())
            .map(|text| matches!(text.trim().to_ascii_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false);
        let port = node
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Port")
            .and_then(|child| child.text())
            .and_then(|text| text.trim().parse::<u16>().ok())
            .unwrap_or(0);
        out.push(OnvifNetworkProtocol {
            name,
            enabled,
            port,
        });
    }
    out
}

fn parse_ptz_pose(doc: &Document<'_>) -> Option<OnvifPtzPose> {
    let position = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "Position")?;
    let pan_tilt = position
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "PanTilt");
    let zoom = position
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "Zoom");
    let pose = OnvifPtzPose {
        pan: pan_tilt
            .and_then(|node| node.attribute("x"))
            .and_then(|value| value.trim().parse::<f32>().ok()),
        tilt: pan_tilt
            .and_then(|node| node.attribute("y"))
            .and_then(|value| value.trim().parse::<f32>().ok()),
        zoom: zoom
            .and_then(|node| node.attribute("x"))
            .and_then(|value| value.trim().parse::<f32>().ok()),
    };
    if pose.pan.is_none() && pose.tilt.is_none() && pose.zoom.is_none() {
        None
    } else {
        Some(pose)
    }
}

fn parse_ptz_move_status(doc: &Document<'_>) -> String {
    doc.descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "MoveStatus")
        .map(|node| {
            let pan_tilt = node
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == "PanTilt")
                .and_then(|child| child.text())
                .unwrap_or_default()
                .trim()
                .to_string();
            let zoom = node
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == "Zoom")
                .and_then(|child| child.text())
                .unwrap_or_default()
                .trim()
                .to_string();
            match (pan_tilt.is_empty(), zoom.is_empty()) {
                (false, false) => format!("{pan_tilt}/{zoom}"),
                (false, true) => pan_tilt,
                (true, false) => zoom,
                (true, true) => String::new(),
            }
        })
        .unwrap_or_default()
}

fn clamp_pose(value: f32) -> f32 {
    value.clamp(-1.0, 1.0)
}

fn local_datetime_value(doc: &Document<'_>) -> String {
    let local = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "LocalDateTime");
    let Some(local) = local else {
        return String::new();
    };
    datetime_from_node(local)
}

fn datetime_from_node(node: Node<'_, '_>) -> String {
    let year = child_numeric(node, "Year");
    let month = child_numeric(node, "Month");
    let day = child_numeric(node, "Day");
    let hour = child_numeric(node, "Hour");
    let minute = child_numeric(node, "Minute");
    let second = child_numeric(node, "Second");
    match (year, month, day, hour, minute, second) {
        (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) => {
            format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
        }
        _ => String::new(),
    }
}

fn child_numeric(node: Node<'_, '_>, name: &str) -> Option<u32> {
    node.descendants()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .and_then(|value| value.trim().parse::<u32>().ok())
}

fn capability_xaddr(doc: &Document<'_>, capability_name: &str) -> Option<String> {
    let capability = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == capability_name)?;
    capability
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "XAddr")
        .and_then(|node| node.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn preferred_profile_token(doc: &Document<'_>) -> Option<String> {
    let profiles = doc.descendants().filter(|node| {
        node.is_element()
            && (node.tag_name().name() == "Profiles" || node.tag_name().name() == "Profile")
    });
    for profile in profiles.clone() {
        let has_ptz_configuration = profile
            .children()
            .any(|child| child.is_element() && child.tag_name().name() == "PTZConfiguration");
        if !has_ptz_configuration {
            continue;
        }
        if let Some(token) = profile
            .attribute("token")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Some(token);
        }
    }
    profiles
        .filter_map(|node| node.attribute("token"))
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn pose_looks_updated(previous: Option<&OnvifPtzPose>, next: &OnvifPtzPose) -> bool {
    let Some(previous_pose) = previous else {
        return next.pan.is_some() || next.tilt.is_some() || next.zoom.is_some();
    };
    pose_delta(previous_pose.pan, next.pan) > 0.005
        || pose_delta(previous_pose.tilt, next.tilt) > 0.005
        || pose_delta(previous_pose.zoom, next.zoom) > 0.005
}

fn pose_matches_target(current: &OnvifPtzPose, target: &OnvifPtzPose) -> bool {
    pose_axis_matches(current.pan, target.pan)
        && pose_axis_matches(current.tilt, target.tilt)
        && pose_axis_matches(current.zoom, target.zoom)
}

fn pose_axis_matches(current: Option<f32>, target: Option<f32>) -> bool {
    match target {
        Some(target_value) => pose_delta(current, Some(target_value)) <= 0.02,
        None => true,
    }
}

fn pose_delta(left: Option<f32>, right: Option<f32>) -> f32 {
    match (left, right) {
        (Some(left_value), Some(right_value)) => (left_value - right_value).abs(),
        _ => 1.0,
    }
}

fn first_ntp_server(doc: &Document<'_>) -> String {
    let server = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "DNSname")
        .and_then(|node| node.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    if let Some(server) = server {
        return server;
    }
    doc.descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "IPv4Address")
        .and_then(|node| node.text())
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

fn ntp_manual_entry(server: &str) -> String {
    let trimmed = server.trim();
    if trimmed.parse::<IpAddr>().is_ok() {
        format!(
            "<tds:NTPManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>{}</tt:IPv4Address></tds:NTPManual>",
            escape_xml(trimmed)
        )
    } else {
        format!(
            "<tds:NTPManual><tt:Type>DNS</tt:Type><tt:DNSname>{}</tt:DNSname></tds:NTPManual>",
            escape_xml(trimmed)
        )
    }
}

fn build_manual_datetime_xml(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let (date, time) = trimmed
        .split_once('T')
        .ok_or_else(|| anyhow!("manual_time must use YYYY-MM-DDTHH:MM[:SS] format"))?;
    let date_parts = date
        .split('-')
        .map(|part| part.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("manual_time has an invalid date")?;
    let time_parts = time
        .split(':')
        .map(|part| part.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("manual_time has an invalid time")?;
    if date_parts.len() != 3 || !(time_parts.len() == 2 || time_parts.len() == 3) {
        return Err(anyhow!("manual_time must use YYYY-MM-DDTHH:MM[:SS] format"));
    }
    let second = *time_parts.get(2).unwrap_or(&0);
    Ok(format!(
        "<tt:Time><tt:Hour>{}</tt:Hour><tt:Minute>{}</tt:Minute><tt:Second>{}</tt:Second></tt:Time><tt:Date><tt:Year>{}</tt:Year><tt:Month>{}</tt:Month><tt:Day>{}</tt:Day></tt:Date>",
        time_parts[0], time_parts[1], second, date_parts[0], date_parts[1], date_parts[2],
    ))
}

fn iso8601_now_utc() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_iso8601(now)
}

fn unix_to_iso8601(ts: u64) -> String {
    // Howard Hinnant civil-from-days adaptation, enough for ONVIF WSSE timestamps.
    let days = (ts / 86_400) as i64;
    let secs_of_day = (ts % 86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, minute, second,
    )
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_datetime_xml_accepts_datetime_local_values() {
        let xml = build_manual_datetime_xml("2026-04-05T22:51").unwrap();
        assert!(xml.contains("<tt:Hour>22</tt:Hour>"));
        assert!(xml.contains("<tt:Second>0</tt:Second>"));
    }

    #[test]
    fn ntp_manual_entry_uses_ipv4_or_dns() {
        assert!(ntp_manual_entry("192.168.250.1").contains("IPv4Address"));
        assert!(ntp_manual_entry("pool.ntp.org").contains("DNSname"));
    }
}
