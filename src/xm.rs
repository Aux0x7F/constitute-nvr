//! XM / NetSurveillance 40E driver lane.
//!
//! Driver-specific operational truth belongs here first, with only the high-level
//! compatibility/operator summary duplicated in shared docs.
//!
//! Active product boundary:
//! - authenticated XM SOAP-style management over the camera web endpoint
//! - baked title via `TitleOverlay.TitleUtf8`
//! - site time via manual seed -> NTP transition on `TimeConfig`
//! - hidden `UserOverlay` lane cleared so stale lower-left text does not leak
//! - no PTZ support on the validated 40E lab model

use anyhow::{Context, Result, anyhow};
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use regex::Regex;
use reqwest::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use roxmltree::Document;
use serde::Serialize;

const XM_LOGIN_KEY: &[u8; 8] = b"WebLogin";

#[derive(Clone, Debug)]
pub struct XmConnectRequest {
    pub host: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct XmSiteTimePolicy {
    pub ntp_server: String,
    pub timezone_code: i32,
    pub current_local_time: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmReadState {
    pub system: XmSystemInfo,
    pub time: XmTimeConfig,
    pub video: XmVideoConfig,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmSystemInfo {
    pub vendor: String,
    pub model_family: String,
    pub firmware_version: String,
    pub kernel_version: String,
    pub serial_number: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmTimeConfig {
    pub time_mode: String,
    pub current_time: String,
    pub current_time_iso: String,
    pub timezone_code: i32,
    pub timezone_offset_minutes: i32,
    pub timezone_offset_label: String,
    pub ntp_server: String,
    pub ntp_port: u16,
    pub refresh_interval_secs: u32,
    pub summer_time: XmSummerTime,
    #[serde(skip_serializing)]
    pub raw_xml: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmSummerTime {
    pub enabled: bool,
    pub automatic: bool,
    pub offset_minutes: i32,
    pub start: XmSummerTimePoint,
    pub end: XmSummerTimePoint,
}

impl Default for XmSummerTime {
    fn default() -> Self {
        Self {
            enabled: false,
            automatic: false,
            offset_minutes: 60,
            start: XmSummerTimePoint::default(),
            end: XmSummerTimePoint::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmSummerTimePoint {
    pub month: u8,
    pub week: u8,
    pub weekday: u8,
    pub hour: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XmVideoConfig {
    pub overlay_enabled: bool,
    pub title_text: String,
    pub title_hex: String,
    pub user_title_text: String,
    pub user_title_hex: String,
    pub time_format: String,
    pub time_24_or_12: String,
    pub show_weekday: bool,
    pub main_stream_format: String,
    pub preview_stream_format: String,
    pub preview_requires_transcode: bool,
    #[serde(skip_serializing)]
    pub raw_xml: String,
}

pub async fn read_state(request: &XmConnectRequest) -> Result<XmReadState> {
    let session = XmSession::connect(request).await?;
    session.read_state().await
}

pub async fn apply_state(
    request: &XmConnectRequest,
    desired_display_title: Option<&str>,
    desired_overlay_title: Option<&str>,
    site_time: Option<&XmSiteTimePolicy>,
) -> Result<XmReadState> {
    let session = XmSession::connect(request).await?;
    let initial = session.read_state().await?;
    let mut wrote = false;

    if let Some(title) = desired_display_title {
        let title = title.trim();
        if !title.is_empty() && title != initial.video.title_text.trim() {
            let patched = render_overlay_config_xml(&initial.video.raw_xml, title)?;
            session
                .write_xml("/setMediaVideoOverlayConfig", &patched)
                .await
                .context("XM overlay write failed")?;
            wrote = true;
        }
    }

    match desired_overlay_title.map(str::trim) {
        Some(title) if !title.is_empty() => {
            if title != initial.video.user_title_text.trim() {
                let patched = render_user_overlay_config_xml(&initial.video.raw_xml, title)?;
                session
                    .write_xml("/setMediaVideoUserOverlayConfig", &patched)
                    .await
                    .context("XM custom title write failed")?;
                wrote = true;
            }
        }
        _ => {
            if user_overlay_requires_clear(&initial.video.raw_xml)? {
                let patched = clear_user_overlay_config_xml(&initial.video.raw_xml)?;
                session
                    .write_xml("/setMediaVideoUserOverlayConfig", &patched)
                    .await
                    .context("XM user overlay clear failed")?;
                wrote = true;
            }
        }
    }

    if let Some(policy) = site_time {
        let desired_ntp_time_xml = render_ntp_time_config_xml(&initial.time, policy);
        if normalize_for_compare(&desired_ntp_time_xml) != normalize_for_compare(&initial.time.raw_xml)
        {
            let manual_seed_xml = render_manual_time_config_xml(&initial.time, policy);
            session
                .write_xml("/setTimeConfig", &manual_seed_xml)
                .await
                .context("XM manual time seed failed")?;
            session
                .write_xml("/setTimeConfig", &desired_ntp_time_xml)
                .await
                .context("XM time write failed")?;
            wrote = true;
        }
    }

    if wrote {
        return session.read_state().await;
    }
    Ok(initial)
}

pub fn timezone_code_to_offset_minutes(code: i32) -> i32 {
    code - 720
}

pub fn timezone_offset_label(code: i32) -> String {
    let offset = timezone_code_to_offset_minutes(code);
    let sign = if offset >= 0 { '+' } else { '-' };
    let abs = offset.abs();
    format!("UTC{}{:02}:{:02}", sign, abs / 60, abs % 60)
}

fn normalize_for_compare(xml: &str) -> String {
    xml.chars().filter(|ch| !ch.is_whitespace()).collect()
}

struct XmSession {
    client: Client,
    base_url: String,
    user_token: String,
    pass_token: String,
}

impl XmSession {
    async fn connect(request: &XmConnectRequest) -> Result<Self> {
        let host = request.host.trim();
        if host.is_empty() {
            return Err(anyhow!("XM host is missing"));
        }
        let username = request.username.trim();
        let password = request.password.trim();
        if username.is_empty() || password.is_empty() {
            return Err(anyhow!("XM credentials are required"));
        }

        let client = xm_http_client()?;
        let user_token = encode_login_token(username)?;
        let pass_token = encode_login_token(password)?;
        let login_xml = soap_request_xml(&user_token, &pass_token, "");
        let mut last_error = None;
        for base_url in [format!("http://{host}"), format!("https://{host}")] {
            match xm_post(&client, &base_url, "/ipcLogin", &login_xml).await {
                Ok(body) if body.contains("<SystemFunction") => {
                    return Ok(Self {
                        client,
                        base_url,
                        user_token,
                        pass_token,
                    });
                }
                Ok(body) => {
                    last_error = Some(anyhow!(
                        "XM login returned an unexpected payload from {}: {}",
                        base_url,
                        truncate_payload(&body)
                    ));
                }
                Err(error) => {
                    last_error = Some(error.context(format!("XM login failed via {}", base_url)));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("XM login failed")))
    }

    async fn read_state(&self) -> Result<XmReadState> {
        let system_xml = self.read_xml("/getSystemVersionInfo").await?;
        let time_xml = self.read_xml("/getTimeConfig").await?;
        let video_xml = self.read_xml("/getMediaVideoConfig").await?;
        Ok(XmReadState {
            system: parse_system_info(&system_xml)?,
            time: parse_time_config(&time_xml)?,
            video: parse_video_config(&video_xml)?,
        })
    }

    async fn read_xml(&self, path: &str) -> Result<String> {
        let body = soap_request_xml(&self.user_token, &self.pass_token, "");
        xm_post(&self.client, &self.base_url, path, &body).await
    }

    async fn write_xml(&self, path: &str, body: &str) -> Result<String> {
        let body = soap_request_xml(&self.user_token, &self.pass_token, body);
        xm_post(&self.client, &self.base_url, path, &body).await
    }
}

fn xm_http_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .context("failed building XM HTTP client")
}

async fn xm_post(client: &Client, base_url: &str, path: &str, body: &str) -> Result<String> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let response = client
        .post(&url)
        .headers(xm_headers()?)
        .body(body.to_string())
        .send()
        .await
        .with_context(|| format!("XM POST {} failed", url))?;
    if !response.status().is_success() {
        let status = response.status();
        let payload = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "XM POST {} returned {}: {}",
            url,
            status,
            truncate_payload(&payload)
        ));
    }
    response
        .text()
        .await
        .with_context(|| format!("XM POST {} returned unreadable body", url))
}

fn xm_headers() -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert("X-Requested-With", HeaderValue::from_static("XMLHttpRequest"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/javascript, text/html, application/xml, text/xml, */*"),
    );
    Ok(headers)
}

fn truncate_payload(payload: &str) -> String {
    let trimmed = payload.trim();
    if trimmed.len() > 200 {
        format!("{}...", &trimmed[..200])
    } else {
        trimmed.to_string()
    }
}

fn soap_request_xml(user_token: &str, pass_token: &str, body: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2001/12/soap-envelope"><soap:Header><userid>{}</userid><passwd>{}</passwd></soap:Header><soap:Body>{}</soap:Body></soap:Envelope>"#,
        user_token, pass_token, body
    )
}

fn encode_login_token(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let mut bytes = value.as_bytes().to_vec();
    let padding = (8 - (bytes.len() % 8)) % 8;
    if padding > 0 {
        bytes.resize(bytes.len() + padding, 0);
    }
    let cipher = Des::new_from_slice(XM_LOGIN_KEY).context("invalid XM DES key")?;
    for chunk in bytes.chunks_mut(8) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(hex::encode(bytes))
}

fn parse_system_info(xml: &str) -> Result<XmSystemInfo> {
    let doc = Document::parse(xml).context("invalid XM system info XML")?;
    let version = doc
        .descendants()
        .find(|node| node.has_tag_name("VersionInfo"))
        .ok_or_else(|| anyhow!("XM system info missing VersionInfo"))?;
    let serial = doc
        .descendants()
        .find(|node| node.has_tag_name("SerialNumber"));
    let firmware_version = version.attribute("fsVersion").unwrap_or_default().trim();
    Ok(XmSystemInfo {
        vendor: "XM/NetSurveillance".to_string(),
        model_family: parse_model_family(firmware_version),
        firmware_version: firmware_version.to_string(),
        kernel_version: version
            .attribute("kernelVersion")
            .unwrap_or_default()
            .trim()
            .to_string(),
        serial_number: serial
            .and_then(|node| node.attribute("serialNumber"))
            .unwrap_or_default()
            .trim()
            .to_string(),
    })
}

fn parse_model_family(fs_version: &str) -> String {
    let trimmed = fs_version.trim();
    let token = trimmed
        .split(['_', ' '])
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default();
    if token.is_empty() {
        "XM Camera".to_string()
    } else {
        token.to_string()
    }
}

fn parse_time_config(xml: &str) -> Result<XmTimeConfig> {
    let doc = Document::parse(xml).context("invalid XM time XML")?;
    let root = doc
        .descendants()
        .find(|node| node.has_tag_name("TimeConfig"))
        .ok_or_else(|| anyhow!("XM time XML missing TimeConfig"))?;
    let ntp = root
        .children()
        .find(|node| node.has_tag_name("NTPConfig"));
    let summer = root
        .children()
        .find(|node| node.has_tag_name("SummerTime"));
    let timezone_code = root
        .attribute("TimeZone")
        .unwrap_or("720")
        .trim()
        .parse::<i32>()
        .unwrap_or(720);
    Ok(XmTimeConfig {
        time_mode: root
            .attribute("TimeMode")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase(),
        current_time: root.attribute("CurTime").unwrap_or_default().trim().to_string(),
        current_time_iso: normalize_time_value(root.attribute("CurTime").unwrap_or_default()),
        timezone_code,
        timezone_offset_minutes: timezone_code_to_offset_minutes(timezone_code),
        timezone_offset_label: timezone_offset_label(timezone_code),
        ntp_server: ntp
            .and_then(|node| node.attribute("ServerIP"))
            .unwrap_or_default()
            .trim()
            .to_string(),
        ntp_port: ntp
            .and_then(|node| node.attribute("ServerPort"))
            .unwrap_or("123")
            .trim()
            .parse::<u16>()
            .unwrap_or(123),
        refresh_interval_secs: ntp
            .and_then(|node| node.attribute("RefreshInterval"))
            .unwrap_or("60")
            .trim()
            .parse::<u32>()
            .unwrap_or(60),
        summer_time: parse_summer_time(summer),
        raw_xml: xml.trim().to_string(),
    })
}

fn parse_summer_time(node: Option<roxmltree::Node<'_, '_>>) -> XmSummerTime {
    let Some(node) = node else {
        return XmSummerTime::default();
    };
    let start = node.children().find(|child| child.has_tag_name("start"));
    let end = node.children().find(|child| child.has_tag_name("end"));
    XmSummerTime {
        enabled: node.attribute("enable").unwrap_or("0").trim() == "1",
        automatic: node.attribute("auto").unwrap_or("0").trim() == "1",
        offset_minutes: node
            .attribute("offset")
            .unwrap_or("60")
            .trim()
            .parse::<i32>()
            .unwrap_or(60),
        start: parse_summer_time_point(start),
        end: parse_summer_time_point(end),
    }
}

fn parse_summer_time_point(node: Option<roxmltree::Node<'_, '_>>) -> XmSummerTimePoint {
    let Some(node) = node else {
        return XmSummerTimePoint::default();
    };
    XmSummerTimePoint {
        month: node
            .attribute("month")
            .unwrap_or("0")
            .trim()
            .parse::<u8>()
            .unwrap_or(0),
        week: node
            .attribute("week")
            .unwrap_or("0")
            .trim()
            .parse::<u8>()
            .unwrap_or(0),
        weekday: node
            .attribute("weekday")
            .unwrap_or("0")
            .trim()
            .parse::<u8>()
            .unwrap_or(0),
        hour: node
            .attribute("hour")
            .unwrap_or("0")
            .trim()
            .parse::<u8>()
            .unwrap_or(0),
    }
}

fn parse_video_config(xml: &str) -> Result<XmVideoConfig> {
    let doc = Document::parse(xml).context("invalid XM video XML")?;
    let overlay = doc
        .descendants()
        .find(|node| node.has_tag_name("Overlay"))
        .ok_or_else(|| anyhow!("XM video XML missing Overlay"))?;
    let title = overlay
        .children()
        .find(|node| node.has_tag_name("TitleOverlay"))
        .ok_or_else(|| anyhow!("XM video XML missing TitleOverlay"))?;
    let time_overlay = overlay
        .children()
        .find(|node| node.has_tag_name("TimeOverlay"));
    let mut main_stream_format = String::new();
    let mut preview_stream_format = String::new();
    for node in doc.descendants().filter(|node| node.has_tag_name("EncodeConfig")) {
        match node.attribute("Stream").unwrap_or_default().trim() {
            "1" => {
                main_stream_format = node
                    .attribute("EncodeFormat")
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }
            "2" => {
                preview_stream_format = node
                    .attribute("EncodeFormat")
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }
            _ => {}
        }
    }
    let title_hex = first_nonempty(
        title.attribute("TitleUtf8").unwrap_or_default(),
        title.attribute("Title").unwrap_or_default(),
    );
    let user_title = doc
        .descendants()
        .find(|node| node.has_tag_name("UserOverlay"))
        .and_then(|node| node.children().find(|child| child.has_tag_name("UserOSD")));
    let user_title_hex = user_title
        .and_then(|node| node.attribute("TitleUtf8"))
        .unwrap_or_default()
        .trim()
        .to_string();
    Ok(XmVideoConfig {
        overlay_enabled: overlay.attribute("Enable").unwrap_or("0").trim() == "1",
        title_text: decode_title_hex(&title_hex),
        title_hex,
        user_title_text: decode_title_hex(&user_title_hex),
        user_title_hex,
        time_format: time_overlay
            .and_then(|node| node.attribute("Format"))
            .unwrap_or_default()
            .trim()
            .to_string(),
        time_24_or_12: overlay
            .attribute("time24or12")
            .unwrap_or_default()
            .trim()
            .to_string(),
        show_weekday: overlay.attribute("Week").unwrap_or("0").trim() == "1",
        main_stream_format: main_stream_format.clone(),
        preview_stream_format: preview_stream_format.clone(),
        preview_requires_transcode: !preview_stream_format.eq_ignore_ascii_case("H264"),
        raw_xml: xml.trim().to_string(),
    })
}

fn first_nonempty(preferred: &str, fallback: &str) -> String {
    if !preferred.trim().is_empty() {
        preferred.trim().to_string()
    } else {
        fallback.trim().to_string()
    }
}

fn decode_title_hex(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() % 2 != 0 {
        return String::new();
    }
    hex::decode(trimmed)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn normalize_time_value(value: &str) -> String {
    value.trim().replace(' ', "T")
}

fn render_overlay_config_xml(xml: &str, title: &str) -> Result<String> {
    let mut overlay = extract_xml_section(xml, "<Overlay", "</Overlay>")?;
    let title_hex = hex::encode(title.as_bytes());
    overlay = replace_tag_attr(&overlay, "Week", "0")?;
    overlay = replace_tag_attr(&overlay, "time24or12", "0")?;
    overlay = replace_tag_attr_in_node(&overlay, "TimeOverlay", "Format", "mm-dd-yyyy hh:mm:ss")?;
    overlay = replace_tag_attr_in_node(&overlay, "TitleOverlay", "TitleUtf8", &title_hex)?;
    overlay = replace_tag_attr_in_node(&overlay, "TitleOverlay", "Title", &title_hex)?;
    Ok(overlay)
}

fn render_user_overlay_config_xml(xml: &str, title: &str) -> Result<String> {
    let mut overlay = extract_xml_section(xml, "<UserOverlay", "</UserOverlay>")?;
    let title_hex = hex::encode(title.as_bytes());
    overlay = replace_first_user_overlay_title(&overlay, &title_hex)?;
    Ok(overlay)
}

fn clear_user_overlay_config_xml(xml: &str) -> Result<String> {
    let mut overlay = extract_xml_section(xml, "<UserOverlay", "</UserOverlay>")?;
    overlay = replace_all_attrs(&overlay, "enable", "0")?;
    overlay = replace_all_attrs(&overlay, "TitleUtf8", "")?;
    overlay = replace_all_attrs(&overlay, "Title", "")?;
    Ok(overlay)
}

fn replace_tag_attr(tag: &str, name: &str, value: &str) -> Result<String> {
    let re = Regex::new(&format!(r#"{name}="[^"]*""#)).context("invalid XM tag regex")?;
    if re.is_match(tag) {
        Ok(re
            .replace(tag, format!(r#"{name}="{value}""#))
            .into_owned())
    } else if let Some(index) = tag.rfind("/>") {
        let mut out = String::with_capacity(tag.len() + name.len() + value.len() + 4);
        out.push_str(&tag[..index]);
        out.push(' ');
        out.push_str(name);
        out.push_str("=\"");
        out.push_str(value);
        out.push('"');
        out.push_str(&tag[index..]);
        Ok(out)
    } else {
        Err(anyhow!("XM tag does not support attribute insertion"))
    }
}

fn replace_tag_attr_in_node(xml: &str, node_name: &str, attr_name: &str, value: &str) -> Result<String> {
    let start = xml
        .find(&format!("<{node_name}"))
        .ok_or_else(|| anyhow!("XM XML missing {node_name} tag"))?;
    let end = xml[start..]
        .find("/>")
        .map(|offset| start + offset + 2)
        .ok_or_else(|| anyhow!("XM {node_name} tag is not self-closing"))?;
    let mut tag = xml[start..end].to_string();
    tag = replace_tag_attr(&tag, attr_name, value)?;
    Ok(format!("{}{}{}", &xml[..start], tag, &xml[end..]))
}

fn replace_first_user_overlay_title(xml: &str, title_hex: &str) -> Result<String> {
    let start = xml
        .find("<UserOSD")
        .ok_or_else(|| anyhow!("XM XML missing UserOSD tag"))?;
    let end = xml[start..]
        .find("/>")
        .map(|offset| start + offset + 2)
        .ok_or_else(|| anyhow!("XM UserOSD tag is not self-closing"))?;
    let mut tag = xml[start..end].to_string();
    tag = replace_tag_attr(&tag, "TitleUtf8", title_hex)?;
    Ok(format!("{}{}{}", &xml[..start], tag, &xml[end..]))
}

fn replace_all_attrs(xml: &str, name: &str, value: &str) -> Result<String> {
    let re = Regex::new(&format!(r#"{name}="[^"]*""#)).context("invalid XM attr regex")?;
    Ok(re
        .replace_all(xml, format!(r#"{name}="{value}""#))
        .into_owned())
}

fn extract_xml_section(xml: &str, start_tag: &str, end_tag: &str) -> Result<String> {
    let start = xml
        .find(start_tag)
        .ok_or_else(|| anyhow!("XM XML missing {}", start_tag.trim_start_matches('<')))?;
    let end = xml[start..]
        .find(end_tag)
        .map(|offset| start + offset + end_tag.len())
        .ok_or_else(|| anyhow!("XM XML missing {}", end_tag.trim_start_matches("</")))?;
    Ok(xml[start..end].trim().to_string())
}

fn user_overlay_requires_clear(xml: &str) -> Result<bool> {
    let doc = Document::parse(xml).context("invalid XM user overlay XML")?;
    Ok(doc
        .descendants()
        .filter(|node| node.has_tag_name("UserOSD"))
        .any(|node| {
            node.attribute("enable").unwrap_or("0").trim() == "1"
                || !node.attribute("TitleUtf8").unwrap_or_default().trim().is_empty()
                || !node.attribute("Title").unwrap_or_default().trim().is_empty()
        }))
}

fn render_ntp_time_config_xml(current: &XmTimeConfig, policy: &XmSiteTimePolicy) -> String {
    format!(
        "<TimeConfig TimeMode=\"NTP\" CurTime=\"{}\" TimeZone=\"{}\"><NTPConfig ServerIP=\"{}\" ServerPort=\"{}\" RefreshInterval=\"{}\" /><SummerTime enable=\"{}\" auto=\"{}\" offset=\"{}\"><start month=\"{}\" week=\"{}\" weekday=\"{}\" hour=\"{}\" /><end month=\"{}\" week=\"{}\" weekday=\"{}\" hour=\"{}\" /></SummerTime></TimeConfig>",
        xml_escape_attr(&policy.current_local_time),
        policy.timezone_code,
        xml_escape_attr(&policy.ntp_server),
        current.ntp_port,
        current.refresh_interval_secs,
        if current.summer_time.enabled { 1 } else { 0 },
        if current.summer_time.automatic { 1 } else { 0 },
        current.summer_time.offset_minutes,
        current.summer_time.start.month,
        current.summer_time.start.week,
        current.summer_time.start.weekday,
        current.summer_time.start.hour,
        current.summer_time.end.month,
        current.summer_time.end.week,
        current.summer_time.end.weekday,
        current.summer_time.end.hour,
    )
}

fn render_manual_time_config_xml(current: &XmTimeConfig, policy: &XmSiteTimePolicy) -> String {
    format!(
        "<TimeConfig TimeMode=\"MANUAL\" CurTime=\"{}\" TimeZone=\"{}\"><NTPConfig ServerIP=\"{}\" ServerPort=\"{}\" RefreshInterval=\"{}\" /><SummerTime enable=\"{}\" auto=\"{}\" offset=\"{}\"><start month=\"{}\" week=\"{}\" weekday=\"{}\" hour=\"{}\" /><end month=\"{}\" week=\"{}\" weekday=\"{}\" hour=\"{}\" /></SummerTime></TimeConfig>",
        xml_escape_attr(&policy.current_local_time),
        policy.timezone_code,
        xml_escape_attr(&policy.ntp_server),
        current.ntp_port,
        current.refresh_interval_secs,
        if current.summer_time.enabled { 1 } else { 0 },
        if current.summer_time.automatic { 1 } else { 0 },
        current.summer_time.offset_minutes,
        current.summer_time.start.month,
        current.summer_time.start.week,
        current.summer_time.start.weekday,
        current.summer_time.start.hour,
        current.summer_time.end.month,
        current.summer_time.end.week,
        current.summer_time.end.weekday,
        current.summer_time.end.hour,
    )
}

fn xml_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_login_token_matches_camera_vector() {
        assert_eq!(encode_login_token("admin").unwrap(), "52851dbd7918bbae");
        assert_eq!(encode_login_token("123456").unwrap(), "a17faccd02661e4c");
    }

    #[test]
    fn parse_system_info_extracts_40e_family() {
        let xml = r#"<SystemVersionInfo><VersionInfo kernelVersion="Linux" fsVersion="40E_19_DL_c1_V3-A-RTMP-H5 V3.4.0.3 build 2025-01-09 17:38:27 " /><SerialNumber serialNumber="EF123" /></SystemVersionInfo>"#;
        let system = parse_system_info(xml).unwrap();
        assert_eq!(system.vendor, "XM/NetSurveillance");
        assert_eq!(system.model_family, "40E");
        assert_eq!(system.serial_number, "EF123");
    }

    #[test]
    fn parse_time_config_extracts_ntp_and_timezone_code() {
        let xml = r#"<TimeConfig TimeMode="NTP" CurTime="2026-04-18 09:54:18" TimeZone="300"><NTPConfig ServerIP="192.168.0.2" ServerPort="123" RefreshInterval="60" /><SummerTime enable="0" auto="0" offset="60"><start month="3" week="3" weekday="0" hour="2" /><end month="11" week="2" weekday="0" hour="2" /></SummerTime></TimeConfig>"#;
        let time = parse_time_config(xml).unwrap();
        assert_eq!(time.time_mode, "ntp");
        assert_eq!(time.current_time_iso, "2026-04-18T09:54:18");
        assert_eq!(time.ntp_server, "192.168.0.2");
        assert_eq!(time.timezone_code, 300);
        assert_eq!(time.timezone_offset_label, "UTC-07:00");
    }

    #[test]
    fn parse_video_config_extracts_title_and_formats() {
        let xml = r#"<Video><Encode><EncodeConfig Stream="1" EncodeFormat="H265" /><EncodeConfig Stream="2" EncodeFormat="H265" /></Encode><Overlay Enable="1" time24or12="0" Week="1"><TimeOverlay Format="mm-dd-yyyy hh:mm:ss" /><TitleOverlay TitleUtf8="43616D657261" Title="43616D657261" /></Overlay><UserOverlay><UserOSD TitleUtf8="46726f6e7420446f6f72" /></UserOverlay></Video>"#;
        let video = parse_video_config(xml).unwrap();
        assert_eq!(video.title_text, "Camera");
        assert_eq!(video.user_title_text, "Front Door");
        assert_eq!(video.main_stream_format, "H265");
        assert_eq!(video.preview_stream_format, "H265");
        assert!(video.preview_requires_transcode);
    }

    #[test]
    fn render_overlay_config_xml_extracts_overlay_payload() {
        let xml = r#"<Video><Overlay Enable="1" time24or12="1" Week="1"><TimeOverlay Format="yyyy-mm-dd hh:mm:ss" /><TitleOverlay PosX="0" TitleUtf8="43616D657261" Title="43616D657261" /></Overlay><UserOverlay><UserOSD TitleUtf8="" /></UserOverlay></Video>"#;
        let patched = render_overlay_config_xml(xml, "Carport").unwrap();
        assert!(!patched.contains("<Video>"));
        assert!(patched.contains(r#"Week="0""#));
        assert!(patched.contains(r#"time24or12="0""#));
        assert!(patched.contains(r#"Format="mm-dd-yyyy hh:mm:ss""#));
        assert!(patched.contains(r#"TitleUtf8="436172706f7274""#));
        assert!(patched.contains(r#"Title="436172706f7274""#));
    }

    #[test]
    fn render_user_overlay_config_xml_updates_first_user_overlay() {
        let xml = r#"<Video><Overlay><TitleOverlay TitleUtf8="43616D657261" /></Overlay><UserOverlay><UserOSD TitleUtf8="" /><UserOSD TitleUtf8="5061636B616765205A6F6E65" /></UserOverlay></Video>"#;
        let patched = render_user_overlay_config_xml(xml, "Front Door").unwrap();
        assert!(!patched.contains("<Video>"));
        assert!(patched.contains(r#"TitleUtf8="46726f6e7420446f6f72""#));
        assert!(patched.contains(r#"TitleUtf8="5061636B616765205A6F6E65""#));
    }

    #[test]
    fn clear_user_overlay_config_xml_blanks_all_slots() {
        let xml = r#"<Video><Overlay><TitleOverlay TitleUtf8="46726f6e7420446f6f72" /></Overlay><UserOverlay><UserOSD enable="1" TitleUtf8="683a6d6d3a7373" Title="683a6d6d3a7373" /><UserOSD enable="0" TitleUtf8="46726f6e7420446f6f72" /></UserOverlay></Video>"#;
        let patched = clear_user_overlay_config_xml(xml).unwrap();
        assert!(!patched.contains(r#"TitleUtf8="683a6d6d3a7373""#));
        assert!(!patched.contains(r#"Title="683a6d6d3a7373""#));
        assert_eq!(patched.matches(r#"enable="0""#).count(), 2);
        assert_eq!(patched.matches(r#"TitleUtf8="""#).count(), 2);
    }

    #[test]
    fn user_overlay_requires_clear_detects_hidden_text_or_enabled_slots() {
        let xml = r#"<Video><UserOverlay><UserOSD enable="0" TitleUtf8="" /><UserOSD enable="1" TitleUtf8="" /><UserOSD enable="0" TitleUtf8="683a6d6d3a7373" /></UserOverlay></Video>"#;
        assert!(user_overlay_requires_clear(xml).unwrap());
        let clean = r#"<Video><UserOverlay><UserOSD enable="0" TitleUtf8="" /><UserOSD enable="0" TitleUtf8="" /></UserOverlay></Video>"#;
        assert!(!user_overlay_requires_clear(clean).unwrap());
    }

    #[test]
    fn render_ntp_time_config_xml_preserves_summer_shape() {
        let current = parse_time_config(r#"<TimeConfig TimeMode="MANUAL" CurTime="2026-04-18 09:54:18" TimeZone="300"><NTPConfig ServerIP="192.168.0.2" ServerPort="123" RefreshInterval="60" /><SummerTime enable="1" auto="1" offset="60"><start month="3" week="3" weekday="0" hour="2" /><end month="11" week="2" weekday="0" hour="2" /></SummerTime></TimeConfig>"#).unwrap();
        let policy = XmSiteTimePolicy {
            ntp_server: "192.168.0.2".to_string(),
            timezone_code: 300,
            current_local_time: "2026-04-18 10:00:00".to_string(),
        };
        let rendered = render_ntp_time_config_xml(&current, &policy);
        assert!(rendered.contains(r#"TimeMode="NTP""#));
        assert!(rendered.contains(r#"ServerIP="192.168.0.2""#));
        assert!(rendered.contains(r#"TimeZone="300""#));
        assert!(rendered.contains(r#"<SummerTime enable="1" auto="1" offset="60">"#));
    }

    #[test]
    fn render_manual_time_config_xml_switches_to_manual() {
        let current = parse_time_config(r#"<TimeConfig TimeMode="NTP" CurTime="2026-04-18 09:54:18" TimeZone="300"><NTPConfig ServerIP="192.168.0.2" ServerPort="123" RefreshInterval="60" /><SummerTime enable="0" auto="0" offset="60"><start month="3" week="3" weekday="0" hour="2" /><end month="11" week="2" weekday="0" hour="2" /></SummerTime></TimeConfig>"#).unwrap();
        let policy = XmSiteTimePolicy {
            ntp_server: "192.168.0.2".to_string(),
            timezone_code: 300,
            current_local_time: "2026-04-18 10:00:00".to_string(),
        };
        let rendered = render_manual_time_config_xml(&current, &policy);
        assert!(rendered.contains(r#"TimeMode="MANUAL""#));
        assert!(rendered.contains(r#"CurTime="2026-04-18 10:00:00""#));
    }
}
