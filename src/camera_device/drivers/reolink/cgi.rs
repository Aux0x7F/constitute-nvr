use crate::reolink::{
    ReolinkAdvancedPortConfig, ReolinkNormalPortConfig, ReolinkP2PConfig, ReolinkSetupBridgeResult,
    ReolinkSetupRequest, ReolinkStateApplyRequest, ReolinkStateApplyResult, ReolinkStateResult,
    ReolinkStateSnapshot,
};
use aes::Aes128;
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use md5::{Digest, Md5};
use rand::Rng;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error, fmt};
use tokio::time::{Duration, Instant, sleep};
use tracing::warn;

const HTTP_TIMEOUT_SECS: u64 = 10;
const HTTP_ENDPOINTS: [(&str, u16); 2] = [("http", 80), ("https", 443)];
const HTTPS_FIRST_ENDPOINTS: [(&str, u16); 2] = [("https", 443), ("http", 80)];
const ZERO_BLOCK: usize = 16;
const PRESENTATION_VERIFY_TIMEOUT_SECS: u64 = 8;
const PRESENTATION_VERIFY_POLL_MILLIS: u64 = 500;
const REOLINK_TIME_FMT_MM_DD_YYYY: i64 = 1;
const REOLINK_TIME_FMT_MM_DD_YYYY_LABEL: &str = "MM/DD/YYYY";
const REOLINK_TIME_FMT_YYYY_MM_DD_LABEL: &str = "YYYY/MM/DD";
const REOLINK_TIME_FMT_DD_MM_YYYY_LABEL: &str = "DD/MM/YYYY";
const REOLINK_HOUR_FMT_24H: i64 = 0;
const REOLINK_TIMEZONE_UTC_SECONDS: i64 = 0;
const REOLINK_TIMEZONE_PHOENIX_SECONDS: i64 = 25_200;

type Aes128CfbEnc = cfb_mode::Encryptor<Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<Aes128>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReolinkCgiNetPort {
    media_port: i32,
    http_enable: i32,
    http_port: i32,
    https_enable: i32,
    https_port: i32,
    onvif_enable: i32,
    onvif_port: i32,
    rtsp_enable: i32,
    rtsp_port: i32,
    rtmp_enable: i32,
    rtmp_port: i32,
}

impl ReolinkCgiNetPort {
    fn from_value(value: &Value) -> Result<Self> {
        Ok(Self {
            media_port: int_field(value, "mediaPort"),
            http_enable: int_field(value, "httpEnable"),
            http_port: int_field(value, "httpPort"),
            https_enable: int_field(value, "httpsEnable"),
            https_port: int_field(value, "httpsPort"),
            onvif_enable: int_field(value, "onvifEnable"),
            onvif_port: int_field(value, "onvifPort"),
            rtsp_enable: int_field(value, "rtspEnable"),
            rtsp_port: int_field(value, "rtspPort"),
            rtmp_enable: int_field(value, "rtmpEnable"),
            rtmp_port: int_field(value, "rtmpPort"),
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "mediaPort": self.media_port,
            "httpEnable": self.http_enable,
            "httpPort": self.http_port,
            "httpsEnable": self.https_enable,
            "httpsPort": self.https_port,
            "onvifEnable": self.onvif_enable,
            "onvifPort": self.onvif_port,
            "rtspEnable": self.rtsp_enable,
            "rtspPort": self.rtsp_port,
            "rtmpEnable": self.rtmp_enable,
            "rtmpPort": self.rtmp_port,
        })
    }

    fn normal(&self) -> ReolinkNormalPortConfig {
        ReolinkNormalPortConfig {
            i_surv_port_enable: 1,
            i_surv_port: self.media_port,
            i_http_port_enable: self.http_enable,
            i_http_port: self.http_port,
            i_https_port_enable: self.https_enable,
            i_https_port: self.https_port,
        }
    }

    fn advanced(&self) -> ReolinkAdvancedPortConfig {
        ReolinkAdvancedPortConfig {
            i_onvif_port_enable: self.onvif_enable,
            i_onvif_port: self.onvif_port,
            i_rtsp_port_enable: self.rtsp_enable,
            i_rtsp_port: self.rtsp_port,
            i_rtmp_port_enable: self.rtmp_enable,
            i_rtmp_port: self.rtmp_port,
        }
    }

    fn with_updates(
        _current: &Self,
        normal: &ReolinkNormalPortConfig,
        advanced: &ReolinkAdvancedPortConfig,
    ) -> Self {
        Self {
            media_port: normal.i_surv_port,
            http_enable: normal.i_http_port_enable,
            http_port: normal.i_http_port,
            https_enable: normal.i_https_port_enable,
            https_port: normal.i_https_port,
            onvif_enable: advanced.i_onvif_port_enable,
            onvif_port: advanced.i_onvif_port,
            rtsp_enable: advanced.i_rtsp_port_enable,
            rtsp_port: advanced.i_rtsp_port,
            rtmp_enable: advanced.i_rtmp_port_enable,
            rtmp_port: advanced.i_rtmp_port,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReolinkCgiP2P {
    enable: i32,
    uid: String,
}

impl ReolinkCgiP2P {
    fn from_value(value: &Value) -> Self {
        Self {
            enable: int_field(value, "enable"),
            uid: str_field(value, "uid"),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "enable": self.enable,
            "uid": self.uid,
        })
    }

    fn config(&self) -> ReolinkP2PConfig {
        ReolinkP2PConfig {
            i_enable: self.enable,
            i_port: 0,
            server_domain_name: String::new(),
        }
    }

    fn with_updates(current: &Self, p2p: &ReolinkP2PConfig) -> Self {
        Self {
            enable: p2p.i_enable,
            uid: current.uid.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct ReolinkHttpCounter {
    id: u32,
    value: u32,
}

#[derive(Clone, Debug)]
struct ReolinkHttpCrypto {
    key: [u8; 16],
    iv: [u8; 16],
}

impl ReolinkHttpCrypto {
    fn from_login(username: &str, password: &str, nonce: &str, cnonce: &str) -> Self {
        let key = upper16(&md5_hex(&format!("{nonce}-{password}-{cnonce}")));
        let iv = upper16(&md5_hex(&format!(
            "webapp-{cnonce}-{password}-{nonce}-{username}"
        )));
        Self { key, iv }
    }

    fn encrypt_string(&self, plain: &str) -> String {
        let mut buf = plain.as_bytes().to_vec();
        let rem = buf.len() % ZERO_BLOCK;
        if rem != 0 {
            buf.extend(std::iter::repeat_n(0u8, ZERO_BLOCK - rem));
        }
        Aes128CfbEnc::new((&self.key).into(), (&self.iv).into()).encrypt(&mut buf);
        BASE64.encode(buf)
    }

    fn decrypt_string(&self, encoded: &str) -> Result<String> {
        let mut buf = BASE64
            .decode(encoded.trim())
            .with_context(|| "failed decoding Reolink CGI payload base64")?;
        Aes128CfbDec::new((&self.key).into(), (&self.iv).into()).decrypt(&mut buf);
        while matches!(buf.last(), Some(0)) {
            buf.pop();
        }
        String::from_utf8(buf).context("failed decoding Reolink CGI payload as UTF-8")
    }
}

#[derive(Clone, Debug)]
struct ReolinkHttpSession {
    client: Client,
    base_url: String,
    token: String,
    counters: Vec<ReolinkHttpCounter>,
    crypto: ReolinkHttpCrypto,
}

#[derive(Clone, Debug)]
enum LoginOnOutcome {
    Session(ReolinkHttpSession),
    Uninitialized,
}

#[derive(Clone, Debug)]
enum ReolinkLoginOutcome {
    Session(ReolinkHttpSession),
    Uninitialized { client: Client, base_url: String },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkPresentationState {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub time_mode: String,
    #[serde(default)]
    pub ntp_server: String,
    #[serde(default)]
    pub manual_time: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub clock_date_format: String,
    #[serde(default)]
    pub clock_hour_format: String,
    #[serde(default)]
    pub overlay_text: String,
    #[serde(default)]
    pub overlay_timestamp: Option<bool>,
    #[serde(default)]
    pub time: Value,
    #[serde(default)]
    pub osd: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReolinkPresentationApplyRequest {
    #[serde(flatten)]
    pub connection: crate::reolink::ReolinkConnectRequest,
    #[serde(default)]
    pub time_mode: Option<String>,
    #[serde(default)]
    pub ntp_server: Option<String>,
    #[serde(default)]
    pub manual_time: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub enforce_clock_display: bool,
    #[serde(default)]
    pub overlay_text: Option<String>,
    #[serde(default)]
    pub overlay_timestamp: Option<bool>,
}

#[derive(Clone, Debug)]
struct ReolinkCgiCommandError {
    cmd: String,
    code: i64,
    rsp_code: i64,
    detail: String,
}

impl ReolinkCgiCommandError {
    fn is_rsp_code(&self, value: i64) -> bool {
        self.rsp_code == value
    }
}

impl fmt::Display for ReolinkCgiCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Reolink CGI command {} failed with code {} (rspCode {}): {}",
            self.cmd, self.code, self.rsp_code, self.detail
        )
    }
}

impl Error for ReolinkCgiCommandError {}

impl ReolinkHttpSession {
    async fn login(ip: &str, username: &str, password: &str) -> Result<ReolinkLoginOutcome> {
        let client = build_http_client()?;
        Self::login_with_endpoints(&client, &HTTP_ENDPOINTS, ip, username, password).await
    }

    async fn login_prefer_https(
        ip: &str,
        username: &str,
        password: &str,
    ) -> Result<ReolinkLoginOutcome> {
        let client = build_http_client()?;
        Self::login_with_endpoints(&client, &HTTPS_FIRST_ENDPOINTS, ip, username, password).await
    }

    async fn login_with_endpoints(
        client: &Client,
        endpoints: &[(&str, u16)],
        ip: &str,
        username: &str,
        password: &str,
    ) -> Result<ReolinkLoginOutcome> {
        let mut last_error = None;
        for (scheme, port) in endpoints {
            let base_url = format!("{scheme}://{ip}:{port}");
            match Self::login_on(client, &base_url, username, password).await {
                Ok(LoginOnOutcome::Session(session)) => {
                    return Ok(ReolinkLoginOutcome::Session(session));
                }
                Ok(LoginOnOutcome::Uninitialized) => {
                    return Ok(ReolinkLoginOutcome::Uninitialized {
                        client: client.clone(),
                        base_url,
                    });
                }
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!("Reolink CGI endpoint not reachable on http/80 or https/443")
        }))
    }

    async fn login_on(
        client: &Client,
        base_url: &str,
        username: &str,
        password: &str,
    ) -> Result<LoginOnOutcome> {
        let login_path = "cgi-bin/api.cgi?cmd=Login";
        let url = format!("{base_url}/{login_path}");
        let first = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&vec![json!({
                "cmd": "Login",
                "action": 0,
                "param": {"Version": 1},
            })])?)
            .send()
            .await
            .with_context(|| format!("failed reaching {url}"))?;

        let challenge_header = first
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let first_body = first
            .text()
            .await
            .context("failed reading Reolink CGI login probe response")?;

        if challenge_header.is_none() {
            let entry = response_entry("Login", &first_body, None)?;
            if let Some(error) = command_error("Login", &entry) {
                if error.is_rsp_code(-505) {
                    return Ok(LoginOnOutcome::Uninitialized);
                }
                return Err(error.into());
            }
            return Err(anyhow!(
                "Reolink CGI login did not return a digest challenge"
            ));
        }

        let challenge = parse_digest_header(challenge_header.as_deref().unwrap_or_default())?;
        let cnonce = random_hex(48);
        let response = md5_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            md5_hex(&format!("{username}:{}:{password}", challenge.realm)),
            challenge.nonce,
            challenge.nc,
            cnonce,
            challenge.qop,
            md5_hex(&format!("POST:{login_path}")),
        ));

        let crypto = ReolinkHttpCrypto::from_login(username, password, &challenge.nonce, &cnonce);
        let second = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&vec![json!({
                "cmd": "Login",
                "action": 0,
                "param": {
                    "Version": 1,
                    "Digest": {
                        "UserName": username,
                        "Realm": challenge.realm,
                        "Method": "POST",
                        "Uri": login_path,
                        "Nonce": challenge.nonce,
                        "Nc": challenge.nc,
                        "Cnonce": cnonce,
                        "Qop": challenge.qop,
                        "Response": response,
                    }
                },
            })])?)
            .send()
            .await
            .context("failed submitting Reolink CGI digest login")?;

        if !second.status().is_success() {
            return Err(anyhow!(
                "Reolink CGI login failed with HTTP {}",
                second.status()
            ));
        }

        let body = second
            .text()
            .await
            .context("failed reading Reolink CGI login response")?;
        let entry = response_entry("Login", &body, Some(&crypto))?;
        if let Some(error) = command_error("Login", &entry) {
            if error.is_rsp_code(-505) {
                return Ok(LoginOnOutcome::Uninitialized);
            }
            return Err(error.into());
        }

        let token = entry
            .get("value")
            .and_then(|value| value.get("Token"))
            .ok_or_else(|| anyhow!("Reolink CGI login response missing Token"))?;

        let token_name = token
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Reolink CGI login response missing token name"))?
            .to_string();
        let check_basic = token
            .get("checkBasic")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u32;
        let count_total = token
            .get("countTotal")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as u32;
        let counters = (0..count_total)
            .map(|id| ReolinkHttpCounter {
                id,
                value: check_basic,
            })
            .collect();

        Ok(LoginOnOutcome::Session(Self {
            client: client.clone(),
            base_url: base_url.to_string(),
            token: token_name,
            counters,
            crypto,
        }))
    }

    async fn get_net_port(&mut self) -> Result<ReolinkCgiNetPort> {
        let entry = self.send_command("GetNetPort", json!({})).await?;
        let value = entry
            .get("value")
            .and_then(|value| value.get("NetPort"))
            .ok_or_else(|| anyhow!("Reolink CGI GetNetPort response missing NetPort"))?;
        ReolinkCgiNetPort::from_value(value)
    }

    async fn set_net_port(&mut self, net_port: &ReolinkCgiNetPort) -> Result<()> {
        self.send_command("SetNetPort", json!({ "NetPort": net_port.to_value() }))
            .await?;
        Ok(())
    }

    async fn get_p2p(&mut self) -> Result<ReolinkCgiP2P> {
        let entry = self.send_command("GetP2p", json!({})).await?;
        let value = entry
            .get("value")
            .and_then(|value| value.get("P2p"))
            .ok_or_else(|| anyhow!("Reolink CGI GetP2p response missing P2p"))?;
        Ok(ReolinkCgiP2P::from_value(value))
    }

    async fn set_p2p(&mut self, p2p: &ReolinkCgiP2P) -> Result<()> {
        self.send_command("SetP2p", json!({ "P2p": p2p.to_value() }))
            .await?;
        Ok(())
    }

    async fn modify_user(
        &mut self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        self.send_command(
            "ModifyUser",
            json!({
                "User": {
                    "userName": username,
                    "oldPassword": old_password,
                    "newPassword": new_password,
                }
            }),
        )
        .await?;
        Ok(())
    }

    async fn logout(&mut self) -> Result<()> {
        self.send_command("Logout", json!({})).await?;
        Ok(())
    }

    async fn read_state_snapshot(&mut self) -> Result<ReolinkStateSnapshot> {
        let net = self.get_net_port().await?;
        let p2p = self.get_p2p().await?;
        Ok(ReolinkStateSnapshot {
            normal: serde_json::to_value(net.normal())
                .context("failed encoding CGI normal state")?,
            advanced: serde_json::to_value(net.advanced())
                .context("failed encoding CGI advanced state")?,
            p2p: serde_json::to_value(p2p.config()).context("failed encoding CGI p2p state")?,
            ..ReolinkStateSnapshot::default()
        })
    }

    async fn read_presentation_state(&mut self) -> Result<ReolinkPresentationState> {
        let time_entry = self.send_command("GetTime", json!({})).await.ok();
        let osd_entry = self.send_command("GetOsd", json!({})).await.ok();
        Ok(build_presentation_state(
            time_entry.as_ref(),
            osd_entry.as_ref(),
        ))
    }

    async fn send_command(&mut self, cmd: &str, param: Value) -> Result<Value> {
        let first = self.send_command_entry(cmd, param).await?;
        if let Some(error) = command_error(cmd, &first) {
            return Err(error.into());
        }
        Ok(first)
    }

    async fn send_command_entry(&mut self, cmd: &str, param: Value) -> Result<Value> {
        let encrypt_query = self.next_query(cmd)?;
        let request_url = format!(
            "{}/cgi-bin/api.cgi?token={}&encrypt={}",
            self.base_url, self.token, encrypt_query
        );

        let body = serde_json::to_string(&vec![json!({
            "cmd": cmd,
            "action": 0,
            "param": param,
        })])
        .context("failed serializing Reolink CGI request")?;
        let encrypted_body = self.crypto.encrypt_string(&body);

        let response = self
            .client
            .post(request_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(encrypted_body)
            .send()
            .await
            .with_context(|| format!("failed sending Reolink CGI command {cmd}"))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Reolink CGI command {cmd} failed with HTTP {}",
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .with_context(|| format!("failed reading Reolink CGI response for {cmd}"))?;
        response_entry(cmd, &body, Some(&self.crypto))
    }

    async fn send_command_without_token(
        client: &Client,
        base_url: &str,
        cmd: &str,
        param: Value,
    ) -> Result<Value> {
        let request_url = format!("{base_url}/cgi-bin/api.cgi?cmd={cmd}");
        let body = serde_json::to_vec(&vec![json!({
            "cmd": cmd,
            "action": 0,
            "param": param,
        })])
        .context("failed serializing Reolink CGI request")?;
        let response = client
            .post(&request_url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .with_context(|| format!("failed sending Reolink CGI command {cmd}"))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Reolink CGI command {cmd} failed with HTTP {}",
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .with_context(|| format!("failed reading Reolink CGI response for {cmd}"))?;
        response_entry(cmd, &body, None)
    }

    fn next_query(&mut self, cmd: &str) -> Result<String> {
        if self.counters.is_empty() {
            self.counters.push(ReolinkHttpCounter { id: 0, value: 0 });
        }

        let index = self
            .counters
            .iter()
            .position(|counter| counter.id > 2)
            .unwrap_or(0);
        let counter = &mut self.counters[index];
        counter.value = counter.value.saturating_add(1);
        let plain = format!(
            "countId={}&checkNum={}&cmd={cmd}",
            counter.id, counter.value
        );
        Ok(self.crypto.encrypt_string(&plain))
    }
}

#[derive(Clone, Debug)]
struct DigestChallenge {
    realm: String,
    qop: String,
    nonce: String,
    nc: String,
}

pub async fn setup(request: &ReolinkSetupRequest) -> Result<ReolinkSetupBridgeResult> {
    let desired_password = request.desired_password.trim();
    let mut login_password = request.password.trim().to_string();
    let mut bootstrapped = false;

    let mut session = match ReolinkHttpSession::login(
        &request.ip,
        &request.username,
        &login_password,
    )
    .await?
    {
        ReolinkLoginOutcome::Session(session) => session,
        ReolinkLoginOutcome::Uninitialized { client, base_url } => {
            let bootstrap_password = if !desired_password.is_empty() {
                desired_password.to_string()
            } else if !login_password.is_empty() {
                login_password.clone()
            } else {
                return Err(anyhow!(
                    "Reolink device is uninitialized; provide desired_password or enable generate_password"
                ));
            };
            bootstrap_user(&client, &base_url, &request.username, &bootstrap_password).await?;
            bootstrapped = true;
            login_password = bootstrap_password;
            match ReolinkHttpSession::login_on(
                &client,
                &base_url,
                &request.username,
                &login_password,
            )
            .await?
            {
                LoginOnOutcome::Session(session) => session,
                LoginOnOutcome::Uninitialized => {
                    return Err(anyhow!(
                        "Reolink device remained uninitialized after bootstrap user setup"
                    ));
                }
            }
        }
    };

    let result = async {
        let before_net = session.get_net_port().await?;
        let before_p2p = session.get_p2p().await?;
        let before_normal = before_net.normal();
        let before_advanced = before_net.advanced();

        let target_normal = merge_normal(&before_normal, request.normal.as_ref());
        let target_advanced = merge_advanced(&before_advanced, request.advanced.as_ref());
        let target_p2p = merge_p2p(request.p2p.as_ref());

        let target_net =
            ReolinkCgiNetPort::with_updates(&before_net, &target_normal, &target_advanced);
        if target_net != before_net {
            session.set_net_port(&target_net).await?;
        }

        let target_p2p_wire = ReolinkCgiP2P::with_updates(&before_p2p, &target_p2p);
        if target_p2p_wire != before_p2p {
            session.set_p2p(&target_p2p_wire).await?;
        }

        if !bootstrapped && !desired_password.is_empty() && desired_password != login_password {
            session
                .modify_user(&request.username, &login_password, desired_password)
                .await?;
        }

        let after_net = session.get_net_port().await?;
        let after_p2p = session.get_p2p().await?;

        Ok::<ReolinkSetupBridgeResult, anyhow::Error>(ReolinkSetupBridgeResult {
            ip: request.ip.clone(),
            username: request.username.clone(),
            before_normal,
            before_advanced,
            before_p2p: before_p2p.config(),
            after_normal: after_net.normal(),
            after_advanced: after_net.advanced(),
            after_p2p: after_p2p.config(),
        })
    }
    .await;
    best_effort_logout(&mut session, "setup").await;
    result
}

pub async fn read_state(
    request: &crate::reolink::ReolinkConnectRequest,
) -> Result<ReolinkStateResult> {
    let mut session = login_existing_session(request).await?;
    let result = session
        .read_state_snapshot()
        .await
        .map(|state| ReolinkStateResult {
            state,
            active_password: request.password.clone(),
        });
    best_effort_logout(&mut session, "read_state").await;
    result
}

pub async fn apply_state(request: &ReolinkStateApplyRequest) -> Result<ReolinkStateApplyResult> {
    if request.auto_reboot.is_some()
        || request.ptz.is_some()
        || request.ptz_position.is_some()
        || request.smart_track_task.is_some()
        || request.smart_track_limit.is_some()
        || request.signature_login.is_some()
        || request.user_config.is_some()
    {
        return Err(anyhow!(
            "Reolink CGI fallback only supports normal ports, advanced ports, and P2P state"
        ));
    }

    let mut session = login_existing_session(&request.connection).await?;
    let result = async {
        let before_net = session.get_net_port().await?;
        let before_p2p = session.get_p2p().await?;

        let before_normal = before_net.normal();
        let before_advanced = before_net.advanced();
        let before_p2p_cfg = before_p2p.config();

        let target_normal = match request.normal.as_ref() {
            Some(value) => serde_json::from_value::<ReolinkNormalPortConfig>(value.clone())
                .context("invalid CGI normal port state payload")?,
            None => before_normal.clone(),
        };
        let target_advanced = match request.advanced.as_ref() {
            Some(value) => serde_json::from_value::<ReolinkAdvancedPortConfig>(value.clone())
                .context("invalid CGI advanced port state payload")?,
            None => before_advanced.clone(),
        };
        let target_p2p_cfg = match request.p2p.as_ref() {
            Some(value) => serde_json::from_value::<ReolinkP2PConfig>(value.clone())
                .context("invalid CGI P2P state payload")?,
            None => before_p2p_cfg.clone(),
        };

        let target_net =
            ReolinkCgiNetPort::with_updates(&before_net, &target_normal, &target_advanced);
        if target_net != before_net {
            session.set_net_port(&target_net).await?;
        }

        let target_p2p = ReolinkCgiP2P::with_updates(&before_p2p, &target_p2p_cfg);
        if target_p2p != before_p2p {
            session.set_p2p(&target_p2p).await?;
        }

        let after_net = session.get_net_port().await?;
        let after_p2p = session.get_p2p().await?;

        Ok::<ReolinkStateApplyResult, anyhow::Error>(ReolinkStateApplyResult {
            before: ReolinkStateSnapshot {
                normal: serde_json::to_value(before_normal)
                    .context("failed encoding CGI pre-update normal state")?,
                advanced: serde_json::to_value(before_advanced)
                    .context("failed encoding CGI pre-update advanced state")?,
                p2p: serde_json::to_value(before_p2p_cfg)
                    .context("failed encoding CGI pre-update p2p state")?,
                ..ReolinkStateSnapshot::default()
            },
            after: ReolinkStateSnapshot {
                normal: serde_json::to_value(after_net.normal())
                    .context("failed encoding CGI post-update normal state")?,
                advanced: serde_json::to_value(after_net.advanced())
                    .context("failed encoding CGI post-update advanced state")?,
                p2p: serde_json::to_value(after_p2p.config())
                    .context("failed encoding CGI post-update p2p state")?,
                ..ReolinkStateSnapshot::default()
            },
            active_password: request.connection.password.clone(),
        })
    }
    .await;
    best_effort_logout(&mut session, "apply_state").await;
    result
}

pub async fn read_presentation_state(
    request: &crate::reolink::ReolinkConnectRequest,
) -> Result<ReolinkPresentationState> {
    let mut session = login_existing_session(request).await?;
    let result = session.read_presentation_state().await;
    best_effort_logout(&mut session, "read_presentation_state").await;
    result
}

pub async fn apply_presentation_state(
    request: &ReolinkPresentationApplyRequest,
) -> Result<ReolinkPresentationState> {
    let mut session = login_existing_session(&request.connection).await?;
    let time_entry = session.send_command("GetTime", json!({})).await.ok();
    let osd_entry = session.send_command("GetOsd", json!({})).await.ok();
    let mut errors = Vec::new();

    if (request.time_mode.is_some()
        || request.ntp_server.is_some()
        || request.manual_time.is_some()
        || request.timezone.is_some()
        || request.enforce_clock_display)
        && let Some(mut time_value) = time_entry
            .as_ref()
            .and_then(|entry| entry.get("value"))
            .and_then(|value| value.get("Time"))
            .cloned()
    {
        mutate_time_value(&mut time_value, request);
        if let Err(error) = session
            .send_command("SetTime", json!({ "Time": time_value }))
            .await
        {
            errors.push(format!("Reolink CGI SetTime failed: {error}"));
        }
    }

    if (request.overlay_text.is_some() || request.overlay_timestamp.is_some())
        && let Some(mut osd_value) = osd_entry
            .as_ref()
            .and_then(|entry| entry.get("value"))
            .and_then(|value| value.get("Osd"))
            .cloned()
    {
        mutate_osd_value(&mut osd_value, request);
        if let Err(error) = session
            .send_command("SetOsd", json!({ "Osd": osd_value }))
            .await
        {
            errors.push(format!("Reolink CGI SetOsd failed: {error}"));
        }
    }

    let result = if errors.is_empty() {
        verify_presentation_apply(&mut session, request).await
    } else {
        Err(anyhow!(errors.join(" | ")))
    };
    best_effort_logout(&mut session, "apply_presentation_state").await;
    result
}

pub async fn ptz_command(
    request: &crate::reolink::ReolinkConnectRequest,
    op: &str,
    speed: i32,
) -> Result<()> {
    let mut session = login_existing_session_prefer_https(request).await?;
    let result = session
        .send_command(
            "PtzCtrl",
            json!({
                "channel": request.channel.max(0),
                "op": op,
                "speed": speed.max(1),
            }),
        )
        .await
        .map(|_| ());
    best_effort_logout(&mut session, "ptz_command").await;
    result
}

pub async fn ptz_stop(request: &crate::reolink::ReolinkConnectRequest) -> Result<()> {
    let mut session = login_existing_session_prefer_https(request).await?;
    let result = session
        .send_command(
            "PtzCtrl",
            json!({
                "channel": request.channel.max(0),
                "op": "Stop",
            }),
        )
        .await
        .map(|_| ());
    best_effort_logout(&mut session, "ptz_stop").await;
    result
}

async fn login_existing_session(
    request: &crate::reolink::ReolinkConnectRequest,
) -> Result<ReolinkHttpSession> {
    match ReolinkHttpSession::login(&request.ip, &request.username, &request.password).await? {
        ReolinkLoginOutcome::Session(session) => Ok(session),
        ReolinkLoginOutcome::Uninitialized { .. } => Err(anyhow!(
            "Reolink CGI fallback cannot initialize a factory-reset device; use the proprietary 9000 provisioning path first"
        )),
    }
}

async fn login_existing_session_prefer_https(
    request: &crate::reolink::ReolinkConnectRequest,
) -> Result<ReolinkHttpSession> {
    match ReolinkHttpSession::login_prefer_https(&request.ip, &request.username, &request.password)
        .await?
    {
        ReolinkLoginOutcome::Session(session) => Ok(session),
        ReolinkLoginOutcome::Uninitialized { .. } => Err(anyhow!(
            "Reolink CGI fallback cannot initialize a factory-reset device; use the proprietary 9000 provisioning path first"
        )),
    }
}

fn build_http_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .context("failed building Reolink HTTP client")
}

async fn bootstrap_user(
    client: &Client,
    base_url: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let existing =
        ReolinkHttpSession::send_command_without_token(client, base_url, "GetUser", json!({}))
            .await
            .ok();
    let user_exists = existing
        .as_ref()
        .and_then(|entry| entry.get("value"))
        .and_then(|value| value.get("User"))
        .and_then(Value::as_array)
        .map(|users| {
            users.iter().any(|user| {
                user.get("userName")
                    .and_then(Value::as_str)
                    .map(|value| value.eq_ignore_ascii_case(username))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if !user_exists {
        match ReolinkHttpSession::send_command_without_token(
            client,
            base_url,
            "AddUser",
            json!({
                "User": {
                    "userName": username,
                    "password": password,
                    "level": "admin",
                }
            }),
        )
        .await
        {
            Ok(entry) => {
                if let Some(error) = command_error("AddUser", &entry) {
                    if !error.is_rsp_code(-28) {
                        return Err(error.into());
                    }
                } else {
                    return Ok(());
                }
            }
            Err(err) => {
                if err
                    .downcast_ref::<ReolinkCgiCommandError>()
                    .is_none_or(|error| !error.is_rsp_code(-28))
                {
                    return Err(err.context("failed creating bootstrap Reolink user"));
                }
            }
        }
    }

    let entry = ReolinkHttpSession::send_command_without_token(
        client,
        base_url,
        "ModifyUser",
        json!({
            "User": {
                "userName": username,
                "oldPassword": "",
                "newPassword": password,
            }
        }),
    )
    .await
    .context("failed updating bootstrap Reolink user password")?;
    if let Some(error) = command_error("ModifyUser", &entry) {
        return Err(error.into());
    }
    Ok(())
}

async fn best_effort_logout(session: &mut ReolinkHttpSession, context: &str) {
    if let Err(error) = session.logout().await {
        warn!(context, error = %error, "failed closing Reolink CGI session");
    }
}

async fn verify_presentation_apply(
    session: &mut ReolinkHttpSession,
    request: &ReolinkPresentationApplyRequest,
) -> Result<ReolinkPresentationState> {
    let deadline = Instant::now() + Duration::from_secs(PRESENTATION_VERIFY_TIMEOUT_SECS);
    let mut last_state = session.read_presentation_state().await?;
    if presentation_verify_failures(&last_state, request).is_empty() {
        return Ok(last_state);
    }

    loop {
        if Instant::now() >= deadline {
            let failures = presentation_verify_failures(&last_state, request);
            return Err(anyhow!(
                "requested presentation state did not verify: {} (observed overlay {:?}, timestamp {:?}, time mode {:?}, ntp {:?}, timezone {:?}, date format {:?}, hour format {:?})",
                failures.join(", "),
                last_state.overlay_text,
                last_state.overlay_timestamp,
                last_state.time_mode,
                last_state.ntp_server,
                last_state.timezone,
                last_state.clock_date_format,
                last_state.clock_hour_format,
            ));
        }
        sleep(Duration::from_millis(PRESENTATION_VERIFY_POLL_MILLIS)).await;
        last_state = session.read_presentation_state().await?;
        if presentation_verify_failures(&last_state, request).is_empty() {
            return Ok(last_state);
        }
    }
}

fn presentation_verify_failures(
    observed: &ReolinkPresentationState,
    request: &ReolinkPresentationApplyRequest,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if let Some(expected) = &request.time_mode
        && !expected.trim().is_empty()
        && observed.time_mode.trim() != expected.trim()
    {
        fields.push("time_mode");
    }
    if let Some(expected) = &request.ntp_server
        && observed.ntp_server.trim() != expected.trim()
    {
        fields.push("ntp_server");
    }
    if let Some(expected) = &request.manual_time
        && !expected.trim().is_empty()
        && observed.manual_time.trim() != expected.trim()
    {
        fields.push("manual_time");
    }
    if let Some(expected) = &request.timezone
        && observed.timezone.trim() != expected.trim()
    {
        fields.push("timezone");
    }
    if request.enforce_clock_display {
        if observed.clock_date_format.trim() != "MM/DD/YYYY" {
            fields.push("clock_date_format");
        }
        if observed.clock_hour_format.trim() != "24h" {
            fields.push("clock_hour_format");
        }
    }
    if let Some(expected) = &request.overlay_text
        && observed.overlay_text.trim() != expected.trim()
    {
        fields.push("overlay_text");
    }
    if let Some(expected) = request.overlay_timestamp
        && observed.overlay_timestamp != Some(expected)
    {
        fields.push("overlay_timestamp");
    }
    fields
}

fn merge_normal(
    current: &ReolinkNormalPortConfig,
    requested: Option<&ReolinkNormalPortConfig>,
) -> ReolinkNormalPortConfig {
    requested.cloned().unwrap_or(ReolinkNormalPortConfig {
        i_surv_port_enable: current.i_surv_port_enable,
        i_surv_port: current.i_surv_port,
        i_http_port_enable: 0,
        i_http_port: current.i_http_port,
        i_https_port_enable: 0,
        i_https_port: current.i_https_port,
    })
}

fn merge_advanced(
    current: &ReolinkAdvancedPortConfig,
    requested: Option<&ReolinkAdvancedPortConfig>,
) -> ReolinkAdvancedPortConfig {
    let base = ReolinkAdvancedPortConfig {
        i_onvif_port_enable: 1,
        i_onvif_port: 8000,
        i_rtsp_port_enable: 1,
        i_rtsp_port: 554,
        i_rtmp_port_enable: current.i_rtmp_port_enable,
        i_rtmp_port: current.i_rtmp_port,
    };
    if let Some(requested) = requested {
        ReolinkAdvancedPortConfig {
            i_onvif_port_enable: requested.i_onvif_port_enable,
            i_onvif_port: requested.i_onvif_port,
            i_rtsp_port_enable: requested.i_rtsp_port_enable,
            i_rtsp_port: requested.i_rtsp_port,
            i_rtmp_port_enable: requested.i_rtmp_port_enable,
            i_rtmp_port: requested.i_rtmp_port,
        }
    } else {
        base
    }
}

fn merge_p2p(requested: Option<&ReolinkP2PConfig>) -> ReolinkP2PConfig {
    requested.cloned().unwrap_or_else(|| ReolinkP2PConfig {
        i_enable: 0,
        i_port: 0,
        server_domain_name: String::new(),
    })
}

fn build_presentation_state(
    time_entry: Option<&Value>,
    osd_entry: Option<&Value>,
) -> ReolinkPresentationState {
    let time_value = time_entry
        .and_then(|entry| entry.get("value"))
        .and_then(|value| value.get("Time"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let osd_value = osd_entry
        .and_then(|entry| entry.get("value"))
        .and_then(|value| value.get("Osd"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    ReolinkPresentationState {
        model: string_at_any(&osd_value, &["channelName", "name"]),
        time_mode: if bool_at_any(&time_value, &["ntpEnable", "NtpEnable", "ntp_enabled"])
            .unwrap_or(false)
        {
            "ntp".to_string()
        } else {
            "manual".to_string()
        },
        ntp_server: string_at_any(&time_value, &["ntpServer", "NtpServer", "server"]),
        manual_time: manual_time_from_value(&time_value),
        timezone: reolink_timezone_label(&time_value),
        clock_date_format: reolink_date_format_label(&time_value),
        clock_hour_format: reolink_hour_format_label(&time_value),
        overlay_text: overlay_text_from_value(&osd_value),
        overlay_timestamp: overlay_timestamp_from_value(&osd_value),
        time: time_value,
        osd: osd_value,
    }
}

fn mutate_time_value(value: &mut Value, request: &ReolinkPresentationApplyRequest) {
    if let Some(mode) = &request.time_mode {
        let use_ntp = mode.trim().eq_ignore_ascii_case("ntp");
        set_bool_at_any(value, &["ntpEnable", "NtpEnable", "ntp_enabled"], use_ntp);
    }
    if let Some(server) = &request.ntp_server {
        set_string_at_any(value, &["ntpServer", "NtpServer", "server"], server);
    }
    if let Some(zone) = &request.timezone {
        set_reolink_timezone_at_any(value, &["timeZone", "TimeZone", "zone"], zone);
        if zone.trim().eq_ignore_ascii_case("America/Phoenix") {
            set_i64_at_any(value, &["isDst", "IsDst"], 0);
        }
    }
    if request.enforce_clock_display {
        set_reolink_date_format_at_any(
            value,
            &["timeFmt", "TimeFmt"],
            REOLINK_TIME_FMT_MM_DD_YYYY,
            REOLINK_TIME_FMT_MM_DD_YYYY_LABEL,
        );
        set_i64_at_any(value, &["hourFmt", "HourFmt"], REOLINK_HOUR_FMT_24H);
    }
    if let Some(manual_time) = &request.manual_time
        && let Some((year, month, day, hour, minute, second)) =
            parse_manual_datetime(manual_time.trim())
    {
        set_i64_at_any(value, &["year", "Year"], year);
        set_i64_at_any(value, &["mon", "Mon", "month"], month);
        set_i64_at_any(value, &["day", "Day"], day);
        set_i64_at_any(value, &["hour", "Hour"], hour);
        set_i64_at_any(value, &["min", "Min", "minute"], minute);
        set_i64_at_any(value, &["sec", "Sec", "second"], second);
    }
}

fn mutate_osd_value(value: &mut Value, request: &ReolinkPresentationApplyRequest) {
    if let Some(text) = &request.overlay_text {
        if let Some(channel) = value.get_mut("osdChannel").and_then(Value::as_object_mut) {
            channel.insert("name".to_string(), Value::String(text.trim().to_string()));
            set_object_bool_like(channel, "enable", !text.trim().is_empty());
        }
        set_string_at_any(value, &["channelName", "name"], text);
    }
    if let Some(show_timestamp) = request.overlay_timestamp {
        if let Some(time_value) = value.get_mut("osdTime").and_then(Value::as_object_mut) {
            set_object_bool_like(time_value, "enable", show_timestamp);
        }
        set_bool_at_any(value, &["timeEnable", "showTime", "enable"], show_timestamp);
    }
}

fn overlay_text_from_value(value: &Value) -> String {
    if let Some(name) = value
        .get("osdChannel")
        .and_then(|channel| channel.get("name"))
        .and_then(Value::as_str)
    {
        return name.trim().to_string();
    }
    string_at_any(value, &["channelName", "name"])
}

fn overlay_timestamp_from_value(value: &Value) -> Option<bool> {
    if let Some(enabled) = value.get("osdTime").and_then(|time| time.get("enable")) {
        if let Some(boolean) = enabled.as_bool() {
            return Some(boolean);
        }
        if let Some(integer) = enabled.as_i64() {
            return Some(integer != 0);
        }
    }
    bool_at_any(value, &["timeEnable", "showTime", "enable"])
}

fn manual_time_from_value(value: &Value) -> String {
    let Some(year) = int_at_any(value, &["year", "Year"]) else {
        return String::new();
    };
    let Some(month) = int_at_any(value, &["mon", "Mon", "month"]) else {
        return String::new();
    };
    let Some(day) = int_at_any(value, &["day", "Day"]) else {
        return String::new();
    };
    let Some(hour) = int_at_any(value, &["hour", "Hour"]) else {
        return String::new();
    };
    let Some(minute) = int_at_any(value, &["min", "Min", "minute"]) else {
        return String::new();
    };
    let second = int_at_any(value, &["sec", "Sec", "second"]).unwrap_or(0);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
}

fn string_at_any(value: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(raw) = value.get(*key).and_then(Value::as_str) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

fn bool_at_any(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Some(raw) = value.get(*key).and_then(Value::as_bool) {
            return Some(raw);
        }
        if let Some(raw) = value.get(*key).and_then(Value::as_i64) {
            return Some(raw != 0);
        }
    }
    None
}

fn int_at_any(value: &Value, keys: &[&str]) -> Option<i64> {
    for key in keys {
        if let Some(raw) = value.get(*key).and_then(Value::as_i64) {
            return Some(raw);
        }
    }
    None
}

fn set_string_at_any(value: &mut Value, keys: &[&str], next: &str) {
    if let Some(map) = value.as_object_mut() {
        for key in keys {
            if map.contains_key(*key) {
                map.insert((*key).to_string(), Value::String(next.trim().to_string()));
                return;
            }
        }
        if let Some(key) = keys.first() {
            map.insert((*key).to_string(), Value::String(next.trim().to_string()));
        }
    }
}

fn set_bool_at_any(value: &mut Value, keys: &[&str], next: bool) {
    if let Some(map) = value.as_object_mut() {
        for key in keys {
            if map.contains_key(*key) {
                let replacement = match map.get(*key) {
                    Some(existing) if existing.is_i64() || existing.is_u64() => {
                        json!(i32::from(next))
                    }
                    _ => Value::Bool(next),
                };
                map.insert((*key).to_string(), replacement);
                return;
            }
        }
        if let Some(key) = keys.first() {
            map.insert((*key).to_string(), Value::Bool(next));
        }
    }
}

fn set_object_bool_like(map: &mut serde_json::Map<String, Value>, key: &str, next: bool) {
    let replacement = match map.get(key) {
        Some(existing) if existing.is_i64() || existing.is_u64() => json!(i32::from(next)),
        _ => Value::Bool(next),
    };
    map.insert(key.to_string(), replacement);
}

fn set_i64_at_any(value: &mut Value, keys: &[&str], next: i64) {
    if let Some(map) = value.as_object_mut() {
        for key in keys {
            if map.contains_key(*key) {
                map.insert((*key).to_string(), Value::Number(next.into()));
                return;
            }
        }
        if let Some(key) = keys.first() {
            map.insert((*key).to_string(), Value::Number(next.into()));
        }
    }
}

fn parse_manual_datetime(value: &str) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let (date, time) = value.split_once('T')?;
    let date_parts = date
        .split('-')
        .map(|part| part.trim().parse::<i64>().ok())
        .collect::<Option<Vec<_>>>()?;
    let time_parts = time
        .split(':')
        .map(|part| part.trim().parse::<i64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if date_parts.len() != 3 || !(time_parts.len() == 2 || time_parts.len() == 3) {
        return None;
    }
    Some((
        date_parts[0],
        date_parts[1],
        date_parts[2],
        time_parts[0],
        time_parts[1],
        *time_parts.get(2).unwrap_or(&0),
    ))
}

fn response_entry(cmd: &str, body: &str, crypto: Option<&ReolinkHttpCrypto>) -> Result<Value> {
    let parsed: Value = if let Some(crypto) = crypto {
        if let Ok(decrypted) = crypto.decrypt_string(body) {
            serde_json::from_str(&decrypted)
                .with_context(|| format!("failed parsing decrypted Reolink CGI JSON for {cmd}"))?
        } else {
            serde_json::from_str(body)
                .with_context(|| format!("failed parsing Reolink CGI JSON for {cmd}"))?
        }
    } else {
        serde_json::from_str(body)
            .with_context(|| format!("failed parsing Reolink CGI JSON for {cmd}"))?
    };

    let first = parsed
        .as_array()
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow!("Reolink CGI {cmd} returned an empty response"))?
        .clone();
    let actual_cmd = first.get("cmd").and_then(Value::as_str).unwrap_or_default();
    if !actual_cmd.is_empty() && actual_cmd != cmd {
        return Err(anyhow!(
            "Reolink CGI response command mismatch: expected {cmd}, got {actual_cmd}"
        ));
    }
    Ok(first)
}

fn command_error(cmd: &str, entry: &Value) -> Option<ReolinkCgiCommandError> {
    let code = entry.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code == 0 {
        return None;
    }

    let detail = entry
        .get("error")
        .and_then(|error| error.get("detail"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let rsp_code = entry
        .get("error")
        .and_then(|error| error.get("rspCode"))
        .and_then(Value::as_i64)
        .unwrap_or_default();
    Some(ReolinkCgiCommandError {
        cmd: cmd.to_string(),
        code,
        rsp_code,
        detail,
    })
}

fn parse_digest_header(header_value: &str) -> Result<DigestChallenge> {
    let raw = header_value
        .trim()
        .strip_prefix("Digest")
        .unwrap_or(header_value)
        .trim();
    let mut realm = String::new();
    let mut qop = String::new();
    let mut nonce = String::new();
    let mut nc = String::new();

    for part in raw.split(',') {
        let mut pieces = part.trim().splitn(2, '=');
        let key = pieces.next().unwrap_or_default().trim();
        let value = pieces
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .to_string();
        match key {
            "realm" => realm = value,
            "qop" => qop = value,
            "nonce" => nonce = value,
            "nc" => nc = value,
            _ => {}
        }
    }

    if realm.is_empty() || qop.is_empty() || nonce.is_empty() || nc.is_empty() {
        return Err(anyhow!("Reolink CGI digest challenge was incomplete"));
    }

    Ok(DigestChallenge {
        realm,
        qop,
        nonce,
        nc,
    })
}

fn int_field(value: &Value, key: &str) -> i32 {
    value.get(key).and_then(Value::as_i64).unwrap_or_default() as i32
}

fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("{:032x}", digest)
}

fn upper16(value: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = value.as_bytes();
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = bytes.get(idx).copied().unwrap_or(b'0').to_ascii_uppercase();
    }
    out
}

fn random_hex(len: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| HEX[rng.gen_range(0..HEX.len())] as char)
        .collect()
}

fn set_reolink_date_format_at_any(
    value: &mut Value,
    keys: &[&str],
    next_i64: i64,
    next_label: &str,
) {
    if let Some(map) = value.as_object_mut() {
        for key in keys {
            if let Some(existing) = map.get(*key) {
                let replacement = if existing.is_string() {
                    Value::String(next_label.to_string())
                } else {
                    Value::Number(next_i64.into())
                };
                map.insert((*key).to_string(), replacement);
                return;
            }
        }
        if let Some(key) = keys.first() {
            map.insert((*key).to_string(), Value::String(next_label.to_string()));
        }
    }
}

fn reolink_date_format_label(value: &Value) -> String {
    let string_value = string_at_any(value, &["timeFmt", "TimeFmt"]);
    match string_value.trim() {
        REOLINK_TIME_FMT_MM_DD_YYYY_LABEL => return REOLINK_TIME_FMT_MM_DD_YYYY_LABEL.to_string(),
        REOLINK_TIME_FMT_YYYY_MM_DD_LABEL => return REOLINK_TIME_FMT_YYYY_MM_DD_LABEL.to_string(),
        REOLINK_TIME_FMT_DD_MM_YYYY_LABEL => return REOLINK_TIME_FMT_DD_MM_YYYY_LABEL.to_string(),
        "" => {}
        other => return format!("raw:{other}"),
    }
    match int_at_any(value, &["timeFmt", "TimeFmt"]) {
        Some(REOLINK_TIME_FMT_MM_DD_YYYY) => REOLINK_TIME_FMT_MM_DD_YYYY_LABEL.to_string(),
        Some(0) => REOLINK_TIME_FMT_YYYY_MM_DD_LABEL.to_string(),
        Some(2) => REOLINK_TIME_FMT_DD_MM_YYYY_LABEL.to_string(),
        Some(other) => format!("raw:{other}"),
        None => String::new(),
    }
}

fn reolink_hour_format_label(value: &Value) -> String {
    match int_at_any(value, &["hourFmt", "HourFmt"]) {
        Some(REOLINK_HOUR_FMT_24H) => "24h".to_string(),
        Some(1) => "12h".to_string(),
        Some(other) => format!("raw:{other}"),
        None => String::new(),
    }
}

fn reolink_timezone_label(value: &Value) -> String {
    let string_value = string_at_any(value, &["timeZone", "TimeZone", "zone"]);
    match string_value.trim() {
        "UTC" => return "UTC".to_string(),
        "America/Phoenix" | "MST7" | "UTC+07:00:00" | "GMT+07:00:00" => {
            return "America/Phoenix".to_string();
        }
        "" => {}
        other => return other.to_string(),
    }
    match int_at_any(value, &["timeZone", "TimeZone", "zone"]) {
        Some(REOLINK_TIMEZONE_UTC_SECONDS) => "UTC".to_string(),
        Some(REOLINK_TIMEZONE_PHOENIX_SECONDS) => "America/Phoenix".to_string(),
        Some(other) => format!("raw:{other}"),
        None => String::new(),
    }
}

fn reolink_timezone_seconds(label: &str) -> Option<i64> {
    match label.trim() {
        "UTC" => Some(REOLINK_TIMEZONE_UTC_SECONDS),
        "America/Phoenix" => Some(REOLINK_TIMEZONE_PHOENIX_SECONDS),
        _ => None,
    }
}

fn set_reolink_timezone_at_any(value: &mut Value, keys: &[&str], next_label: &str) {
    let trimmed = next_label.trim();
    let numeric = reolink_timezone_seconds(trimmed);
    if let Some(map) = value.as_object_mut() {
        for key in keys {
            if let Some(existing) = map.get(*key) {
                let replacement = if existing.is_i64() || existing.is_u64() {
                    numeric
                        .map(|seconds| Value::Number(seconds.into()))
                        .unwrap_or_else(|| Value::String(trimmed.to_string()))
                } else {
                    Value::String(trimmed.to_string())
                };
                map.insert((*key).to_string(), replacement);
                return;
            }
        }
        if let Some(key) = keys.first() {
            let replacement = numeric
                .map(|seconds| Value::Number(seconds.into()))
                .unwrap_or_else(|| Value::String(trimmed.to_string()));
            map.insert((*key).to_string(), replacement);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_digest_challenge() {
        let parsed = parse_digest_header(
            "Digest realm=\"IPC\", qop=\"auth\", nonce=\"abc\", nc=\"00000001\"",
        )
        .expect("challenge");
        assert_eq!(parsed.realm, "IPC");
        assert_eq!(parsed.qop, "auth");
        assert_eq!(parsed.nonce, "abc");
        assert_eq!(parsed.nc, "00000001");
    }

    #[test]
    fn reolink_http_crypto_roundtrips() {
        let crypto =
            ReolinkHttpCrypto::from_login("admin", "test1234", "nonce123", "abcdef0123456789");
        let plain = r#"[{\"cmd\":\"GetNetPort\",\"action\":0,\"param\":{}}]"#;
        let encoded = crypto.encrypt_string(plain);
        let decoded = crypto.decrypt_string(&encoded).expect("decode");
        assert_eq!(decoded, plain);
    }

    #[test]
    fn cgi_net_port_maps_to_setup_configs() {
        let port = ReolinkCgiNetPort {
            media_port: 9000,
            http_enable: 1,
            http_port: 80,
            https_enable: 0,
            https_port: 443,
            onvif_enable: 1,
            onvif_port: 8000,
            rtsp_enable: 1,
            rtsp_port: 554,
            rtmp_enable: 0,
            rtmp_port: 1935,
        };
        assert_eq!(port.normal().i_http_port, 80);
        assert_eq!(port.advanced().i_onvif_port, 8000);
        assert_eq!(port.advanced().i_rtsp_port, 554);
    }

    #[test]
    fn parses_login_uninitialized_error() {
        let entry = response_entry(
            "Login",
            r#"[{"cmd":"Login","code":1,"error":{"rspCode":-505,"detail":"login not init"}}]"#,
            None,
        )
        .expect("entry");
        let error = command_error("Login", &entry).expect("error");
        assert!(error.is_rsp_code(-505));
    }

    #[test]
    fn presentation_verify_failures_detect_requested_overlay_drift() {
        let observed = ReolinkPresentationState {
            overlay_text: "Reolink E1 Outdoor SE".to_string(),
            overlay_timestamp: Some(true),
            ..Default::default()
        };
        let request = ReolinkPresentationApplyRequest {
            connection: crate::reolink::ReolinkConnectRequest {
                ip: "192.168.0.10".to_string(),
                username: "admin".to_string(),
                password: "test".to_string(),
                channel: 0,
            },
            overlay_text: Some("Carport".to_string()),
            overlay_timestamp: Some(true),
            time_mode: None,
            ntp_server: None,
            manual_time: None,
            timezone: None,
            enforce_clock_display: false,
        };
        assert_eq!(
            presentation_verify_failures(&observed, &request),
            vec!["overlay_text"]
        );
    }

    #[test]
    fn presentation_verify_failures_accept_matching_requested_fields() {
        let observed = ReolinkPresentationState {
            overlay_text: "Test".to_string(),
            overlay_timestamp: Some(false),
            time_mode: "ntp".to_string(),
            ntp_server: "pool.ntp.org".to_string(),
            timezone: "UTC".to_string(),
            ..Default::default()
        };
        let request = ReolinkPresentationApplyRequest {
            connection: crate::reolink::ReolinkConnectRequest {
                ip: "192.168.0.10".to_string(),
                username: "admin".to_string(),
                password: "test".to_string(),
                channel: 0,
            },
            overlay_text: Some("Test".to_string()),
            overlay_timestamp: Some(false),
            time_mode: Some("ntp".to_string()),
            ntp_server: Some("pool.ntp.org".to_string()),
            manual_time: None,
            timezone: Some("UTC".to_string()),
            enforce_clock_display: false,
        };
        assert!(presentation_verify_failures(&observed, &request).is_empty());
    }

    #[test]
    fn reolink_date_format_label_accepts_string_payloads() {
        let value = json!({
            "timeFmt": "DD/MM/YYYY",
            "hourFmt": 0
        });
        assert_eq!(reolink_date_format_label(&value), "DD/MM/YYYY");
        assert_eq!(reolink_hour_format_label(&value), "24h");
    }

    #[test]
    fn reolink_hour_format_label_maps_one_to_12h() {
        let value = json!({
            "hourFmt": 1
        });
        assert_eq!(reolink_hour_format_label(&value), "12h");
    }

    #[test]
    fn set_reolink_date_format_preserves_string_wire_shape() {
        let mut value = json!({
            "timeFmt": "DD/MM/YYYY"
        });
        set_reolink_date_format_at_any(
            &mut value,
            &["timeFmt", "TimeFmt"],
            REOLINK_TIME_FMT_MM_DD_YYYY,
            REOLINK_TIME_FMT_MM_DD_YYYY_LABEL,
        );
        assert_eq!(
            value.get("timeFmt").and_then(Value::as_str),
            Some(REOLINK_TIME_FMT_MM_DD_YYYY_LABEL)
        );
    }

    #[test]
    fn reolink_timezone_label_accepts_numeric_payloads() {
        let value = json!({
            "timeZone": 25200,
            "isDst": 0
        });
        assert_eq!(reolink_timezone_label(&value), "America/Phoenix");
    }

    #[test]
    fn set_reolink_timezone_preserves_numeric_wire_shape() {
        let mut value = json!({
            "timeZone": 28800
        });
        set_reolink_timezone_at_any(
            &mut value,
            &["timeZone", "TimeZone", "zone"],
            "America/Phoenix",
        );
        assert_eq!(
            value.get("timeZone").and_then(Value::as_i64),
            Some(REOLINK_TIMEZONE_PHOENIX_SECONDS)
        );
    }
}
