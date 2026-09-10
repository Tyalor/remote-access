//! Minimal client for Apollo's web UI API (`apollo/src/confighttp.cpp`).
//!
//! Auth is a session cookie obtained from `POST /api/login`. Apollo keeps a
//! single global session, so logging in here evicts an open browser session.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApolloClient {
    pub name: String,
    pub uuid: String,
    #[serde(default)]
    pub perm: u32,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub display_mode: String,
    #[serde(default = "t")]
    pub enable_legacy_ordering: bool,
    #[serde(default = "t")]
    pub allow_client_commands: bool,
    #[serde(default)]
    pub always_use_virtual_display: bool,
    #[serde(default, rename = "do")]
    pub do_cmds: Vec<serde_json::Value>,
    #[serde(default)]
    pub undo: Vec<serde_json::Value>,
}

fn t() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct OtpResponse {
    pub otp: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: bool,
    #[serde(default)]
    pub message: String,
}

pub struct Apollo {
    base: String,
    username: String,
    password: String,
    http: reqwest::Client,
    cookie: tokio::sync::Mutex<Option<String>>,
}

#[allow(dead_code)]
impl Apollo {
    pub fn new(base: &str, username: &str, password: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            // Apollo serves its web UI with the same self-signed cert as GameStream.
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            username: username.into(),
            password: password.into(),
            http,
            cookie: tokio::sync::Mutex::new(None),
        })
    }

    async fn login(&self) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/api/login", self.base))
            .json(&serde_json::json!({ "username": self.username, "password": self.password }))
            .send()
            .await
            .context("connecting to Apollo web UI")?;
        if resp.status() == 401 {
            bail!("Apollo rejected the web UI credentials");
        }
        let resp = resp.error_for_status()?;
        let cookie = resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.split(';').next().filter(|kv| kv.starts_with("auth=")).map(|s| s.to_string()))
            .ok_or_else(|| anyhow!("Apollo login did not return an auth cookie"))?;
        Ok(cookie)
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> Result<reqwest::Response> {
        for attempt in 0..2 {
            let cookie = {
                let mut c = self.cookie.lock().await;
                if c.is_none() {
                    *c = Some(self.login().await?);
                }
                c.clone().unwrap()
            };
            let mut req = self
                .http
                .request(method.clone(), format!("{}{}", self.base, path))
                .header("cookie", &cookie);
            if let Some(b) = &body {
                req = req.json(b);
            } else if method != reqwest::Method::GET {
                req = req.header("content-type", "application/json").body("{}");
            }
            let resp = req.send().await?;
            if resp.status() == 401 && attempt == 0 {
                *self.cookie.lock().await = None;
                continue;
            }
            return Ok(resp);
        }
        unreachable!()
    }

    /// Feed a PIN to a pending Moonlight pairing. Returns `Ok(false)` when
    /// no pairing request is waiting yet.
    pub async fn submit_pin(&self, pin: &str, name: &str) -> Result<bool> {
        let resp = self
            .call(reqwest::Method::POST, "/api/pin", Some(serde_json::json!({ "pin": pin, "name": name })))
            .await?;
        let v: serde_json::Value = resp.json().await?;
        Ok(v.get("status").and_then(|s| s.as_bool()).unwrap_or(false))
    }

    /// Request a one-time PIN bound to `passphrase` (Apollo `otpauth`).
    pub async fn request_otp(&self, passphrase: &str, device_name: &str) -> Result<OtpResponse> {
        let resp = self
            .call(
                reqwest::Method::POST,
                "/api/otp",
                Some(serde_json::json!({ "passphrase": passphrase, "deviceName": device_name })),
            )
            .await?;
        let r: OtpResponse = resp.json().await?;
        if !r.status || r.otp.is_empty() {
            bail!("Apollo refused OTP: {}", r.message);
        }
        Ok(r)
    }

    pub async fn list_clients(&self) -> Result<Vec<ApolloClient>> {
        let resp = self.call(reqwest::Method::GET, "/api/clients/list", None).await?;
        #[derive(Deserialize)]
        struct L {
            #[serde(default)]
            named_certs: Vec<ApolloClient>,
        }
        Ok(resp.json::<L>().await?.named_certs)
    }

    pub async fn update_client(&self, client: &ApolloClient) -> Result<()> {
        let body = serde_json::json!({
            "uuid": client.uuid,
            "name": client.name,
            "display_mode": client.display_mode,
            "enable_legacy_ordering": client.enable_legacy_ordering,
            "allow_client_commands": client.allow_client_commands,
            "always_use_virtual_display": client.always_use_virtual_display,
            "do": client.do_cmds,
            "undo": client.undo,
            "perm": client.perm,
        });
        let resp = self.call(reqwest::Method::POST, "/api/clients/update", Some(body)).await?;
        let v: serde_json::Value = resp.json().await?;
        if !v.get("status").and_then(|s| s.as_bool()).unwrap_or(false) {
            bail!("Apollo refused client update: {v}");
        }
        Ok(())
    }

    pub async fn unpair(&self, uuid: &str) -> Result<()> {
        self.call(reqwest::Method::POST, "/api/clients/unpair", Some(serde_json::json!({ "uuid": uuid }))).await?;
        Ok(())
    }

    pub async fn disconnect(&self, uuid: &str) -> Result<()> {
        self.call(reqwest::Method::POST, "/api/clients/disconnect", Some(serde_json::json!({ "uuid": uuid }))).await?;
        Ok(())
    }

    /// `GET /api/config` — used as a health check and to read `sunshine_name`.
    pub async fn config(&self) -> Result<serde_json::Value> {
        Ok(self.call(reqwest::Method::GET, "/api/config", None).await?.json().await?)
    }
}
