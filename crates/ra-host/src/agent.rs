//! The host agent loop: keep the ID registered, and turn incoming
//! password-authenticated pair requests into completed Apollo pairings.

use crate::apollo::Apollo;
use crate::config::Config;
use anyhow::{Context, Result};
use ra_proto::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long we wait for Moonlight's `getservercert` to show up after
/// accepting a password.
const PIN_WAIT: Duration = Duration::from_secs(90);
/// How long we wait for the paired client to appear in Apollo's list.
const CLIENT_APPEAR_WAIT: Duration = Duration::from_secs(60);

pub struct Agent {
    cfg: Config,
    http: reqwest::Client,
    apollo: Arc<Apollo>,
    /// Consecutive wrong-password attempts; used for backoff.
    failures: u32,
}

impl Agent {
    pub fn new(cfg: Config) -> Result<Self> {
        let apollo = Apollo::new(&cfg.apollo_url, &cfg.apollo_username, &cfg.apollo_password)?;
        let http = reqwest::Client::builder().timeout(Duration::from_secs(45)).build()?;
        Ok(Self { cfg, http, apollo: Arc::new(apollo), failures: 0 })
    }

    fn rv(&self, path: &str) -> String {
        format!("{}/{}{}", self.cfg.rendezvous_url.trim_end_matches('/'), API_VERSION, path)
    }

    pub fn endpoints(&self, observed: Option<&str>) -> Vec<Endpoint> {
        let mut eps = Vec::new();
        let mut seen = HashSet::new();
        let port = self.cfg.gamestream_port;
        if self.cfg.advertise_lan_ips {
            if let Ok(ifaces) = if_addrs::get_if_addrs() {
                for i in ifaces {
                    if i.is_loopback() {
                        continue;
                    }
                    let ip = i.ip();
                    if let std::net::IpAddr::V6(v6) = ip {
                        if v6.segments()[0] & 0xffc0 == 0xfe80 {
                            continue; // link-local needs a scope id
                        }
                    }
                    let kind = if i.name.starts_with("tailscale") || i.name.starts_with("utun") || i.name.starts_with("wg") || i.name.starts_with("zt") {
                        "vpn"
                    } else {
                        "lan"
                    };
                    let s = ip.to_string();
                    if seen.insert(s.clone()) {
                        eps.push(Endpoint { host: s, port, kind: kind.into() });
                    }
                }
            }
        }
        for e in &self.cfg.extra_endpoints {
            if seen.insert(e.host.clone()) {
                eps.push(e.clone());
            }
        }
        if self.cfg.advertise_public_ip {
            if let Some(o) = observed {
                if seen.insert(o.to_string()) {
                    eps.push(Endpoint { host: o.to_string(), port, kind: "public".into() });
                }
            }
        }
        eps.truncate(16);
        eps
    }

    /// Register (or re-register) and return the assigned ID.
    pub async fn register(&mut self, config_path: &std::path::Path) -> Result<RegisterResponse> {
        let req = RegisterRequest {
            id: self.cfg.id.clone(),
            token: self.cfg.token.clone(),
            name: self.cfg.name.clone(),
            platform: std::env::consts::OS.into(),
            endpoints: self.endpoints(None),
            password_salt: self.cfg.password_salt.clone(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
        };
        let resp: RegisterResponse = self
            .http
            .post(self.rv("/hosts/register"))
            .json(&req)
            .send()
            .await
            .context("contacting rendezvous server")?
            .error_for_status()
            .context("rendezvous rejected registration")?
            .json()
            .await?;
        if self.cfg.id.as_deref() != Some(&resp.id) {
            self.cfg.id = Some(resp.id.clone());
            self.cfg.save(config_path)?;
        }
        // Second pass to advertise the observed public address.
        if let Some(obs) = &resp.observed_addr {
            let eps = self.endpoints(Some(obs));
            let _ = self
                .http
                .post(self.rv(&format!("/hosts/{}/heartbeat", resp.id)))
                .bearer_auth(&self.cfg.token)
                .json(&serde_json::json!({ "endpoints": eps }))
                .send()
                .await;
        }
        Ok(resp)
    }

    pub async fn run(mut self, config_path: &std::path::Path) -> Result<()> {
        if self.cfg.password_h1.is_none() {
            anyhow::bail!("no password set; run `ra-host set-password` first");
        }
        match self.apollo.config().await {
            Ok(_) => tracing::info!(url = %self.cfg.apollo_url, "connected to Apollo web UI"),
            Err(e) => tracing::warn!(error = %e, "Apollo web UI not reachable yet; will retry when needed"),
        }
        let reg = self.register(config_path).await?;
        let id = reg.id.clone();
        tracing::info!(%id, name = %self.cfg.name, "host online");
        println!("Your ID: {}", pretty_id(&id));

        let mut last_heartbeat = Instant::now();
        let mut observed = reg.observed_addr.clone();
        loop {
            // Long-poll for pair requests; this also counts as liveness.
            let poll = self
                .http
                .get(self.rv(&format!("/hosts/{id}/pair-requests?wait=25")))
                .bearer_auth(&self.cfg.token)
                .send()
                .await;
            match poll {
                Ok(resp) if resp.status().is_success() => {
                    let reqs: Vec<PairRequest> = resp.json().await.unwrap_or_default();
                    for pr in reqs {
                        let res = self.handle_pair(&pr).await;
                        let result = match res {
                            Ok(()) => PairResult { request_id: pr.request_id.clone(), status: PairStatus::Paired, message: None },
                            Err(e) if e.to_string() == "wrong password" => {
                                self.failures += 1;
                                let delay = Duration::from_secs((2u64.pow(self.failures.min(6))).min(60));
                                tracing::warn!(device = %pr.device_name, failures = self.failures, "wrong password; backing off {delay:?}");
                                tokio::time::sleep(delay).await;
                                PairResult { request_id: pr.request_id.clone(), status: PairStatus::Rejected, message: Some("wrong password".into()) }
                            }
                            Err(e) => {
                                tracing::error!(error = %e, device = %pr.device_name, "pairing failed");
                                PairResult { request_id: pr.request_id.clone(), status: PairStatus::Failed, message: Some(e.to_string()) }
                            }
                        };
                        let _ = self
                            .http
                            .post(self.rv(&format!("/hosts/{id}/pair-results")))
                            .bearer_auth(&self.cfg.token)
                            .json(&result)
                            .send()
                            .await;
                    }
                }
                Ok(resp) if resp.status() == 404 || resp.status() == 403 => {
                    tracing::warn!(status = %resp.status(), "registration lost; re-registering");
                    if let Ok(r) = self.register(config_path).await {
                        observed = r.observed_addr;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "unexpected rendezvous response");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "rendezvous unreachable; retrying");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
            if last_heartbeat.elapsed() >= Duration::from_secs(ra_proto_heartbeat_secs(&reg)) {
                let eps = self.endpoints(observed.as_deref());
                if let Ok(resp) = self
                    .http
                    .post(self.rv(&format!("/hosts/{id}/heartbeat")))
                    .bearer_auth(&self.cfg.token)
                    .json(&serde_json::json!({ "endpoints": eps }))
                    .send()
                    .await
                {
                    if let Ok(r) = resp.json::<RegisterResponse>().await {
                        observed = r.observed_addr;
                    }
                }
                last_heartbeat = Instant::now();
            }
        }
    }

    /// Verify the password and complete the Apollo pairing for one request.
    async fn handle_pair(&mut self, pr: &PairRequest) -> Result<()> {
        let h1 = self.cfg.password_h1.as_deref().expect("checked in run");
        if !ct_eq(&pr.response, &challenge_response(h1, &pr.challenge)) {
            anyhow::bail!("wrong password");
        }
        self.failures = 0;
        let pin = PairSecret::derive(h1, &pr.challenge)
            .open_pin(&pr.sealed_pin)
            .map_err(|_| anyhow::anyhow!("wrong password"))?;
        let name = sanitize_name(&pr.device_name);
        tracing::info!(device = %name, "password accepted; waiting for Moonlight pairing request");

        let before: HashSet<String> = self.apollo.list_clients().await?.into_iter().map(|c| c.uuid).collect();

        // Moonlight's getservercert parks on the host until a PIN is posted.
        // Apollo answers {"status":false} while nothing is parked.
        let start = Instant::now();
        loop {
            if self.apollo.submit_pin(&pin, &name).await? {
                break;
            }
            if start.elapsed() > PIN_WAIT {
                anyhow::bail!("timed out waiting for the client's pairing request to reach Apollo");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tracing::info!(device = %name, "PIN delivered to Apollo");

        // Wait for the new client to appear, then apply permissions.
        let start = Instant::now();
        let new_client = loop {
            let clients = self.apollo.list_clients().await?;
            if let Some(c) = clients.into_iter().find(|c| !before.contains(&c.uuid)) {
                break c;
            }
            if start.elapsed() > CLIENT_APPEAR_WAIT {
                anyhow::bail!("client never completed pairing with Apollo (wrong PIN or aborted)");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let mut updated = new_client.clone();
        updated.perm = self.cfg.client_permissions;
        if updated.name.is_empty() {
            updated.name = name.clone();
        }
        self.apollo.update_client(&updated).await?;
        tracing::info!(device = %updated.name, uuid = %updated.uuid, perm = format!("{:#x}", updated.perm), "client paired and permissions applied");
        Ok(())
    }
}

fn ra_proto_heartbeat_secs(r: &RegisterResponse) -> u64 {
    r.heartbeat_secs.clamp(10, 300)
}

/// Apollo rewrites `(`/`)` to `[`/`]`; keep names simple.
pub fn sanitize_name(n: &str) -> String {
    let s: String = n.chars().filter(|c| c.is_alphanumeric() || " -_.[]".contains(*c)).take(48).collect();
    if s.trim().is_empty() {
        "Remote client".into()
    } else {
        s
    }
}

/// `123456789` -> `123 456 789`.
pub fn pretty_id(id: &str) -> String {
    id.as_bytes().chunks(3).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(" ")
}
