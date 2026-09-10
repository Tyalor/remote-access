//! Resolve → probe → pair → stream.

use crate::config::{ClientConfig, RememberedHost};
use crate::moonlight::Moonlight;
use anyhow::{anyhow, bail, Context, Result};
use ra_gamestream::{GsHttp, HostAddr, Identity, ServerInfo};
use ra_proto::*;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Resolved {
    pub info: HostInfo,
    pub addr: HostAddr,
    pub endpoint: Endpoint,
    pub server_info: ServerInfo,
}

impl Resolved {
    /// `host:port` form accepted by Moonlight's CLI.
    pub fn moonlight_host(&self) -> String {
        let h = if self.addr.host.contains(':') { format!("[{}]", self.addr.host) } else { self.addr.host.clone() };
        format!("{}:{}", h, self.addr.http_port)
    }
}

/// Progress events for UIs.
#[derive(Debug, Clone)]
pub enum Event {
    Resolving(String),
    Probing(Endpoint),
    Reachable(Endpoint),
    AlreadyPaired,
    PairingStarted,
    PairAccepted,
    Paired,
    Streaming(String),
    Info(String),
}

pub struct Session {
    pub cfg: ClientConfig,
    http: reqwest::Client,
    gs: GsHttp,
    pub on_event: Box<dyn Fn(Event) + Send + Sync>,
}

fn rank(kind: &str) -> u8 {
    match kind {
        "lan" => 0,
        "vpn" => 1,
        "manual" => 2,
        "public" => 3,
        _ => 4,
    }
}

impl Session {
    pub fn new(cfg: ClientConfig) -> Result<Self> {
        let identity = Identity::load_or_create(&ClientConfig::dir().join("identity"))?;
        Ok(Self {
            cfg,
            http: reqwest::Client::builder().timeout(Duration::from_secs(45)).build()?,
            gs: GsHttp::new(identity)?,
            on_event: Box::new(|_| {}),
        })
    }

    fn emit(&self, e: Event) {
        (self.on_event)(e);
    }

    fn rv(&self, path: &str) -> String {
        format!("{}/{}{}", self.cfg.rendezvous_url.trim_end_matches('/'), API_VERSION, path)
    }

    pub fn normalize_id(input: &str) -> Result<String> {
        let id: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
        if !is_valid_id(&id) {
            bail!("'{input}' is not a valid 9-digit ID");
        }
        Ok(id)
    }

    pub async fn lookup(&self, id: &str) -> Result<HostInfo> {
        self.emit(Event::Resolving(id.into()));
        let resp = self.http.get(self.rv(&format!("/hosts/{id}"))).send().await.context("contacting rendezvous server")?;
        if resp.status() == 404 {
            bail!("ID {id} is not registered");
        }
        Ok(resp.error_for_status()?.json().await?)
    }

    /// Probe all advertised endpoints concurrently and pick the best reachable one.
    pub async fn resolve(&self, id: &str) -> Result<Resolved> {
        let info = self.lookup(id).await?;
        if info.endpoints.is_empty() {
            bail!("host {id} advertises no endpoints");
        }
        let mut eps = info.endpoints.clone();
        eps.sort_by_key(|e| rank(&e.kind));
        let probes = eps.iter().map(|e| {
            let addr = HostAddr::new(e.host.clone(), e.port);
            let gs = self.gs.clone();
            let e = e.clone();
            async move {
                self.emit(Event::Probing(e.clone()));
                let r = tokio::time::timeout(Duration::from_secs(4), gs.server_info_http(&addr)).await;
                (e, addr, r)
            }
        });
        let results = futures::future::join_all(probes).await;
        let mut best: Option<Resolved> = None;
        for (e, addr, r) in results {
            if let Ok(Ok(si)) = r {
                if best.as_ref().map(|b| rank(&e.kind) < rank(&b.endpoint.kind)).unwrap_or(true) {
                    best = Some(Resolved { info: info.clone(), addr, endpoint: e, server_info: si });
                }
            }
        }
        let best = best.ok_or_else(|| {
            anyhow!(
                "host {} ({}) is {} but none of its {} endpoint(s) answered on the GameStream port. \
                 Over the internet this needs a VPN (Tailscale, WireGuard) or port forwarding of TCP/UDP 47984-48010.",
                info.name,
                id,
                if info.online { "online" } else { "OFFLINE" },
                info.endpoints.len()
            )
        })?;
        self.emit(Event::Reachable(best.endpoint.clone()));
        Ok(best)
    }

    /// Run the password exchange through the rendezvous server while
    /// `present_pin` performs the actual GameStream pairing with the PIN.
    /// Returns the PIN that was used.
    pub async fn pair_with<F, Fut>(&self, id: &str, h1: &str, remember: bool, present_pin: F) -> Result<()>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let ch: ChallengeResponse = self
            .http
            .post(self.rv(&format!("/hosts/{id}/challenge")))
            .send()
            .await?
            .error_for_status()
            .context("rendezvous refused challenge (rate limited?)")?
            .json()
            .await?;
        let pin = random_pin();
        let secret = PairSecret::derive(h1, &ch.challenge);
        let req = SubmitPairRequest {
            request_id: ch.request_id.clone(),
            response: challenge_response(h1, &ch.challenge),
            device_name: self.cfg.device_name.clone(),
            client_uid: Some(self.gs.identity().unique_id.clone()),
            sealed_pin: secret.seal_pin(&pin)?,
            remember,
        };
        let resp = self.http.post(self.rv(&format!("/hosts/{id}/pair"))).json(&req).send().await?;
        if !resp.status().is_success() {
            let body: ErrorBody = resp.json().await.unwrap_or(ErrorBody { error: "unknown".into() });
            bail!("pair request refused: {}", body.error);
        }
        self.emit(Event::PairingStarted);

        // The host will post the PIN into Apollo as soon as our getservercert
        // request parks there, so start the GameStream pairing right away and
        // watch the rendezvous result in parallel to surface a wrong password.
        let watcher = async {
            let deadline = Instant::now() + Duration::from_secs(150);
            loop {
                let r: Option<PairResult> = self
                    .http
                    .get(self.rv(&format!("/pair/{}?wait=20", ch.request_id)))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if let Some(r) = r {
                    return Ok::<PairResult, anyhow::Error>(r);
                }
                if Instant::now() > deadline {
                    bail!("timed out waiting for the host to answer");
                }
            }
        };
        tokio::pin!(watcher);
        let presenter = present_pin(pin.clone());
        tokio::pin!(presenter);
        let mut presenter_done: Option<Result<()>> = None;
        let result = loop {
            tokio::select! {
                r = &mut watcher => break r?,
                p = &mut presenter, if presenter_done.is_none() => {
                    presenter_done = Some(p);
                }
            }
        };
        match result.status {
            PairStatus::Paired => {
                self.emit(Event::Paired);
                if let Some(Err(e)) = presenter_done {
                    tracing::warn!(error = format!("{e:#}"), "host reports paired but local pairing step returned an error");
                }
                Ok(())
            }
            PairStatus::Rejected => bail!("wrong password"),
            PairStatus::Accepted => Ok(()),
            PairStatus::Failed => bail!("host failed to pair: {}", result.message.unwrap_or_default()),
        }
    }

    /// Full RustDesk-style flow with the Moonlight binary as the media client.
    pub async fn connect(
        &mut self,
        id: &str,
        password: Option<String>,
        app: Option<String>,
        remember_password: bool,
        config_path: &std::path::Path,
        extra_stream_args: &[String],
    ) -> Result<std::process::ExitStatus> {
        let bin = crate::moonlight::find_moonlight(self.cfg.moonlight_path.as_deref())
            .ok_or_else(|| anyhow!("Moonlight not found; install it or set moonlight_path / MOONLIGHT_BIN"))?;
        let ml = Moonlight::new(bin);
        let resolved = self.resolve(id).await?;
        let host = resolved.moonlight_host();

        let paired_apps = ml.list(&host).await.ok();
        if paired_apps.is_some() {
            self.emit(Event::AlreadyPaired);
        } else {
            let h1 = self.h1_for(id, &resolved.info.password_salt, password)?;
            let ml_ref = &ml;
            let host_ref = host.clone();
            self.pair_with(id, &h1, remember_password, |pin| async move {
                let mut child = ml_ref.spawn_pair(&host_ref, &pin)?;
                let status = child.wait().await?;
                if !status.success() {
                    bail!("moonlight pair exited with {status}");
                }
                Ok(())
            })
            .await?;
            if remember_password {
                let entry = self.cfg.hosts.entry(id.into()).or_default();
                entry.password_h1 = Some(h1);
                entry.password_salt = Some(resolved.info.password_salt.clone());
            }
        }
        let entry = self.cfg.hosts.entry(id.into()).or_default();
        entry.name = resolved.info.name.clone();
        entry.last_endpoint = Some(host.clone());
        let app = match app.or_else(|| entry.last_app.clone()) {
            Some(a) => a,
            None => {
                let apps = paired_apps.unwrap_or(ml.list(&host).await.unwrap_or_default());
                apps.iter().find(|a| a.eq_ignore_ascii_case("desktop")).cloned().or_else(|| apps.first().cloned()).unwrap_or_else(|| "Desktop".into())
            }
        };
        entry.last_app = Some(app.clone());
        self.cfg.save(config_path)?;
        self.emit(Event::Streaming(app.clone()));
        let mut args = self.cfg.stream_args.clone();
        args.extend_from_slice(extra_stream_args);
        ml.stream(&host, &app, &args).await
    }

    /// Native pairing with this crate's own identity (no Moonlight needed);
    /// used to validate the protocol implementation against a real host.
    pub async fn pair_native(&mut self, id: &str, password: Option<String>, config_path: &std::path::Path) -> Result<Vec<ra_gamestream::App>> {
        let resolved = self.resolve(id).await?;
        let h1 = self.h1_for(id, &resolved.info.password_salt, password)?;
        let gs = self.gs.clone();
        let addr = resolved.addr.clone();
        let cert = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let cert2 = cert.clone();
        self.pair_with(id, &h1, true, |pin| async move {
            let out = ra_gamestream::pairing::pair(&gs, &addr, &pin, None, Some(Duration::from_secs(120))).await?;
            *cert2.lock().await = Some(out.server_cert_pem);
            Ok(())
        })
        .await?;
        let pem = cert.lock().await.clone().ok_or_else(|| anyhow!("pairing finished without a server certificate"))?;
        let entry = self.cfg.hosts.entry(id.into()).or_default();
        entry.name = resolved.info.name.clone();
        entry.server_cert_pem = Some(pem.clone());
        entry.password_h1 = Some(h1);
        entry.password_salt = Some(resolved.info.password_salt.clone());
        self.cfg.save(config_path)?;
        Ok(self.gs.app_list(&resolved.addr, &pem).await?)
    }

    pub async fn apps_native(&self, id: &str) -> Result<Vec<ra_gamestream::App>> {
        let pem = self
            .cfg
            .hosts
            .get(id)
            .and_then(|h| h.server_cert_pem.clone())
            .ok_or_else(|| anyhow!("not natively paired with {id}; run `ra pair {id} --native`"))?;
        let resolved = self.resolve(id).await?;
        Ok(self.gs.app_list(&resolved.addr, &pem).await?)
    }

    fn h1_for(&self, id: &str, salt: &str, password: Option<String>) -> Result<String> {
        if let Some(p) = password {
            return Ok(password_h1(&p, salt));
        }
        if let Some(RememberedHost { password_h1: Some(h1), password_salt: Some(s), .. }) = self.cfg.hosts.get(id) {
            if s == salt {
                return Ok(h1.clone());
            }
        }
        let p = rpassword::prompt_password(format!("Password for {id}: "))?;
        Ok(password_h1(&p, salt))
    }
}
