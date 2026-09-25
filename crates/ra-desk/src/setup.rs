//! First-run wizard for turning this machine into a host, without a
//! terminal: find Apollo, check its web credentials, choose a password,
//! register, done.

use anyhow::{Context, Result};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApolloProbe {
    Unknown,
    Checking,
    /// Web UI answered; `first_run` means it still wants /welcome credentials.
    Found { first_run: bool },
    NotFound(String),
}

#[derive(Clone)]
pub struct Wizard {
    pub rendezvous_url: String,
    pub apollo_url: String,
    pub apollo_username: String,
    pub apollo_password: String,
    pub host_name: String,
    pub access_password: String,
    pub show_access_password: bool,
    pub probe: ApolloProbe,
    pub creds_ok: Option<Result<String, String>>,
    pub error: Option<String>,
    pub busy: bool,
}

impl Wizard {
    pub fn new(rendezvous_url: String) -> Self {
        Self {
            rendezvous_url,
            apollo_url: "https://127.0.0.1:47990".into(),
            apollo_username: String::new(),
            apollo_password: String::new(),
            host_name: hostname::get().ok().and_then(|h| h.into_string().ok()).map(|h| h.trim_end_matches(".local").to_string()).unwrap_or_else(|| "My PC".into()),
            access_password: ra_host::config::random_password(),
            show_access_password: true,
            probe: ApolloProbe::Unknown,
            creds_ok: None,
            error: None,
            busy: false,
        }
    }
}

/// Is Apollo's web UI answering? `/api/configLocale` needs no auth.
pub async fn probe_apollo(url: &str) -> ApolloProbe {
    let http = match reqwest::Client::builder().danger_accept_invalid_certs(true).timeout(std::time::Duration::from_secs(4)).build() {
        Ok(c) => c,
        Err(e) => return ApolloProbe::NotFound(e.to_string()),
    };
    let base = url.trim_end_matches('/');
    match http.get(format!("{base}/api/configLocale")).send().await {
        Ok(r) if r.status().is_success() => {
            // Apollo redirects to /welcome while no username is set.
            let first_run = match http.get(format!("{base}/")).send().await {
                Ok(r) => r.url().path().starts_with("/welcome"),
                Err(_) => false,
            };
            ApolloProbe::Found { first_run }
        }
        Ok(r) => ApolloProbe::NotFound(format!("web UI answered {}", r.status())),
        Err(e) => ApolloProbe::NotFound(if e.is_connect() { "nothing is listening; is Apollo installed and running?".into() } else { e.to_string() }),
    }
}

/// Check the web UI credentials by fetching /api/config; returns the host name Apollo reports.
pub async fn test_creds(url: &str, user: &str, pass: &str) -> Result<String> {
    let apollo = ra_host::apollo::Apollo::new(url, user, pass)?;
    let cfg = apollo.config().await.context("Apollo login")?;
    Ok(cfg.get("sunshine_name").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

/// Write the host config and register it. Returns the assigned ID.
pub async fn finish(w: Wizard, config_path: &Path) -> Result<String> {
    let mut cfg = ra_host::Config::new_default(w.rendezvous_url.clone(), w.apollo_username.clone(), w.apollo_password.clone());
    cfg.apollo_url = w.apollo_url.clone();
    cfg.name = if w.host_name.trim().is_empty() { cfg.name } else { w.host_name.trim().chars().take(64).collect() };
    cfg.set_password(&w.access_password);
    cfg.password_display = Some(w.access_password.clone());
    cfg.save(config_path)?;
    let mut agent = ra_host::Agent::new(cfg)?;
    let reg = agent.register(config_path).await.context("registering with the rendezvous server")?;
    Ok(reg.id)
}
