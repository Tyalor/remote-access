use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RememberedHost {
    pub name: String,
    /// Cached `h1` so the password need not be retyped (opt-in).
    #[serde(default)]
    pub password_h1: Option<String>,
    #[serde(default)]
    pub password_salt: Option<String>,
    #[serde(default)]
    pub last_endpoint: Option<String>,
    #[serde(default)]
    pub last_app: Option<String>,
    /// Server certificate PEM from a native (ra-gamestream) pairing.
    #[serde(default)]
    pub server_cert_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub rendezvous_url: String,
    #[serde(default)]
    pub moonlight_path: Option<PathBuf>,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    #[serde(default)]
    pub hosts: BTreeMap<String, RememberedHost>,
    /// Extra arguments always passed to `moonlight stream`.
    #[serde(default)]
    pub stream_args: Vec<String>,
}

fn default_device_name() -> String {
    hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "remote-access client".into())
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            rendezvous_url: std::env::var("RA_RENDEZVOUS").unwrap_or_else(|_| "http://127.0.0.1:21114".into()),
            moonlight_path: None,
            device_name: default_device_name(),
            hosts: BTreeMap::new(),
            stream_args: vec![],
        }
    }
}

impl ClientConfig {
    pub fn dir() -> PathBuf {
        if let Some(p) = std::env::var_os("RA_HOME") {
            return PathBuf::from(p);
        }
        directories::ProjectDirs::from("dev", "remote-access", "ra")
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn default_path() -> PathBuf {
        Self::dir().join("client.toml")
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
