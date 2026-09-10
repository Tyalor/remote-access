use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Apollo permission bits (apollo/src/crypto.h).
#[allow(dead_code)]
pub mod perm {
    pub const INPUT_CONTROLLER: u32 = 0x0000_0100;
    pub const INPUT_TOUCH: u32 = 0x0000_0200;
    pub const INPUT_PEN: u32 = 0x0000_0400;
    pub const INPUT_MOUSE: u32 = 0x0000_0800;
    pub const INPUT_KBD: u32 = 0x0000_1000;
    pub const ALL_INPUTS: u32 = 0x0000_1F00;
    pub const CLIPBOARD_SET: u32 = 0x0001_0000;
    pub const CLIPBOARD_READ: u32 = 0x0002_0000;
    pub const FILE_UPLOAD: u32 = 0x0004_0000;
    pub const FILE_DOWNLOAD: u32 = 0x0008_0000;
    pub const SERVER_CMD: u32 = 0x0010_0000;
    pub const LIST: u32 = 0x0100_0000;
    pub const VIEW: u32 = 0x0200_0000;
    pub const LAUNCH: u32 = 0x0400_0000;
    pub const ALL_ACTIONS: u32 = 0x0700_0000;
    pub const ALL: u32 = 0x071F_1F00;
    /// Full control minus server commands: what a RustDesk-style "control
    /// this desktop" session expects.
    pub const CONTROL: u32 = ALL_ACTIONS | ALL_INPUTS | CLIPBOARD_SET | CLIPBOARD_READ;
    /// View-only.
    pub const VIEW_ONLY: u32 = LIST | VIEW;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Base URL of the rendezvous server, e.g. `https://rv.example.com`.
    pub rendezvous_url: String,
    /// Assigned 9-digit ID (filled in after first registration).
    #[serde(default)]
    pub id: Option<String>,
    /// Secret proving ownership of `id` at the rendezvous server.
    pub token: String,
    /// Friendly name shown to clients.
    pub name: String,
    /// Salted password hash `h1 = SHA256(password || salt)`, hex.
    #[serde(default)]
    pub password_h1: Option<String>,
    pub password_salt: String,
    /// Apollo web UI, default `https://127.0.0.1:47990`.
    pub apollo_url: String,
    pub apollo_username: String,
    pub apollo_password: String,
    /// Apollo base port advertised to clients (HTTP GameStream port).
    pub gamestream_port: u16,
    /// Permission bitmask granted to freshly paired clients.
    pub client_permissions: u32,
    /// Extra endpoints to advertise (e.g. a DDNS name or Tailscale IP).
    #[serde(default)]
    pub extra_endpoints: Vec<ra_proto::Endpoint>,
    /// Advertise the address the rendezvous server sees us from.
    #[serde(default = "default_true")]
    pub advertise_public_ip: bool,
    /// Advertise LAN interface addresses.
    #[serde(default = "default_true")]
    pub advertise_lan_ips: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn default_path() -> PathBuf {
        if let Some(p) = std::env::var_os("RA_HOST_CONFIG") {
            return PathBuf::from(p);
        }
        directories::ProjectDirs::from("dev", "remote-access", "ra-host")
            .map(|d| d.config_dir().join("host.toml"))
            .unwrap_or_else(|| PathBuf::from("host.toml"))
    }

    pub fn load(path: &Path) -> Result<Self> {
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

    pub fn new_default(rendezvous_url: String, apollo_username: String, apollo_password: String) -> Self {
        Self {
            rendezvous_url,
            id: None,
            token: ra_proto::random_hex(32),
            name: hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "Apollo Host".into()),
            password_h1: None,
            password_salt: ra_proto::random_salt(16),
            apollo_url: "https://127.0.0.1:47990".into(),
            apollo_username,
            apollo_password,
            gamestream_port: ra_proto::DEFAULT_GAMESTREAM_PORT,
            client_permissions: perm::CONTROL,
            extra_endpoints: vec![],
            advertise_public_ip: true,
            advertise_lan_ips: true,
        }
    }

    pub fn set_password(&mut self, password: &str) {
        self.password_salt = ra_proto::random_salt(16);
        self.password_h1 = Some(ra_proto::password_h1(password, &self.password_salt));
    }
}
