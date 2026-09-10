//! `/serverinfo` parsing. Field names follow `moonlight-qt/app/backend/nvcomputer.cpp`.

use crate::xml::Root;
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerInfo {
    pub hostname: String,
    /// Host UUID (`uniqueid` in the XML).
    pub uuid: String,
    pub app_version: String,
    pub gfe_version: String,
    pub https_port: u16,
    pub external_port: Option<u16>,
    pub local_ip: Option<String>,
    pub external_ip: Option<String>,
    pub mac: Option<String>,
    pub paired: bool,
    /// `SUNSHINE_SERVER_BUSY` / `SUNSHINE_SERVER_FREE` etc.
    pub state: String,
    pub current_game: u32,
    pub server_codec_mode_support: u32,
    /// Apollo only: permission bitmask of the calling client (HTTPS only).
    pub permission: Option<u32>,
    /// Apollo only, Windows.
    pub virtual_display_capable: Option<bool>,
}

impl ServerInfo {
    pub fn parse(body: &str) -> Result<Self> {
        let root = Root::parse(body)?;
        let get = |n: &str| root.child(n).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let num = |n: &str| get(n).and_then(|s| s.parse::<u32>().ok());
        Ok(Self {
            hostname: get("hostname").unwrap_or_default(),
            uuid: get("uniqueid").unwrap_or_default(),
            app_version: get("appversion").unwrap_or_default(),
            gfe_version: get("GfeVersion").unwrap_or_default(),
            https_port: num("HttpsPort").map(|p| p as u16).unwrap_or(crate::DEFAULT_HTTPS_PORT),
            external_port: num("ExternalPort").map(|p| p as u16),
            local_ip: get("LocalIP").filter(|ip| !ip.starts_with("127.")),
            external_ip: get("ExternalIP"),
            mac: get("mac").filter(|m| m != "00:00:00:00:00:00"),
            paired: get("PairStatus").as_deref() == Some("1"),
            state: get("state").unwrap_or_default(),
            current_game: num("currentgame").unwrap_or(0),
            server_codec_mode_support: num("ServerCodecModeSupport").unwrap_or(0),
            permission: num("Permission"),
            virtual_display_capable: get("VirtualDisplayCapable").map(|v| v == "1"),
        })
    }

    /// Major component of `appversion`; >= 7 means SHA-256 pairing.
    pub fn major_version(&self) -> u32 {
        self.app_version.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    pub fn is_busy(&self) -> bool {
        self.state.ends_with("_SERVER_BUSY")
    }

    pub fn is_sunshine_family(&self) -> bool {
        !self.state.contains("MJOLNIR")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apollo_like_serverinfo() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<root status_code="200"><hostname>Gaming-PC</hostname><appversion>7.1.431.-1</appversion>
<GfeVersion>3.23.0.74</GfeVersion><uniqueid>7f2b0c3a-1111-2222-3333-444455556666</uniqueid>
<HttpsPort>47984</HttpsPort><ExternalPort>47989</ExternalPort><MaxLumaPixelsHEVC>1869449984</MaxLumaPixelsHEVC>
<mac>00:00:00:00:00:00</mac><LocalIP>192.168.1.50</LocalIP><ServerCodecModeSupport>259</ServerCodecModeSupport>
<PairStatus>0</PairStatus><currentgame>0</currentgame><state>SUNSHINE_SERVER_FREE</state></root>"#;
        let si = ServerInfo::parse(xml).unwrap();
        assert_eq!(si.hostname, "Gaming-PC");
        assert_eq!(si.major_version(), 7);
        assert_eq!(si.https_port, 47984);
        assert_eq!(si.local_ip.as_deref(), Some("192.168.1.50"));
        assert!(si.mac.is_none());
        assert!(!si.paired);
        assert!(!si.is_busy());
        assert!(si.is_sunshine_family());
    }
}
