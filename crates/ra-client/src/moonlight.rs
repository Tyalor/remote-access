//! Driving the stock Moonlight Qt binary through its CLI
//! (`moonlight-qt/app/cli/commandlineparser.cpp`).

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};

pub fn find_moonlight(configured: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = configured {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    if let Some(p) = std::env::var_os("MOONLIGHT_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/Moonlight.app/Contents/MacOS/Moonlight",
            "/opt/homebrew/bin/moonlight",
            "/usr/local/bin/moonlight",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            "C:\\Program Files\\Moonlight Game Streaming\\Moonlight.exe",
            "C:\\Program Files (x86)\\Moonlight Game Streaming\\Moonlight.exe",
        ]
    } else {
        &["/usr/bin/moonlight-qt", "/usr/bin/moonlight", "/usr/local/bin/moonlight", "/var/lib/flatpak/exports/bin/com.moonlight_stream.Moonlight"]
    };
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    // PATH lookup
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            for name in ["moonlight", "moonlight-qt", "Moonlight.exe"] {
                let p = dir.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

pub struct Moonlight {
    bin: PathBuf,
}

impl Moonlight {
    pub fn new(bin: PathBuf) -> Self {
        Self { bin }
    }

    pub fn path(&self) -> &Path {
        &self.bin
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.bin);
        c.stdin(Stdio::null());
        // Quiet the Qt logging; users can raise it with QT_LOGGING_RULES.
        c.env("QT_LOGGING_RULES", std::env::var("QT_LOGGING_RULES").unwrap_or_else(|_| "*.debug=false".into()));
        c
    }

    /// `moonlight list <host>` — returns app titles, or an error if the host
    /// is unknown or not paired with this Moonlight identity.
    pub async fn list(&self, host: &str) -> Result<Vec<String>> {
        let out = self
            .cmd()
            .args(["list", host])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("running {}", self.bin.display()))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("moonlight list failed: {}", err.trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// Spawn `moonlight pair <host> --pin <pin>`; the caller waits on the child.
    pub fn spawn_pair(&self, host: &str, pin: &str) -> Result<Child> {
        self.cmd()
            .args(["pair", host, "--pin", pin])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("running {}", self.bin.display()))
    }

    /// `moonlight stream <host> "<app>" [args...]`, waiting until the stream ends.
    pub async fn stream(&self, host: &str, app: &str, extra: &[String]) -> Result<std::process::ExitStatus> {
        let mut c = self.cmd();
        c.args(["stream", host, app]).args(extra);
        let status = c.status().await.with_context(|| format!("running {}", self.bin.display()))?;
        Ok(status)
    }

    pub async fn quit(&self, host: &str) -> Result<()> {
        self.cmd().args(["quit", host]).status().await?;
        Ok(())
    }
}
