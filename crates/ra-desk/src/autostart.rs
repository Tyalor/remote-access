//! "Start with system": run `ra-desk --headless` at login so this machine
//! is reachable without anyone opening the window. launchd on macOS,
//! systemd --user on Linux, the HKCU Run key on Windows.

use anyhow::{Context, Result};
use std::path::PathBuf;

const LABEL: &str = "dev.remote-access.host";

fn exe() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.canonicalize()?)
}

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
}

#[cfg(target_os = "macos")]
pub fn is_installed() -> bool {
    plist_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub fn install() -> Result<()> {
    let p = plist_path()?;
    std::fs::create_dir_all(p.parent().unwrap())?;
    let log = std::env::temp_dir().join("remote-access-host.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{}</string><string>--headless</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
        exe()?.display(),
        log = log.display()
    );
    std::fs::write(&p, plist)?;
    let _ = std::process::Command::new("launchctl").args(["unload", p.to_str().unwrap()]).output();
    let out = std::process::Command::new("launchctl").args(["load", "-w", p.to_str().unwrap()]).output()?;
    anyhow::ensure!(out.status.success(), "launchctl load failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    let p = plist_path()?;
    if p.exists() {
        let _ = std::process::Command::new("launchctl").args(["unload", "-w", p.to_str().unwrap()]).output();
        std::fs::remove_file(&p)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unit_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("no config dir")?;
    Ok(base.join("systemd/user").join(format!("{LABEL}.service")))
}

#[cfg(target_os = "linux")]
pub fn is_installed() -> bool {
    unit_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn install() -> Result<()> {
    let p = unit_path()?;
    std::fs::create_dir_all(p.parent().unwrap())?;
    let unit = format!(
        "[Unit]\nDescription=remote-access host agent\nAfter=network-online.target\n\n[Service]\nExecStart={} --headless\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        exe()?.display()
    );
    std::fs::write(&p, unit)?;
    let _ = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).output();
    let out = std::process::Command::new("systemctl").args(["--user", "enable", "--now", &format!("{LABEL}.service")]).output()?;
    anyhow::ensure!(out.status.success(), "systemctl enable failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<()> {
    let p = unit_path()?;
    let _ = std::process::Command::new("systemctl").args(["--user", "disable", "--now", &format!("{LABEL}.service")]).output();
    if p.exists() {
        std::fs::remove_file(&p)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(target_os = "windows")]
pub fn is_installed() -> bool {
    std::process::Command::new("reg")
        .args(["query", RUN_KEY, "/v", LABEL])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
pub fn install() -> Result<()> {
    let cmd = format!("\"{}\" --headless", exe()?.display());
    let out = std::process::Command::new("reg").args(["add", RUN_KEY, "/v", LABEL, "/t", "REG_SZ", "/d", &cmd, "/f"]).output()?;
    anyhow::ensure!(out.status.success(), "reg add failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall() -> Result<()> {
    let _ = std::process::Command::new("reg").args(["delete", RUN_KEY, "/v", LABEL, "/f"]).output();
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn is_installed() -> bool {
    false
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn install() -> Result<()> {
    anyhow::bail!("autostart is not supported on this platform")
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn uninstall() -> Result<()> {
    Ok(())
}
