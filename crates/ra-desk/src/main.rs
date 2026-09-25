//! `ra-desk`: one app that is both the host and the client, like RustDesk.
//!
//! * Left, "Your Desktop": this machine's 9-digit ID and access password.
//!   The host agent runs inside this process (or as a background service
//!   installed with one click), so nobody has to open a terminal.
//! * Right, "Control Remote Desktop": ID + password → Connect. Pairing goes
//!   through the rendezvous server; the video is the stock Moonlight window.
//! * `ra-desk --headless` runs only the host agent (used by "start with system").

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod agent_runner;
mod autostart;
mod setup;

use agent_runner::{AgentRunner, AgentState};
use eframe::egui;
use ra_client::session::Event;
use ra_client::{ClientConfig, Prepared, Session};
use setup::{ApolloProbe, Wizard};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RED: egui::Color32 = egui::Color32::from_rgb(231, 76, 60);
const GREEN: egui::Color32 = egui::Color32::from_rgb(46, 204, 113);

enum Msg {
    Event(Event),
    Prepared(Prepared),
    StreamEnded(String),
    HostOnline(Option<bool>),
    Error(String),
    Log(String),
    Probe(ApolloProbe),
    Creds(Result<String, String>),
    SetupDone(Result<String, String>),
    PasswordChanged(Result<(), String>),
}

struct Desk {
    cfg: ClientConfig,
    cfg_path: PathBuf,
    host_cfg_path: PathBuf,
    host_cfg: Option<ra_host::Config>,
    host_online: Option<bool>,
    agent: AgentRunner,
    autostart: bool,
    wizard: Option<Wizard>,
    show_host_password: bool,
    remote_id: String,
    remote_password: String,
    remote_app: String,
    remember: bool,
    busy: bool,
    need_password: bool,
    log: Vec<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    rt: Arc<tokio::runtime::Runtime>,
    stream: Option<Arc<Mutex<Option<tokio::process::Child>>>>,
    current: Option<Prepared>,
    moonlight_found: Option<PathBuf>,
    last_host_poll: f64,
    settings_open: bool,
    settings_rendezvous: String,
}

impl Desk {
    fn new(_cc: &eframe::CreationContext<'_>, rt: Arc<tokio::runtime::Runtime>) -> Self {
        let cfg_path = ClientConfig::default_path();
        let cfg = ClientConfig::load_or_default(&cfg_path).unwrap_or_default();
        let (tx, rx) = channel();
        let host_cfg_path = ra_host::Config::default_path();
        let host_cfg = ra_host::Config::load(&host_cfg_path).ok();
        let mut agent = AgentRunner::new(rt.clone());
        if host_cfg.as_ref().map(|c| c.autostart_agent).unwrap_or(false) {
            let _ = agent.start(&host_cfg_path);
        } else if host_cfg.is_none() {
            *agent.state.lock().unwrap() = AgentState::NotConfigured;
        }
        let moonlight_found = ra_client::moonlight::find_moonlight(cfg.moonlight_path.as_deref());
        let remote_id = cfg.hosts.keys().next_back().cloned().unwrap_or_default();
        let remote_app = cfg.hosts.get(&remote_id).and_then(|h| h.last_app.clone()).unwrap_or_else(|| "Desktop".into());
        let settings_rendezvous = cfg.rendezvous_url.clone();
        Self {
            cfg,
            cfg_path,
            host_cfg_path,
            host_cfg,
            host_online: None,
            agent,
            autostart: autostart::is_installed(),
            wizard: None,
            show_host_password: true,
            remote_id,
            remote_password: String::new(),
            remote_app,
            remember: true,
            busy: false,
            need_password: false,
            log: vec![],
            tx,
            rx,
            rt,
            stream: None,
            current: None,
            moonlight_found,
            last_host_poll: -1e9,
            settings_open: false,
            settings_rendezvous,
        }
    }

    fn push_log(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 200 {
            self.log.drain(..100);
        }
    }

    // ----- client side -------------------------------------------------

    fn start_connect(&mut self) {
        let id = match Session::normalize_id(&self.remote_id) {
            Ok(id) => id,
            Err(e) => {
                self.push_log(format!("✗ {e}"));
                return;
            }
        };
        self.busy = true;
        self.need_password = false;
        self.log.clear();
        let tx = self.tx.clone();
        let cfg = self.cfg.clone();
        let cfg_path = self.cfg_path.clone();
        let password = if self.remote_password.is_empty() { None } else { Some(self.remote_password.clone()) };
        let app = if self.remote_app.trim().is_empty() { None } else { Some(self.remote_app.trim().to_string()) };
        let remember = self.remember;
        self.rt.spawn(async move {
            let mut session = match Session::new(cfg) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Msg::Error(format!("{e:#}")));
                    return;
                }
            };
            session.interactive = false;
            let tx2 = tx.clone();
            session.on_event = Box::new(move |e| {
                let _ = tx2.send(Msg::Event(e));
            });
            match session.prepare(&id, password, app, remember, &cfg_path).await {
                Ok(p) => {
                    let _ = tx.send(Msg::Prepared(p));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Error(format!("{e:#}")));
                }
            }
        });
    }

    fn start_stream(&mut self, p: Prepared) {
        let ml = match Session::new(self.cfg.clone()).and_then(|s| s.moonlight()) {
            Ok(m) => m,
            Err(e) => {
                self.push_log(format!("✗ {e:#}"));
                self.busy = false;
                return;
            }
        };
        let extra = self.cfg.stream_args.clone();
        let _guard = self.rt.enter();
        match ml.spawn_stream(&p.host, &p.app, &extra) {
            Ok(child) => {
                let slot = Arc::new(Mutex::new(Some(child)));
                self.stream = Some(slot.clone());
                let tx = self.tx.clone();
                self.rt.spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let mut guard = slot.lock().unwrap();
                        match guard.as_mut() {
                            Some(c) => match c.try_wait() {
                                Ok(Some(status)) => {
                                    *guard = None;
                                    let _ = tx.send(Msg::StreamEnded(format!("stream ended ({status})")));
                                    break;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    *guard = None;
                                    let _ = tx.send(Msg::StreamEnded(format!("wait failed: {e}")));
                                    break;
                                }
                            },
                            None => break,
                        }
                    }
                });
                self.push_log(format!("▶ streaming \"{}\" from {}", p.app, p.host));
                self.current = Some(p);
            }
            Err(e) => {
                self.push_log(format!("✗ {e:#}"));
                self.busy = false;
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(slot) = self.stream.take() {
            let _guard = self.rt.enter();
            if let Some(mut c) = slot.lock().unwrap().take() {
                let _ = c.start_kill();
            }
        }
        self.current = None;
        self.busy = false;
        self.push_log("■ disconnected");
    }

    fn quit_remote_app(&mut self) {
        let Some(p) = self.current.clone() else { return };
        let tx = self.tx.clone();
        let cfg = self.cfg.clone();
        self.rt.spawn(async move {
            let r = match Session::new(cfg).and_then(|s| s.moonlight()) {
                Ok(ml) => ml.quit(&p.host).await.map(|_| "✓ asked host to quit the running app".to_string()),
                Err(e) => Err(e),
            };
            let _ = tx.send(Msg::Log(r.unwrap_or_else(|e| format!("✗ {e:#}"))));
        });
    }

    // ----- host side ---------------------------------------------------

    fn poll_host_online(&mut self, now: f64) {
        if now - self.last_host_poll < 10.0 {
            return;
        }
        self.last_host_poll = now;
        let Some(id) = self.host_cfg.as_ref().and_then(|c| c.id.clone()) else { return };
        let rv = self.host_cfg.as_ref().map(|c| c.rendezvous_url.clone()).unwrap_or_default();
        let url = format!("{}/v1/hosts/{id}", rv.trim_end_matches('/'));
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let r = reqwest::Client::new().get(url).timeout(Duration::from_secs(5)).send().await;
            let online = match r {
                Ok(resp) if resp.status().is_success() => resp.json::<ra_proto::HostInfo>().await.ok().map(|h| h.online),
                _ => None,
            };
            let _ = tx.send(Msg::HostOnline(online));
        });
    }

    fn regenerate_password(&mut self) {
        let Some(mut cfg) = self.host_cfg.clone() else { return };
        let pw = cfg.set_random_password();
        self.apply_host_cfg(cfg, format!("✓ new access password: {pw}"));
    }

    fn set_custom_password(&mut self, pw: String, display: bool) {
        let Some(mut cfg) = self.host_cfg.clone() else { return };
        cfg.set_password(&pw);
        cfg.password_display = if display { Some(pw) } else { None };
        self.apply_host_cfg(cfg, "✓ access password changed".into());
    }

    /// Save, re-register (salt changed) and restart the in-process agent.
    fn apply_host_cfg(&mut self, cfg: ra_host::Config, ok_msg: String) {
        if let Err(e) = cfg.save(&self.host_cfg_path) {
            self.push_log(format!("✗ {e:#}"));
            return;
        }
        self.host_cfg = Some(cfg.clone());
        let path = self.host_cfg_path.clone();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let r = async {
                let mut agent = ra_host::Agent::new(cfg)?;
                agent.register(&path).await.map(|_| ())
            }
            .await;
            let _ = tx.send(Msg::PasswordChanged(r.map_err(|e| format!("{e:#}"))));
        });
        if matches!(self.agent.state(), AgentState::Running | AgentState::Failed(_)) {
            let _ = self.agent.restart(&self.host_cfg_path);
        }
        self.push_log(ok_msg);
    }

    fn toggle_autostart(&mut self, on: bool) {
        let r = if on { autostart::install() } else { autostart::uninstall() };
        match r {
            Ok(()) => {
                self.autostart = on;
                if on {
                    // The service now owns the agent; release ours so the lock passes over.
                    self.agent.stop();
                    self.push_log("✓ background service installed; it will keep this PC reachable after a reboot");
                } else {
                    let _ = self.agent.start(&self.host_cfg_path);
                    self.push_log("✓ background service removed; agent runs while this window is open");
                }
            }
            Err(e) => self.push_log(format!("✗ autostart: {e:#}")),
        }
    }

    // ----- wizard ------------------------------------------------------

    fn wizard_probe(&mut self) {
        let Some(w) = self.wizard.as_mut() else { return };
        w.probe = ApolloProbe::Checking;
        let url = w.apollo_url.clone();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let _ = tx.send(Msg::Probe(setup::probe_apollo(&url).await));
        });
    }

    fn wizard_test_creds(&mut self) {
        let Some(w) = self.wizard.as_mut() else { return };
        w.busy = true;
        let (u, user, pass) = (w.apollo_url.clone(), w.apollo_username.clone(), w.apollo_password.clone());
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let _ = tx.send(Msg::Creds(setup::test_creds(&u, &user, &pass).await.map_err(|e| format!("{e:#}"))));
        });
    }

    fn wizard_finish(&mut self) {
        let Some(w) = self.wizard.as_mut() else { return };
        w.busy = true;
        w.error = None;
        let w2 = w.clone();
        let path = self.host_cfg_path.clone();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let _ = tx.send(Msg::SetupDone(setup::finish(w2, &path).await.map_err(|e| format!("{e:#}"))));
        });
    }

    // ----- message pump ------------------------------------------------

    fn drain(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Event(e) => {
                    let line = match e {
                        Event::Resolving(id) => format!("→ looking up {}", ra_host::pretty_id(&id)),
                        Event::Probing(ep) => format!("  probing {}:{} ({})", ep.host, ep.port, ep.kind),
                        Event::Reachable(ep) => format!("✓ reachable at {}:{} ({})", ep.host, ep.port, ep.kind),
                        Event::AlreadyPaired => "✓ already paired".into(),
                        Event::PairingStarted => "→ pairing… (host is checking the password)".into(),
                        Event::PairAccepted => "✓ password accepted".into(),
                        Event::Paired => "✓ paired".into(),
                        Event::Streaming(a) => format!("→ streaming {a}"),
                        Event::Info(s) => s,
                    };
                    self.push_log(line);
                }
                Msg::Prepared(p) => {
                    self.remote_password.clear();
                    self.remote_app = p.app.clone();
                    if let Ok(c) = ClientConfig::load_or_default(&self.cfg_path) {
                        self.cfg = c;
                    }
                    self.start_stream(p);
                }
                Msg::StreamEnded(s) => {
                    self.push_log(s);
                    self.stream = None;
                    self.current = None;
                    self.busy = false;
                }
                Msg::HostOnline(o) => self.host_online = o,
                Msg::Error(e) => {
                    if e.contains("password required") {
                        self.need_password = true;
                        self.push_log("this host needs a password — enter it and press Connect again");
                    } else if e.contains("wrong password") {
                        self.need_password = true;
                        self.push_log("✗ wrong password");
                    } else {
                        self.push_log(format!("✗ {e}"));
                    }
                    self.busy = false;
                }
                Msg::Log(s) => self.push_log(s),
                Msg::Probe(p) => {
                    if let Some(w) = self.wizard.as_mut() {
                        w.probe = p;
                    }
                }
                Msg::Creds(r) => {
                    if let Some(w) = self.wizard.as_mut() {
                        w.busy = false;
                        if let Ok(name) = &r {
                            if !name.is_empty() && w.host_name.is_empty() {
                                w.host_name = name.clone();
                            }
                        }
                        w.creds_ok = Some(r);
                    }
                }
                Msg::SetupDone(r) => match r {
                    Ok(id) => {
                        self.wizard = None;
                        self.host_cfg = ra_host::Config::load(&self.host_cfg_path).ok();
                        let _ = self.agent.start(&self.host_cfg_path);
                        self.last_host_poll = -1e9;
                        self.push_log(format!("✓ this PC is now reachable as {}", ra_host::pretty_id(&id)));
                    }
                    Err(e) => {
                        if let Some(w) = self.wizard.as_mut() {
                            w.busy = false;
                            w.error = Some(e);
                        }
                    }
                },
                Msg::PasswordChanged(r) => {
                    if let Err(e) = r {
                        self.push_log(format!("✗ saved locally, but the rendezvous server could not be updated: {e}"));
                    }
                }
            }
        }
    }

    // ----- UI ----------------------------------------------------------

    fn ui_your_desktop(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Your Desktop");
        ui.label(egui::RichText::new("Share the ID and password to let someone control this PC.").weak());
        ui.add_space(12.0);

        let Some(cfg) = self.host_cfg.clone() else {
            ui.label("This PC is not set up as a host yet.");
            ui.add_space(8.0);
            if ui.add(egui::Button::new(egui::RichText::new("Set up this PC as a host").size(15.0)).min_size([260.0, 34.0].into())).clicked() {
                self.wizard = Some(Wizard::new(self.cfg.rendezvous_url.clone()));
                self.wizard_probe();
            }
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Needs Apollo installed on this PC. Takes about a minute.").weak().small());
            return;
        };

        ui.label("ID");
        ui.horizontal(|ui| {
            match &cfg.id {
                Some(id) => {
                    ui.label(egui::RichText::new(ra_host::pretty_id(id)).size(30.0).strong().monospace());
                    if ui.small_button("copy").clicked() {
                        if let Ok(mut cb) = arboard::Clipboard::new() {
                            let _ = cb.set_text(id.clone());
                        }
                    }
                }
                None => {
                    ui.label(egui::RichText::new("not registered").size(20.0));
                }
            }
        });

        let (col, txt) = match (self.agent.state(), self.host_online) {
            (AgentState::NotConfigured, _) => (egui::Color32::GRAY, "not configured".to_string()),
            (AgentState::Failed(e), _) => (RED, format!("agent error: {e}")),
            (AgentState::Stopped, Some(true)) => (GREEN, "Online (background service)".into()),
            (AgentState::Stopped, _) => (RED, "Stopped".into()),
            (AgentState::RunningElsewhere, Some(true)) => (GREEN, "Online (background service)".into()),
            (AgentState::RunningElsewhere, _) => (egui::Color32::GOLD, "background service running, waiting for rendezvous…".into()),
            (AgentState::Running, Some(true)) => (GREEN, "Online".into()),
            (AgentState::Running, Some(false)) => (egui::Color32::GOLD, "registering…".into()),
            (AgentState::Running, None) => (egui::Color32::GOLD, "connecting to rendezvous…".into()),
        };
        ui.horizontal(|ui| {
            ui.colored_label(col, "●");
            ui.label(txt);
        });

        ui.add_space(12.0);
        ui.label("Password");
        ui.horizontal(|ui| {
            match (&cfg.password_display, self.show_host_password) {
                (Some(pw), true) => {
                    ui.label(egui::RichText::new(pw).size(22.0).strong().monospace());
                }
                (Some(_), false) => {
                    ui.label(egui::RichText::new("••••••••").size(22.0).monospace());
                }
                (None, _) => {
                    ui.label(egui::RichText::new("custom (hidden)").monospace());
                }
            }
            if cfg.password_display.is_some() && ui.small_button(if self.show_host_password { "hide" } else { "show" }).clicked() {
                self.show_host_password = !self.show_host_password;
            }
            if ui.small_button("⟳ new").on_hover_text("Generate a new random password").clicked() {
                self.regenerate_password();
            }
            if let Some(pw) = &cfg.password_display {
                if ui.small_button("copy").clicked() {
                    if let Ok(mut cb) = arboard::Clipboard::new() {
                        let _ = cb.set_text(pw.clone());
                    }
                }
            }
        });
        ui.collapsing("Set my own password", |ui| {
            let id = ui.make_persistent_id("custom_pw");
            let mut pw: String = ui.data_mut(|d| d.get_temp(id).unwrap_or_default());
            ui.add(egui::TextEdit::singleline(&mut pw).password(true).hint_text("at least 6 characters"));
            ui.data_mut(|d| d.insert_temp(id, pw.clone()));
            ui.horizontal(|ui| {
                if ui.button("Save & show").clicked() && pw.len() >= 6 {
                    self.set_custom_password(pw.clone(), true);
                    ui.data_mut(|d| d.insert_temp(id, String::new()));
                }
                if ui.button("Save hidden").clicked() && pw.len() >= 6 {
                    self.set_custom_password(pw.clone(), false);
                    ui.data_mut(|d| d.insert_temp(id, String::new()));
                }
            });
        });

        ui.add_space(14.0);
        let mut auto = self.autostart;
        if ui.checkbox(&mut auto, "Start with system (stay reachable after reboot)").changed() {
            self.toggle_autostart(auto);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            match self.agent.state() {
                AgentState::Running => {
                    if ui.small_button("Stop sharing").clicked() {
                        self.agent.stop();
                    }
                }
                AgentState::Stopped | AgentState::Failed(_) => {
                    if ui.small_button("Start sharing").clicked() {
                        let _ = self.agent.start(&self.host_cfg_path);
                    }
                }
                _ => {}
            }
            if ui.small_button("Re-run setup").clicked() {
                self.wizard = Some(Wizard::new(cfg.rendezvous_url.clone()));
                if let Some(w) = self.wizard.as_mut() {
                    w.apollo_url = cfg.apollo_url.clone();
                    w.apollo_username = cfg.apollo_username.clone();
                    w.apollo_password = cfg.apollo_password.clone();
                    w.host_name = cfg.name.clone();
                }
                self.wizard_probe();
            }
        });
        ui.label(egui::RichText::new(format!("{} · {}", cfg.name, cfg.rendezvous_url)).weak().small());
    }

    fn ui_wizard(&mut self, ctx: &egui::Context) {
        let Some(mut w) = self.wizard.clone() else { return };
        let mut close = false;
        let mut action: Option<&str> = None;
        egui::Window::new("Set up this PC as a host")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(520.0);
                ui.label(egui::RichText::new("1. Apollo").strong());
                ui.horizontal(|ui| {
                    ui.label("Web UI");
                    if ui.add(egui::TextEdit::singleline(&mut w.apollo_url).desired_width(260.0)).lost_focus() {
                        action = Some("probe");
                    }
                    if ui.small_button("check").clicked() {
                        action = Some("probe");
                    }
                });
                match &w.probe {
                    ApolloProbe::Unknown => {}
                    ApolloProbe::Checking => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("looking for Apollo…");
                        });
                    }
                    ApolloProbe::Found { first_run: false } => {
                        ui.colored_label(GREEN, "✓ Apollo is running");
                    }
                    ApolloProbe::Found { first_run: true } => {
                        ui.colored_label(egui::Color32::GOLD, "Apollo is running but has no web credentials yet — open its web UI once to create them, then continue.");
                        if ui.link("Open Apollo web UI").clicked() {
                            let _ = open_url(&w.apollo_url);
                        }
                    }
                    ApolloProbe::NotFound(e) => {
                        ui.colored_label(RED, format!("✗ {e}"));
                        if ui.link("Download Apollo").clicked() {
                            let _ = open_url("https://github.com/ClassicOldSong/Apollo/releases");
                        }
                    }
                }
                ui.add_space(6.0);
                egui::Grid::new("wiz_creds").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Username");
                    ui.add(egui::TextEdit::singleline(&mut w.apollo_username).desired_width(260.0));
                    ui.end_row();
                    ui.label("Password");
                    ui.add(egui::TextEdit::singleline(&mut w.apollo_password).password(true).desired_width(260.0));
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(!w.busy && !w.apollo_username.is_empty(), egui::Button::new("Test login")).clicked() {
                        action = Some("creds");
                    }
                    match &w.creds_ok {
                        Some(Ok(name)) => {
                            ui.colored_label(GREEN, format!("✓ logged in{}", if name.is_empty() { String::new() } else { format!(" to {name}") }));
                        }
                        Some(Err(e)) => {
                            ui.colored_label(RED, format!("✗ {e}"));
                        }
                        None => {}
                    }
                });
                ui.label(egui::RichText::new("These are Apollo's own web UI credentials. Note: Apollo keeps one web session, so the agent will log your browser out when it needs the API.").weak().small());

                ui.add_space(12.0);
                ui.label(egui::RichText::new("2. This PC").strong());
                egui::Grid::new("wiz_pc").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut w.host_name).desired_width(260.0));
                    ui.end_row();
                    ui.label("Access password");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut w.access_password).password(!w.show_access_password).desired_width(180.0));
                        if ui.small_button(if w.show_access_password { "hide" } else { "show" }).clicked() {
                            w.show_access_password = !w.show_access_password;
                        }
                        if ui.small_button("⟳").clicked() {
                            w.access_password = ra_host::config::random_password();
                        }
                    });
                    ui.end_row();
                    ui.label("Rendezvous");
                    ui.add(egui::TextEdit::singleline(&mut w.rendezvous_url).desired_width(260.0));
                    ui.end_row();
                });
                ui.label(egui::RichText::new("People who know the ID and this password can control this PC.").weak().small());

                if let Some(e) = &w.error {
                    ui.add_space(6.0);
                    ui.colored_label(RED, e);
                }
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let ready = !w.busy && w.access_password.len() >= 6 && !w.apollo_username.is_empty() && !w.rendezvous_url.is_empty();
                    if ui.add_enabled(ready, egui::Button::new(egui::RichText::new("Finish").size(15.0)).min_size([120.0, 32.0].into())).clicked() {
                        action = Some("finish");
                    }
                    if w.busy {
                        ui.spinner();
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        self.wizard = Some(w);
        if close {
            self.wizard = None;
            return;
        }
        match action {
            Some("probe") => self.wizard_probe(),
            Some("creds") => self.wizard_test_creds(),
            Some("finish") => self.wizard_finish(),
            _ => {}
        }
    }

    fn ui_session(&mut self, ui: &mut egui::Ui, p: Prepared) {
        ui.heading(format!("Connected to {} ({})", p.resolved.info.name, ra_host::pretty_id(&p.id)));
        ui.label(format!("Streaming \"{}\" — Moonlight window is open", p.app));
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button("■ Disconnect").clicked() {
                self.disconnect();
            }
            if ui.button("⏻ Quit app on host").clicked() {
                self.quit_remote_app();
            }
        });
        if !p.apps.is_empty() {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Switch app").strong());
            ui.horizontal_wrapped(|ui| {
                for a in &p.apps {
                    if ui.add_enabled(*a != p.app, egui::Button::new(a)).clicked() {
                        self.remote_app = a.clone();
                        self.disconnect();
                        self.remote_id = p.id.clone();
                        self.start_connect();
                    }
                }
            });
        }
        ui.add_space(12.0);
        ui.collapsing("Keyboard shortcuts inside the stream", |ui| {
            egui::Grid::new("hotkeys").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                for (k, v) in [
                    ("Ctrl+Alt+Shift+Q", "Quit stream"),
                    ("Ctrl+Alt+Shift+X", "Toggle fullscreen"),
                    ("Ctrl+Alt+Shift+S", "Toggle stats overlay"),
                    ("Ctrl+Alt+Shift+M", "Toggle mouse mode"),
                    ("Ctrl+Alt+Shift+V", "Type clipboard text into host"),
                    ("Ctrl+Alt+Shift+Z", "Release keyboard/mouse grab"),
                    ("Ctrl+Alt+Shift+K", "Toggle system key capture"),
                ] {
                    ui.monospace(k);
                    ui.label(v);
                    ui.end_row();
                }
            });
        });
    }

    fn ui_connect(&mut self, ui: &mut egui::Ui) {
        ui.heading("Control Remote Desktop");
        ui.label(egui::RichText::new("Enter the ID shown on the other PC.").weak());
        ui.add_space(12.0);
        egui::Grid::new("connect").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            ui.label("Remote ID");
            let r = ui.add(egui::TextEdit::singleline(&mut self.remote_id).hint_text("123 456 789").desired_width(240.0).font(egui::TextStyle::Heading));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !self.busy {
                self.start_connect();
            }
            ui.end_row();
            ui.label("Password");
            let r = ui.add(egui::TextEdit::singleline(&mut self.remote_password).password(true).hint_text(if self.need_password { "required" } else { "only needed the first time" }).desired_width(240.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !self.busy {
                self.start_connect();
            }
            ui.end_row();
            ui.label("App");
            ui.add(egui::TextEdit::singleline(&mut self.remote_app).hint_text("Desktop").desired_width(240.0));
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut self.remember, "Remember password on this device");
            ui.end_row();
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let can = !self.busy && self.moonlight_found.is_some();
            if ui.add_enabled(can, egui::Button::new(egui::RichText::new("Connect").size(18.0)).min_size([140.0, 36.0].into())).clicked() {
                self.start_connect();
            }
            if self.busy {
                ui.spinner();
                ui.label("working…");
            }
        });
        if self.moonlight_found.is_none() {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.colored_label(RED, "Moonlight is not installed —");
                if ui.link("download it").clicked() {
                    let _ = open_url("https://github.com/moonlight-stream/moonlight-qt/releases");
                }
                if ui.small_button("re-check").clicked() {
                    self.moonlight_found = ra_client::moonlight::find_moonlight(self.cfg.moonlight_path.as_deref());
                }
            });
        }

        if !self.cfg.hosts.is_empty() {
            ui.add_space(20.0);
            ui.label(egui::RichText::new("Recent").strong());
            let hosts: Vec<(String, String, Option<String>, bool)> = self
                .cfg
                .hosts
                .iter()
                .map(|(id, h)| (id.clone(), h.name.clone(), h.last_app.clone(), h.password_h1.is_some()))
                .collect();
            let mut forget: Option<String> = None;
            let mut connect: Option<(String, Option<String>)> = None;
            ui.horizontal_wrapped(|ui| {
                for (id, name, app, remembered) in hosts {
                    let card = egui::Frame::group(ui.style()).inner_margin(8.0).show(ui, |ui| {
                        ui.set_width(190.0);
                        ui.label(egui::RichText::new(if name.is_empty() { "unnamed host".into() } else { name.clone() }).strong());
                        ui.monospace(ra_host::pretty_id(&id));
                        ui.label(egui::RichText::new(format!("{}{}", app.clone().unwrap_or_else(|| "Desktop".into()), if remembered { " · password saved" } else { "" })).weak().small());
                        ui.horizontal(|ui| {
                            if ui.small_button("Connect").clicked() {
                                connect = Some((id.clone(), app.clone()));
                            }
                            if ui.small_button("forget").clicked() {
                                forget = Some(id.clone());
                            }
                        });
                    });
                    if card.response.interact(egui::Sense::click()).clicked() {
                        self.remote_id = id.clone();
                        if let Some(a) = app {
                            self.remote_app = a;
                        }
                    }
                }
            });
            if let Some(id) = forget {
                self.cfg.hosts.remove(&id);
                let _ = self.cfg.save(&self.cfg_path);
            }
            if let Some((id, app)) = connect {
                self.remote_id = id;
                if let Some(a) = app {
                    self.remote_app = a;
                }
                if !self.busy {
                    self.start_connect();
                }
            }
        }
    }

    fn ui_settings(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Settings").open(&mut open).collapsible(false).show(ctx, |ui| {
            ui.label("Rendezvous server (client side)");
            ui.add(egui::TextEdit::singleline(&mut self.settings_rendezvous).desired_width(320.0));
            ui.label("Moonlight");
            ui.label(egui::RichText::new(self.moonlight_found.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "not found (set MOONLIGHT_BIN)".into())).small());
            ui.label(egui::RichText::new(format!("client config: {}\nhost config: {}", self.cfg_path.display(), self.host_cfg_path.display())).weak().small());
            if ui.button("Save").clicked() {
                self.cfg.rendezvous_url = self.settings_rendezvous.trim().to_string();
                let _ = self.cfg.save(&self.cfg_path);
                self.push_log("✓ settings saved");
            }
        });
        self.settings_open = open;
    }
}

fn open_url(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut c = { let mut c = std::process::Command::new("open"); c.arg(url); c };
    #[cfg(target_os = "windows")]
    let mut c = { let mut c = std::process::Command::new("cmd"); c.args(["/C", "start", "", url]); c };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut c = { let mut c = std::process::Command::new("xdg-open"); c.arg(url); c };
    c.spawn().map(|_| ())
}

impl eframe::App for Desk {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.poll_host_online(ctx.input(|i| i.time));
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("remote-access");
                ui.separator();
                ui.label(egui::RichText::new("Apollo + Moonlight, RustDesk-style").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙").on_hover_text("Settings").clicked() {
                        self.settings_open = !self.settings_open;
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("log").resizable(true).default_height(120.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Activity").strong());
                if ui.small_button("clear").clicked() {
                    self.log.clear();
                }
            });
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for l in &self.log {
                    ui.monospace(l);
                }
            });
        });

        egui::SidePanel::left("your_desktop").resizable(false).exact_width(340.0).show(ctx, |ui| {
            self.ui_your_desktop(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            match self.current.clone() {
                Some(p) => self.ui_session(ui, p),
                None => self.ui_connect(ui),
            }
        });

        self.ui_wizard(ctx);
        self.ui_settings(ctx);
    }
}

fn run_headless(rt: Arc<tokio::runtime::Runtime>) -> anyhow::Result<()> {
    let path = ra_host::Config::default_path();
    let cfg = ra_host::Config::load(&path).map_err(|e| anyhow::anyhow!("no host config at {}: {e}", path.display()))?;
    let _lock = std::net::TcpListener::bind(("127.0.0.1", agent_runner::LOCK_PORT))
        .map_err(|_| anyhow::anyhow!("another host agent is already running on this machine"))?;
    if let Some(id) = &cfg.id {
        tracing::info!(id = %ra_host::pretty_id(id), "headless host agent starting");
    }
    rt.block_on(async {
        loop {
            let r = async {
                let agent = ra_host::Agent::new(cfg.clone())?;
                agent.run(&path).await
            }
            .await;
            if let Err(e) = r {
                tracing::warn!(error = %e, "agent stopped; retrying in 10s");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    })
}

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let rt = Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio"));
    if std::env::args().any(|a| a == "--headless") {
        if let Err(e) = run_headless(rt) {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([980.0, 640.0]).with_min_inner_size([780.0, 500.0]).with_title("remote-access"),
        ..Default::default()
    };
    eframe::run_native("remote-access", options, Box::new(move |cc| Ok(Box::new(Desk::new(cc, rt)))))
}
