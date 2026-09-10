//! `ra-desk`: the RustDesk-shaped front door for Apollo + Moonlight.
//!
//! Left: "Your Desktop" — this machine's 9-digit ID and access password
//! (from the ra-host config, if this machine is a host).
//! Right: "Control Remote Desktop" — enter an ID and password, pick an app,
//! press Connect. Pairing runs through the rendezvous server; the stream is
//! the stock Moonlight window. While a stream runs, a session panel offers
//! the controls Moonlight only exposes as hotkeys.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use ra_client::session::Event;
use ra_client::{ClientConfig, Prepared, Session};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

enum Msg {
    Event(Event),
    Prepared(Prepared),
    StreamEnded(String),
    HostOnline(Option<bool>),
    Error(String),
    Log(String),
}

#[derive(Default, Clone)]
struct HostPanel {
    id: Option<String>,
    online: Option<bool>,
    config_path: PathBuf,
    has_password: bool,
    new_password: String,
    show_password_editor: bool,
    error: Option<String>,
}

struct Desk {
    cfg: ClientConfig,
    cfg_path: PathBuf,
    host: HostPanel,
    remote_id: String,
    remote_password: String,
    remote_app: String,
    remember: bool,
    busy: bool,
    log: Vec<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    rt: Arc<tokio::runtime::Runtime>,
    stream: Option<Arc<Mutex<Option<tokio::process::Child>>>>,
    current: Option<Prepared>,
    moonlight_found: Option<PathBuf>,
    last_host_poll: f64,
}

impl Desk {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_pixels_per_point(cc.egui_ctx.pixels_per_point().max(1.0));
        let cfg_path = ClientConfig::default_path();
        let cfg = ClientConfig::load_or_default(&cfg_path).unwrap_or_default();
        let (tx, rx) = channel();
        let rt = Arc::new(tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio"));
        let host_path = ra_host::Config::default_path();
        let host = match ra_host::Config::load(&host_path) {
            Ok(h) => HostPanel { id: h.id.clone(), has_password: h.password_h1.is_some(), config_path: host_path, ..Default::default() },
            Err(_) => HostPanel { config_path: host_path, ..Default::default() },
        };
        let moonlight_found = ra_client::moonlight::find_moonlight(cfg.moonlight_path.as_deref());
        let remote_id = cfg.hosts.keys().next_back().cloned().unwrap_or_default();
        let remote_app = cfg.hosts.get(&remote_id).and_then(|h| h.last_app.clone()).unwrap_or_else(|| "Desktop".into());
        Self {
            cfg,
            cfg_path,
            host,
            remote_id,
            remote_password: String::new(),
            remote_app,
            remember: true,
            busy: false,
            log: vec![],
            tx,
            rx,
            rt,
            stream: None,
            current: None,
            moonlight_found,
            last_host_poll: -1e9,
        }
    }

    fn push_log(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
        if self.log.len() > 200 {
            self.log.drain(..100);
        }
    }

    fn start_connect(&mut self) {
        let id = match Session::normalize_id(&self.remote_id) {
            Ok(id) => id,
            Err(e) => {
                self.push_log(format!("✗ {e}"));
                return;
            }
        };
        self.busy = true;
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
                let app = p.app.clone();
                self.rt.spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let mut guard = slot.lock().unwrap();
                        match guard.as_mut() {
                            Some(c) => match c.try_wait() {
                                Ok(Some(status)) => {
                                    *guard = None;
                                    let _ = tx.send(Msg::StreamEnded(format!("Moonlight exited ({status})")));
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
                self.push_log(format!("▶ streaming \"{app}\" from {}", p.host));
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
            match Session::new(cfg).and_then(|s| s.moonlight()) {
                Ok(ml) => {
                    let r = ml.quit(&p.host).await;
                    let _ = tx.send(Msg::Log(match r {
                        Ok(()) => "✓ asked host to quit the running app".into(),
                        Err(e) => format!("✗ quit failed: {e:#}"),
                    }));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Log(format!("✗ {e:#}")));
                }
            }
        });
    }

    fn poll_host_online(&mut self, now: f64) {
        if now - self.last_host_poll < 15.0 {
            return;
        }
        self.last_host_poll = now;
        let Some(id) = self.host.id.clone() else { return };
        let url = format!("{}/v1/hosts/{id}", self.cfg.rendezvous_url.trim_end_matches('/'));
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

    fn save_host_password(&mut self) {
        let pw = self.host.new_password.clone();
        if pw.len() < 6 {
            self.host.error = Some("password must be at least 6 characters".into());
            return;
        }
        let path = self.host.config_path.clone();
        match ra_host::Config::load(&path) {
            Ok(mut cfg) => {
                cfg.set_password(&pw);
                if let Err(e) = cfg.save(&path) {
                    self.host.error = Some(format!("{e:#}"));
                    return;
                }
                // Re-register so the new salt is published.
                let tx = self.tx.clone();
                self.rt.spawn(async move {
                    let r = async {
                        let mut agent = ra_host::Agent::new(cfg)?;
                        agent.register(&path).await
                    }
                    .await;
                    let _ = tx.send(Msg::Log(match r {
                        Ok(_) => "✓ access password updated (restart ra-host run to apply)".into(),
                        Err(e) => format!("✗ password saved locally but re-registration failed: {e:#}"),
                    }));
                });
                self.host.has_password = true;
                self.host.new_password.clear();
                self.host.show_password_editor = false;
                self.host.error = None;
            }
            Err(e) => self.host.error = Some(format!("no host config at {}: {e}", path.display())),
        }
    }

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
                Msg::HostOnline(o) => self.host.online = o,
                Msg::Error(e) => {
                    self.push_log(format!("✗ {e}"));
                    self.busy = false;
                }
                Msg::Log(s) => self.push_log(s),
            }
        }
    }
}

fn big_id(ui: &mut egui::Ui, id: &str) {
    ui.label(egui::RichText::new(ra_host::pretty_id(id)).size(30.0).strong().monospace());
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
                ui.label(egui::RichText::new("Apollo + Moonlight streaming, RustDesk-style access").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("rendezvous: {}", self.cfg.rendezvous_url)).weak().small());
                });
            });
        });

        egui::TopBottomPanel::bottom("log").resizable(true).default_height(140.0).show(ctx, |ui| {
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

        egui::SidePanel::left("your_desktop").resizable(false).exact_width(320.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("Your Desktop");
            ui.label(egui::RichText::new("Others can control this machine with the ID and password below.").weak());
            ui.add_space(12.0);
            match self.host.id.clone() {
                Some(id) => {
                    ui.label("ID");
                    ui.horizontal(|ui| {
                        big_id(ui, &id);
                        if ui.small_button("copy").clicked() {
                            if let Ok(mut cb) = arboard::Clipboard::new() {
                                let _ = cb.set_text(id.clone());
                            }
                        }
                    });
                    let (dot, txt) = match self.host.online {
                        Some(true) => (egui::Color32::from_rgb(46, 204, 113), "Online — host agent is registered"),
                        Some(false) => (egui::Color32::from_rgb(231, 76, 60), "Offline — start `ra-host run`"),
                        None => (egui::Color32::GRAY, "Checking…"),
                    };
                    ui.horizontal(|ui| {
                        ui.colored_label(dot, "●");
                        ui.label(txt);
                    });
                    ui.add_space(12.0);
                    ui.label("Access password");
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(if self.host.has_password { "••••••••" } else { "not set" }).monospace());
                        if ui.small_button(if self.host.show_password_editor { "cancel" } else { "change" }).clicked() {
                            self.host.show_password_editor = !self.host.show_password_editor;
                        }
                    });
                    if self.host.show_password_editor {
                        ui.add(egui::TextEdit::singleline(&mut self.host.new_password).password(true).hint_text("new password (min 6)"));
                        if ui.button("Save").clicked() {
                            self.save_host_password();
                        }
                    }
                    if let Some(e) = &self.host.error {
                        ui.colored_label(egui::Color32::from_rgb(231, 76, 60), e);
                    }
                }
                None => {
                    ui.label("This machine is not set up as a host.");
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Install Apollo, then run:").weak());
                    ui.code("ra-host init --rendezvous <url> --apollo-username <u>");
                    ui.code("ra-host run");
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(format!("expected config: {}", self.host.config_path.display())).weak().small());
                }
            }
            ui.add_space(16.0);
            ui.separator();
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Moonlight client").strong());
            match &self.moonlight_found {
                Some(p) => ui.label(egui::RichText::new(p.display().to_string()).small()),
                None => ui.colored_label(egui::Color32::from_rgb(231, 76, 60), "not found — install Moonlight or set MOONLIGHT_BIN"),
            };
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            if let Some(p) = self.current.clone() {
                ui.heading(format!("Session: {} ({})", p.resolved.info.name, ra_host::pretty_id(&p.id)));
                ui.label(format!("Streaming \"{}\" via Moonlight at {}", p.app, p.host));
                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("■ Disconnect").clicked() {
                        self.disconnect();
                    }
                    if ui.button("⏻ Quit app on host").clicked() {
                        self.quit_remote_app();
                    }
                });
                ui.add_space(12.0);
                ui.label(egui::RichText::new("In-stream hotkeys (Moonlight)").strong());
                egui::Grid::new("hotkeys").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                    for (k, v) in [
                        ("Ctrl+Alt+Shift+Q", "Quit stream"),
                        ("Ctrl+Alt+Shift+X", "Toggle fullscreen"),
                        ("Ctrl+Alt+Shift+S", "Toggle stats overlay"),
                        ("Ctrl+Alt+Shift+M", "Toggle mouse mode (absolute/relative)"),
                        ("Ctrl+Alt+Shift+V", "Type clipboard text into host"),
                        ("Ctrl+Alt+Shift+Z", "Release keyboard/mouse grab"),
                        ("Ctrl+Alt+Shift+C", "Toggle local cursor"),
                        ("Ctrl+Alt+Shift+K", "Toggle system key capture"),
                    ] {
                        ui.monospace(k);
                        ui.label(v);
                        ui.end_row();
                    }
                });
                if !p.apps.is_empty() {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Other apps on this host").strong());
                    ui.horizontal_wrapped(|ui| {
                        for a in &p.apps {
                            if ui.small_button(a).clicked() {
                                self.remote_app = a.clone();
                                self.disconnect();
                                self.remote_id = p.id.clone();
                                self.start_connect();
                            }
                        }
                    });
                }
                return;
            }

            ui.heading("Control Remote Desktop");
            ui.label(egui::RichText::new("Enter the ID and password shown on the other machine.").weak());
            ui.add_space(12.0);
            egui::Grid::new("connect").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label("Remote ID");
                ui.add(egui::TextEdit::singleline(&mut self.remote_id).hint_text("123 456 789").desired_width(240.0).font(egui::TextStyle::Heading));
                ui.end_row();
                ui.label("Password");
                ui.add(egui::TextEdit::singleline(&mut self.remote_password).password(true).hint_text("leave empty if remembered").desired_width(240.0));
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

            if !self.cfg.hosts.is_empty() {
                ui.add_space(20.0);
                ui.label(egui::RichText::new("Recent").strong());
                let hosts: Vec<(String, String, Option<String>, bool)> = self
                    .cfg
                    .hosts
                    .iter()
                    .map(|(id, h)| (id.clone(), h.name.clone(), h.last_app.clone(), h.password_h1.is_some()))
                    .collect();
                ui.horizontal_wrapped(|ui| {
                    for (id, name, app, remembered) in hosts {
                        let card = egui::Frame::group(ui.style()).inner_margin(8.0).show(ui, |ui| {
                            ui.set_width(180.0);
                            ui.label(egui::RichText::new(if name.is_empty() { "unnamed host".into() } else { name.clone() }).strong());
                            ui.monospace(ra_host::pretty_id(&id));
                            ui.label(egui::RichText::new(format!("{}{}", app.clone().unwrap_or_else(|| "Desktop".into()), if remembered { " · password saved" } else { "" })).weak().small());
                        });
                        if card.response.interact(egui::Sense::click()).clicked() {
                            self.remote_id = id.clone();
                            if let Some(a) = app {
                                self.remote_app = a;
                            }
                        }
                    }
                });
            }
        });
    }
}

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 620.0]).with_min_inner_size([760.0, 480.0]).with_title("remote-access"),
        ..Default::default()
    };
    eframe::run_native("remote-access", options, Box::new(|cc| Ok(Box::new(Desk::new(cc)))))
}
