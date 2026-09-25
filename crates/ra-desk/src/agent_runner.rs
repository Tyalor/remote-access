//! Runs the host agent inside this process, guarded by a local port so the
//! GUI and a background `--headless` service never register twice.

use anyhow::Result;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

/// Loopback port used purely as a cross-process mutex.
pub const LOCK_PORT: u16 = 21116;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// No host config on this machine.
    NotConfigured,
    Stopped,
    /// Running inside this process.
    Running,
    /// Another process (the headless service) holds the lock.
    RunningElsewhere,
    Failed(String),
}

pub struct AgentRunner {
    rt: Arc<tokio::runtime::Runtime>,
    lock: Option<TcpListener>,
    task: Option<JoinHandle<()>>,
    pub state: Arc<Mutex<AgentState>>,
}

impl AgentRunner {
    pub fn new(rt: Arc<tokio::runtime::Runtime>) -> Self {
        Self { rt, lock: None, task: None, state: Arc::new(Mutex::new(AgentState::Stopped)) }
    }

    pub fn state(&self) -> AgentState {
        self.state.lock().unwrap().clone()
    }

    /// Start the agent if a host config exists and nobody else runs it.
    pub fn start(&mut self, config_path: &std::path::Path) -> Result<()> {
        if self.task.is_some() {
            return Ok(());
        }
        let cfg = match ra_host::Config::load(config_path) {
            Ok(c) => c,
            Err(_) => {
                *self.state.lock().unwrap() = AgentState::NotConfigured;
                return Ok(());
            }
        };
        if cfg.password_h1.is_none() {
            *self.state.lock().unwrap() = AgentState::Failed("no access password set".into());
            return Ok(());
        }
        let lock = match TcpListener::bind(("127.0.0.1", LOCK_PORT)) {
            Ok(l) => l,
            Err(_) => {
                *self.state.lock().unwrap() = AgentState::RunningElsewhere;
                return Ok(());
            }
        };
        self.lock = Some(lock);
        let state = self.state.clone();
        let path = config_path.to_path_buf();
        *state.lock().unwrap() = AgentState::Running;
        self.task = Some(self.rt.spawn(async move {
            loop {
                let r = async {
                    let agent = ra_host::Agent::new(cfg.clone())?;
                    agent.run(&path).await
                }
                .await;
                match r {
                    Ok(()) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "host agent stopped; restarting in 10s");
                        *state.lock().unwrap() = AgentState::Failed(format!("{e:#}"));
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        *state.lock().unwrap() = AgentState::Running;
                    }
                }
            }
        }));
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        self.lock = None;
        *self.state.lock().unwrap() = AgentState::Stopped;
    }

    /// Restart to pick up a changed config (new password, name, ...).
    pub fn restart(&mut self, config_path: &std::path::Path) -> Result<()> {
        self.stop();
        self.start(config_path)
    }
}
