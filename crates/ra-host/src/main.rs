use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ra_host::{agent, apollo, config, Config};
use std::path::PathBuf;

/// remote-access host agent. Runs next to Apollo and gives it a RustDesk-style
/// ID + password front door.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to host.toml.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create the config file and register with the rendezvous server.
    Init {
        /// Rendezvous server base URL.
        #[arg(long, env = "RA_RENDEZVOUS")]
        rendezvous: String,
        /// Apollo web UI username.
        #[arg(long, env = "APOLLO_USERNAME")]
        apollo_username: String,
        /// Apollo web UI password (prompted if omitted).
        #[arg(long, env = "APOLLO_PASSWORD")]
        apollo_password: Option<String>,
        /// Apollo web UI URL.
        #[arg(long, default_value = "https://127.0.0.1:47990")]
        apollo_url: String,
        /// Friendly host name.
        #[arg(long)]
        name: Option<String>,
        /// Access password clients must present (prompted if omitted).
        #[arg(long, env = "RA_HOST_PASSWORD")]
        password: Option<String>,
    },
    /// Set the access password clients must present.
    SetPassword {
        /// Password (prompted if omitted).
        #[arg(long)]
        password: Option<String>,
    },
    /// Print this host's ID.
    Id,
    /// Run the agent (foreground).
    Run,
    /// Show paired clients known to Apollo.
    Clients,
    /// Set the permission mask applied to new clients: control | view | all | <hex>.
    Permissions { mask: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let path = args.config.unwrap_or_else(Config::default_path);
    match args.cmd {
        Cmd::Init { rendezvous, apollo_username, apollo_password, apollo_url, name, password } => {
            if path.exists() {
                anyhow::bail!("{} already exists; delete it to re-initialise", path.display());
            }
            let apollo_password = match apollo_password {
                Some(p) => p,
                None => rpassword::prompt_password("Apollo web UI password: ")?,
            };
            let mut cfg = Config::new_default(rendezvous, apollo_username, apollo_password);
            cfg.apollo_url = apollo_url;
            if let Some(n) = name {
                cfg.name = n;
            }
            let pw = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Choose an access password for this host: ")?,
            };
            if pw.len() < 6 {
                anyhow::bail!("password must be at least 6 characters");
            }
            cfg.set_password(&pw);
            cfg.save(&path)?;
            let mut agent = agent::Agent::new(cfg)?;
            let reg = agent.register(&path).await?;
            println!("Config written to {}", path.display());
            println!("Your ID: {}", agent::pretty_id(&reg.id));
        }
        Cmd::SetPassword { password } => {
            let mut cfg = Config::load(&path)?;
            let pw = match password {
                Some(p) => p,
                None => rpassword::prompt_password("New access password: ")?,
            };
            if pw.len() < 6 {
                anyhow::bail!("password must be at least 6 characters");
            }
            cfg.set_password(&pw);
            cfg.save(&path)?;
            // Salt changed: re-register so clients derive h1 with the new salt.
            let mut agent = agent::Agent::new(cfg)?;
            agent.register(&path).await.context("re-registering with new salt")?;
            println!("Password updated.");
        }
        Cmd::Id => {
            let cfg = Config::load(&path)?;
            match cfg.id {
                Some(id) => println!("{}", agent::pretty_id(&id)),
                None => println!("not registered yet; run `ra-host run`"),
            }
        }
        Cmd::Run => {
            let cfg = Config::load(&path)?;
            if let Some(id) = &cfg.id {
                println!("Your ID: {}", agent::pretty_id(id));
            }
            agent::Agent::new(cfg)?.run(&path).await?;
        }
        Cmd::Clients => {
            let cfg = Config::load(&path)?;
            let apollo = apollo::Apollo::new(&cfg.apollo_url, &cfg.apollo_username, &cfg.apollo_password)?;
            for c in apollo.list_clients().await? {
                println!("{:<30} {:<38} perm={:#010x} {}", c.name, c.uuid, c.perm, if c.connected { "connected" } else { "" });
            }
        }
        Cmd::Permissions { mask } => {
            let mut cfg = Config::load(&path)?;
            cfg.client_permissions = match mask.as_str() {
                "control" => config::perm::CONTROL,
                "view" => config::perm::VIEW_ONLY,
                "all" => config::perm::ALL,
                hex => u32::from_str_radix(hex.trim_start_matches("0x"), 16).context("mask must be control|view|all|<hex>")?,
            };
            cfg.save(&path)?;
            println!("New clients will get {:#010x}", cfg.client_permissions);
        }
    }
    Ok(())
}
