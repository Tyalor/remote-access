use anyhow::Result;
use clap::{Parser, Subcommand};
use ra_client::{session::Event, ClientConfig, Session};
use std::path::PathBuf;

/// remote-access client: connect to an Apollo host by 9-digit ID.
#[derive(Parser, Debug)]
#[command(name = "ra", version, about)]
struct Args {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Resolve, pair if needed, and start streaming with Moonlight.
    Connect {
        id: String,
        /// Access password (prompted if omitted and not remembered).
        #[arg(short, long)]
        password: Option<String>,
        /// App to launch (defaults to "Desktop" or the last used app).
        #[arg(short, long)]
        app: Option<String>,
        /// Cache the password hash for this host.
        #[arg(long)]
        remember: bool,
        /// Extra arguments passed to `moonlight stream` (after `--`).
        #[arg(last = true)]
        moonlight_args: Vec<String>,
    },
    /// Show what the rendezvous server knows about an ID and which endpoint answers.
    Info { id: String },
    /// Pair only. `--native` uses the built-in Rust GameStream client instead of Moonlight.
    Pair {
        id: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        native: bool,
    },
    /// List apps on a host (natively paired hosts only).
    Apps { id: String },
    /// Show or change client settings.
    Config {
        #[arg(long)]
        rendezvous: Option<String>,
        #[arg(long)]
        moonlight: Option<PathBuf>,
        #[arg(long)]
        device_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();
    let args = Args::parse();
    let path = args.config.unwrap_or_else(ClientConfig::default_path);
    let cfg = ClientConfig::load_or_default(&path)?;

    if let Cmd::Config { rendezvous, moonlight, device_name } = &args.cmd {
        let mut cfg = cfg;
        if let Some(r) = rendezvous {
            cfg.rendezvous_url = r.clone();
        }
        if let Some(m) = moonlight {
            cfg.moonlight_path = Some(m.clone());
        }
        if let Some(d) = device_name {
            cfg.device_name = d.clone();
        }
        cfg.save(&path)?;
        println!("rendezvous_url = {}", cfg.rendezvous_url);
        println!("moonlight      = {}", ra_client::moonlight::find_moonlight(cfg.moonlight_path.as_deref()).map(|p| p.display().to_string()).unwrap_or_else(|| "NOT FOUND".into()));
        println!("device_name    = {}", cfg.device_name);
        println!("config file    = {}", path.display());
        return Ok(());
    }

    let mut session = Session::new(cfg)?;
    session.on_event = Box::new(|e| match e {
        Event::Resolving(id) => eprintln!("→ looking up {id}"),
        Event::Probing(ep) => eprintln!("  probing {}:{} ({})", ep.host, ep.port, ep.kind),
        Event::Reachable(ep) => eprintln!("✓ reachable at {}:{} ({})", ep.host, ep.port, ep.kind),
        Event::AlreadyPaired => eprintln!("✓ already paired"),
        Event::PairingStarted => eprintln!("→ pairing (password accepted by rendezvous, waiting for host)"),
        Event::PairAccepted => eprintln!("✓ host accepted password"),
        Event::Paired => eprintln!("✓ paired"),
        Event::Streaming(app) => eprintln!("→ streaming \"{app}\""),
        Event::Info(s) => eprintln!("{s}"),
    });

    match args.cmd {
        Cmd::Connect { id, password, app, remember, moonlight_args } => {
            let id = Session::normalize_id(&id)?;
            let status = session.connect(&id, password, app, remember, &path, &moonlight_args).await?;
            if !status.success() {
                eprintln!("moonlight exited with {status}");
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Cmd::Info { id } => {
            let id = Session::normalize_id(&id)?;
            let info = session.lookup(&id).await?;
            println!("{:<12} {}", "name", info.name);
            println!("{:<12} {}", "platform", info.platform);
            println!("{:<12} {}", "online", if info.online { "yes".to_string() } else { format!("no (last seen {}s ago)", info.last_seen_secs) });
            for e in &info.endpoints {
                println!("{:<12} {}:{} ({})", "endpoint", e.host, e.port, e.kind);
            }
            match session.resolve(&id).await {
                Ok(r) => println!("{:<12} {} — {} v{} state={}", "reachable", r.moonlight_host(), r.server_info.hostname, r.server_info.app_version, r.server_info.state),
                Err(e) => println!("{:<12} {e}", "reachable"),
            }
        }
        Cmd::Pair { id, password, native } => {
            let id = Session::normalize_id(&id)?;
            if native {
                let apps = session.pair_native(&id, password, &path).await?;
                println!("paired natively; {} app(s):", apps.len());
                for a in apps {
                    println!("  [{}] {}", a.id, a.title);
                }
            } else {
                let bin = ra_client::moonlight::find_moonlight(session.cfg.moonlight_path.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("Moonlight not found"))?;
                let ml = ra_client::moonlight::Moonlight::new(bin);
                let resolved = session.resolve(&id).await?;
                let host = resolved.moonlight_host();
                let p = password.unwrap_or_else(|| rpassword::prompt_password("Password: ").unwrap_or_default());
                let h1 = ra_proto::password_h1(&p, &resolved.info.password_salt);
                let ml = &ml;
                session
                    .pair_with(&id, &h1, true, |pin| async move {
                        let mut child = ml.spawn_pair(&host, &pin)?;
                        let st = child.wait().await?;
                        anyhow::ensure!(st.success(), "moonlight pair exited with {st}");
                        Ok(())
                    })
                    .await?;
                println!("paired");
            }
        }
        Cmd::Apps { id } => {
            let id = Session::normalize_id(&id)?;
            for a in session.apps_native(&id).await? {
                println!("[{}] {}{}", a.id, a.title, if a.hdr_supported { " (HDR)" } else { "" });
            }
        }
        Cmd::Config { .. } => unreachable!(),
    }
    Ok(())
}
