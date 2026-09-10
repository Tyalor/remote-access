use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// remote-access rendezvous / ID server.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "RA_LISTEN", default_value = "0.0.0.0:21114")]
    listen: SocketAddr,
    /// JSON file to persist host registrations across restarts.
    #[arg(long, env = "RA_STATE_FILE")]
    state_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let state = ra_rendezvous::AppState::new(args.state_file);
    ra_rendezvous::serve(args.listen, state).await
}
