//! Debug helper: `cargo run -p ra-gamestream --example https_probe -- <host> <base_port> <server.pem>`
use ra_gamestream::{GsHttp, HostAddr, Identity};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pem = std::fs::read_to_string(&args[3]).unwrap();
    let id = Identity::generate().unwrap();
    let gs = GsHttp::new(id).unwrap();
    let addr = HostAddr::new(args[1].clone(), args[2].parse().unwrap());
    match gs.server_info_https(&addr, &pem).await {
        Ok(si) => println!("ok: {si:?}"),
        Err(e) => {
            let e: anyhow::Error = e.into();
            println!("error: {e:#}");
        }
    }
}
