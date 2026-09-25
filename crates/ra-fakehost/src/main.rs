//! A stand-in for Apollo that speaks just enough of both of its faces:
//!
//! * GameStream HTTP (`base`) and HTTPS (`base-5`, client cert required):
//!   `/serverinfo`, `/pair` (all phases; `getservercert` parks until a PIN is
//!   posted, exactly like Apollo), `/unpair`, `/applist`.
//! * Web API (`base+1`, plain HTTP here): `/api/login`, `/api/pin`,
//!   `/api/clients/list`, `/api/clients/update`, `/api/config`.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use ra_gamestream::testing::FakeHost;
use rsa::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

#[derive(Parser)]
struct Args {
    /// GameStream base port (HTTP). HTTPS = base-5, web API = base+1.
    #[arg(long, default_value_t = 47989)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    #[arg(long, default_value = "admin")]
    username: String,
    #[arg(long, default_value = "admin")]
    password: String,
    #[arg(long, default_value = "Fake Apollo")]
    name: String,
}

struct Inner {
    host: FakeHost,
    /// A parked getservercert waiting for a PIN, with the salt/args it needs.
    parked: Option<(String, oneshot::Sender<(String, String)>)>,
    clients: Vec<serde_json::Value>,
    pending_name: Option<String>,
}

#[derive(Clone)]
struct App {
    inner: Arc<Mutex<Inner>>,
    args: Arc<Args>,
    uuid: String,
}

fn xml_err(code: u16, msg: &str) -> String {
    format!("<root status_code=\"{code}\" status_message=\"{msg}\"/>")
}

fn param<'a>(q: &'a str, k: &str) -> Option<&'a str> {
    q.split('&').find_map(|kv| kv.strip_prefix(&format!("{k}=")))
}

async fn serverinfo(State(app): State<App>, RawQuery(q): RawQuery, headers: HeaderMap) -> String {
    let https = headers.get("x-ra-https").is_some();
    let paired = https && q.as_deref().and_then(|q| param(q, "uniqueid")).is_some();
    format!(
        "<?xml version=\"1.0\"?><root status_code=\"200\"><hostname>{}</hostname><appversion>7.1.431.-1</appversion><GfeVersion>3.23.0.74</GfeVersion><uniqueid>{}</uniqueid><HttpsPort>{}</HttpsPort><ExternalPort>{}</ExternalPort><mac>00:00:00:00:00:00</mac><LocalIP>127.0.0.1</LocalIP><ServerCodecModeSupport>259</ServerCodecModeSupport><PairStatus>{}</PairStatus><currentgame>0</currentgame><state>SUNSHINE_SERVER_FREE</state></root>",
        app.args.name,
        app.uuid,
        app.args.port - 5,
        app.args.port,
        if paired { 1 } else { 0 }
    )
}

async fn pair(State(app): State<App>, RawQuery(q): RawQuery, headers: HeaderMap) -> String {
    let https = headers.get("x-ra-https").is_some();
    let q = q.unwrap_or_default();
    if param(&q, "uniqueid").is_none() {
        return xml_err(400, "Missing uniqueid parameter");
    }
    if param(&q, "phrase") == Some("getservercert") {
        // Park until the web API delivers a PIN.
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = app.inner.lock().await;
            inner.parked = Some((q.clone(), tx));
        }
        tracing::info!("pairing request parked; waiting for PIN via /api/pin");
        let Ok((pin, name)) = rx.await else { return xml_err(503, "pairing aborted") };
        let mut inner = app.inner.lock().await;
        inner.host.pin = pin;
        inner.pending_name = Some(name);
        return inner.host.handle_query(&q, false);
    }
    let mut inner = app.inner.lock().await;
    let body = inner.host.handle_query(&q, https);
    if param(&q, "clientpairingsecret").is_some() && body.contains("<paired>1</paired>") {
        let name = inner.pending_name.take().unwrap_or_else(|| "Unnamed".into());
        let uuid = uuid::Uuid::new_v4().to_string();
        tracing::info!(%name, %uuid, "client paired (default perm view|list)");
        inner.clients.push(serde_json::json!({
            "name": name, "uuid": uuid, "display_mode": "", "perm": 0x0300_0000u32,
            "enable_legacy_ordering": true, "allow_client_commands": true,
            "always_use_virtual_display": false, "connected": false
        }));
    }
    body
}

async fn unpair() -> String {
    "<root status_code=\"200\"/>".into()
}

async fn applist(State(app): State<App>) -> String {
    let inner = app.inner.lock().await;
    let n = inner.clients.len();
    format!("<root status_code=\"200\"><App><IsHdrSupported>1</IsHdrSupported><AppTitle>Desktop</AppTitle><UUID>desk</UUID><IDX>0</IDX><ID>1</ID></App><App><IsHdrSupported>0</IsHdrSupported><AppTitle>Steam Big Picture</AppTitle><UUID>steam</UUID><IDX>1</IDX><ID>2</ID></App><App><IsHdrSupported>0</IsHdrSupported><AppTitle>Paired clients: {n}</AppTitle><ID>3</ID></App></root>")
}

// --- web API ---------------------------------------------------------------

fn authed(headers: &HeaderMap) -> bool {
    headers.get("cookie").and_then(|c| c.to_str().ok()).map(|c| c.contains("auth=fake-session")).unwrap_or(false)
}

async fn login(State(app): State<App>, Json(v): Json<serde_json::Value>) -> impl IntoResponse {
    let ok = v.get("username").and_then(|s| s.as_str()) == Some(&app.args.username)
        && v.get("password").and_then(|s| s.as_str()) == Some(&app.args.password);
    if ok {
        ([("set-cookie", "auth=fake-session; Path=/")], StatusCode::OK).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn api_pin(State(app): State<App>, headers: HeaderMap, Json(v): Json<serde_json::Value>) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"status_code":401,"status":false,"error":"Unauthorized"})));
    }
    let pin = v.get("pin").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let name = v.get("name").and_then(|s| s.as_str()).unwrap_or("").to_string();
    if pin.len() != 4 || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return (StatusCode::OK, Json(serde_json::json!({"status": false})));
    }
    let mut inner = app.inner.lock().await;
    match inner.parked.take() {
        Some((_q, tx)) => {
            // A stale entry (client went away) behaves like Apollo: the PIN is
            // consumed by a session that can never finish.
            let live = tx.send((pin, name)).is_ok();
            tracing::info!(live, "PIN delivered to parked session");
            (StatusCode::OK, Json(serde_json::json!({"status": true})))
        }
        None => (StatusCode::OK, Json(serde_json::json!({"status": false}))),
    }
}

async fn clients_list(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"})));
    }
    let inner = app.inner.lock().await;
    (StatusCode::OK, Json(serde_json::json!({"named_certs": inner.clients, "status": true})))
}

async fn clients_update(State(app): State<App>, headers: HeaderMap, Json(v): Json<serde_json::Value>) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"})));
    }
    let mut inner = app.inner.lock().await;
    let uuid = v.get("uuid").and_then(|s| s.as_str()).unwrap_or("");
    let Some(c) = inner.clients.iter_mut().find(|c| c["uuid"] == uuid) else {
        return (StatusCode::OK, Json(serde_json::json!({"status": false})));
    };
    for k in ["name", "perm", "display_mode", "enable_legacy_ordering", "allow_client_commands", "always_use_virtual_display"] {
        if let Some(val) = v.get(k) {
            c[k] = val.clone();
        }
    }
    tracing::info!(%uuid, perm = ?c["perm"], "client updated");
    (StatusCode::OK, Json(serde_json::json!({"status": true})))
}

async fn api_config(State(app): State<App>, headers: HeaderMap) -> impl IntoResponse {
    if !authed(&headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"})));
    }
    (StatusCode::OK, Json(serde_json::json!({"status": true, "platform": "fake", "version": "0", "sunshine_name": app.args.name})))
}

#[derive(Debug)]
struct AcceptAnyClient(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AcceptAnyClient {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Arc::new(Args::parse());
    tracing::info!("generating host RSA key…");
    let host = FakeHost::new("0000");
    let cert_pem = host.cert_pem.clone();
    let key_pem = host.key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?.to_string();
    let app = App {
        inner: Arc::new(Mutex::new(Inner { host, parked: None, clients: vec![], pending_name: None })),
        args: args.clone(),
        uuid: uuid::Uuid::new_v4().to_string(),
    };

    let gs = Router::new()
        .route("/serverinfo", get(serverinfo))
        .route("/pair", get(pair))
        .route("/unpair", get(unpair))
        .route("/applist", get(applist))
        .with_state(app.clone());
    let web = Router::new()
        .route("/api/login", post(login))
        .route("/api/pin", post(api_pin))
        .route("/api/clients/list", get(clients_list))
        .route("/api/clients/update", post(clients_update))
        .route("/api/config", get(api_config))
        .with_state(app.clone());

    // HTTPS: mark requests so handlers know they arrived with a client cert.
    let gs_https = gs.clone().layer(axum::middleware::map_request(|mut req: axum::extract::Request| async move {
        req.headers_mut().insert("x-ra-https", "1".parse().unwrap());
        req
    }));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.expect("key");
    let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(AcceptAnyClient(provider)))
        .with_single_cert(certs, key)?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));

    let http_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let https_addr: SocketAddr = format!("{}:{}", args.bind, args.port - 5).parse()?;
    let web_addr: SocketAddr = format!("{}:{}", args.bind, args.port + 1).parse()?;
    tracing::info!(%http_addr, %https_addr, %web_addr, "fake Apollo listening");

    let h1 = tokio::spawn(async move { axum_server::bind(http_addr).serve(gs.into_make_service()).await });
    let h2 = tokio::spawn(async move { axum_server::bind_rustls(https_addr, tls).serve(gs_https.into_make_service()).await });
    let h3 = tokio::spawn(async move { axum_server::bind(web_addr).serve(web.into_make_service()).await });
    let _ = tokio::try_join!(h1, h2, h3)?;
    Ok(())
}
