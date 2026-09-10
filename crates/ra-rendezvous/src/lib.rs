//! Rendezvous ("ID server") for remote-access. Think RustDesk's `hbbs`, but
//! only the parts we need: ID registration, liveness, address lookup, and a
//! queue that carries password-authenticated pairing requests from a client
//! to the host agent sitting next to Apollo.
//!
//! The server is deliberately *untrusted*: it sees `h2` (a challenge hash)
//! and a sealed PIN it cannot open, never the password.

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ra_proto::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock};

pub const HEARTBEAT_SECS: u64 = 30;
pub const OFFLINE_AFTER_SECS: u64 = 90;
pub const CHALLENGE_TTL_SECS: u64 = 120;
pub const RESULT_TTL_SECS: u64 = 300;
pub const MAX_LONG_POLL_SECS: u64 = 30;
/// Max challenges per host per minute, to slow online password guessing.
pub const CHALLENGES_PER_MINUTE: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    pub id: String,
    pub token_fp: String,
    pub name: String,
    pub platform: String,
    pub endpoints: Vec<Endpoint>,
    pub password_salt: String,
    pub agent_version: String,
    #[serde(skip)]
    pub last_seen: Option<Instant>,
    #[serde(skip)]
    pub last_seen_unix: u64,
}

#[derive(Default)]
struct HostRuntime {
    pending: VecDeque<PairRequest>,
    notify: Arc<Notify>,
    challenge_times: VecDeque<Instant>,
}

struct Challenge {
    host_id: String,
    challenge: String,
    created: Instant,
}

struct ResultSlot {
    result: Option<PairResult>,
    notify: Arc<Notify>,
    created: Instant,
}

#[derive(Default)]
pub struct Store {
    hosts: HashMap<String, HostRecord>,
    runtime: HashMap<String, HostRuntime>,
    challenges: HashMap<String, Challenge>,
    results: HashMap<String, ResultSlot>,
}

#[derive(Clone)]
pub struct AppState {
    store: Arc<RwLock<Store>>,
    state_file: Option<PathBuf>,
}

impl AppState {
    pub fn new(state_file: Option<PathBuf>) -> Self {
        let mut store = Store::default();
        if let Some(p) = &state_file {
            if let Ok(text) = std::fs::read_to_string(p) {
                if let Ok(hosts) = serde_json::from_str::<Vec<HostRecord>>(&text) {
                    for h in hosts {
                        store.hosts.insert(h.id.clone(), h);
                    }
                    tracing::info!(count = store.hosts.len(), "loaded hosts from state file");
                }
            }
        }
        Self { store: Arc::new(RwLock::new(store)), state_file }
    }

    async fn persist(&self) {
        let Some(p) = &self.state_file else { return };
        let hosts: Vec<HostRecord> = self.store.read().await.hosts.values().cloned().collect();
        match serde_json::to_string_pretty(&hosts) {
            Ok(text) => {
                if let Err(e) = tokio::fs::write(p, text).await {
                    tracing::warn!(error = %e, "failed to persist state");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to serialize state"),
        }
    }

    /// Drop expired challenges and results. Called opportunistically.
    async fn gc(&self) {
        let mut s = self.store.write().await;
        let now = Instant::now();
        s.challenges.retain(|_, c| now.duration_since(c.created).as_secs() < CHALLENGE_TTL_SECS);
        s.results.retain(|_, r| now.duration_since(r.created).as_secs() < RESULT_TTL_SECS);
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/hosts/register", post(register))
        .route("/v1/hosts/:id", get(host_info))
        .route("/v1/hosts/:id/heartbeat", post(heartbeat))
        .route("/v1/hosts/:id/pair-requests", get(poll_pair_requests))
        .route("/v1/hosts/:id/pair-results", post(post_pair_result))
        .route("/v1/hosts/:id/challenge", post(challenge))
        .route("/v1/hosts/:id/pair", post(submit_pair))
        .route("/v1/pair/:request_id", get(poll_pair_result))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "rendezvous listening");
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorBody { error: self.1 })).into_response()
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

async fn authorize(store: &Store, id: &str, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = bearer(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let host = store.hosts.get(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown host id"))?;
    if !ct_eq(&host.token_fp, &token_fingerprint(&token)) {
        return Err(err(StatusCode::FORBIDDEN, "bad token"));
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn observed_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| peer.map(|p| p.ip().to_string()))
}

async fn health() -> &'static str {
    "ok"
}

async fn register(
    State(st): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    if req.token.len() < 32 {
        return Err(err(StatusCode::BAD_REQUEST, "token too short"));
    }
    if req.name.is_empty() || req.name.len() > 64 {
        return Err(err(StatusCode::BAD_REQUEST, "name must be 1..64 chars"));
    }
    if req.endpoints.len() > 16 {
        return Err(err(StatusCode::BAD_REQUEST, "too many endpoints"));
    }
    let fp = token_fingerprint(&req.token);
    let mut s = st.store.write().await;
    let id = match &req.id {
        Some(id) => {
            if !is_valid_id(id) {
                return Err(err(StatusCode::BAD_REQUEST, "malformed id"));
            }
            match s.hosts.get(id) {
                Some(existing) if !ct_eq(&existing.token_fp, &fp) => {
                    return Err(err(StatusCode::FORBIDDEN, "id is owned by a different token"))
                }
                _ => id.clone(),
            }
        }
        None => loop {
            let candidate = random_id();
            if !s.hosts.contains_key(&candidate) {
                break candidate;
            }
        },
    };
    let rec = HostRecord {
        id: id.clone(),
        token_fp: fp,
        name: req.name,
        platform: req.platform,
        endpoints: req.endpoints,
        password_salt: req.password_salt,
        agent_version: req.agent_version,
        last_seen: Some(Instant::now()),
        last_seen_unix: now_unix(),
    };
    s.hosts.insert(id.clone(), rec);
    s.runtime.entry(id.clone()).or_default();
    drop(s);
    st.persist().await;
    tracing::info!(%id, "host registered");
    Ok(Json(RegisterResponse {
        id,
        observed_addr: observed_ip(&headers, peer.map(|p| p.0)),
        heartbeat_secs: HEARTBEAT_SECS,
    }))
}

#[derive(Deserialize, Default)]
pub struct HeartbeatBody {
    #[serde(default)]
    pub endpoints: Option<Vec<Endpoint>>,
}

async fn heartbeat(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    body: Option<Json<HeartbeatBody>>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let mut s = st.store.write().await;
    authorize(&s, &id, &headers).await?;
    let host = s.hosts.get_mut(&id).expect("authorized");
    host.last_seen = Some(Instant::now());
    host.last_seen_unix = now_unix();
    let mut changed = false;
    if let Some(Json(HeartbeatBody { endpoints: Some(eps) })) = body {
        if eps.len() <= 16 && host.endpoints != eps {
            host.endpoints = eps;
            changed = true;
        }
    }
    drop(s);
    if changed {
        st.persist().await;
    }
    Ok(Json(RegisterResponse {
        id,
        observed_addr: observed_ip(&headers, peer.map(|p| p.0)),
        heartbeat_secs: HEARTBEAT_SECS,
    }))
}

async fn host_info(State(st): State<AppState>, Path(id): Path<String>) -> Result<Json<HostInfo>, ApiError> {
    let s = st.store.read().await;
    let host = s.hosts.get(&id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown host id"))?;
    let last_seen_secs = host.last_seen.map(|t| t.elapsed().as_secs()).unwrap_or(u64::MAX);
    Ok(Json(HostInfo {
        id: host.id.clone(),
        name: host.name.clone(),
        platform: host.platform.clone(),
        online: last_seen_secs < OFFLINE_AFTER_SECS,
        endpoints: host.endpoints.clone(),
        password_salt: host.password_salt.clone(),
        last_seen_secs,
    }))
}

#[derive(Deserialize, Default)]
pub struct WaitQuery {
    #[serde(default)]
    pub wait: Option<u64>,
}

async fn poll_pair_requests(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<WaitQuery>,
) -> Result<Json<Vec<PairRequest>>, ApiError> {
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(MAX_LONG_POLL_SECS));
    let deadline = Instant::now() + wait;
    loop {
        let notify = {
            let mut s = st.store.write().await;
            authorize(&s, &id, &headers).await?;
            if let Some(h) = s.hosts.get_mut(&id) {
                h.last_seen = Some(Instant::now());
                h.last_seen_unix = now_unix();
            }
            let rt = s.runtime.entry(id.clone()).or_default();
            if !rt.pending.is_empty() {
                return Ok(Json(rt.pending.drain(..).collect()));
            }
            rt.notify.clone()
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Json(vec![]));
        }
        let _ = tokio::time::timeout(remaining, notify.notified()).await;
    }
}

async fn post_pair_result(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(res): Json<PairResult>,
) -> Result<StatusCode, ApiError> {
    let mut s = st.store.write().await;
    authorize(&s, &id, &headers).await?;
    let slot = s
        .results
        .get_mut(&res.request_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown request id"))?;
    slot.result = Some(res);
    slot.notify.notify_waiters();
    Ok(StatusCode::NO_CONTENT)
}

async fn challenge(State(st): State<AppState>, Path(id): Path<String>) -> Result<Json<ChallengeResponse>, ApiError> {
    st.gc().await;
    let mut s = st.store.write().await;
    if !s.hosts.contains_key(&id) {
        return Err(err(StatusCode::NOT_FOUND, "unknown host id"));
    }
    let rt = s.runtime.entry(id.clone()).or_default();
    let now = Instant::now();
    while rt.challenge_times.front().map(|t| now.duration_since(*t) > Duration::from_secs(60)).unwrap_or(false) {
        rt.challenge_times.pop_front();
    }
    if rt.challenge_times.len() >= CHALLENGES_PER_MINUTE {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many pairing attempts, slow down"));
    }
    rt.challenge_times.push_back(now);
    let request_id = random_hex(16);
    let chal = random_hex(32);
    s.challenges.insert(request_id.clone(), Challenge { host_id: id, challenge: chal.clone(), created: now });
    Ok(Json(ChallengeResponse { request_id, challenge: chal, ttl_secs: CHALLENGE_TTL_SECS }))
}

async fn submit_pair(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SubmitPairRequest>,
) -> Result<StatusCode, ApiError> {
    if req.device_name.is_empty() || req.device_name.len() > 64 {
        return Err(err(StatusCode::BAD_REQUEST, "device_name must be 1..64 chars"));
    }
    if req.response.len() != 64 || req.sealed_pin.len() > 256 {
        return Err(err(StatusCode::BAD_REQUEST, "malformed response or sealed_pin"));
    }
    let mut s = st.store.write().await;
    let ch = s.challenges.remove(&req.request_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown or expired challenge"))?;
    if ch.host_id != id {
        return Err(err(StatusCode::BAD_REQUEST, "challenge belongs to a different host"));
    }
    if ch.created.elapsed().as_secs() >= CHALLENGE_TTL_SECS {
        return Err(err(StatusCode::GONE, "challenge expired"));
    }
    let online = s
        .hosts
        .get(&id)
        .and_then(|h| h.last_seen)
        .map(|t| t.elapsed().as_secs() < OFFLINE_AFTER_SECS)
        .unwrap_or(false);
    if !online {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "host is offline"));
    }
    let pr = PairRequest {
        request_id: req.request_id.clone(),
        challenge: ch.challenge,
        response: req.response,
        device_name: req.device_name,
        client_uid: req.client_uid,
        sealed_pin: req.sealed_pin,
        remember: req.remember,
    };
    s.results.insert(
        req.request_id,
        ResultSlot { result: None, notify: Arc::new(Notify::new()), created: Instant::now() },
    );
    let rt = s.runtime.entry(id).or_default();
    rt.pending.push_back(pr);
    rt.notify.notify_waiters();
    Ok(StatusCode::ACCEPTED)
}

async fn poll_pair_result(
    State(st): State<AppState>,
    Path(request_id): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<Option<PairResult>>, ApiError> {
    let wait = Duration::from_secs(q.wait.unwrap_or(0).min(MAX_LONG_POLL_SECS));
    let deadline = Instant::now() + wait;
    loop {
        let notify = {
            let s = st.store.read().await;
            let slot = s.results.get(&request_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown request id"))?;
            if let Some(r) = &slot.result {
                return Ok(Json(Some(r.clone())));
            }
            slot.notify.clone()
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Json(None));
        }
        let _ = tokio::time::timeout(remaining, notify.notified()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(AppState::new(None)).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn register_lookup_pair_flow() {
        let base = spawn().await;
        let c = reqwest::Client::new();
        let token = random_hex(32);
        let salt = random_salt(16);

        // host registers and gets an id
        let reg: RegisterResponse = c
            .post(format!("{base}/v1/hosts/register"))
            .json(&RegisterRequest {
                id: None,
                token: token.clone(),
                name: "Gaming PC".into(),
                platform: "windows".into(),
                endpoints: vec![Endpoint { host: "192.168.1.50".into(), port: 47989, kind: "lan".into() }],
                password_salt: salt.clone(),
                agent_version: "test".into(),
            })
            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        assert!(is_valid_id(&reg.id));
        assert_eq!(reg.observed_addr.as_deref(), Some("127.0.0.1"));

        // re-register with same id but wrong token is refused
        let r = c.post(format!("{base}/v1/hosts/register"))
            .json(&RegisterRequest { id: Some(reg.id.clone()), token: random_hex(32), name: "x".into(), platform: "p".into(), endpoints: vec![], password_salt: "s".into(), agent_version: "t".into() })
            .send().await.unwrap();
        assert_eq!(r.status(), 403);

        // client looks the host up
        let info: HostInfo = c.get(format!("{base}/v1/hosts/{}", reg.id)).send().await.unwrap().json().await.unwrap();
        assert!(info.online);
        assert_eq!(info.password_salt, salt);
        assert_eq!(info.endpoints[0].host, "192.168.1.50");

        // client gets a challenge and submits a pair request
        let h1 = password_h1("hunter2", &salt);
        let ch: ChallengeResponse = c.post(format!("{base}/v1/hosts/{}/challenge", reg.id)).send().await.unwrap().json().await.unwrap();
        let secret = PairSecret::derive(&h1, &ch.challenge);
        let r = c.post(format!("{base}/v1/hosts/{}/pair", reg.id))
            .json(&SubmitPairRequest {
                request_id: ch.request_id.clone(),
                response: challenge_response(&h1, &ch.challenge),
                device_name: "Laptop".into(),
                client_uid: None,
                sealed_pin: secret.seal_pin("1234").unwrap(),
                remember: true,
            })
            .send().await.unwrap();
        assert_eq!(r.status(), 202);

        // host long-polls and receives it
        let reqs: Vec<PairRequest> = c.get(format!("{base}/v1/hosts/{}/pair-requests?wait=5", reg.id))
            .bearer_auth(&token).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let pr = &reqs[0];
        assert!(ct_eq(&pr.response, &challenge_response(&h1, &pr.challenge)));
        assert_eq!(PairSecret::derive(&h1, &pr.challenge).open_pin(&pr.sealed_pin).unwrap(), "1234");

        // unauthenticated poll is refused
        let r = c.get(format!("{base}/v1/hosts/{}/pair-requests", reg.id)).send().await.unwrap();
        assert_eq!(r.status(), 401);

        // client waits for a result while host posts one
        let base2 = base.clone();
        let id2 = reg.id.clone();
        let rid = pr.request_id.clone();
        let tok2 = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            reqwest::Client::new().post(format!("{base2}/v1/hosts/{id2}/pair-results")).bearer_auth(tok2)
                .json(&PairResult { request_id: rid, status: PairStatus::Paired, message: None })
                .send().await.unwrap().error_for_status().unwrap();
        });
        let res: Option<PairResult> = c.get(format!("{base}/v1/pair/{}?wait=5", pr.request_id)).send().await.unwrap().json().await.unwrap();
        assert_eq!(res.unwrap().status, PairStatus::Paired);

        // challenge cannot be reused
        let r = c.post(format!("{base}/v1/hosts/{}/pair", reg.id))
            .json(&SubmitPairRequest { request_id: ch.request_id, response: "0".repeat(64), device_name: "L".into(), client_uid: None, sealed_pin: "00".into(), remember: false })
            .send().await.unwrap();
        assert_eq!(r.status(), 404);
    }

    #[tokio::test]
    async fn challenge_rate_limit() {
        let base = spawn().await;
        let c = reqwest::Client::new();
        let reg: RegisterResponse = c.post(format!("{base}/v1/hosts/register"))
            .json(&RegisterRequest { id: None, token: random_hex(32), name: "h".into(), platform: "p".into(), endpoints: vec![], password_salt: "s".into(), agent_version: "t".into() })
            .send().await.unwrap().json().await.unwrap();
        let mut last = 0;
        for _ in 0..=CHALLENGES_PER_MINUTE {
            last = c.post(format!("{base}/v1/hosts/{}/challenge", reg.id)).send().await.unwrap().status().as_u16();
        }
        assert_eq!(last, 429);
    }
}
