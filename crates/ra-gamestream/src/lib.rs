//! Client implementation of the NVIDIA GameStream HTTP protocol as spoken by
//! Moonlight, Sunshine and Apollo.
//!
//! Scope: identity certificate, `/serverinfo`, the five-step pairing
//! handshake (including Apollo's one-time-PIN `otpauth` extension), and
//! `/applist`. The RTSP/ENet media session itself is *not* implemented here;
//! `ra-client` hands that off to the Moonlight binary.
//!
//! Protocol details were taken from `moonlight-qt/app/backend/nvpairingmanager.cpp`
//! and `apollo/src/nvhttp.cpp`.

pub mod apps;
pub mod crypto;
pub mod http;
pub mod identity;
pub mod pairing;
pub mod serverinfo;
pub mod xml;

pub use apps::App;
pub use http::{GsHttp, HostAddr};
pub use identity::Identity;
pub use pairing::{OtpAuth, PairError, PairOutcome};
pub use serverinfo::ServerInfo;

/// Default GameStream HTTP port (Apollo/Sunshine "base port").
pub const DEFAULT_HTTP_PORT: u16 = 47989;
/// Default HTTPS port, base - 5.
pub const DEFAULT_HTTPS_PORT: u16 = 47984;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("xml: {0}")]
    Xml(String),
    #[error("server returned status {code}: {message}")]
    Status { code: i32, message: String },
    #[error("missing field {0} in response")]
    Missing(&'static str),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("pairing: {0}")]
    Pair(#[from] PairError),
}

pub type Result<T> = std::result::Result<T, Error>;
