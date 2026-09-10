//! Wire types and small crypto helpers shared by `ra-rendezvous`, `ra-host`
//! and `ra-client`.
//!
//! Transport is plain JSON over HTTPS. The rendezvous server is treated as
//! *untrusted*: it never sees the host password, and the pairing PIN that
//! travels through it is sealed with a key only the host and the client can
//! derive (see [`PairSecret`]).
//!
//! Password model (mirrors RustDesk):
//!
//! ```text
//! h1 = SHA256(password || salt)               stored on the host, cached by the client
//! h2 = SHA256(h1 || challenge)                sent through the rendezvous, verified by the host
//! k  = SHA256("ra-pair-v1" || h1 || challenge) seals the 4-digit Moonlight PIN
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const API_VERSION: &str = "v1";

/// Length of a host ID in decimal digits (same as RustDesk).
pub const ID_DIGITS: usize = 9;

/// Default Apollo / Sunshine base port. HTTPS is base-5, web UI is base+1.
pub const DEFAULT_GAMESTREAM_PORT: u16 = 47989;

// ---------------------------------------------------------------------------
// Host side messages
// ---------------------------------------------------------------------------

/// A network endpoint where a host's Apollo instance can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// IP address or DNS name.
    pub host: String,
    /// Apollo base port (HTTP GameStream port, default 47989).
    pub port: u16,
    /// How this address was learned: `lan`, `public`, `manual`, `vpn`.
    pub kind: String,
}

/// Sent by the host agent to claim or refresh its registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Existing ID, or `None` to be assigned one.
    pub id: Option<String>,
    /// Bearer token proving ownership of `id` (random 32 bytes, hex). On first
    /// registration the server stores its SHA-256 and returns the ID.
    pub token: String,
    pub name: String,
    pub platform: String,
    pub endpoints: Vec<Endpoint>,
    /// Salt used for the password hash, published so clients can derive `h1`.
    pub password_salt: String,
    /// Version of the host agent.
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    /// Address the rendezvous server observed the host connecting from.
    pub observed_addr: Option<String>,
    /// Seconds between heartbeats.
    pub heartbeat_secs: u64,
}

/// A pairing request queued for the host. Produced by a client, consumed by
/// the host agent via long-poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    /// Opaque request id assigned by the rendezvous server.
    pub request_id: String,
    /// Random challenge minted by the rendezvous server for this request.
    pub challenge: String,
    /// `hex(SHA256(h1 || challenge))`.
    pub response: String,
    /// Friendly name of the client device, shown in Apollo's client list.
    pub device_name: String,
    /// Moonlight client's `uniqueid`, if known, so the host can find the
    /// paired certificate afterwards. Optional.
    pub client_uid: Option<String>,
    /// The 4-digit PIN the client will present to Apollo, sealed with the
    /// pair key (hex of nonce || ciphertext).
    pub sealed_pin: String,
    /// Whether the client wants to stay paired after the session ends.
    pub remember: bool,
}

/// Outcome the host agent reports back for a [`PairRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResult {
    pub request_id: String,
    pub status: PairStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    /// The host has accepted the password and is waiting for the Moonlight
    /// pairing request to arrive.
    Accepted,
    /// Apollo completed pairing and permissions were applied.
    Paired,
    /// Wrong password.
    Rejected,
    /// Host-side failure (Apollo unreachable, timeout, ...).
    Failed,
}

// ---------------------------------------------------------------------------
// Client side messages
// ---------------------------------------------------------------------------

/// Public view of a registered host, returned to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub online: bool,
    pub endpoints: Vec<Endpoint>,
    pub password_salt: String,
    /// Seconds since the last heartbeat.
    pub last_seen_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub request_id: String,
    pub challenge: String,
    /// Seconds until the challenge expires.
    pub ttl_secs: u64,
}

/// Body a client posts to complete a pair request after obtaining a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPairRequest {
    pub request_id: String,
    pub response: String,
    pub device_name: String,
    pub client_uid: Option<String>,
    pub sealed_pin: String,
    pub remember: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("sealed payload too short")]
    TooShort,
    #[error("decryption failed")]
    Decrypt,
    #[error("pin must be exactly 4 ASCII digits")]
    BadPin,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `h1 = hex(SHA256(password || salt))`. This is what the host stores.
pub fn password_h1(password: &str, salt: &str) -> String {
    hex::encode(sha256(&[password.as_bytes(), salt.as_bytes()]))
}

/// `h2 = hex(SHA256(h1 || challenge))`. This is what crosses the rendezvous.
pub fn challenge_response(h1_hex: &str, challenge: &str) -> String {
    hex::encode(sha256(&[h1_hex.as_bytes(), challenge.as_bytes()]))
}

/// Constant-time comparison of two hex strings.
pub fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Random alphanumeric salt of `n` chars.
pub fn random_salt(n: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// Random hex string of `n` bytes.
pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Random 4-digit Moonlight PIN, zero padded.
pub fn random_pin() -> String {
    use rand::Rng;
    format!("{:04}", rand::thread_rng().gen_range(0..10000u32))
}

/// Random 9-digit host ID that never starts with 0.
pub fn random_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let first = rng.gen_range(1..10u32);
    let rest: String = (1..ID_DIGITS).map(|_| char::from(b'0' + rng.gen_range(0..10u8))).collect();
    format!("{first}{rest}")
}

pub fn is_valid_id(id: &str) -> bool {
    id.len() == ID_DIGITS && id.bytes().all(|b| b.is_ascii_digit()) && !id.starts_with('0')
}

pub fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// Symmetric key shared by host and client for one pair request, derived
/// from the password hash and the challenge. The rendezvous server knows the
/// challenge but not `h1`, so it cannot derive it.
pub struct PairSecret {
    key: [u8; 32],
}

impl PairSecret {
    pub fn derive(h1_hex: &str, challenge: &str) -> Self {
        Self { key: sha256(&[b"ra-pair-v1", h1_hex.as_bytes(), challenge.as_bytes()]) }
    }

    /// Seal a 4-digit PIN. Returns hex(nonce || ciphertext || tag).
    pub fn seal_pin(&self, pin: &str) -> Result<String, CryptoError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        use rand::RngCore;
        if !is_valid_pin(pin) {
            return Err(CryptoError::BadPin);
        }
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), pin.as_bytes())
            .map_err(|_| CryptoError::Decrypt)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(hex::encode(out))
    }

    pub fn open_pin(&self, sealed_hex: &str) -> Result<String, CryptoError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        let raw = hex::decode(sealed_hex)?;
        if raw.len() < 12 + 16 {
            return Err(CryptoError::TooShort);
        }
        let (nonce, ct) = raw.split_at(12);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let pt = cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| CryptoError::Decrypt)?;
        let pin = String::from_utf8(pt).map_err(|_| CryptoError::Decrypt)?;
        if !is_valid_pin(&pin) {
            return Err(CryptoError::BadPin);
        }
        Ok(pin)
    }
}

/// `hex(SHA256(token))`, what the rendezvous server stores for a host token.
pub fn token_fingerprint(token: &str) -> String {
    hex::encode(sha256(&[token.as_bytes()]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h1_h2_are_deterministic_and_bound_to_inputs() {
        let h1 = password_h1("hunter2", "salt");
        assert_eq!(h1, password_h1("hunter2", "salt"));
        assert_ne!(h1, password_h1("hunter2", "salt2"));
        let h2 = challenge_response(&h1, "c1");
        assert_ne!(h2, challenge_response(&h1, "c2"));
        assert!(ct_eq(&h2, &challenge_response(&h1, "c1")));
    }

    #[test]
    fn pin_roundtrip_and_wrong_key_fails() {
        let h1 = password_h1("pw", "s");
        let good = PairSecret::derive(&h1, "chal");
        let sealed = good.seal_pin("0042").unwrap();
        assert_eq!(good.open_pin(&sealed).unwrap(), "0042");
        let bad = PairSecret::derive(&password_h1("wrong", "s"), "chal");
        assert!(bad.open_pin(&sealed).is_err());
        assert!(good.seal_pin("12345").is_err());
    }

    #[test]
    fn ids_and_pins_validate() {
        for _ in 0..100 {
            assert!(is_valid_id(&random_id()));
            assert!(is_valid_pin(&random_pin()));
        }
        assert!(!is_valid_id("012345678"));
        assert!(!is_valid_id("12345678"));
    }
}
