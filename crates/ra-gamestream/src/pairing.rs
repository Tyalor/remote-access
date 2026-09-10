//! The GameStream pairing handshake, as a pure state machine plus an async
//! driver.
//!
//! Sequence (all over plain HTTP except the last step):
//!
//! ```text
//! 1. /pair?phrase=getservercert&salt=S&clientcert=C[&otpauth=O]   -> plaincert
//! 2. /pair?clientchallenge=AES(rand16)                            -> challengeresponse
//! 3. /pair?serverchallengeresp=AES(SHA256(sChal||sig(ourCert)||cSecret)) -> pairingsecret
//! 4. /pair?clientpairingsecret=cSecret||RSA(cSecret)              -> paired
//! 5. https /pair?phrase=pairchallenge                              -> paired
//! ```
//!
//! Apollo's `otpauth` lets a caller who knows a one-time PIN and passphrase
//! pair without anyone typing the PIN into the web UI:
//! `otpauth = UPPERHEX(SHA256(pin || salt_hex_string || passphrase))`.

use crate::crypto::*;
use crate::http::{GsHttp, HostAddr};
use crate::identity::Identity;
use crate::xml::Root;
use crate::Result;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("host reports server version {0} < 7; only SHA-256 pairing is supported")]
    OldServer(u32),
    #[error("host did not return paired=1")]
    NotPaired,
    #[error("another pairing is already in progress on the host")]
    AlreadyInProgress,
    #[error("wrong PIN")]
    WrongPin,
    #[error("server signature invalid (possible MITM)")]
    BadServerSignature,
    #[error("malformed response: {0}")]
    Malformed(String),
}

/// Apollo one-time-PIN credentials obtained from `POST /api/otp`.
#[derive(Debug, Clone)]
pub struct OtpAuth {
    pub pin: String,
    pub passphrase: String,
}

#[derive(Debug, Clone)]
pub struct PairOutcome {
    pub server_cert_pem: String,
}

/// Query-string fragment for step N, produced by the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub args: String,
    /// True for the final `pairchallenge` step which must go over HTTPS.
    pub https: bool,
}

/// Pure pairing state machine. Feed each server response body into `next`.
pub struct Pairing {
    identity: Identity,
    pin: String,
    salt: [u8; 16],
    aes_key: [u8; 16],
    rand_challenge: [u8; 16],
    client_secret: [u8; 16],
    server_cert_pem: Option<String>,
    server_response: Vec<u8>,
    phase: u8,
    otp: Option<OtpAuth>,
}

impl Pairing {
    /// `pin` is the 4-digit PIN. If `otp` is given, `pin` must equal `otp.pin`.
    pub fn new(identity: Identity, pin: &str, otp: Option<OtpAuth>) -> Self {
        Self::with_random(identity, pin, otp, random16(), random16(), random16())
    }

    pub fn with_random(
        identity: Identity,
        pin: &str,
        otp: Option<OtpAuth>,
        salt: [u8; 16],
        rand_challenge: [u8; 16],
        client_secret: [u8; 16],
    ) -> Self {
        let aes_key = derive_aes_key(&salt, pin);
        Self {
            identity,
            pin: pin.to_string(),
            salt,
            aes_key,
            rand_challenge,
            client_secret,
            server_cert_pem: None,
            server_response: Vec::new(),
            phase: 0,
            otp,
        }
    }

    pub fn salt_hex(&self) -> String {
        hex::encode(self.salt)
    }

    pub fn otpauth(&self) -> Option<String> {
        self.otp.as_ref().map(|o| {
            hex::encode_upper(sha256(&[o.pin.as_bytes(), self.salt_hex().as_bytes(), o.passphrase.as_bytes()]))
        })
    }

    /// Step 1 request.
    pub fn start(&self) -> Step {
        let mut args = format!(
            "devicename=roth&updateState=1&phrase=getservercert&salt={}&clientcert={}",
            self.salt_hex(),
            self.identity.cert_hex()
        );
        if let Some(o) = self.otpauth() {
            args.push_str("&otpauth=");
            args.push_str(&o);
        }
        Step { args, https: false }
    }

    /// Feed the response body to the previous step; returns the next step or
    /// `None` when pairing is complete.
    pub fn next(&mut self, body: &str) -> Result<Option<Step>> {
        let root = Root::parse(body)?;
        let paired = root.child("paired").map(|s| s.trim() == "1").unwrap_or(false);
        match self.phase {
            0 => {
                if !paired {
                    return Err(PairError::NotPaired.into());
                }
                let plaincert = root.child("plaincert").unwrap_or("").trim();
                if plaincert.is_empty() {
                    return Err(PairError::AlreadyInProgress.into());
                }
                let pem = String::from_utf8(hex::decode(plaincert)?)
                    .map_err(|e| PairError::Malformed(format!("plaincert utf8: {e}")))?;
                self.server_cert_pem = Some(pem);
                self.phase = 1;
                let enc = aes_ecb_encrypt(&self.aes_key, &self.rand_challenge)?;
                Ok(Some(Step { args: format!("devicename=roth&updateState=1&clientchallenge={}", hex::encode(enc)), https: false }))
            }
            1 => {
                if !paired {
                    return Err(PairError::NotPaired.into());
                }
                let enc = hex::decode(root.require("challengeresponse")?.trim())?;
                let dec = aes_ecb_decrypt(&self.aes_key, &enc)?;
                if dec.len() < 48 {
                    return Err(PairError::Malformed(format!("challengeresponse is {} bytes, expected >= 48", dec.len())).into());
                }
                self.server_response = dec[..32].to_vec();
                let server_challenge = &dec[32..48];
                let our_sig = cert_signature(&self.identity.cert_pem)?;
                let mut msg = server_challenge.to_vec();
                msg.extend_from_slice(&our_sig);
                msg.extend_from_slice(&self.client_secret);
                let hash = sha256(&[&msg]);
                let enc = aes_ecb_encrypt(&self.aes_key, &hash)?;
                self.phase = 2;
                Ok(Some(Step { args: format!("devicename=roth&updateState=1&serverchallengeresp={}", hex::encode(enc)), https: false }))
            }
            2 => {
                if !paired {
                    return Err(PairError::NotPaired.into());
                }
                let secret = hex::decode(root.require("pairingsecret")?.trim())?;
                if secret.len() <= 16 {
                    return Err(PairError::Malformed("pairingsecret too short".into()).into());
                }
                let (server_secret, server_sig) = secret.split_at(16);
                let server_pem = self.server_cert_pem.as_deref().expect("phase 2 requires server cert");
                let server_pk = cert_public_key(server_pem)?;
                if !verify_sha256(&server_pk, server_secret, server_sig) {
                    return Err(PairError::BadServerSignature.into());
                }
                let server_cert_sig = cert_signature(server_pem)?;
                let expect = sha256(&[&self.rand_challenge, &server_cert_sig, server_secret]);
                if expect[..] != self.server_response[..] {
                    return Err(PairError::WrongPin.into());
                }
                let mut payload = self.client_secret.to_vec();
                payload.extend_from_slice(&sign_sha256(self.identity.private_key(), &self.client_secret));
                self.phase = 3;
                Ok(Some(Step { args: format!("devicename=roth&updateState=1&clientpairingsecret={}", hex::encode(payload)), https: false }))
            }
            3 => {
                if !paired {
                    return Err(PairError::NotPaired.into());
                }
                self.phase = 4;
                Ok(Some(Step { args: "devicename=roth&updateState=1&phrase=pairchallenge".into(), https: true }))
            }
            _ => {
                if !paired {
                    return Err(PairError::NotPaired.into());
                }
                self.phase = 5;
                Ok(None)
            }
        }
    }

    pub fn server_cert_pem(&self) -> Option<&str> {
        self.server_cert_pem.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.phase == 5
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }
}

fn random16() -> [u8; 16] {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Drive a full pairing over the network. The first request blocks until the
/// host accepts the PIN (via web UI, or immediately when `otp` is given).
pub async fn pair(http: &GsHttp, addr: &HostAddr, pin: &str, otp: Option<OtpAuth>, first_step_timeout: Option<Duration>) -> Result<PairOutcome> {
    let info = http.server_info_http(addr).await?;
    let major = info.major_version();
    if major < 7 {
        return Err(PairError::OldServer(major).into());
    }
    let mut pairing = Pairing::new(http.identity().clone(), pin, otp);
    let mut step = pairing.start();
    let mut timeout = first_step_timeout;
    let short = Some(Duration::from_secs(5));
    loop {
        let body = if step.https {
            let cert = pairing.server_cert_pem().expect("https step after cert").to_string();
            http.get_https(addr, &cert, "pair", &step.args).await
        } else {
            http.get_http(addr, "pair", &step.args, timeout).await
        };
        let body = match body {
            Ok(b) => b,
            Err(e) => {
                let _ = http.unpair(addr).await;
                return Err(e);
            }
        };
        timeout = short;
        match pairing.next(&body) {
            Ok(Some(s)) => step = s,
            Ok(None) => break,
            Err(e) => {
                let _ = http.unpair(addr).await;
                return Err(e);
            }
        }
    }
    Ok(PairOutcome { server_cert_pem: pairing.server_cert_pem().unwrap().to_string() })
}

#[cfg(test)]
mod tests {
    //! Our client state machine against the simulated host in `crate::testing`.
    use super::*;
    use crate::testing::FakeHost;

    fn run(host: &mut FakeHost, mut p: Pairing) -> Result<()> {
        let mut step = p.start();
        loop {
            let body = host.handle(&step);
            match p.next(&body)? {
                Some(s) => step = s,
                None => break,
            }
        }
        assert!(p.is_complete());
        assert_eq!(p.server_cert_pem().unwrap(), host.cert_pem);
        Ok(())
    }

    #[test]
    fn full_handshake_with_correct_pin() {
        let id = Identity::generate().unwrap();
        let mut host = FakeHost::new("1234");
        run(&mut host, Pairing::new(id, "1234", None)).unwrap();
    }

    #[test]
    fn wrong_pin_is_detected_client_side() {
        let id = Identity::generate().unwrap();
        let mut host = FakeHost::new("1234");
        let err = run(&mut host, Pairing::new(id, "4321", None)).unwrap_err();
        assert!(matches!(err, crate::Error::Pair(PairError::WrongPin)), "{err:?}");
    }

    #[test]
    fn otp_auth_pairs_without_pin_entry() {
        let id = Identity::generate().unwrap();
        let mut host = FakeHost::new("0000");
        host.otp = Some(("5678".into(), "secretphrase".into()));
        let otp = OtpAuth { pin: "5678".into(), passphrase: "secretphrase".into() };
        run(&mut host, Pairing::new(id.clone(), "5678", Some(otp))).unwrap();
        // wrong passphrase -> host silently uses a garbage pin -> WrongPin
        let otp = OtpAuth { pin: "5678".into(), passphrase: "nope".into() };
        let err = run(&mut host, Pairing::new(id, "5678", Some(otp))).unwrap_err();
        assert!(matches!(err, crate::Error::Pair(PairError::WrongPin)), "{err:?}");
    }

    #[test]
    fn tampered_server_signature_is_rejected() {
        let id = Identity::generate().unwrap();
        let mut host = FakeHost::new("1234");
        let mut p = Pairing::new(id, "1234", None);
        let s1 = p.start();
        let s2 = p.next(&host.handle(&s1)).unwrap().unwrap();
        let s3 = p.next(&host.handle(&s2)).unwrap().unwrap();
        // forge pairingsecret with a different key
        let other = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let mut out = host.server_secret.to_vec();
        out.extend_from_slice(&sign_sha256(&other, &host.server_secret));
        let _ = s3;
        let body = format!("<root status_code=\"200\"><paired>1</paired><pairingsecret>{}</pairingsecret></root>", hex::encode(out));
        let err = p.next(&body).unwrap_err();
        assert!(matches!(err, crate::Error::Pair(PairError::BadServerSignature)), "{err:?}");
    }
}
