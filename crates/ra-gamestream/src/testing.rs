//! A simulated Apollo host: the *server* side of the pairing handshake as
//! implemented in `apollo/src/nvhttp.cpp`. Used by unit tests and by the
//! `ra-fakehost` end-to-end tool.

use crate::crypto::*;
use crate::pairing::Step;
use rsa::pkcs8::EncodePrivateKey;

pub struct FakeHost {
    pub key: rsa::RsaPrivateKey,
    pub cert_pem: String,
    pub pin: String,
    pub aes_key: Option<[u8; 16]>,
    pub server_secret: [u8; 16],
    pub server_challenge: [u8; 16],
    pub client_cert_pem: Option<String>,
    pub client_hash: Vec<u8>,
    pub otp: Option<(String, String)>,
}

impl FakeHost {
    pub fn new(pin: &str) -> Self {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
        let cert_pem = crate::identity::self_signed_cert(&pem, "Sunshine Gamestream Host").unwrap();
        Self { key, cert_pem, pin: pin.into(), aes_key: None, server_secret: [3u8; 16], server_challenge: [4u8; 16], client_cert_pem: None, client_hash: vec![], otp: None }
    }

    pub fn param<'a>(args: &'a str, key: &str) -> Option<&'a str> {
        args.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}=")))
    }

    /// Handle one client step and produce the XML body Apollo would send.
    pub fn handle(&mut self, step: &Step) -> String {
        let a = &step.args;
        if step.https {
            return "<root status_code=\"200\"><paired>1</paired></root>".into();
        }
        if Self::param(a, "phrase") == Some("getservercert") {
            let salt_hex = Self::param(a, "salt").unwrap();
            let salt: [u8; 16] = hex::decode(salt_hex).unwrap()[..16].try_into().unwrap();
            let client_pem = String::from_utf8(hex::decode(Self::param(a, "clientcert").unwrap()).unwrap()).unwrap();
            self.client_cert_pem = Some(client_pem);
            let mut pin = self.pin.clone();
            if let Some(otpauth) = Self::param(a, "otpauth") {
                let (opin, pass) = self.otp.clone().expect("otp configured");
                let expect = hex::encode_upper(sha256(&[opin.as_bytes(), salt_hex.as_bytes(), pass.as_bytes()]));
                pin = if expect == otpauth { opin } else { "9999".into() }; // wrong -> garbage pin
            }
            self.aes_key = Some(derive_aes_key(&salt, &pin));
            return format!("<root status_code=\"200\"><paired>1</paired><plaincert>{}</plaincert></root>", hex::encode(self.cert_pem.as_bytes()));
        }
        if let Some(cc) = Self::param(a, "clientchallenge") {
            let key = self.aes_key.unwrap();
            let dec = aes_ecb_decrypt(&key, &hex::decode(cc).unwrap()).unwrap();
            let sig = cert_signature(&self.cert_pem).unwrap();
            let mut msg = dec;
            msg.extend_from_slice(&sig);
            msg.extend_from_slice(&self.server_secret);
            let mut out = sha256(&[&msg]).to_vec();
            out.extend_from_slice(&self.server_challenge);
            let enc = aes_ecb_encrypt(&key, &out).unwrap();
            return format!("<root status_code=\"200\"><paired>1</paired><challengeresponse>{}</challengeresponse></root>", hex::encode(enc));
        }
        if let Some(sr) = Self::param(a, "serverchallengeresp") {
            let key = self.aes_key.unwrap();
            self.client_hash = aes_ecb_decrypt(&key, &hex::decode(sr).unwrap()).unwrap();
            let mut out = self.server_secret.to_vec();
            out.extend_from_slice(&sign_sha256(&self.key, &self.server_secret));
            return format!("<root status_code=\"200\"><paired>1</paired><pairingsecret>{}</pairingsecret></root>", hex::encode(out));
        }
        if let Some(cps) = Self::param(a, "clientpairingsecret") {
            let raw = hex::decode(cps).unwrap();
            let (secret, sig) = raw.split_at(16);
            let client_pem = self.client_cert_pem.as_ref().unwrap();
            let client_sig = cert_signature(client_pem).unwrap();
            let expect = sha256(&[&self.server_challenge, &client_sig, secret]);
            let hash_ok = expect[..] == self.client_hash[..32];
            let sig_ok = verify_sha256(&cert_public_key(client_pem).unwrap(), secret, sig);
            let paired = if hash_ok && sig_ok { 1 } else { 0 };
            return format!("<root status_code=\"200\"><paired>{paired}</paired></root>");
        }
        panic!("unexpected step {a}");
    }
}


impl FakeHost {
    /// Dispatch a raw `/pair` query string (without the leading `?`).
    pub fn handle_query(&mut self, query: &str, https: bool) -> String {
        self.handle(&Step { args: query.to_string(), https })
    }
}
