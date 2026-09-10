//! Client identity: a 2048-bit RSA key and a self-signed certificate with
//! `CN=NVIDIA GameStream Client`, plus a 16-hex-char `uniqueid`. Mirrors
//! `moonlight-qt/app/backend/identitymanager.cpp`.

use crate::{Error, Result};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::RsaPrivateKey;
use std::path::{Path, PathBuf};

pub const CERT_FILE: &str = "client.crt";
pub const KEY_FILE: &str = "client.key";
pub const UID_FILE: &str = "uniqueid";

#[derive(Clone)]
pub struct Identity {
    pub unique_id: String,
    pub cert_pem: String,
    pub key_pem: String,
    key: RsaPrivateKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("unique_id", &self.unique_id).finish()
    }
}

impl Identity {
    /// Generate a fresh identity (slow: RSA-2048 keygen).
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| Error::Identity(e.to_string()))?;
        let key_pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::Identity(e.to_string()))?
            .to_string();
        let cert_pem = self_signed_cert(&key_pem, "NVIDIA GameStream Client")?;
        Ok(Self { unique_id: random_unique_id(), cert_pem, key_pem, key })
    }

    pub fn from_pem(unique_id: String, cert_pem: String, key_pem: String) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
            .or_else(|_| {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                RsaPrivateKey::from_pkcs1_pem(&key_pem)
            })
            .map_err(|e| Error::Identity(format!("private key: {e}")))?;
        Ok(Self { unique_id, cert_pem, key_pem, key })
    }

    /// Load from `dir`, generating and saving a new identity if absent.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let cert = dir.join(CERT_FILE);
        let key = dir.join(KEY_FILE);
        let uid = dir.join(UID_FILE);
        if cert.exists() && key.exists() && uid.exists() {
            return Self::from_pem(
                std::fs::read_to_string(&uid)?.trim().to_string(),
                std::fs::read_to_string(&cert)?,
                std::fs::read_to_string(&key)?,
            );
        }
        std::fs::create_dir_all(dir)?;
        let id = Self::generate()?;
        id.save(dir)?;
        Ok(id)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join(CERT_FILE), &self.cert_pem)?;
        write_private(&dir.join(KEY_FILE), self.key_pem.as_bytes())?;
        std::fs::write(dir.join(UID_FILE), &self.unique_id)?;
        Ok(())
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.key
    }

    /// Hex encoding of the PEM text, as sent in the `clientcert` query param.
    pub fn cert_hex(&self) -> String {
        hex::encode(self.cert_pem.as_bytes())
    }

    pub fn default_dir() -> PathBuf {
        dirs_fallback().join("identity")
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn dirs_fallback() -> PathBuf {
    if let Some(p) = std::env::var_os("RA_HOME") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("remote-access")
}

/// Moonlight renders 8 random bytes as lowercase hex without zero padding;
/// we always emit 16 hex chars, which Apollo accepts as-is.
pub fn random_unique_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Build a self-signed X.509 v3 certificate valid for 20 years.
pub fn self_signed_cert(key_pkcs8_pem: &str, common_name: &str) -> Result<String> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256};
    let kp = KeyPair::from_pkcs8_pem_and_sign_algo(key_pkcs8_pem, &PKCS_RSA_SHA256)
        .map_err(|e| Error::Identity(format!("rcgen key: {e}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| Error::Identity(format!("rcgen params: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 20);
    let cert = params.self_signed(&kp).map_err(|e| Error::Identity(format!("rcgen sign: {e}")))?;
    Ok(cert.pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ra-id-test-{}", std::process::id()));
        let a = Identity::load_or_create(&dir).unwrap();
        let b = Identity::load_or_create(&dir).unwrap();
        assert_eq!(a.unique_id, b.unique_id);
        assert_eq!(a.cert_pem, b.cert_pem);
        assert!(a.cert_pem.contains("BEGIN CERTIFICATE"));
        // signature from cert must verify with the cert's own key
        let sig = crate::crypto::cert_signature(&a.cert_pem).unwrap();
        assert_eq!(sig.len(), 256);
        let pk = crate::crypto::cert_public_key(&a.cert_pem).unwrap();
        let s = crate::crypto::sign_sha256(a.private_key(), b"hello");
        assert!(crate::crypto::verify_sha256(&pk, b"hello", &s));
        assert!(!crate::crypto::verify_sha256(&pk, b"hellp", &s));
        std::fs::remove_dir_all(&dir).ok();
    }
}
