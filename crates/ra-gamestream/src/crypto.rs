//! Primitives used by the pairing handshake: AES-128-ECB (no padding),
//! SHA-256, RSA PKCS#1 v1.5 signatures, and certificate helpers.

use crate::{Error, Result};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer, Verifier};

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// AES key = first 16 bytes of `SHA256(salt || pin)`. GFE < 7 used SHA-1,
/// which Apollo and Sunshine never report, so it is not supported here.
pub fn derive_aes_key(salt: &[u8; 16], pin: &str) -> [u8; 16] {
    let d = sha256(&[salt, pin.as_bytes()]);
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    k
}

fn check_block_len(data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(Error::Crypto(format!("AES-ECB input length {} is not a multiple of 16", data.len())));
    }
    Ok(())
}

pub fn aes_ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    check_block_len(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}

pub fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    check_block_len(data)?;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}

/// Parse a PEM certificate into DER.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor).collect::<std::result::Result<_, _>>()?;
    certs
        .into_iter()
        .next()
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| Error::Crypto("no certificate found in PEM".into()))
}

/// The raw signature bit-string of an X.509 certificate (what Moonlight's
/// `getSignatureFromCert` returns).
pub fn cert_signature(pem: &str) -> Result<Vec<u8>> {
    let der = pem_to_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| Error::Crypto(format!("x509 parse: {e}")))?;
    Ok(cert.signature_value.data.to_vec())
}

/// RSA public key embedded in a PEM certificate.
pub fn cert_public_key(pem: &str) -> Result<RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let der = pem_to_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| Error::Crypto(format!("x509 parse: {e}")))?;
    let spki = &cert.tbs_certificate.subject_pki.subject_public_key.data;
    RsaPublicKey::from_pkcs1_der(spki).map_err(|e| Error::Crypto(format!("rsa pubkey: {e}")))
}

/// RSA PKCS#1 v1.5 + SHA-256 signature, as `EVP_DigestSign` with `EVP_sha256`.
pub fn sign_sha256(key: &RsaPrivateKey, msg: &[u8]) -> Vec<u8> {
    let sk = SigningKey::<Sha256>::new(key.clone());
    sk.sign(msg).to_vec()
}

pub fn verify_sha256(key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let vk = VerifyingKey::<Sha256>::new(key.clone());
    match Signature::try_from(sig) {
        Ok(s) => vk.verify(msg, &s).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip_and_length_check() {
        let key = derive_aes_key(&[7u8; 16], "1234");
        let pt = [1u8; 48];
        let ct = aes_ecb_encrypt(&key, &pt).unwrap();
        assert_ne!(ct, pt);
        assert_eq!(aes_ecb_decrypt(&key, &ct).unwrap(), pt);
        assert!(aes_ecb_encrypt(&key, &[0u8; 20]).is_err());
    }

    #[test]
    fn derive_key_matches_moonlight_layout() {
        // salt || "1234" hashed with SHA-256, truncated to 16 bytes.
        let salt = [0xABu8; 16];
        let mut expect = Sha256::new();
        expect.update(salt);
        expect.update(b"1234");
        let d: [u8; 32] = expect.finalize().into();
        assert_eq!(derive_aes_key(&salt, "1234"), d[..16]);
    }
}
