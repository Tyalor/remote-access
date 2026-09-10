//! HTTP/HTTPS transport for GameStream requests.
//!
//! Every request carries `uniqueid=<client uid>&uuid=<random 16 bytes hex>`
//! first, as Moonlight does. HTTPS uses the client identity as TLS client
//! certificate and *pins* the host's self-signed certificate instead of
//! doing PKI validation.

use crate::identity::Identity;
use crate::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    pub host: String,
    pub http_port: u16,
    pub https_port: u16,
}

impl HostAddr {
    pub fn new(host: impl Into<String>, base_port: u16) -> Self {
        Self { host: host.into(), http_port: base_port, https_port: base_port.wrapping_sub(5) }
    }

    fn fmt_host(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    pub fn http_base(&self) -> String {
        format!("http://{}:{}", self.fmt_host(), self.http_port)
    }

    pub fn https_base(&self) -> String {
        format!("https://{}:{}", self.fmt_host(), self.https_port)
    }
}

/// Verifier that accepts exactly one DER certificate.
#[derive(Debug)]
struct PinnedCert {
    der: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate does not match pinned certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// GameStream HTTP client bound to one identity.
#[derive(Clone)]
pub struct GsHttp {
    identity: Arc<Identity>,
    plain: reqwest::Client,
}

impl GsHttp {
    pub fn new(identity: Identity) -> Result<Self> {
        let plain = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()?;
        Ok(Self { identity: Arc::new(identity), plain })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    fn query_prefix(&self) -> String {
        use rand::RngCore;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        format!("uniqueid={}&uuid={}", self.identity.unique_id, hex::encode(b))
    }

    pub fn url(&self, base: &str, command: &str, args: &str) -> String {
        if args.is_empty() {
            format!("{base}/{command}?{}", self.query_prefix())
        } else {
            format!("{base}/{command}?{}&{args}", self.query_prefix())
        }
    }

    /// Plain HTTP GET, returning the body. `timeout` of `None` waits forever
    /// (needed for `getservercert`, which parks until the PIN is entered).
    pub async fn get_http(&self, addr: &HostAddr, command: &str, args: &str, timeout: Option<Duration>) -> Result<String> {
        let url = self.url(&addr.http_base(), command, args);
        tracing::debug!(%url, "GET");
        let mut req = self.plain.get(&url);
        req = match timeout {
            Some(t) => req.timeout(t),
            None => req.timeout(Duration::from_secs(60 * 60)),
        };
        Ok(req.send().await?.error_for_status()?.text().await?)
    }

    /// Build an HTTPS client that authenticates with our cert and pins `server_cert_pem`.
    pub fn https_client(&self, server_cert_pem: &str) -> Result<reqwest::Client> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_der = crate::crypto::pem_to_der(server_cert_pem)?;
        let client_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.identity.cert_pem.as_bytes())
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| Error::Tls(format!("client cert: {e}")))?;
        let client_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut self.identity.key_pem.as_bytes())
            .map_err(|e| Error::Tls(format!("client key: {e}")))?
            .ok_or_else(|| Error::Tls("no private key in identity".into()))?;
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert { der: server_der, provider }))
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        Ok(reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .build()?)
    }

    pub async fn get_https(&self, addr: &HostAddr, server_cert_pem: &str, command: &str, args: &str) -> Result<String> {
        let client = self.https_client(server_cert_pem)?;
        let url = self.url(&addr.https_base(), command, args);
        tracing::debug!(%url, "GET (https)");
        Ok(client.get(&url).send().await?.error_for_status()?.text().await?)
    }

    /// `/serverinfo` over plain HTTP (works unpaired).
    pub async fn server_info_http(&self, addr: &HostAddr) -> Result<crate::ServerInfo> {
        let body = self.get_http(addr, "serverinfo", "", Some(Duration::from_secs(3))).await?;
        crate::ServerInfo::parse(&body)
    }

    /// `/serverinfo` over HTTPS with our cert; `paired` will be true if the
    /// host knows us.
    pub async fn server_info_https(&self, addr: &HostAddr, server_cert_pem: &str) -> Result<crate::ServerInfo> {
        let body = self.get_https(addr, server_cert_pem, "serverinfo", "").await?;
        crate::ServerInfo::parse(&body)
    }

    pub async fn app_list(&self, addr: &HostAddr, server_cert_pem: &str) -> Result<Vec<crate::App>> {
        let body = self.get_https(addr, server_cert_pem, "applist", "").await?;
        crate::apps::parse_applist(&body)
    }

    /// Ask the host to forget us.
    pub async fn unpair(&self, addr: &HostAddr) -> Result<()> {
        self.get_http(addr, "unpair", "", Some(Duration::from_secs(3))).await?;
        Ok(())
    }
}
