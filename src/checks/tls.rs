//! The TLS certificate a host presents.
//!
//! The handshake accepts any certificate so that broken ones can still be inspected;
//! trust is then checked separately against the Mozilla root list that browsers use.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_name};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, ProtocolVersion, RootCertStore,
    SignatureScheme,
};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_PKCS1_SHA1WITHRSA;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use super::{Host, date};
use crate::config::Settings;
use crate::i18n::{Lang, days};
use crate::model::{CheckKind, CheckResult, Status};
use crate::tr;

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

fn browser_verifier() -> Option<Arc<WebPkiServerVerifier>> {
    static VERIFIER: OnceLock<Option<Arc<WebPkiServerVerifier>>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .ok()
        })
        .clone()
}

/// Accepts every certificate and remembers the chain the server sent.
#[derive(Debug)]
struct Capture {
    provider: Arc<CryptoProvider>,
    chain: Mutex<Vec<CertificateDer<'static>>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.clone().into_owned()];
        chain.extend(intermediates.iter().map(|cert| cert.clone().into_owned()));
        *self.chain.lock().unwrap() = chain;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Handshake {
    chain: Vec<CertificateDer<'static>>,
    version: Option<ProtocolVersion>,
}

enum HandshakeError {
    Connect(String),
    Tls(String),
}

async fn handshake(host: &Host, wait: Duration, lang: Lang) -> Result<Handshake, HandshakeError> {
    let secs = wait.as_secs();
    let timed_out = || tr!(lang, "no answer within {secs} s", "нет ответа за {secs} с");
    let provider = provider();
    let capture = Arc::new(Capture {
        provider: provider.clone(),
        chain: Mutex::default(),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| HandshakeError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.name.clone())
        .map_err(|e| HandshakeError::Connect(e.to_string()))?;

    let tcp = timeout(wait, TcpStream::connect((host.name.as_str(), host.port)))
        .await
        .map_err(|_| HandshakeError::Connect(timed_out()))?
        .map_err(|e| HandshakeError::Connect(e.to_string()))?;
    let stream = timeout(
        wait,
        TlsConnector::from(Arc::new(config)).connect(server_name, tcp),
    )
    .await
    .map_err(|_| HandshakeError::Tls(timed_out()))?
    .map_err(|e| HandshakeError::Tls(e.to_string()))?;
    let version = stream.get_ref().1.protocol_version();
    let chain = std::mem::take(&mut *capture.chain.lock().unwrap());
    if chain.is_empty() {
        return Err(HandshakeError::Tls("the server sent no certificate".into()));
    }
    Ok(Handshake { chain, version })
}

pub async fn check(
    host: &Host,
    settings: &Settings,
    lang: Lang,
    now: OffsetDateTime,
) -> CheckResult {
    let label = host.label();
    let mut result = CheckResult::new(CheckKind::Tls, &label);

    let handshake = match handshake(host, settings.timeout(), lang).await {
        Ok(handshake) => handshake,
        Err(HandshakeError::Connect(err)) => {
            result.add(
                Status::Critical,
                "tls.connect",
                tr!(
                    lang,
                    "can't connect over HTTPS: {err}",
                    "не удаётся подключиться по HTTPS: {err}"
                ),
            );
            return result;
        }
        Err(HandshakeError::Tls(err)) => {
            let hint = if err.contains("ProtocolVersion") || err.contains("HandshakeFailure") {
                tr!(
                    lang,
                    " (the server probably supports only outdated TLS 1.0/1.1 or old ciphers)",
                    " (похоже, сервер поддерживает только устаревшие TLS 1.0/1.1 или старые шифры)"
                )
            } else {
                String::new()
            };
            result.add(
                Status::Critical,
                "tls.handshake",
                tr!(
                    lang,
                    "secure connection failed: {err}{hint}",
                    "не удалось установить защищённое соединение: {err}{hint}"
                ),
            );
            return result;
        }
    };

    let Ok((_, cert)) = X509Certificate::from_der(&handshake.chain[0]) else {
        result.add(
            Status::Critical,
            "tls.bad_certificate",
            tr!(
                lang,
                "the server sent a certificate that can't be read",
                "сервер прислал сертификат, который невозможно прочитать"
            ),
        );
        return result;
    };

    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let days_left = (not_after - now).whole_days();
    let issuer = issuer_name(&cert);
    let names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let self_signed = cert.issuer().as_raw() == cert.subject().as_raw();
    let version = match handshake.version {
        Some(ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "",
    };

    let until = date(not_after);
    let left = days(lang, days_left.max(0));
    let mut summary = if not_after < now {
        tr!(
            lang,
            "expired on {until} · issued by {issuer}",
            "истёк {until} · выдан {issuer}"
        )
    } else {
        tr!(
            lang,
            "valid until {until} ({left} left) · issued by {issuer}",
            "действует до {until} (осталось {left}) · выдан {issuer}"
        )
    };
    if !version.is_empty() {
        summary.push_str(" · ");
        summary.push_str(version);
    }
    result.summary(summary);
    result
        .fact("not_after", not_after.unix_timestamp())
        .fact("expires", until.clone())
        .fact("days_left", days_left)
        .fact("issuer", issuer.clone())
        .fact("names", names.clone());
    if !version.is_empty() {
        result.fact("protocol", version);
    }

    if not_after < now {
        let ago = days(lang, (now - not_after).whole_days().max(1));
        result.add(
            Status::Critical,
            "tls.expired",
            tr!(
                lang,
                "the certificate expired {ago} ago — browsers show visitors a security error",
                "сертификат истёк {ago} назад — браузеры показывают посетителям ошибку безопасности"
            ),
        );
    } else if not_before > now {
        let from = date(not_before);
        result.add(
            Status::Critical,
            "tls.not_yet_valid",
            tr!(
                lang,
                "the certificate only becomes valid on {from}",
                "сертификат начнёт действовать только {from}"
            ),
        );
    } else if days_left <= settings.cert_critical_days {
        result.add(
            Status::Critical,
            "tls.expiring",
            tr!(
                lang,
                "the certificate expires in {left} — renew it now",
                "сертификат истекает через {left} — обновите его сейчас"
            ),
        );
    } else if days_left <= settings.cert_warning_days {
        result.add(
            Status::Warning,
            "tls.expiring",
            tr!(
                lang,
                "the certificate expires in {left} — check that automatic renewal works",
                "сертификат истекает через {left} — проверьте, работает ли автопродление"
            ),
        );
    }

    if !name_matches(&handshake.chain[0], &host.name) {
        let covered = if names.is_empty() {
            subject_name(&cert)
        } else {
            names.join(", ")
        };
        result.add(
            Status::Critical,
            "tls.name_mismatch",
            tr!(
                lang,
                "the certificate is for other names: {covered}",
                "сертификат выдан для других имён: {covered}"
            ),
        );
    }

    // Check trust at a moment inside the certificate's validity,
    // so an expired certificate still gets its other problems reported.
    let (low, high) = (
        not_before + time::Duration::minutes(1),
        not_after - time::Duration::minutes(1),
    );
    let moment = if low <= high {
        now.clamp(low, high)
    } else {
        now
    };
    if let Some(err) = verify(&handshake.chain, &host.name, moment) {
        let trust = Trust {
            self_signed,
            issuer: &issuer,
            chain_len: handshake.chain.len(),
        };
        trust_problem(&mut result, err, &trust, lang);
    }

    if cert.signature_algorithm.algorithm == OID_PKCS1_SHA1WITHRSA {
        result.add(
            Status::Warning,
            "tls.weak_signature",
            tr!(
                lang,
                "the certificate is signed with outdated SHA-1",
                "сертификат подписан устаревшим алгоритмом SHA-1"
            ),
        );
    }
    if let Ok(PublicKey::RSA(rsa)) = cert.public_key().parsed() {
        let bits = rsa.key_size();
        if bits > 0 && bits < 2048 {
            result.add(
                Status::Warning,
                "tls.weak_key",
                tr!(
                    lang,
                    "the certificate uses a weak {bits}-bit RSA key",
                    "в сертификате слабый RSA-ключ на {bits} бит"
                ),
            );
        }
    }
    result
}

fn verify(
    chain: &[CertificateDer<'static>],
    host: &str,
    moment: OffsetDateTime,
) -> Option<rustls::Error> {
    let verifier = browser_verifier()?;
    let name = ServerName::try_from(host.to_string()).ok()?;
    let seconds = u64::try_from(moment.unix_timestamp()).unwrap_or_default();
    let at = UnixTime::since_unix_epoch(Duration::from_secs(seconds));
    verifier
        .verify_server_cert(&chain[0], &chain[1..], &name, &[], at)
        .err()
}

fn name_matches(cert: &CertificateDer<'_>, host: &str) -> bool {
    let (Ok(parsed), Ok(name)) = (
        ParsedCertificate::try_from(cert),
        ServerName::try_from(host.to_string()),
    ) else {
        return true;
    };
    verify_server_name(&parsed, &name).is_ok()
}

struct Trust<'a> {
    self_signed: bool,
    issuer: &'a str,
    chain_len: usize,
}

fn trust_problem(result: &mut CheckResult, err: rustls::Error, trust: &Trust<'_>, lang: Lang) {
    let rustls::Error::InvalidCertificate(err) = err else {
        result.add(Status::Critical, "tls.invalid", err.to_string());
        return;
    };
    let issuer = trust.issuer;
    let (code, message) = match err {
        // Reported separately by name_matches.
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            return;
        }
        CertificateError::UnknownIssuer if trust.self_signed => (
            "tls.self_signed",
            tr!(
                lang,
                "the certificate is self-signed — browsers don't trust it",
                "сертификат самоподписанный — браузеры ему не доверяют"
            ),
        ),
        CertificateError::UnknownIssuer if issuer.contains("Russian Trusted") => (
            "tls.russian_ca",
            tr!(
                lang,
                "the certificate is issued by the Russian Trusted CA: only Yandex Browser and Atom trust it, other browsers show an error",
                "сертификат выдан НУЦ Минцифры: ему доверяют только Яндекс Браузер и Атом, остальные браузеры покажут ошибку"
            ),
        ),
        CertificateError::UnknownIssuer if trust.chain_len == 1 => (
            "tls.incomplete_chain",
            tr!(
                lang,
                "the server doesn't send the intermediate certificate: some browsers and most apps and scripts will refuse to connect",
                "сервер не отдаёт промежуточный сертификат: часть браузеров и большинство приложений и скриптов не смогут подключиться"
            ),
        ),
        CertificateError::UnknownIssuer => (
            "tls.untrusted",
            tr!(
                lang,
                "the certificate isn't issued by a trusted authority (issuer: {issuer})",
                "сертификат выдан не доверенным центром (издатель: {issuer})"
            ),
        ),
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => (
            "tls.chain_expired",
            tr!(
                lang,
                "an intermediate certificate in the chain has expired",
                "в цепочке есть просроченный промежуточный сертификат"
            ),
        ),
        CertificateError::Revoked => (
            "tls.revoked",
            tr!(
                lang,
                "the certificate has been revoked",
                "сертификат отозван"
            ),
        ),
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => return,
        other => (
            "tls.invalid",
            tr!(
                lang,
                "the certificate is invalid: {other:?}",
                "сертификат недействителен: {other:?}"
            ),
        ),
    };
    result.add(Status::Critical, code, message);
}

fn issuer_name(cert: &X509Certificate<'_>) -> String {
    let issuer = cert.issuer();
    let org = issuer
        .iter_organization()
        .next()
        .and_then(|attr| attr.as_str().ok());
    let common = issuer
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok());
    match (org, common) {
        (Some(org), Some(common)) if org != common => format!("{org} ({common})"),
        (Some(name), _) | (None, Some(name)) => name.to_string(),
        (None, None) => "?".to_string(),
    }
}

fn subject_name(cert: &X509Certificate<'_>) -> String {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("?")
        .to_string()
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    /// Serves a self-signed certificate for `localhost` that expires in three days.
    async fn serve_test_certificate() -> u16 {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(30);
        params.not_after = now + time::Duration::days(3) + time::Duration::hours(1);
        let cert = params.self_signed(&key).unwrap();
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn reports_expiring_self_signed_certificate() {
        let port = serve_test_certificate().await;
        let host = Host {
            name: "localhost".into(),
            port,
        };
        let result = check(
            &host,
            &Settings::default(),
            Lang::En,
            OffsetDateTime::now_utc(),
        )
        .await;
        let codes: Vec<_> = result.findings.iter().map(|f| f.code).collect();
        assert_eq!(result.status, Status::Critical, "{result:?}");
        assert!(codes.contains(&"tls.expiring"), "{codes:?}");
        assert!(codes.contains(&"tls.self_signed"), "{codes:?}");
        assert_eq!(result.facts["days_left"], 3);
    }
}
