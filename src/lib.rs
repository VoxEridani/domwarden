//! Domwarden checks domains for expiring certificates and registrations, broken DNS,
//! email authentication records (SPF, DKIM, DMARC) and site availability, and sends
//! the problems it finds to Telegram, email or webhooks.

pub mod checks;
pub mod config;
pub mod dns;
pub mod i18n;
pub mod model;
pub mod notify;
pub mod report;

pub use checks::{Checker, Target};
pub use config::Config;
pub use i18n::Lang;
pub use model::{CheckKind, CheckResult, DomainReport, Finding, Group, Report, Status};

pub const USER_AGENT: &str = concat!(
    "Domwarden/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/VoxEridani/domwarden)"
);

/// Installs the TLS crypto provider used by every HTTPS client. Safe to call repeatedly.
pub fn init_tls() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Wrappers that add nothing to the underlying error.
const GENERIC_ERRORS: &[&str] = &[
    "error sending request",
    "client error (Connect)",
    "client error (SendRequest)",
];

/// An error with its causes: "tcp connect error: connection refused".
pub(crate) fn describe_error(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut current = Some(err);
    while let Some(error) = current {
        let text = error.to_string();
        if !text.is_empty()
            && !GENERIC_ERRORS.contains(&text.as_str())
            && !parts.iter().any(|part| part.contains(&text))
        {
            parts.push(text);
        }
        current = error.source();
    }
    if parts.is_empty() {
        err.to_string()
    } else {
        parts.join(": ")
    }
}
