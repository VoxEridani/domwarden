//! Email over SMTP.

use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use super::Message;
use crate::config::{EmailConfig, Security};

pub async fn send(
    config: &EmailConfig,
    message: &Message,
    timeout: Duration,
) -> Result<(), String> {
    let security = config.security.unwrap_or(match config.port {
        Some(25 | 587) => Security::Starttls,
        _ => Security::Tls,
    });
    let host = config.host.trim();
    let builder = match security {
        Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
        Security::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
        Security::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            host,
        )),
    }
    .map_err(|e| e.to_string())?;
    let port = config.port.unwrap_or(match security {
        Security::Tls => 465,
        Security::Starttls => 587,
        Security::None => 25,
    });
    let mut builder = builder.port(port).timeout(Some(timeout));
    if let Some(password) = &config.password {
        // Most providers use the full address as the login.
        let user = config
            .username
            .clone()
            .unwrap_or_else(|| config.from.clone());
        builder = builder.credentials(Credentials::new(user, password.clone()));
    }
    let transport = builder.build();

    let from: Mailbox = config
        .from
        .parse()
        .map_err(|e| format!("from = \"{}\": {e}", config.from))?;
    let mut mail = lettre::Message::builder()
        .from(from)
        .subject(&message.title);
    if config.to.is_empty() {
        return Err("to is empty".into());
    }
    for to in &config.to {
        let mailbox: Mailbox = to.parse().map_err(|e| format!("to = \"{to}\": {e}"))?;
        mail = mail.to(mailbox);
    }
    let html = format!(
        "<div style=\"font-family:sans-serif;font-size:14px\">{}</div>",
        message.html.replace('\n', "<br>\n")
    );
    let text = format!("{}\n\n{}", message.title, message.text);
    let mail = mail
        .multipart(MultiPart::alternative_plain_html(text, html))
        .map_err(|e| e.to_string())?;
    transport.send(mail).await.map_err(|e| smtp_error(&e))?;
    Ok(())
}

fn smtp_error(err: &lettre::transport::smtp::Error) -> String {
    let mut text = crate::describe_error(err);
    let lower = text.to_lowercase();
    if lower.contains("535") || lower.contains("authentication") || lower.contains("credentials") {
        text.push_str(
            " (check the login; Gmail, Yandex and Mail.ru need an app password, not the usual one)",
        );
    }
    text
}
