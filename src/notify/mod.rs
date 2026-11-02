//! Sending the results to Telegram, email and webhooks.

mod email;
mod telegram;
mod webhook;

use std::fmt::Write;
use std::time::Duration;

use futures::future::join_all;

use crate::config::NotifyConfig;
use crate::i18n::{self, Lang};
use crate::model::{Report, Status};
use crate::tr;

/// A notification in the forms the channels need.
#[derive(Debug, Clone)]
pub struct Message {
    pub title: String,
    pub text: String,
    /// Telegram-flavoured HTML (only <b>, line breaks are plain newlines).
    pub html: String,
    pub status: Status,
}

/// Lists every problem found, grouped by domain.
pub fn compose(report: &Report, lang: Lang) -> Message {
    let affected: Vec<_> = report
        .domains
        .iter()
        .filter(|d| d.status.is_problem())
        .collect();
    let title = if affected.is_empty() {
        tr!(
            lang,
            "Domwarden: all {} are fine",
            "Domwarden: всё в порядке ({})",
            i18n::domains(lang, report.domains.len())
        )
    } else {
        let problems = i18n::problems(lang, report.problem_count());
        let count = affected.len();
        match lang {
            Lang::En => format!("Domwarden: {problems} in {}", i18n::domains(lang, count)),
            Lang::Ru if count == 1 => format!("Domwarden: {problems} в 1 домене"),
            Lang::Ru => format!("Domwarden: {problems} в {count} доменах"),
        }
    };

    let mut text = String::new();
    let mut html = format!("<b>{}</b>\n", escape(&title));
    if affected.is_empty() {
        for domain in &report.domains {
            let _ = writeln!(text, "{} {}", domain.status.icon(), domain.domain);
            let _ = writeln!(html, "{} {}", domain.status.icon(), escape(&domain.domain));
        }
    }
    for domain in affected {
        let _ = writeln!(text, "\n{} {}", domain.status.icon(), domain.domain);
        let _ = writeln!(
            html,
            "\n<b>{} {}</b>",
            domain.status.icon(),
            escape(&domain.domain)
        );
        for check in &domain.checks {
            let label = check.kind.label(lang);
            let place = if check.subject == domain.domain {
                label.to_string()
            } else {
                format!("{label} {}", check.subject)
            };
            for finding in check.findings.iter().filter(|f| f.status.is_problem()) {
                let _ = writeln!(
                    text,
                    "  {} {place}: {}",
                    finding.status.icon(),
                    finding.message
                );
                let _ = writeln!(
                    html,
                    "{} <b>{}</b>: {}",
                    finding.status.icon(),
                    escape(&place),
                    escape(&finding.message)
                );
            }
        }
    }
    Message {
        title,
        text: text.trim_start_matches('\n').to_string(),
        html: html.trim_end().to_string(),
        status: report.status,
    }
}

/// The message sent by `domwarden notify-test`.
pub fn test_message(lang: Lang) -> Message {
    let title = tr!(
        lang,
        "Domwarden: test notification",
        "Domwarden: проверка оповещений"
    );
    let text = tr!(
        lang,
        "If you can read this, notifications work.",
        "Если вы это читаете, оповещения работают."
    );
    Message {
        html: format!("<b>{}</b>\n{}", escape(&title), escape(&text)),
        title,
        text,
        status: Status::Ok,
    }
}

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub struct Outcome {
    pub channel: String,
    pub result: Result<(), String>,
}

pub struct Notifier {
    config: NotifyConfig,
    http: reqwest::Client,
    timeout: Duration,
}

impl Notifier {
    pub fn new(config: NotifyConfig, timeout: Duration) -> Result<Self, String> {
        crate::init_tls();
        let http = reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .connect_timeout(timeout)
            .timeout(timeout * 3)
            .build()
            .map_err(|e| crate::describe_error(&e))?;
        Ok(Notifier {
            config,
            http,
            timeout,
        })
    }

    /// Sends to every configured channel at once. `report` goes into JSON webhooks.
    pub async fn send(&self, message: &Message, report: Option<&Report>) -> Vec<Outcome> {
        let mut jobs: Vec<std::pin::Pin<Box<dyn Future<Output = Outcome> + Send + '_>>> =
            Vec::new();
        if let Some(config) = &self.config.telegram {
            jobs.push(Box::pin(async move {
                Outcome {
                    channel: "Telegram".into(),
                    result: telegram::send(&self.http, config, message).await,
                }
            }));
        }
        if let Some(config) = &self.config.email {
            jobs.push(Box::pin(async move {
                Outcome {
                    channel: "Email".into(),
                    result: email::send(config, message, self.timeout).await,
                }
            }));
        }
        for config in &self.config.webhook {
            jobs.push(Box::pin(async move {
                Outcome {
                    channel: webhook::name(&config.url),
                    result: webhook::send(&self.http, config, message, report).await,
                }
            }));
        }
        join_all(jobs).await
    }
}

/// Cuts `text` to at most `max` characters, adding "…".
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckKind, CheckResult, DomainReport};

    #[test]
    fn composes_problem_list() {
        let mut tls = CheckResult::new(CheckKind::Tls, "www.example.com");
        tls.add(Status::Critical, "tls.expiring", "expires in 3 days <soon>");
        let mut spf = CheckResult::new(CheckKind::Spf, "example.com");
        spf.add(Status::Info, "spf.missing_parked", "advice only");
        let report = Report::new(
            "now".into(),
            1,
            vec![
                DomainReport::new("example.com", vec![tls, spf]),
                DomainReport::new(
                    "example.org",
                    vec![CheckResult::new(CheckKind::Dns, "example.org")],
                ),
            ],
        );
        let message = compose(&report, Lang::Ru);
        assert_eq!(message.title, "Domwarden: 1 проблема в 1 домене");
        assert!(
            message
                .text
                .contains("TLS www.example.com: expires in 3 days")
        );
        assert!(!message.text.contains("advice only"));
        assert!(!message.text.contains("example.org"));
        assert!(message.html.contains("&lt;soon&gt;"));
    }
}
