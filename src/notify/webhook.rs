//! Webhooks: plain JSON, Slack and Discord.

use reqwest::Url;
use serde_json::json;

use super::{Message, truncate};
use crate::config::{WebhookConfig, WebhookFormat};
use crate::model::Report;

/// Picks the payload format from the URL when the config doesn't say.
fn format(config: &WebhookConfig) -> WebhookFormat {
    config.format.unwrap_or_else(|| {
        let url = config.url.to_lowercase();
        if url.contains("hooks.slack.com/") {
            WebhookFormat::Slack
        } else if url.contains("discord.com/api/webhooks/")
            || url.contains("discordapp.com/api/webhooks/")
        {
            WebhookFormat::Discord
        } else {
            WebhookFormat::Json
        }
    })
}

/// "Webhook (hooks.slack.com)" — the path often holds a secret, so only the host is shown.
pub fn name(url: &str) -> String {
    match Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => format!("Webhook ({host})"),
        None => "Webhook".to_string(),
    }
}

pub async fn send(
    http: &reqwest::Client,
    config: &WebhookConfig,
    message: &Message,
    report: Option<&Report>,
) -> Result<(), String> {
    let body = match format(config) {
        WebhookFormat::Slack => json!({ "text": format!("*{}*\n{}", message.title, message.text) }),
        WebhookFormat::Discord => json!({
            "username": "Domwarden",
            "content": truncate(&format!("**{}**\n{}", message.title, message.text), 2000),
        }),
        WebhookFormat::Json => json!({
            "event": if report.is_some() { "domwarden.report" } else { "domwarden.test" },
            "title": message.title,
            "text": message.text,
            "status": message.status,
            "report": report,
        }),
    };
    let mut request = http.post(&config.url).json(&body);
    for (key, value) in &config.headers {
        request = request.header(key, value);
    }
    let response = request
        .send()
        .await
        .map_err(|e| crate::describe_error(&e.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(format!(
            "the webhook answered {}: {}",
            status.as_u16(),
            truncate(text.trim(), 200)
        ));
    }
    Ok(())
}
