//! Telegram Bot API.

use serde_json::{Value, json};

use super::Message;
use crate::config::TelegramConfig;

/// Telegram's limit is 4096 characters; stay a little below.
const MAX_LENGTH: usize = 4000;

pub async fn send(
    http: &reqwest::Client,
    config: &TelegramConfig,
    message: &Message,
) -> Result<(), String> {
    let base = config
        .api_url
        .as_deref()
        .unwrap_or("https://api.telegram.org")
        .trim_end_matches('/');
    let token = config.bot_token.trim();
    let token = token.strip_prefix("bot").unwrap_or(token);
    if token.is_empty() {
        return Err("bot_token is empty".into());
    }
    if config.chat_id.is_empty() {
        return Err("chat_id is empty".into());
    }
    let url = format!("{base}/bot{token}/sendMessage");
    for chat in &config.chat_id {
        for part in split(&message.html) {
            let mut body = json!({
                "chat_id": chat.trim(),
                "text": part,
                "parse_mode": "HTML",
                "link_preview_options": { "is_disabled": true },
            });
            if let Some(thread) = config.thread_id {
                body["message_thread_id"] = thread.into();
            }
            // The URL holds the bot token, so it's never shown in errors.
            let response = http
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| crate::describe_error(&e.without_url()))?;
            let status = response.status();
            let answer: Value = response.json().await.unwrap_or_default();
            if answer["ok"].as_bool() != Some(true) {
                let reason = answer["description"]
                    .as_str()
                    .unwrap_or("unexpected answer");
                return Err(format!(
                    "Telegram answered {}: {reason}{}",
                    status.as_u16(),
                    hint(status.as_u16())
                ));
            }
        }
    }
    Ok(())
}

fn hint(status: u16) -> &'static str {
    match status {
        401 | 404 => " (check bot_token)",
        400 | 403 => " (check chat_id and that you pressed Start in the chat with the bot)",
        _ => "",
    }
}

/// Splits on line boundaries so every part keeps its HTML tags balanced.
fn split(html: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    for line in html.lines() {
        let line = super::truncate(line, MAX_LENGTH);
        if current.chars().count() + line.chars().count() + 1 > MAX_LENGTH && !current.is_empty() {
            parts.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(&line);
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::i18n::Lang;

    #[tokio::test]
    async fn sends_html_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bot123:abc/sendMessage"))
            .and(body_partial_json(
                json!({ "chat_id": "42", "parse_mode": "HTML" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .expect(1)
            .mount(&server)
            .await;
        let config = TelegramConfig {
            bot_token: "123:abc".into(),
            chat_id: vec!["42".into()],
            thread_id: None,
            api_url: Some(server.uri()),
        };
        crate::init_tls();
        let http = reqwest::Client::new();
        send(&http, &config, &super::super::test_message(Lang::En))
            .await
            .unwrap();
    }
}
