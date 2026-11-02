//! Whether the site opens: status, redirects, speed, HTTP → HTTPS.

use std::collections::HashSet;
use std::time::Instant;

use reqwest::header::{HeaderMap, LOCATION, SERVER, STRICT_TRANSPORT_SECURITY};
use reqwest::{Client, StatusCode, Url};

use super::Host;
use crate::config::Settings;
use crate::i18n::Lang;
use crate::model::{CheckKind, CheckResult, Status};
use crate::tr;

const MAX_REDIRECTS: usize = 10;

struct Page {
    status: StatusCode,
    headers: HeaderMap,
    url: Url,
}

enum Failure {
    /// The request to `url` failed; `first` tells whether it was the starting address.
    Request {
        url: Url,
        first: bool,
        error: String,
    },
    Loop,
    TooManyRedirects,
}

struct Visit {
    /// Every address passed through, starting one first.
    urls: Vec<Url>,
    outcome: Result<Page, Failure>,
}

impl Visit {
    fn redirects(&self) -> usize {
        self.urls.len().saturating_sub(1)
    }
}

async fn visit(client: &Client, start: &str, lang: Lang, timeout_secs: u64) -> Visit {
    let mut url = match Url::parse(start) {
        Ok(url) => url,
        Err(err) => {
            return Visit {
                urls: Vec::new(),
                outcome: Err(Failure::Request {
                    url: Url::parse("https://invalid/").unwrap(),
                    first: true,
                    error: err.to_string(),
                }),
            };
        }
    };
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(url.clone()) {
            urls.push(url);
            return Visit {
                urls,
                outcome: Err(Failure::Loop),
            };
        }
        urls.push(url.clone());
        let response = match client.get(url.clone()).send().await {
            Ok(response) => response,
            Err(err) => {
                let error = if err.is_timeout() {
                    tr!(
                        lang,
                        "no answer within {timeout_secs} s",
                        "нет ответа за {timeout_secs} с"
                    )
                } else {
                    crate::describe_error(&err.without_url())
                };
                return Visit {
                    outcome: Err(Failure::Request {
                        url,
                        first: urls.len() == 1,
                        error,
                    }),
                    urls,
                };
            }
        };
        let status = response.status();
        let next = status
            .is_redirection()
            .then(|| response.headers().get(LOCATION))
            .flatten()
            .and_then(|location| location.to_str().ok())
            .and_then(|location| url.join(location).ok());
        match next {
            Some(_) if urls.len() > MAX_REDIRECTS => {
                return Visit {
                    urls,
                    outcome: Err(Failure::TooManyRedirects),
                };
            }
            Some(next) => url = next,
            None => {
                let headers = response.headers().clone();
                return Visit {
                    urls,
                    outcome: Ok(Page {
                        status,
                        headers,
                        url,
                    }),
                };
            }
        }
    }
}

/// `https://host/path` without the query string, at most 60 characters.
fn short_url(url: &Url) -> String {
    let mut text = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.path()
    );
    if url.query().is_some() || text.chars().count() > 60 {
        text = text.chars().take(59).collect();
        text.push('…');
    }
    text
}

fn status_text(status: StatusCode) -> String {
    match status.canonical_reason() {
        Some(reason) => format!("{} {reason}", status.as_u16()),
        None => status.as_u16().to_string(),
    }
}

/// Bot-protection services answer robots with challenges instead of the page.
fn bot_protection(page: &Page) -> Option<&'static str> {
    let server = page
        .headers
        .get(SERVER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_lowercase();
    let blocked = matches!(page.status.as_u16(), 403 | 429 | 503);
    if page.headers.contains_key("cf-mitigated") || (blocked && server.contains("cloudflare")) {
        Some("Cloudflare")
    } else if server.contains("ddos-guard") {
        Some("DDoS-Guard")
    } else if blocked && server.contains("qrator") {
        Some("Qrator")
    } else if blocked && server.contains("variti") {
        Some("Variti")
    } else {
        None
    }
}

pub async fn check(client: &Client, host: &Host, settings: &Settings, lang: Lang) -> CheckResult {
    let label = host.label();
    let mut result = CheckResult::new(CheckKind::Http, &label);
    let timeout_secs = settings.timeout().as_secs();
    let https_start = format!("https://{}/", host.authority());
    let http_start = format!("http://{}/", host.name);

    let secure = async {
        let started = Instant::now();
        let visit = visit(client, &https_start, lang, timeout_secs).await;
        (visit, started.elapsed())
    };
    let plain = async {
        // Only meaningful for sites on the standard port.
        if host.port == 443 {
            Some(visit(client, &http_start, lang, timeout_secs).await)
        } else {
            None
        }
    };
    let ((visit, elapsed), plain) = tokio::join!(secure, plain);
    let redirects = visit.redirects();
    let Visit { urls, outcome } = visit;

    let page = match outcome {
        Ok(page) => page,
        Err(Failure::Request { url, first, error }) => {
            if first {
                result.add(
                    Status::Critical,
                    "http.unreachable",
                    tr!(
                        lang,
                        "the site doesn't open over HTTPS: {error}",
                        "сайт не открывается по HTTPS: {error}"
                    ),
                );
            } else {
                result.add(
                    Status::Critical,
                    "http.redirect_broken",
                    tr!(
                        lang,
                        "the redirect to {url} leads nowhere: {error}",
                        "перенаправление на {url} никуда не ведёт: {error}"
                    ),
                );
            }
            return result;
        }
        Err(Failure::Loop) => {
            result.add(
                Status::Critical,
                "http.redirect_loop",
                tr!(
                    lang,
                    "endless redirect loop — browsers show an error",
                    "бесконечный круг перенаправлений — браузеры покажут ошибку"
                ),
            );
            return result;
        }
        Err(Failure::TooManyRedirects) => {
            result.add(
                Status::Critical,
                "http.too_many_redirects",
                tr!(
                    lang,
                    "more than {MAX_REDIRECTS} redirects in a row — browsers give up",
                    "больше {MAX_REDIRECTS} перенаправлений подряд — браузеры сдадутся"
                ),
            );
            return result;
        }
    };

    let ms = elapsed.as_millis() as u64;
    let status = status_text(page.status);
    let mut summary = tr!(lang, "{status} · {ms} ms", "{status} · {ms} мс");
    if redirects > 0 {
        summary.push_str(&format!(" · → {}", short_url(&page.url)));
    }
    result
        .fact("status", page.status.as_u16())
        .fact("response_ms", ms)
        .fact("final_url", page.url.as_str())
        .fact("redirects", redirects);

    let code = page.status.as_u16();
    if let Some(service) = bot_protection(&page).filter(|_| !page.status.is_success()) {
        result.add(
            Status::Info,
            "http.bot_protection",
            tr!(
                lang,
                "the site is behind {service} bot protection, so the page itself couldn't be checked",
                "сайт закрыт защитой от ботов {service}, поэтому саму страницу проверить не удалось"
            ),
        );
    } else if page.status.is_redirection() {
        result.add(
            Status::Warning,
            "http.bad_redirect",
            tr!(
                lang,
                "the site answers {status} but doesn't say where to go",
                "сайт отвечает {status}, но не сообщает, куда перейти"
            ),
        );
    } else if code >= 500 {
        result.add(
            Status::Critical,
            "http.server_error",
            tr!(
                lang,
                "the site answers {status} — the server is failing",
                "сайт отвечает {status} — сбой на стороне сервера"
            ),
        );
    } else if code >= 400 {
        result.add(
            Status::Warning,
            "http.client_error",
            tr!(
                lang,
                "the home page answers {status}",
                "главная страница отвечает {status}"
            ),
        );
    }

    if let Some(downgrade) = urls.iter().skip(1).find(|url| url.scheme() == "http") {
        result.add(
            Status::Warning,
            "http.downgrade",
            tr!(
                lang,
                "redirects from HTTPS to unprotected HTTP: {downgrade}",
                "перенаправляет с HTTPS на незащищённый HTTP: {downgrade}"
            ),
        );
    }
    if redirects > 3 {
        result.add(
            Status::Warning,
            "http.long_redirects",
            tr!(
                lang,
                "{redirects} redirects in a row slow the site down",
                "{redirects} перенаправлений подряд замедляют сайт"
            ),
        );
    }
    if ms > settings.slow_response_ms {
        result.add(
            Status::Warning,
            "http.slow",
            tr!(
                lang,
                "slow: the page took {ms} ms to answer",
                "медленно: страница отвечала {ms} мс"
            ),
        );
    }
    if page.url.scheme() == "https"
        && page.status.is_success()
        && !page.headers.contains_key(STRICT_TRANSPORT_SECURITY)
    {
        result.add(
            Status::Info,
            "http.no_hsts",
            tr!(
                lang,
                "no HSTS header: a browser may first open the unprotected http:// version",
                "нет заголовка HSTS: браузер может сначала открыть незащищённую версию http://"
            ),
        );
    }

    if let Some(plain) = plain {
        match plain.outcome {
            Ok(page) if page.url.scheme() == "https" => {
                summary.push_str(&tr!(lang, " · http:// → https://", " · http:// → https://"));
            }
            Ok(page) if page.status.is_success() => {
                result.add(
                    Status::Warning,
                    "http.no_https_redirect",
                    tr!(
                        lang,
                        "the http:// version opens without switching to https:// — visitors can end up on the unprotected version",
                        "версия http:// открывается без перехода на https:// — посетители могут попасть на незащищённую версию"
                    ),
                );
            }
            Err(Failure::Request { first: true, .. }) => {
                result.add(
                    Status::Info,
                    "http.port80_closed",
                    tr!(
                        lang,
                        "http:// (port 80) doesn't answer: typing the address without https:// may not open the site",
                        "http:// (порт 80) не отвечает: если набрать адрес без https://, сайт может не открыться"
                    ),
                );
            }
            _ => {}
        }
    }

    result.summary(summary);
    result
}
