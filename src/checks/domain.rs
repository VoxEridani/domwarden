//! Domain registration: when it expires and whether the registry suspended it.
//!
//! RDAP (JSON over HTTPS) is tried first; registries without it, like .ru and .рф,
//! are asked over classic WHOIS.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio::time::timeout;

use super::{Target, date, unicode};
use crate::config::Settings;
use crate::i18n::{Lang, days};
use crate::model::{CheckKind, CheckResult, Status};
use crate::tr;

const RDAP_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

/// Zones whose registry only answers WHOIS.
const WHOIS_SERVERS: &[(&str, &str)] = &[
    ("ru", "whois.tcinet.ru"),
    ("su", "whois.tcinet.ru"),
    ("xn--p1ai", "whois.tcinet.ru"),
];

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DomainInfo {
    pub expires: Option<OffsetDateTime>,
    pub registrar: Option<String>,
    pub statuses: Vec<String>,
}

enum Lookup {
    Found(DomainInfo, String),
    NotRegistered,
    Failed(String),
}

pub struct Registry {
    http: reqwest::Client,
    wait: Duration,
    bootstrap: OnceCell<Option<HashMap<String, String>>>,
}

impl Registry {
    pub fn new(http: reqwest::Client, wait: Duration) -> Self {
        Registry {
            http,
            wait,
            bootstrap: OnceCell::new(),
        }
    }

    pub async fn check(
        &self,
        target: &Target,
        settings: &Settings,
        lang: Lang,
        now: OffsetDateTime,
    ) -> CheckResult {
        let shown = unicode(&target.registrable);
        let mut result = CheckResult::new(CheckKind::Domain, &shown);
        let (info, source) = match self.lookup(&target.registrable).await {
            Lookup::Found(info, source) => (info, source),
            Lookup::NotRegistered => {
                result.add(
                    Status::Critical,
                    "domain.not_registered",
                    tr!(
                        lang,
                        "{shown} isn't registered — anyone can buy it",
                        "{shown} не зарегистрирован — его может купить кто угодно"
                    ),
                );
                return result;
            }
            Lookup::Failed(err) => {
                result.add(
                    Status::Unknown,
                    "domain.lookup_failed",
                    tr!(
                        lang,
                        "couldn't get registration data: {err}",
                        "не удалось получить данные о регистрации: {err}"
                    ),
                );
                return result;
            }
        };
        result.fact("source", source);

        let registrar = info
            .registrar
            .as_deref()
            .map(|name| tr!(lang, " · registrar {name}", " · регистратор {name}"))
            .unwrap_or_default();
        if let Some(name) = &info.registrar {
            result.fact("registrar", name.clone());
        }
        if !info.statuses.is_empty() {
            result.fact("statuses", info.statuses.clone());
        }

        match info.expires {
            Some(expires) => {
                let until = date(expires);
                let days_left = (expires - now).whole_days();
                let left = days(lang, days_left.max(0));
                result
                    .fact("expires", until.clone())
                    .fact("days_left", days_left);
                if expires < now {
                    let ago = days(lang, (now - expires).whole_days().max(1));
                    result.summary(tr!(
                        lang,
                        "registration expired on {until}{registrar}",
                        "регистрация истекла {until}{registrar}"
                    ));
                    result.add(
                        Status::Critical,
                        "domain.expired",
                        tr!(
                            lang,
                            "the registration expired {ago} ago — renew it right away or the domain can be lost",
                            "срок регистрации истёк {ago} назад — продлите домен немедленно, иначе его могут забрать"
                        ),
                    );
                } else {
                    result.summary(tr!(
                        lang,
                        "paid until {until} ({left} left){registrar}",
                        "оплачен до {until} (осталось {left}){registrar}"
                    ));
                    if days_left <= settings.domain_critical_days {
                        result.add(
                            Status::Critical,
                            "domain.expiring",
                            tr!(
                                lang,
                                "the registration ends in {left} — renew the domain now",
                                "регистрация заканчивается через {left} — продлите домен сейчас"
                            ),
                        );
                    } else if days_left <= settings.domain_warning_days {
                        result.add(
                            Status::Warning,
                            "domain.expiring",
                            tr!(
                                lang,
                                "the registration ends in {left} — don't forget to renew it",
                                "регистрация заканчивается через {left} — не забудьте продлить"
                            ),
                        );
                    }
                }
            }
            None => {
                result.summary(tr!(
                    lang,
                    "registered{registrar}",
                    "зарегистрирован{registrar}"
                ));
                result.add(
                    Status::Info,
                    "domain.no_expiry",
                    tr!(
                        lang,
                        "the registry doesn't publish the expiry date — check it with your registrar",
                        "реестр не публикует дату окончания — уточните её у регистратора"
                    ),
                );
            }
        }

        status_problems(&mut result, &info.statuses, lang);
        result
    }

    async fn lookup(&self, domain: &str) -> Lookup {
        let tld = domain.rsplit('.').next().unwrap_or(domain);
        let whois_only = WHOIS_SERVERS.iter().find(|(zone, _)| *zone == tld);
        let mut rdap_error = None;
        if whois_only.is_none()
            && let Some(base) = self.rdap_base(tld).await
        {
            match self.rdap(&base, domain).await {
                Ok(Some(info)) => return Lookup::Found(info, "rdap".into()),
                Ok(None) => return Lookup::NotRegistered,
                Err(err) => rdap_error = Some(err),
            }
        }
        let server = match whois_only {
            Some((_, server)) => server.to_string(),
            None => match self.whois_server(tld).await {
                Some(server) => server,
                None => {
                    return Lookup::Failed(rdap_error.unwrap_or_else(|| {
                        format!("no RDAP or WHOIS service is known for .{tld}")
                    }));
                }
            },
        };
        // WHOIS servers (the .ru one especially) are often slow; give them extra time.
        match whois(&server, domain, self.wait * 2).await {
            Ok(text) => match parse_whois(&text) {
                Some(info) => Lookup::Found(info, server),
                None => Lookup::NotRegistered,
            },
            Err(err) => Lookup::Failed(format!("{server}: {err}")),
        }
    }

    async fn rdap_base(&self, tld: &str) -> Option<String> {
        let services = self
            .bootstrap
            .get_or_init(|| async {
                let response = self.http.get(RDAP_BOOTSTRAP).send().await.ok()?;
                let json: Value = response.error_for_status().ok()?.json().await.ok()?;
                Some(parse_bootstrap(&json))
            })
            .await;
        services.as_ref()?.get(tld).cloned()
    }

    async fn rdap(&self, base: &str, domain: &str) -> Result<Option<DomainInfo>, String> {
        let url = format!("{}/domain/{domain}", base.trim_end_matches('/'));
        let response = self
            .http
            .get(url)
            .header(
                reqwest::header::ACCEPT,
                "application/rdap+json, application/json",
            )
            .send()
            .await
            .map_err(|e| crate::describe_error(&e.without_url()))?;
        match response.status().as_u16() {
            404 => return Ok(None),
            200..=299 => {}
            code => return Err(format!("RDAP answered {code}")),
        }
        let json: Value = response
            .json()
            .await
            .map_err(|e| crate::describe_error(&e.without_url()))?;
        Ok(Some(parse_rdap(&json)))
    }

    /// Asks IANA which WHOIS server serves the zone.
    async fn whois_server(&self, tld: &str) -> Option<String> {
        let answer = whois("whois.iana.org", tld, self.wait).await.ok()?;
        answer.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim().eq_ignore_ascii_case("whois") && !value.trim().is_empty())
                .then(|| value.trim().to_string())
        })
    }
}

fn status_problems(result: &mut CheckResult, statuses: &[String], lang: Lang) {
    for status in statuses {
        let flat: String = status
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect();
        if flat.contains("hold") {
            result.add(
                Status::Critical,
                "domain.hold",
                tr!(
                    lang,
                    "the domain is suspended (status {status}) — the site and mail don't work",
                    "домен приостановлен (статус {status}) — сайт и почта не работают"
                ),
            );
        } else if flat.contains("redemption") || flat.contains("pendingdelete") {
            result.add(
                Status::Critical,
                "domain.deleting",
                tr!(
                    lang,
                    "the domain wasn't renewed and is being deleted (status {status}) — contact the registrar urgently",
                    "домен не продлён и удаляется (статус {status}) — срочно свяжитесь с регистратором"
                ),
            );
        } else if flat.contains("notdelegated") {
            result.add(
                Status::Critical,
                "domain.not_delegated",
                tr!(
                    lang,
                    "the domain isn't delegated (status {status}) — it doesn't work",
                    "домен не делегирован (статус {status}) — он не работает"
                ),
            );
        }
    }
}

fn parse_bootstrap(json: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for service in json["services"].as_array().into_iter().flatten() {
        let urls: Vec<&str> = service[1]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let Some(url) = urls
            .iter()
            .find(|url| url.starts_with("https://"))
            .or(urls.first())
        else {
            continue;
        };
        for tld in service[0]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            map.insert(tld.to_lowercase(), url.to_string());
        }
    }
    map
}

pub fn parse_rdap(json: &Value) -> DomainInfo {
    let expires = json["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|event| event["eventAction"].as_str() == Some("expiration"))
        .and_then(|event| event["eventDate"].as_str())
        .and_then(parse_date);
    let registrar = json["entities"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entity| {
            entity["roles"]
                .as_array()
                .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some("registrar")))
        })
        .and_then(|entity| {
            entity["vcardArray"][1]
                .as_array()?
                .iter()
                .find(|item| item[0].as_str() == Some("fn"))?[3]
                .as_str()
                .map(str::to_string)
        })
        .filter(|name| !name.trim().is_empty());
    let statuses = json["status"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    DomainInfo {
        expires,
        registrar,
        statuses,
    }
}

const EXPIRY_KEYS: &[&str] = &[
    "registry expiry date",
    "registrar registration expiration date",
    "expiration date",
    "expiry date",
    "expire date",
    "expires on",
    "expires",
    "expire",
    "paid-till",
    "renewal date",
    "valid until",
    "domain expiration date",
];

const REGISTRAR_KEYS: &[&str] = &["registrar", "registrar name", "sponsoring registrar"];

const STATUS_KEYS: &[&str] = &["domain status", "status", "state"];

const NOT_FOUND: &[&str] = &[
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "no object found",
    "status: free",
    "status: available",
    "is available for registration",
];

/// Reads a WHOIS answer; `None` means the domain isn't registered.
pub fn parse_whois(text: &str) -> Option<DomainInfo> {
    let mut info = DomainInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if info.expires.is_none() && EXPIRY_KEYS.contains(&key.as_str()) {
            info.expires = parse_date(value);
        } else if info.registrar.is_none() && REGISTRAR_KEYS.contains(&key.as_str()) {
            info.registrar = Some(value.to_string());
        } else if STATUS_KEYS.contains(&key.as_str()) {
            // "clientTransferProhibited https://icann.org/epp#…" → keep the status word only.
            let status = value.split_whitespace().next().unwrap_or(value);
            let status = if key == "state" { value } else { status };
            info.statuses.push(status.to_string());
        }
    }
    let lower = text.to_lowercase();
    let empty = info == DomainInfo::default();
    if empty && NOT_FOUND.iter().any(|pattern| lower.contains(pattern)) {
        return None;
    }
    Some(info)
}

/// Parses the date formats registries use: RFC 3339, `2026-05-12`, `2026.05.12`,
/// `12.05.2026`, `12-May-2026`.
pub fn parse_date(value: &str) -> Option<OffsetDateTime> {
    let value = value.trim();
    if let Ok(time) = OffsetDateTime::parse(value, &Rfc3339) {
        return Some(time);
    }
    let token = value.split_whitespace().next()?.split('T').next()?;
    let parts: Vec<&str> = token.split(['-', '.', '/']).collect();
    let [a, b, c] = parts.as_slice() else {
        return None;
    };
    let (year, month, day) = if a.len() == 4 { (a, b, c) } else { (c, b, a) };
    let year: i32 = year.parse().ok()?;
    let day: u8 = day.parse().ok()?;
    let month = match month.parse::<u8>() {
        Ok(number) => Month::try_from(number).ok()?,
        Err(_) => month_by_name(month)?,
    };
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Some(date.midnight().assume_utc())
}

fn month_by_name(name: &str) -> Option<Month> {
    const NAMES: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let lower = name.to_lowercase();
    let index = NAMES.iter().position(|month| lower.starts_with(month))?;
    Month::try_from(index as u8 + 1).ok()
}

async fn whois(server: &str, query: &str, wait: Duration) -> Result<String, String> {
    let request = async {
        let mut stream = TcpStream::connect((server, 43)).await?;
        stream.write_all(format!("{query}\r\n").as_bytes()).await?;
        let mut answer = Vec::new();
        stream.take(1 << 20).read_to_end(&mut answer).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&answer).into_owned())
    };
    timeout(wait, request)
        .await
        .map_err(|_| format!("no answer within {} s", wait.as_secs()))?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dates() {
        let expected = Date::from_calendar_date(2026, Month::May, 12).unwrap();
        for value in [
            "2026-05-12",
            "2026-05-12T21:00:00+0000",
            "2026.05.12 00:00:00",
            "12.05.2026",
            "12-May-2026",
        ] {
            assert_eq!(parse_date(value).unwrap().date(), expected, "{value}");
        }
        assert_eq!(
            parse_date("2026-05-12T21:00:00Z").unwrap().unix_timestamp(),
            1_778_619_600
        );
        assert!(parse_date("someday").is_none());
    }

    #[test]
    fn parses_whois_answers() {
        let tcinet = "domain:        EXAMPLE.RU\nnserver:       ns1.reg.ru.\nstate:         REGISTERED, DELEGATED, VERIFIED\norg:           Example LLC\nregistrar:     REGRU-RU\npaid-till:     2027-03-01T21:00:00Z\nfree-date:     2027-04-02\nsource:        TCI\n";
        let info = parse_whois(tcinet).unwrap();
        assert_eq!(info.registrar.as_deref(), Some("REGRU-RU"));
        assert_eq!(info.expires.unwrap().year(), 2027);
        assert_eq!(info.statuses, ["REGISTERED, DELEGATED, VERIFIED"]);

        let verisign = "   Domain Name: EXAMPLE.COM\n   Registrar: RESERVED-Internet Assigned Numbers Authority\n   Registry Expiry Date: 2026-08-13T04:00:00Z\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n";
        let info = parse_whois(verisign).unwrap();
        assert_eq!(info.statuses, ["clientDeleteProhibited"]);
        assert_eq!(info.expires.unwrap().month(), Month::August);

        assert_eq!(
            parse_whois("No entries found for the selected source(s).\n"),
            None
        );
    }

    #[test]
    fn parses_rdap_answer() {
        let json: Value = serde_json::from_str(
            r#"{
              "status": ["client transfer prohibited"],
              "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
              ],
              "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]
              }]
            }"#,
        )
        .unwrap();
        let info = parse_rdap(&json);
        assert_eq!(info.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(info.expires.unwrap().year(), 2026);
        assert_eq!(info.statuses, ["client transfer prohibited"]);
    }
}
