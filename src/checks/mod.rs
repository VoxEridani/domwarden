//! Running every check for a list of domains.

mod dns;
mod domain;
mod http;
mod mail;
mod tls;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::future::join_all;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;

use crate::config::{DomainConfig, Settings};
use crate::dns::Dns;
use crate::i18n::Lang;
use crate::model::{DomainReport, Group, Report};

/// A host whose certificate and site are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// ASCII (punycode) name used for connections.
    pub name: String,
    pub port: u16,
}

impl Host {
    /// `example.com`, or `example.com:8443` for non-standard ports; IDN names in Unicode.
    pub fn label(&self) -> String {
        let name = unicode(&self.name);
        if self.port == 443 {
            name
        } else {
            format!("{name}:{}", self.port)
        }
    }

    /// The host and port as they go into a URL.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.name.clone()
        } else {
            format!("{}:{}", self.name, self.port)
        }
    }
}

/// A domain from the list, normalized and ready to check.
#[derive(Debug, Clone)]
pub struct Target {
    /// As shown in the report (Unicode for IDN domains).
    pub name: String,
    /// ASCII (punycode) form.
    pub ascii: String,
    /// The registered domain: `shop.example.co.uk` → `example.co.uk`.
    pub registrable: String,
    pub hosts: Vec<Host>,
    pub skip: Vec<Group>,
    pub dkim_selectors: Vec<String>,
}

impl Target {
    pub fn from_config(config: &DomainConfig) -> Result<Target, String> {
        let (ascii, port) = normalize_host(&config.name)?;
        if ascii.parse::<IpAddr>().is_ok() {
            return Err(format!(
                "'{}' is an IP address; list domain names instead",
                config.name
            ));
        }
        let registrable = psl::domain_str(&ascii)
            .map(str::to_string)
            .ok_or_else(|| format!("'{}' is not a registrable domain name", config.name))?;
        let mut hosts = Vec::new();
        for host in &config.hosts {
            let (name, port) = normalize_host(host)?;
            let host = Host {
                name,
                port: port.unwrap_or(443),
            };
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        if hosts.is_empty() {
            hosts.push(Host {
                name: ascii.clone(),
                port: port.unwrap_or(443),
            });
        }
        Ok(Target {
            name: unicode(&ascii),
            ascii,
            registrable,
            hosts,
            skip: config.skip.clone(),
            dkim_selectors: config.dkim_selectors.clone(),
        })
    }
}

/// Accepts `Example.COM`, `https://example.com/page`, `пример.рф`, `example.com:8443`
/// and returns the lowercase ASCII host plus an optional port.
pub fn normalize_host(input: &str) -> Result<(String, Option<u16>), String> {
    let invalid = || format!("'{input}' is not a valid domain name");
    let mut rest = input.trim();
    for scheme in ["https://", "http://"] {
        if rest
            .get(..scheme.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(scheme))
        {
            rest = &rest[scheme.len()..];
        }
    }
    let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(port.parse::<u16>().map_err(|_| invalid())?))
        }
        _ => (rest, None),
    };
    let host = host.trim_end_matches('.');
    if host.parse::<IpAddr>().is_ok() {
        return Ok((host.to_string(), port));
    }
    let ascii = idna::domain_to_ascii(host).map_err(|_| invalid())?;
    let valid = ascii.contains('.')
        && ascii.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        return Err(invalid());
    }
    Ok((ascii, port))
}

/// Punycode → Unicode for display (`xn--e1afmkfd.xn--p1ai` → `пример.рф`).
pub fn unicode(ascii: &str) -> String {
    let (name, result) = idna::domain_to_unicode(ascii);
    if result.is_ok() {
        name
    } else {
        ascii.to_string()
    }
}

pub(crate) fn date(time: OffsetDateTime) -> String {
    time.format(format_description!("[year]-[month]-[day]"))
        .unwrap_or_default()
}

pub struct Checker {
    settings: Settings,
    lang: Lang,
    groups: Vec<Group>,
    dns: Dns,
    /// For checking sites: never follows redirects, accepts any certificate.
    web: reqwest::Client,
    registry: domain::Registry,
}

impl Checker {
    pub fn new(settings: Settings, lang: Lang, groups: Vec<Group>) -> Result<Self, String> {
        crate::init_tls();
        let timeout = settings.timeout();
        let dns = Dns::new(&settings.dns_servers, timeout)?;
        let web = reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .tls_danger_accept_invalid_certs(true)
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|e| crate::describe_error(&e))?;
        let api = reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|e| crate::describe_error(&e))?;
        Ok(Checker {
            settings,
            lang,
            groups,
            dns,
            web,
            registry: domain::Registry::new(api, timeout),
        })
    }

    fn enabled(&self, target: &Target, group: Group) -> bool {
        self.groups.contains(&group) && !target.skip.contains(&group)
    }

    pub async fn check(&self, target: &Target) -> DomainReport {
        let now = OffsetDateTime::now_utc();
        let lang = self.lang;
        let settings = &self.settings;
        let mut results = Vec::new();
        let mut hosts: Vec<&Host> = target.hosts.iter().collect();
        let mut exists = true;
        if self.enabled(target, Group::Dns) {
            let outcome = dns::check(&self.dns, target, lang).await;
            exists = outcome.exists;
            hosts.retain(|host| outcome.reachable.contains(&host.name));
            results.push(outcome.result);
        }
        if !exists {
            hosts.clear();
        }

        let registration = async {
            if self.enabled(target, Group::Domain) {
                Some(self.registry.check(target, settings, lang, now).await)
            } else {
                None
            }
        };
        let certificates = async {
            if self.enabled(target, Group::Tls) {
                join_all(
                    hosts
                        .iter()
                        .map(|host| tls::check(host, settings, lang, now)),
                )
                .await
            } else {
                Vec::new()
            }
        };
        let sites = async {
            if self.enabled(target, Group::Http) {
                join_all(
                    hosts
                        .iter()
                        .map(|host| http::check(&self.web, host, settings, lang)),
                )
                .await
            } else {
                Vec::new()
            }
        };
        let mail = async {
            if exists && self.enabled(target, Group::Mail) {
                mail::check(&self.dns, target, settings, lang).await
            } else {
                Vec::new()
            }
        };
        let (registration, certificates, sites, mail) =
            tokio::join!(registration, certificates, sites, mail);
        results.extend(registration);
        results.extend(certificates);
        results.extend(sites);
        results.extend(mail);
        DomainReport::new(target.name.clone(), results)
    }

    /// Checks all targets, several at a time, keeping the original order.
    pub async fn check_all(&self, targets: &[Target]) -> Report {
        let started = Instant::now();
        let checked_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();
        let mut reports: Vec<(usize, DomainReport)> =
            futures::stream::iter(targets.iter().enumerate())
                .map(|(index, target)| async move { (index, self.check(target).await) })
                .buffer_unordered(self.settings.concurrency.max(1))
                .collect()
                .await;
        reports.sort_by_key(|(index, _)| *index);
        Report::new(
            checked_at,
            started.elapsed().as_millis() as u64,
            reports.into_iter().map(|(_, report)| report).collect(),
        )
    }
}

impl Settings {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs.clamp(1, 120))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hosts() {
        assert_eq!(
            normalize_host("https://Example.COM/page?x=1").unwrap(),
            ("example.com".to_string(), None)
        );
        assert_eq!(
            normalize_host("example.com:8443").unwrap(),
            ("example.com".to_string(), Some(8443))
        );
        assert_eq!(
            normalize_host("пример.рф").unwrap().0,
            "xn--e1afmkfd.xn--p1ai"
        );
        assert!(normalize_host("not a domain").is_err());
        let target = Target::from_config(&DomainConfig::named("shop.example.co.uk")).unwrap();
        assert_eq!(target.registrable, "example.co.uk");
        assert_eq!(target.hosts[0].label(), "shop.example.co.uk");
        assert!(Target::from_config(&DomainConfig::named("co.uk")).is_err());
    }
}
