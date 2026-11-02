//! Name servers and host addresses.

use std::collections::HashSet;

use futures::future::join_all;

use super::{Target, unicode};
use crate::dns::{DnsError, Resolve};
use crate::i18n::Lang;
use crate::model::{CheckKind, CheckResult, Status};
use crate::tr;

pub struct DnsOutcome {
    pub result: CheckResult,
    /// False when the domain doesn't exist in DNS at all.
    pub exists: bool,
    /// Hosts that have (or may have) an address; the others are skipped by TLS and HTTP.
    pub reachable: HashSet<String>,
}

pub async fn check(dns: &impl Resolve, target: &Target, lang: Lang) -> DnsOutcome {
    let mut result = CheckResult::new(CheckKind::Dns, &target.name);
    let mut parts = Vec::new();
    let mut exists = true;
    let registrable = unicode(&target.registrable);

    match dns.ns(&target.registrable).await {
        Ok(servers) => {
            let mut list = servers
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if servers.len() > 4 {
                list.push_str(&format!(" +{}", servers.len() - 4));
            }
            parts.push(tr!(lang, "name servers: {list}", "DNS-серверы: {list}"));
            if servers.len() == 1 {
                result.add(
                    Status::Warning,
                    "dns.single_ns",
                    tr!(
                        lang,
                        "only one name server — if it fails, the site and mail stop working",
                        "всего один DNS-сервер: если он откажет, перестанут работать и сайт, и почта"
                    ),
                );
            }
            result.fact("name_servers", servers);
        }
        Err(DnsError::NxDomain) => {
            exists = false;
            result.add(
                Status::Critical,
                "dns.nxdomain",
                tr!(
                    lang,
                    "{registrable} doesn't exist in DNS: the domain isn't registered or isn't delegated",
                    "{registrable} нет в DNS: домен не зарегистрирован или не делегирован"
                ),
            );
        }
        Err(DnsError::NoRecords) => {
            result.add(
                Status::Critical,
                "dns.no_ns",
                tr!(
                    lang,
                    "{registrable} has no name servers",
                    "у {registrable} нет DNS-серверов"
                ),
            );
        }
        Err(err) => {
            result.add(
                Status::Unknown,
                "dns.lookup_failed",
                tr!(
                    lang,
                    "couldn't get the name servers: {err}",
                    "не удалось узнать DNS-серверы: {err}"
                ),
            );
        }
    }

    let mut reachable = HashSet::new();
    if exists {
        let mut names: Vec<&str> = Vec::new();
        for host in &target.hosts {
            if !names.contains(&host.name.as_str()) {
                names.push(&host.name);
            }
        }
        let answers = join_all(names.iter().map(|name| dns.ips(name))).await;
        let mut addresses = serde_json::Map::new();
        for (name, answer) in names.into_iter().zip(answers) {
            let shown = unicode(name);
            match answer {
                Ok(ips) => {
                    let list: Vec<String> = ips.iter().map(ToString::to_string).collect();
                    let mut text = list.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                    if list.len() > 3 {
                        text.push_str(", …");
                    }
                    parts.push(format!("{shown} → {text}"));
                    addresses.insert(name.to_string(), list.into());
                    reachable.insert(name.to_string());
                }
                Err(err) if err.is_empty() => {
                    result.add(
                        Status::Critical,
                        "dns.no_address",
                        tr!(
                            lang,
                            "{shown} has no IP address (A/AAAA record) — the site can't be opened",
                            "у {shown} нет IP-адреса (записи A/AAAA) — сайт не открыть"
                        ),
                    );
                }
                Err(err) => {
                    // The lookup itself failed; let the TLS and HTTP checks try anyway.
                    reachable.insert(name.to_string());
                    result.add(
                        Status::Unknown,
                        "dns.lookup_failed",
                        tr!(
                            lang,
                            "couldn't resolve {shown}: {err}",
                            "не удалось получить адрес {shown}: {err}"
                        ),
                    );
                }
            }
        }
        if !addresses.is_empty() {
            result.fact("addresses", addresses);
        }
    }

    if !parts.is_empty() {
        result.summary(parts.join(" · "));
    }
    DnsOutcome {
        result,
        exists,
        reachable,
    }
}
