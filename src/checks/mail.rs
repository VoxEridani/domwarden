//! Email DNS records: MX, SPF, DMARC and DKIM.

use std::collections::{BTreeMap, HashSet, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::future::join_all;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::{Target, unicode};
use crate::config::Settings;
use crate::dns::{DnsError, DnsResult, Resolve};
use crate::i18n::Lang;
use crate::model::{CheckKind, CheckResult, Status};
use crate::tr;

/// SPF allows at most this many DNS lookups (RFC 7208, 4.6.4).
const SPF_LOOKUP_LIMIT: usize = 10;

/// Selectors tried when the config names none.
const COMMON_SELECTORS: &[&str] = &[
    "default",
    "dkim",
    "mail",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "smtp",
    "mailru",
    "sig1",
    "key1",
    "email",
];

/// Mail services recognized by their MX hosts, with the DKIM selectors they use.
struct Provider {
    mx_suffix: &'static str,
    name: &'static str,
    selectors: &'static [&'static str],
}

const PROVIDERS: &[Provider] = &[
    Provider {
        mx_suffix: "yandex.net",
        name: "Yandex 360",
        selectors: &["mail"],
    },
    Provider {
        mx_suffix: "yandex.ru",
        name: "Yandex 360",
        selectors: &["mail"],
    },
    Provider {
        mx_suffix: "google.com",
        name: "Google Workspace",
        selectors: &["google"],
    },
    Provider {
        mx_suffix: "googlemail.com",
        name: "Google Workspace",
        selectors: &["google"],
    },
    Provider {
        mx_suffix: "mail.protection.outlook.com",
        name: "Microsoft 365",
        selectors: &["selector1", "selector2"],
    },
    Provider {
        mx_suffix: "mail.ru",
        name: "VK WorkSpace (Mail.ru)",
        selectors: &["mailru"],
    },
    Provider {
        mx_suffix: "icloud.com",
        name: "iCloud Mail",
        selectors: &["sig1"],
    },
    Provider {
        mx_suffix: "protonmail.ch",
        name: "Proton Mail",
        selectors: &["protonmail", "protonmail2", "protonmail3"],
    },
    Provider {
        mx_suffix: "messagingengine.com",
        name: "Fastmail",
        selectors: &["fm1", "fm2", "fm3"],
    },
    Provider {
        mx_suffix: "zoho.com",
        name: "Zoho Mail",
        selectors: &["zmail"],
    },
    Provider {
        mx_suffix: "zoho.eu",
        name: "Zoho Mail",
        selectors: &["zmail"],
    },
];

fn detect_provider(records: &[(u16, String)]) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| {
        records.iter().any(|(_, host)| {
            host == provider.mx_suffix || host.ends_with(&format!(".{}", provider.mx_suffix))
        })
    })
}

pub async fn check<R: Resolve>(
    dns: &R,
    target: &Target,
    settings: &Settings,
    lang: Lang,
) -> Vec<CheckResult> {
    let domain = target.ascii.as_str();
    let subject = target.name.as_str();
    let mx = check_mx(dns, domain, subject, lang).await;
    if target.ascii != target.registrable && !mx.receives {
        // A subdomain without mail: SPF, DMARC and DKIM would only be noise.
        return vec![mx.result];
    }
    let mut selectors = target.dkim_selectors.clone();
    selectors.extend(settings.dkim_selectors.iter().cloned());
    let (spf, dmarc, dkim) = tokio::join!(
        check_spf(dns, domain, subject, mx.receives, lang),
        check_dmarc(dns, domain, &target.registrable, subject, mx.receives, lang),
        check_dkim(
            dns,
            domain,
            subject,
            &selectors,
            mx.provider,
            mx.receives,
            lang
        ),
    );
    let mut results = vec![mx.result, spf, dmarc];
    results.extend(dkim);
    results
}

struct MxOutcome {
    result: CheckResult,
    /// Whether the domain accepts mail (has usable MX records).
    receives: bool,
    provider: Option<&'static Provider>,
}

async fn check_mx<R: Resolve>(dns: &R, domain: &str, subject: &str, lang: Lang) -> MxOutcome {
    let mut result = CheckResult::new(CheckKind::Mx, subject);
    let records = match dns.mx(domain).await {
        Ok(records) => records,
        Err(err) if err.is_empty() => {
            result.summary(tr!(
                lang,
                "no MX records — the domain doesn't receive mail",
                "нет MX-записей — домен не принимает почту"
            ));
            return MxOutcome {
                result,
                receives: false,
                provider: None,
            };
        }
        Err(err) => {
            result.add(
                Status::Unknown,
                "mx.lookup_failed",
                tr!(
                    lang,
                    "couldn't get MX records: {err}",
                    "не удалось получить MX-записи: {err}"
                ),
            );
            return MxOutcome {
                result,
                receives: true,
                provider: None,
            };
        }
    };

    if records.len() == 1 && (records[0].1.is_empty() || records[0].1 == ".") {
        result.summary(tr!(
            lang,
            "null MX: the domain declares that it doesn't accept mail",
            "null MX: домен заявляет, что не принимает почту"
        ));
        return MxOutcome {
            result,
            receives: false,
            provider: None,
        };
    }

    let provider = detect_provider(&records);
    let mut summary = records
        .iter()
        .map(|(preference, host)| format!("{host} ({preference})"))
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(provider) = provider {
        summary.push_str(&format!(" · {}", provider.name));
        result.fact("provider", provider.name);
    }
    result.summary(summary);
    result.fact(
        "mx",
        records
            .iter()
            .map(|(preference, host)| serde_json::json!({ "preference": preference, "host": host }))
            .collect::<Vec<_>>(),
    );

    let answers = join_all(records.iter().map(|(_, host)| dns.ips(host))).await;
    let broken: Vec<&str> = records
        .iter()
        .zip(&answers)
        .filter(|(_, answer)| matches!(answer, Err(err) if err.is_empty()))
        .map(|((_, host), _)| host.as_str())
        .collect();
    if !broken.is_empty() {
        let status = if broken.len() == records.len() {
            Status::Critical
        } else {
            Status::Warning
        };
        let hosts = broken.join(", ");
        let message = if broken.len() == 1 {
            tr!(
                lang,
                "mail server {hosts} has no IP address — mail sent to it doesn't arrive",
                "у почтового сервера {hosts} нет IP-адреса — письма на него не доходят"
            )
        } else {
            tr!(
                lang,
                "mail servers {hosts} have no IP addresses — mail sent to them doesn't arrive",
                "у почтовых серверов {hosts} нет IP-адресов — письма на них не доходят"
            )
        };
        result.add(status, "mx.unresolvable", message);
    }
    MxOutcome {
        result,
        receives: true,
        provider,
    }
}

fn is_spf(record: &str) -> bool {
    let lower = record.trim_start().to_ascii_lowercase();
    lower == "v=spf1" || lower.starts_with("v=spf1 ")
}

async fn check_spf<R: Resolve>(
    dns: &R,
    domain: &str,
    subject: &str,
    receives: bool,
    lang: Lang,
) -> CheckResult {
    let mut result = CheckResult::new(CheckKind::Spf, subject);
    let shown = unicode(domain);
    let records: Vec<String> = match dns.txt(domain).await {
        Ok(records) => records.into_iter().filter(|r| is_spf(r)).collect(),
        Err(err) if err.is_empty() => Vec::new(),
        Err(err) => {
            result.add(
                Status::Unknown,
                "spf.lookup_failed",
                tr!(
                    lang,
                    "couldn't get TXT records: {err}",
                    "не удалось получить TXT-записи: {err}"
                ),
            );
            return result;
        }
    };
    match records.as_slice() {
        [] if receives => {
            result.add(
                Status::Warning,
                "spf.missing",
                tr!(
                    lang,
                    "no SPF record: anyone can send mail as @{shown}, and your real mail lands in spam more often",
                    "нет SPF-записи: кто угодно может отправлять письма от имени @{shown}, а ваши настоящие письма чаще попадают в спам"
                ),
            );
        }
        [] => {
            result.add(
                Status::Info,
                "spf.missing_parked",
                tr!(
                    lang,
                    "no SPF record. If the domain doesn't send mail, add \"v=spf1 -all\" so nobody can forge it",
                    "нет SPF-записи. Если домен не отправляет почту, добавьте \"v=spf1 -all\", чтобы от его имени нельзя было подделать письмо"
                ),
            );
        }
        [record] => analyze_spf(dns, record, &mut result, lang).await,
        many => {
            let count = many.len();
            result.add(
                Status::Critical,
                "spf.multiple",
                tr!(
                    lang,
                    "{count} SPF records found — only one is allowed, so receivers treat SPF as broken; merge them into one",
                    "найдено {count} SPF-записи — допускается только одна, поэтому получатели считают SPF сломанным; объедините их"
                ),
            );
        }
    }
    result
}

async fn analyze_spf<R: Resolve>(dns: &R, record: &str, result: &mut CheckResult, lang: Lang) {
    let mut all = None;
    let mut redirect = false;
    for term in record.split_whitespace().skip(1) {
        let (qualifier, body) = match term.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &term[1..]),
            _ => ('+', term),
        };
        let lower = body.to_ascii_lowercase();
        if let Some((key, _)) = lower.split_once('=')
            && !key.contains([':', '/'])
        {
            // A modifier: redirect=, exp= or an unknown one (allowed by the RFC).
            redirect |= key == "redirect";
            continue;
        }
        let name = lower.split([':', '/']).next().unwrap_or_default();
        match name {
            "all" => all = Some(qualifier),
            "ptr" => {
                result.add(
                    Status::Warning,
                    "spf.ptr",
                    tr!(
                        lang,
                        "the ptr mechanism is deprecated and slow; many receivers ignore it",
                        "механизм ptr устарел и медленный, многие получатели его игнорируют"
                    ),
                );
            }
            "include" | "a" | "mx" | "ip4" | "ip6" | "exists" => {}
            _ => {
                result.add(
                    Status::Warning,
                    "spf.syntax",
                    tr!(
                        lang,
                        "unknown term \"{term}\" in the record",
                        "непонятная часть записи: \"{term}\""
                    ),
                );
            }
        }
    }
    match all {
        Some('+') => {
            result.add(
                Status::Critical,
                "spf.plus_all",
                tr!(
                    lang,
                    "the record ends with +all — it lets ANY server send mail as you",
                    "запись заканчивается на +all — она разрешает ЛЮБОМУ серверу отправлять письма от вашего имени"
                ),
            );
        }
        Some('?') => {
            result.add(
                Status::Warning,
                "spf.neutral_all",
                tr!(
                    lang,
                    "?all protects nothing: receivers ignore the result. Use ~all or -all",
                    "?all ничего не защищает: получатели игнорируют результат. Используйте ~all или -all"
                ),
            );
        }
        None if !redirect => {
            result.add(
                Status::Warning,
                "spf.no_all",
                tr!(
                    lang,
                    "the record has no final ~all or -all, so mail from other servers isn't rejected",
                    "в записи нет завершающего ~all или -all, поэтому письма с чужих серверов не отклоняются"
                ),
            );
        }
        _ => {}
    }

    let (lookups, broken) = count_lookups(dns, record).await;
    if lookups > SPF_LOOKUP_LIMIT {
        result.add(
            Status::Critical,
            "spf.too_many_lookups",
            tr!(
                lang,
                "SPF needs more than {SPF_LOOKUP_LIMIT} DNS lookups — receivers treat the record as broken",
                "SPF требует больше {SPF_LOOKUP_LIMIT} DNS-запросов — получатели считают запись сломанной"
            ),
        );
    }
    for target in broken {
        result.add(
            Status::Critical,
            "spf.broken_include",
            tr!(
                lang,
                "{target} referenced from the record has no SPF record — the whole check fails",
                "у {target}, на который ссылается запись, нет SPF-записи — вся проверка ломается"
            ),
        );
    }
    let shown_count = lookups.min(SPF_LOOKUP_LIMIT + 1);
    let count = if lookups > SPF_LOOKUP_LIMIT {
        format!("{SPF_LOOKUP_LIMIT}+")
    } else {
        shown_count.to_string()
    };
    result.summary(format!(
        "{} · {}",
        shorten(record, 120),
        tr!(
            lang,
            "{count} of {SPF_LOOKUP_LIMIT} lookups",
            "{count} из {SPF_LOOKUP_LIMIT} DNS-запросов"
        )
    ));
    result.fact("record", record).fact("lookups", shown_count);
}

/// Counts the DNS lookups SPF evaluation needs, following include: and redirect=.
/// Also returns referenced domains that have no SPF record.
async fn count_lookups<R: Resolve>(dns: &R, record: &str) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut broken = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([record.to_string()]);
    while let Some(record) = queue.pop_front() {
        for term in record.split_whitespace().skip(1) {
            let body = term
                .trim_start_matches(['+', '-', '~', '?'])
                .to_ascii_lowercase();
            let (name, target) = match body.split_once([':', '=']) {
                Some((name, target)) => (name, Some(target)),
                None => (body.split('/').next().unwrap_or_default(), None),
            };
            match name {
                "include" | "redirect" => {
                    count += 1;
                    let Some(target) = target else { continue };
                    // Macros (%{d}) can't be expanded without a real message.
                    if target.contains('%') || seen.len() > 30 || !seen.insert(target.to_string()) {
                        continue;
                    }
                    match dns.txt(target).await {
                        Ok(records) => match records.into_iter().find(|r| is_spf(r)) {
                            Some(next) => queue.push_back(next),
                            None => broken.push(target.to_string()),
                        },
                        Err(err) if err.is_empty() => broken.push(target.to_string()),
                        Err(_) => {}
                    }
                }
                "a" | "mx" | "ptr" | "exists" => count += 1,
                _ => {}
            }
        }
        if count > SPF_LOOKUP_LIMIT {
            break;
        }
    }
    (count, broken)
}

/// `v=DMARC1; p=none; rua=mailto:x` → {"v": "DMARC1", "p": "none", "rua": "mailto:x"}.
/// Keys are lowercased; values keep their case (DKIM keys are case-sensitive).
fn parse_tags(record: &str) -> BTreeMap<String, String> {
    record
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

async fn dmarc_records<R: Resolve>(dns: &R, domain: &str) -> DnsResult<Vec<String>> {
    match dns.txt(&format!("_dmarc.{domain}")).await {
        Ok(records) => Ok(records
            .into_iter()
            .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
            .collect()),
        Err(err) if err.is_empty() => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

async fn check_dmarc<R: Resolve>(
    dns: &R,
    domain: &str,
    registrable: &str,
    subject: &str,
    receives: bool,
    lang: Lang,
) -> CheckResult {
    let mut result = CheckResult::new(CheckKind::Dmarc, subject);
    let mut found = dmarc_records(dns, domain).await;
    let mut inherited = false;
    if domain != registrable && matches!(&found, Ok(records) if records.is_empty()) {
        // Subdomains fall under the organizational domain's policy.
        found = dmarc_records(dns, registrable).await;
        inherited = true;
    }
    let records = match found {
        Ok(records) => records,
        Err(err) => {
            result.add(
                Status::Unknown,
                "dmarc.lookup_failed",
                tr!(
                    lang,
                    "couldn't get the DMARC record: {err}",
                    "не удалось получить DMARC-запись: {err}"
                ),
            );
            return result;
        }
    };
    let record = match records.as_slice() {
        [] => {
            if receives {
                result.add(
                    Status::Warning,
                    "dmarc.missing",
                    tr!(
                        lang,
                        "no DMARC record: Gmail, Yandex and Mail.ru trust your mail less, and forged mail isn't blocked. Start with \"v=DMARC1; p=none; rua=mailto:you@your-domain\"",
                        "нет DMARC-записи: Gmail, Яндекс и Mail.ru меньше доверяют вашим письмам, а подделки не блокируются. Начните с \"v=DMARC1; p=none; rua=mailto:вы@ваш-домен\""
                    ),
                );
            } else {
                result.add(
                    Status::Info,
                    "dmarc.missing_parked",
                    tr!(
                        lang,
                        "no DMARC record. If the domain doesn't send mail, \"v=DMARC1; p=reject\" forbids forging it",
                        "нет DMARC-записи. Если домен не отправляет почту, запись \"v=DMARC1; p=reject\" запретит подделывать его письма"
                    ),
                );
            }
            return result;
        }
        [record] => record,
        many => {
            let count = many.len();
            result.add(
                Status::Critical,
                "dmarc.multiple",
                tr!(
                    lang,
                    "{count} DMARC records found — receivers ignore all of them; keep one",
                    "найдено {count} DMARC-записи — получатели игнорируют их все; оставьте одну"
                ),
            );
            return result;
        }
    };

    let tags = parse_tags(record);
    let policy = tags.get("p").map(|p| p.to_ascii_lowercase());
    match policy.as_deref() {
        None => {
            result.add(
                Status::Critical,
                "dmarc.invalid",
                tr!(
                    lang,
                    "the record has no p= policy, so receivers ignore it",
                    "в записи нет политики p=, поэтому получатели её игнорируют"
                ),
            );
        }
        Some("none") => {
            result.add(
                Status::Warning,
                "dmarc.p_none",
                tr!(
                    lang,
                    "policy p=none only collects reports: forged mail is still delivered. Switch to p=quarantine or p=reject once the reports look clean",
                    "политика p=none только собирает отчёты: поддельные письма всё равно доставляются. Перейдите на p=quarantine или p=reject, когда отчёты станут чистыми"
                ),
            );
        }
        Some("quarantine" | "reject") => {}
        Some(other) => {
            result.add(
                Status::Critical,
                "dmarc.invalid",
                tr!(
                    lang,
                    "unknown policy p={other}",
                    "неизвестная политика p={other}"
                ),
            );
        }
    }
    if let Some(pct) = tags.get("pct")
        && pct.parse::<u8>().is_ok_and(|pct| pct < 100)
    {
        result.add(
            Status::Info,
            "dmarc.pct",
            tr!(
                lang,
                "the policy covers only {pct}% of mail",
                "политика действует только на {pct}% писем"
            ),
        );
    }
    let reports = tags.get("rua").filter(|rua| !rua.is_empty());
    if reports.is_none() {
        result.add(
            Status::Info,
            "dmarc.no_reports",
            tr!(
                lang,
                "no rua= address: you won't get reports about who sends mail as your domain",
                "нет адреса rua=: вы не будете получать отчёты о том, кто отправляет письма от имени домена"
            ),
        );
    }

    let mut summary = format!("p={}", policy.as_deref().unwrap_or("?"));
    if let Some(sp) = tags.get("sp") {
        summary.push_str(&format!(", sp={sp}"));
    }
    if let Some(rua) = reports {
        let rua = rua.replace("mailto:", "");
        summary.push_str(&tr!(lang, " · reports to {rua}", " · отчёты на {rua}"));
    }
    if inherited {
        let parent = unicode(registrable);
        summary.push_str(&tr!(
            lang,
            " (inherited from {parent})",
            " (унаследовано от {parent})"
        ));
    }
    result.summary(summary);
    result.fact("record", record.as_str());
    if let Some(policy) = policy {
        result.fact("policy", policy);
    }
    result
}

async fn check_dkim<R: Resolve>(
    dns: &R,
    domain: &str,
    subject: &str,
    configured: &[String],
    provider: Option<&'static Provider>,
    receives: bool,
    lang: Lang,
) -> Option<CheckResult> {
    let explicit = !configured.is_empty();
    if !receives && !explicit {
        return None;
    }
    let mut selectors: Vec<String> = Vec::new();
    let mut candidates: Vec<String> = configured.to_vec();
    if let Some(provider) = provider {
        candidates.extend(provider.selectors.iter().map(|s| s.to_string()));
    }
    if !explicit {
        candidates.extend(COMMON_SELECTORS.iter().map(|s| s.to_string()));
    }
    for selector in candidates {
        let selector = selector.trim().to_ascii_lowercase();
        if !selector.is_empty() && !selectors.contains(&selector) {
            selectors.push(selector);
        }
    }

    let mut result = CheckResult::new(CheckKind::Dkim, subject);
    let names: Vec<String> = selectors
        .iter()
        .map(|selector| format!("{selector}._domainkey.{domain}"))
        .collect();
    let answers = join_all(names.iter().map(|name| dns.txt(name))).await;
    let mut found = Vec::new();
    for (selector, answer) in selectors.iter().zip(answers) {
        match answer {
            Ok(records) => {
                if let Some(record) = records.iter().find(|r| {
                    let lower = r.to_ascii_lowercase();
                    lower.contains("v=dkim1") || lower.contains("p=")
                }) {
                    found.push(describe_key(selector, record, &mut result, lang));
                }
            }
            Err(DnsError::Failed(err)) if configured.contains(selector) => {
                result.add(
                    Status::Unknown,
                    "dkim.lookup_failed",
                    tr!(
                        lang,
                        "couldn't look up selector {selector}: {err}",
                        "не удалось проверить селектор {selector}: {err}"
                    ),
                );
            }
            Err(_) => {}
        }
    }

    if found.is_empty() {
        if explicit {
            let list = configured.join(", ");
            result.add(
                Status::Warning,
                "dkim.missing",
                tr!(
                    lang,
                    "no DKIM key for selector(s) {list} — mail isn't signed and lands in spam more often",
                    "по селекторам {list} нет DKIM-ключа — письма не подписываются и чаще попадают в спам"
                ),
            );
        } else {
            result.add(
                Status::Info,
                "dkim.not_found",
                tr!(
                    lang,
                    "no DKIM key among common selectors. Find your selector in the mail service settings and add it to the config: dkim_selectors = [\"...\"]",
                    "DKIM-ключ не найден среди распространённых селекторов. Узнайте свой селектор в настройках почтового сервиса и добавьте его в настройки: dkim_selectors = [\"...\"]"
                ),
            );
        }
    } else {
        let list = found.join(", ");
        result.summary(tr!(lang, "keys: {list}", "ключи: {list}"));
        result.fact("selectors", found);
    }
    Some(result)
}

/// "mail (RSA 2048)" for the summary; problems go into `result`.
fn describe_key(selector: &str, record: &str, result: &mut CheckResult, lang: Lang) -> String {
    let tags = parse_tags(record);
    let key: String = tags
        .get("p")
        .map(|p| p.chars().filter(|c| !c.is_whitespace()).collect())
        .unwrap_or_default();
    if key.is_empty() {
        result.add(
            Status::Warning,
            "dkim.revoked",
            tr!(
                lang,
                "selector {selector}: the key is revoked (empty p=)",
                "селектор {selector}: ключ отозван (пустой p=)"
            ),
        );
        return tr!(lang, "{selector} (revoked)", "{selector} (отозван)");
    }
    let kind = tags
        .get("k")
        .map(|k| k.to_ascii_lowercase())
        .unwrap_or_else(|| "rsa".into());
    if kind == "ed25519" {
        return format!("{selector} (Ed25519)");
    }
    let Ok(der) = STANDARD.decode(&key) else {
        result.add(
            Status::Warning,
            "dkim.bad_key",
            tr!(
                lang,
                "selector {selector}: the key can't be read",
                "селектор {selector}: ключ не читается"
            ),
        );
        return selector.to_string();
    };
    let bits = SubjectPublicKeyInfo::from_der(&der)
        .ok()
        .and_then(|(_, info)| match info.parsed() {
            Ok(PublicKey::RSA(rsa)) => Some(rsa.key_size()),
            _ => None,
        });
    match bits {
        Some(bits) if bits < 2048 => {
            let status = if bits < 1024 {
                Status::Critical
            } else {
                Status::Warning
            };
            result.add(
                status,
                "dkim.weak_key",
                tr!(
                    lang,
                    "selector {selector}: a {bits}-bit RSA key is weak — switch to 2048 bits",
                    "селектор {selector}: RSA-ключ на {bits} бит слабый — перейдите на 2048 бит"
                ),
            );
            format!("{selector} (RSA {bits})")
        }
        Some(bits) => format!("{selector} (RSA {bits})"),
        None => format!("{selector} (RSA)"),
    }
}

fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::fake::FakeDns;

    fn codes(result: &CheckResult) -> Vec<&'static str> {
        result.findings.iter().map(|f| f.code).collect()
    }

    #[tokio::test]
    async fn spf_problems() {
        let dns = FakeDns::default()
            .with_txt(
                "a.test",
                &["v=spf1 include:b.test include:missing.test +all"],
            )
            .with_txt("b.test", &["v=spf1 ip4:192.0.2.1 -all"]);
        let result = check_spf(&dns, "a.test", "a.test", true, Lang::En).await;
        assert_eq!(result.status, Status::Critical);
        assert_eq!(codes(&result), ["spf.plus_all", "spf.broken_include"]);
        assert_eq!(result.facts["lookups"], 2);

        let dns = FakeDns::default().with_txt("c.test", &["v=spf1 -all", "v=spf1 mx -all"]);
        let result = check_spf(&dns, "c.test", "c.test", true, Lang::En).await;
        assert_eq!(codes(&result), ["spf.multiple"]);
    }

    #[tokio::test]
    async fn spf_lookup_limit() {
        // Eleven includes, each costing one lookup.
        let includes: String = (0..11).map(|i| format!(" include:i{i}.test")).collect();
        let record = format!("v=spf1{includes} -all");
        let mut dns = FakeDns::default().with_txt("big.test", &[&record]);
        for i in 0..11 {
            dns = dns.with_txt(&format!("i{i}.test"), &["v=spf1 ip4:192.0.2.1 -all"]);
        }
        let result = check_spf(&dns, "big.test", "big.test", true, Lang::En).await;
        assert_eq!(codes(&result), ["spf.too_many_lookups"]);
    }

    #[tokio::test]
    async fn dmarc_policy() {
        let dns = FakeDns::default().with_txt("_dmarc.d.test", &["v=DMARC1; p=none"]);
        let result = check_dmarc(&dns, "d.test", "d.test", "d.test", true, Lang::En).await;
        assert_eq!(codes(&result), ["dmarc.p_none", "dmarc.no_reports"]);

        let dns = FakeDns::default().with_txt(
            "_dmarc.d.test",
            &["v=DMARC1; p=reject; rua=mailto:dmarc@d.test"],
        );
        let result =
            check_dmarc(&dns, "shop.d.test", "d.test", "shop.d.test", true, Lang::En).await;
        assert_eq!(result.status, Status::Ok);
        assert!(result.summary.contains("inherited"), "{}", result.summary);
    }
}
