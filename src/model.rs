//! Check results and the overall report.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::i18n::Lang;

/// How bad a result is. Ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    #[default]
    Ok,
    /// Advice; doesn't count as a problem.
    Info,
    /// The check couldn't be completed (registry offline, DNS timeout…).
    Unknown,
    Warning,
    Critical,
}

impl Status {
    pub fn icon(self) -> &'static str {
        match self {
            Status::Ok => "✔",
            Status::Info => "ℹ",
            Status::Unknown => "?",
            Status::Warning => "⚠",
            Status::Critical => "✘",
        }
    }

    /// Unknown, warning and critical results need attention.
    pub fn is_problem(self) -> bool {
        self >= Status::Unknown
    }

    pub fn label(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Status::Ok, Lang::En) => "OK",
            (Status::Ok, Lang::Ru) => "в порядке",
            (Status::Info, Lang::En) => "OK, with advice",
            (Status::Info, Lang::Ru) => "в порядке, есть советы",
            (Status::Unknown, Lang::En) => "not fully checked",
            (Status::Unknown, Lang::Ru) => "проверено не всё",
            (Status::Warning, Lang::En) => "warnings",
            (Status::Warning, Lang::Ru) => "есть предупреждения",
            (Status::Critical, Lang::En) => "critical",
            (Status::Critical, Lang::Ru) => "критично",
        }
    }
}

/// A single kind of check shown as one line of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckKind {
    Dns,
    Domain,
    Tls,
    Http,
    Mx,
    Spf,
    Dmarc,
    Dkim,
}

impl CheckKind {
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            CheckKind::Dns => "DNS",
            CheckKind::Domain if lang == Lang::Ru => "Домен",
            CheckKind::Domain => "Domain",
            CheckKind::Tls => "TLS",
            CheckKind::Http => "HTTP",
            CheckKind::Mx => "MX",
            CheckKind::Spf => "SPF",
            CheckKind::Dmarc => "DMARC",
            CheckKind::Dkim => "DKIM",
        }
    }

    pub fn group(self) -> Group {
        match self {
            CheckKind::Dns => Group::Dns,
            CheckKind::Domain => Group::Domain,
            CheckKind::Tls => Group::Tls,
            CheckKind::Http => Group::Http,
            CheckKind::Mx | CheckKind::Spf | CheckKind::Dmarc | CheckKind::Dkim => Group::Mail,
        }
    }
}

/// Groups of checks that can be turned on and off (`--only`, `--skip`, `skip = [...]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Group {
    Dns,
    Domain,
    Tls,
    Http,
    Mail,
}

impl Group {
    pub const ALL: [Group; 5] = [
        Group::Dns,
        Group::Domain,
        Group::Tls,
        Group::Http,
        Group::Mail,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Group::Dns => "dns",
            Group::Domain => "domain",
            Group::Tls => "tls",
            Group::Http => "http",
            Group::Mail => "mail",
        }
    }
}

impl FromStr for Group {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "dns" => Group::Dns,
            "domain" | "registration" | "whois" | "rdap" | "expiry" => Group::Domain,
            "tls" | "ssl" | "cert" | "certificate" => Group::Tls,
            "http" | "https" | "web" | "site" => Group::Http,
            "mail" | "email" | "e-mail" | "mx" | "spf" | "dkim" | "dmarc" => Group::Mail,
            other => {
                return Err(format!(
                    "unknown check '{other}' (use dns, domain, tls, http or mail)"
                ));
            }
        })
    }
}

impl TryFrom<String> for Group {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Group> for String {
    fn from(group: Group) -> Self {
        group.as_str().to_string()
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One problem or piece of advice found by a check.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub status: Status,
    /// Stable machine-readable id such as `tls.expiring`.
    pub code: &'static str,
    pub message: String,
}

/// The result of one check against one subject (a host or a domain).
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub kind: CheckKind,
    pub subject: String,
    pub status: Status,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub facts: Map<String, Value>,
}

impl CheckResult {
    pub fn new(kind: CheckKind, subject: impl Into<String>) -> Self {
        CheckResult {
            kind,
            subject: subject.into(),
            status: Status::Ok,
            summary: String::new(),
            findings: Vec::new(),
            facts: Map::new(),
        }
    }

    pub fn summary(&mut self, summary: impl Into<String>) -> &mut Self {
        self.summary = summary.into();
        self
    }

    /// Adds a finding; the result's status becomes the worst one seen.
    pub fn add(
        &mut self,
        status: Status,
        code: &'static str,
        message: impl Into<String>,
    ) -> &mut Self {
        self.status = self.status.max(status);
        self.findings.push(Finding {
            status,
            code,
            message: message.into(),
        });
        self
    }

    pub fn fact(&mut self, key: &str, value: impl Into<Value>) -> &mut Self {
        self.facts.insert(key.to_string(), value.into());
        self
    }

    /// The text for the report's main line: the summary, or the first finding when
    /// the check failed before it could describe anything.
    pub fn headline(&self) -> &str {
        if self.summary.is_empty() {
            self.findings.first().map_or("", |f| f.message.as_str())
        } else {
            &self.summary
        }
    }

    /// Findings shown below the headline.
    pub fn details(&self) -> &[Finding] {
        if self.summary.is_empty() && !self.findings.is_empty() {
            &self.findings[1..]
        } else {
            &self.findings
        }
    }
}

/// All results for one domain from the list.
#[derive(Debug, Clone, Serialize)]
pub struct DomainReport {
    /// The domain as the user wrote it (Unicode for IDN domains).
    pub domain: String,
    pub status: Status,
    pub checks: Vec<CheckResult>,
}

impl DomainReport {
    pub fn new(domain: impl Into<String>, checks: Vec<CheckResult>) -> Self {
        let status = checks.iter().map(|c| c.status).max().unwrap_or_default();
        DomainReport {
            domain: domain.into(),
            status,
            checks,
        }
    }

    pub fn problem_count(&self) -> usize {
        self.checks
            .iter()
            .flat_map(|c| &c.findings)
            .filter(|f| f.status.is_problem())
            .count()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: &'static str,
    /// RFC 3339 time when the check started.
    pub checked_at: String,
    pub duration_ms: u64,
    pub status: Status,
    pub domains: Vec<DomainReport>,
}

impl Report {
    pub fn new(checked_at: String, duration_ms: u64, domains: Vec<DomainReport>) -> Self {
        let status = domains.iter().map(|d| d.status).max().unwrap_or_default();
        Report {
            version: env!("CARGO_PKG_VERSION"),
            checked_at,
            duration_ms,
            status,
            domains,
        }
    }

    pub fn count(&self, pred: impl Fn(Status) -> bool) -> usize {
        self.domains.iter().filter(|d| pred(d.status)).count()
    }

    pub fn problem_count(&self) -> usize {
        self.domains.iter().map(DomainReport::problem_count).sum()
    }

    /// 0 — all fine, 1 — warnings or unchecked items, 2 — critical problems.
    pub fn exit_code(&self) -> i32 {
        match self.status {
            Status::Ok | Status::Info => 0,
            Status::Unknown | Status::Warning => 1,
            Status::Critical => 2,
        }
    }
}
