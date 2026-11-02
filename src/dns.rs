//! DNS lookups. Checks talk to the [`Resolve`] trait so tests can use canned answers.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The name doesn't exist at all (NXDOMAIN).
    NxDomain,
    /// The name exists but has no records of this type.
    NoRecords,
    Failed(String),
}

impl DnsError {
    /// True for "nothing there" answers, as opposed to lookup failures.
    pub fn is_empty(&self) -> bool {
        matches!(self, DnsError::NxDomain | DnsError::NoRecords)
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NxDomain => f.write_str("name does not exist"),
            DnsError::NoRecords => f.write_str("no records"),
            DnsError::Failed(reason) => f.write_str(reason),
        }
    }
}

impl From<NetError> for DnsError {
    fn from(err: NetError) -> Self {
        if err.is_nx_domain() {
            DnsError::NxDomain
        } else if err.is_no_records_found() {
            DnsError::NoRecords
        } else {
            DnsError::Failed(err.to_string())
        }
    }
}

pub type DnsResult<T> = Result<T, DnsError>;

pub trait Resolve: Send + Sync {
    /// TXT records, each with its character-strings joined together.
    fn txt(&self, name: &str) -> impl Future<Output = DnsResult<Vec<String>>> + Send;
    /// MX records as (preference, exchange), sorted by preference.
    fn mx(&self, name: &str) -> impl Future<Output = DnsResult<Vec<(u16, String)>>> + Send;
    fn ns(&self, name: &str) -> impl Future<Output = DnsResult<Vec<String>>> + Send;
    fn ips(&self, name: &str) -> impl Future<Output = DnsResult<Vec<IpAddr>>> + Send;
}

/// Asks every configured DNS server at once and takes the first definite answer.
///
/// One resolver per server: a home router that times out on large answers
/// (long SPF and DKIM records) must not hide the answer another server has.
pub struct Dns {
    resolvers: Vec<TokioResolver>,
}

impl Dns {
    /// Uses the system DNS servers, or `servers` when given.
    pub fn new(servers: &[String], timeout: Duration) -> Result<Self, String> {
        let (name_servers, base) = if servers.is_empty() {
            system_servers().unwrap_or_else(|| {
                // No usable system settings: fall back to a public resolver.
                let (_, _, public) = ResolverConfig::udp_and_tcp(&CLOUDFLARE).into_parts();
                (public, ResolverOpts::default())
            })
        } else {
            let mut name_servers = Vec::new();
            for server in servers {
                let ip: IpAddr = server
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{server}' is not an IP address of a DNS server"))?;
                name_servers.push(NameServerConfig::udp_and_tcp(ip));
            }
            (name_servers, ResolverOpts::default())
        };
        let mut resolvers = Vec::with_capacity(name_servers.len());
        for server in name_servers {
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![server]),
                TokioRuntimeProvider::default(),
            );
            let options = builder.options_mut();
            *options = base.clone();
            options.timeout = timeout.min(Duration::from_secs(5));
            options.attempts = 2;
            options.edns0 = true;
            options.try_tcp_on_error = true;
            resolvers.push(builder.build().map_err(|e| e.to_string())?);
        }
        Ok(Dns { resolvers })
    }

    /// Runs `lookup` on every server; "no such name" and "no records" count as answers,
    /// timeouts and server failures don't.
    async fn race<T, F>(&self, lookup: impl Fn(TokioResolver) -> F) -> DnsResult<T>
    where
        F: Future<Output = Result<T, NetError>> + Send,
        T: Send,
    {
        let attempts: Vec<_> = self
            .resolvers
            .iter()
            .cloned()
            .map(|resolver| {
                let query = lookup(resolver);
                Box::pin(async move {
                    match query.await {
                        Ok(answer) => Ok(Ok(answer)),
                        Err(err) => match DnsError::from(err) {
                            empty if empty.is_empty() => Ok(Err(empty)),
                            failed => Err(failed),
                        },
                    }
                })
            })
            .collect();
        if attempts.is_empty() {
            return Err(DnsError::Failed("no DNS servers".into()));
        }
        match futures::future::select_ok(attempts).await {
            Ok((answer, _)) => answer,
            Err(err) => Err(err),
        }
    }
}

/// The system DNS servers without placeholders Windows lists for empty settings
/// (`0.0.0.0`, `fec0:0:0:ffff::1`), which only make every query wait for a timeout.
fn system_servers() -> Option<(Vec<NameServerConfig>, ResolverOpts)> {
    let (config, options) = hickory_resolver::system_conf::read_system_conf().ok()?;
    let (_, _, servers) = config.into_parts();
    let mut usable: Vec<NameServerConfig> = Vec::new();
    for server in servers {
        let placeholder = match server.ip {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified() || (ip.segments()[0] & 0xffc0) == 0xfec0,
        };
        if !placeholder && !usable.iter().any(|known| known.ip == server.ip) {
            usable.push(server);
        }
    }
    (!usable.is_empty()).then_some((usable, options))
}

/// Lookups use fully-qualified names so search domains are never appended.
fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// `mail.example.com.` → `mail.example.com`.
pub fn display_name(name: &impl fmt::Display) -> String {
    name.to_string().trim_end_matches('.').to_lowercase()
}

impl Resolve for Dns {
    async fn txt(&self, name: &str) -> DnsResult<Vec<String>> {
        let name = fqdn(name);
        let lookup = self
            .race(|resolver| {
                let name = name.clone();
                async move { resolver.txt_lookup(name).await }
            })
            .await?;
        let records: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part))
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect();
        non_empty(records)
    }

    async fn mx(&self, name: &str) -> DnsResult<Vec<(u16, String)>> {
        let name = fqdn(name);
        let lookup = self
            .race(|resolver| {
                let name = name.clone();
                async move { resolver.mx_lookup(name).await }
            })
            .await?;
        let mut records: Vec<(u16, String)> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::MX(mx) => Some((mx.preference, display_name(&mx.exchange))),
                _ => None,
            })
            .collect();
        records.sort();
        non_empty(records)
    }

    async fn ns(&self, name: &str) -> DnsResult<Vec<String>> {
        let name = fqdn(name);
        let lookup = self
            .race(|resolver| {
                let name = name.clone();
                async move { resolver.ns_lookup(name).await }
            })
            .await?;
        let mut records: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(display_name(&ns.0)),
                _ => None,
            })
            .collect();
        records.sort();
        non_empty(records)
    }

    async fn ips(&self, name: &str) -> DnsResult<Vec<IpAddr>> {
        let name = fqdn(name);
        let lookup = self
            .race(|resolver| {
                let name = name.clone();
                async move { resolver.lookup_ip(name).await }
            })
            .await?;
        non_empty(lookup.iter().collect())
    }
}

fn non_empty<T>(items: Vec<T>) -> DnsResult<Vec<T>> {
    if items.is_empty() {
        Err(DnsError::NoRecords)
    } else {
        Ok(items)
    }
}

#[cfg(test)]
pub mod fake {
    //! Canned DNS answers for tests.

    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    pub struct FakeDns {
        pub txt: HashMap<String, Vec<String>>,
        pub mx: HashMap<String, Vec<(u16, String)>>,
        pub ips: HashMap<String, Vec<IpAddr>>,
    }

    impl FakeDns {
        pub fn with_txt(mut self, name: &str, records: &[&str]) -> Self {
            self.txt.insert(
                name.to_string(),
                records.iter().map(|r| r.to_string()).collect(),
            );
            self
        }
    }

    fn get<T: Clone>(map: &HashMap<String, Vec<T>>, name: &str) -> DnsResult<Vec<T>> {
        map.get(name).cloned().ok_or(DnsError::NoRecords)
    }

    impl Resolve for FakeDns {
        async fn txt(&self, name: &str) -> DnsResult<Vec<String>> {
            get(&self.txt, name)
        }
        async fn mx(&self, name: &str) -> DnsResult<Vec<(u16, String)>> {
            get(&self.mx, name)
        }
        async fn ns(&self, _name: &str) -> DnsResult<Vec<String>> {
            Err(DnsError::NoRecords)
        }
        async fn ips(&self, name: &str) -> DnsResult<Vec<IpAddr>> {
            get(&self.ips, name)
        }
    }
}
