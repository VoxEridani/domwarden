//! The `domwarden.toml` config file.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

use crate::i18n::Lang;
use crate::model::{Group, Status};

pub const FILE_NAME: &str = "domwarden.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub lang: Option<Lang>,
    /// Short form: `domains = ["example.com", { name = "example.org", skip = ["mail"] }]`.
    #[serde(default)]
    pub domains: Vec<DomainEntry>,
    /// Long form: `[[domain]]` tables.
    #[serde(default, rename = "domain")]
    pub domain_tables: Vec<DomainConfig>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub notify: NotifyConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DomainEntry {
    Name(String),
    Full(DomainConfig),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainConfig {
    pub name: String,
    /// Hosts whose certificate and site are checked; the domain itself by default.
    /// A host may carry a port: `example.com:8443`.
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub skip: Vec<Group>,
    #[serde(default)]
    pub dkim_selectors: Vec<String>,
}

impl DomainConfig {
    pub fn named(name: impl Into<String>) -> Self {
        DomainConfig {
            name: name.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub cert_warning_days: i64,
    pub cert_critical_days: i64,
    pub domain_warning_days: i64,
    pub domain_critical_days: i64,
    pub slow_response_ms: u64,
    pub timeout_secs: u64,
    pub concurrency: usize,
    /// Extra DKIM selectors tried for every domain.
    pub dkim_selectors: Vec<String>,
    /// DNS servers to use instead of the system ones, e.g. `["1.1.1.1"]`.
    pub dns_servers: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            cert_warning_days: 14,
            cert_critical_days: 7,
            domain_warning_days: 30,
            domain_critical_days: 7,
            slow_response_ms: 3000,
            timeout_secs: 10,
            concurrency: 8,
            dkim_selectors: Vec::new(),
            dns_servers: Vec::new(),
        }
    }
}

/// When notifications are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyOn {
    Always,
    #[default]
    #[serde(alias = "problems")]
    Warning,
    Critical,
    Never,
}

impl NotifyOn {
    pub fn wants(self, status: Status) -> bool {
        match self {
            NotifyOn::Always => true,
            NotifyOn::Warning => status.is_problem(),
            NotifyOn::Critical => status == Status::Critical,
            NotifyOn::Never => false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub on: NotifyOn,
    pub telegram: Option<TelegramConfig>,
    pub email: Option<EmailConfig>,
    pub webhook: Vec<WebhookConfig>,
}

impl NotifyConfig {
    pub fn is_empty(&self) -> bool {
        self.telegram.is_none() && self.email.is_none() && self.webhook.is_empty()
    }

    /// Replaces `${NAME}` with environment variables in every notification setting,
    /// so secrets don't have to live in the file.
    fn expand_env(&mut self) -> Result<(), String> {
        if let Some(tg) = &mut self.telegram {
            expand(&mut tg.bot_token, "notify.telegram.bot_token")?;
            for chat in &mut tg.chat_id {
                expand(chat, "notify.telegram.chat_id")?;
            }
            if let Some(url) = &mut tg.api_url {
                expand(url, "notify.telegram.api_url")?;
            }
        }
        if let Some(email) = &mut self.email {
            expand(&mut email.host, "notify.email.host")?;
            expand(&mut email.from, "notify.email.from")?;
            for field in [&mut email.username, &mut email.password]
                .into_iter()
                .flatten()
            {
                expand(field, "notify.email")?;
            }
            for to in &mut email.to {
                expand(to, "notify.email.to")?;
            }
        }
        for hook in &mut self.webhook {
            expand(&mut hook.url, "notify.webhook.url")?;
            for value in hook.headers.values_mut() {
                expand(value, "notify.webhook.headers")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token: String,
    #[serde(deserialize_with = "one_or_many")]
    pub chat_id: Vec<String>,
    pub thread_id: Option<i64>,
    /// For self-hosted Bot API servers or proxies.
    pub api_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    pub host: String,
    pub port: Option<u16>,
    pub security: Option<Security>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    #[serde(deserialize_with = "one_or_many")]
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// Encrypted from the start (usually port 465).
    Tls,
    /// Plain connection upgraded with STARTTLS (usually port 587).
    Starttls,
    /// No encryption — only for local relays.
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    pub format: Option<WebhookFormat>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    Json,
    Slack,
    Discord,
}

#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let error = |message: String| ConfigError {
            path: path.to_path_buf(),
            message,
        };
        let text = std::fs::read_to_string(path).map_err(|e| error(e.to_string()))?;
        Self::parse(&text).map_err(error)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        config.notify.expand_env()?;
        Ok(config)
    }

    /// Both list forms merged, in file order (short form first).
    pub fn domain_list(&self) -> Vec<DomainConfig> {
        self.domains
            .iter()
            .map(|entry| match entry {
                DomainEntry::Name(name) => DomainConfig::named(name),
                DomainEntry::Full(config) => config.clone(),
            })
            .chain(self.domain_tables.iter().cloned())
            .collect()
    }
}

/// Where `domwarden init` puts the config: `%APPDATA%\domwarden\domwarden.toml` on Windows,
/// `~/.config/domwarden/domwarden.toml` on Linux.
pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("domwarden").join(FILE_NAME))
}

/// `domwarden.toml` in the current folder, else the default location.
pub fn find() -> Option<PathBuf> {
    let local = PathBuf::from(FILE_NAME);
    if local.is_file() {
        return Some(local);
    }
    default_path().filter(|path| path.is_file())
}

fn expand(value: &mut String, field: &str) -> Result<(), String> {
    if value.contains("${") {
        *value = expand_env(value, field)?;
    }
    Ok(())
}

fn expand_env(value: &str, field: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("{field}: '${{' without a closing '}}'"))?;
        let name = &after[..end];
        let found = std::env::var(name)
            .map_err(|_| format!("{field}: environment variable {name} is not set"))?;
        out.push_str(&found);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn one_or_many<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Item {
        Text(String),
        Number(i64),
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Item),
        Many(Vec<Item>),
    }
    let text = |item: Item| match item {
        Item::Text(s) => s,
        Item::Number(n) => n.to_string(),
    };
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(item) => vec![text(item)],
        OneOrMany::Many(items) => items.into_iter().map(text).collect(),
    })
}

/// The file written by `domwarden init`.
pub fn starter(lang: Lang) -> &'static str {
    match lang {
        Lang::En => STARTER_EN,
        Lang::Ru => STARTER_RU,
    }
}

const STARTER_EN: &str = r#"# Domwarden settings. Lines starting with # are comments.
# To turn a setting on, remove the # at the start of its line.

# Report language: "en" or "ru". The system language is used when not set.
# lang = "en"

# Domains to check.
domains = [
    "example.com",
    # "example.org",
]

# A domain with its own settings goes into a [[domain]] block.
# [[domain]]
# name = "example.net"
# hosts = ["example.net", "www.example.net"]   # site addresses to check (default: the domain itself)
# skip = ["mail"]                              # checks to skip: dns, domain, tls, http, mail
# dkim_selectors = ["mail"]                    # DKIM selectors of your mail service (see README)

[settings]
# How many days before expiry to warn.
cert_warning_days = 14      # certificate: warning
cert_critical_days = 7      # certificate: critical
domain_warning_days = 30    # domain registration: warning
domain_critical_days = 7    # domain registration: critical
# slow_response_ms = 3000   # warn when the site answers slower than this
# timeout_secs = 10         # how long to wait for an answer
# dns_servers = ["1.1.1.1", "8.8.8.8"]   # your own DNS servers instead of the system ones

[notify]
# When to send notifications: "warning" — on any problem, "critical" — only serious ones,
# "always" — after every check, "never" — don't send.
on = "warning"

# Telegram. How to get a bot token and chat_id — see README.
# [notify.telegram]
# bot_token = "123456789:AAE..."
# chat_id = "123456789"

# Email.
# [notify.email]
# host = "smtp.gmail.com"
# port = 465
# username = "you@gmail.com"
# password = "${DOMWARDEN_SMTP_PASSWORD}"   # secrets can come from environment variables
# from = "you@gmail.com"
# to = ["you@gmail.com"]

# Webhook — you can add several blocks.
# [[notify.webhook]]
# url = "https://hooks.slack.com/services/..."
"#;

const STARTER_RU: &str = r#"# Настройки Domwarden. Строки, которые начинаются с #, — комментарии.
# Чтобы включить настройку, удалите # в начале её строки.

# Язык отчёта: "ru" или "en". Если не указан, берётся язык системы.
# lang = "ru"

# Какие домены проверять.
domains = [
    "example.com",
    # "example.ru",
]

# Домен с особыми настройками записывается отдельным блоком [[domain]].
# [[domain]]
# name = "example.org"
# hosts = ["example.org", "www.example.org"]   # какие адреса сайта проверять (по умолчанию — сам домен)
# skip = ["mail"]                              # какие проверки пропустить: dns, domain, tls, http, mail
# dkim_selectors = ["mail"]                    # селекторы DKIM вашей почты (см. README)

[settings]
# За сколько дней до окончания срока предупреждать.
cert_warning_days = 14      # сертификат: предупреждение
cert_critical_days = 7      # сертификат: тревога
domain_warning_days = 30    # оплата домена: предупреждение
domain_critical_days = 7    # оплата домена: тревога
# slow_response_ms = 3000   # если сайт отвечает дольше (в миллисекундах) — предупреждение
# timeout_secs = 10         # сколько секунд ждать ответа
# dns_servers = ["1.1.1.1", "8.8.8.8"]   # свои DNS-серверы вместо системных

[notify]
# Когда присылать оповещения: "warning" — при любой проблеме, "critical" — только при серьёзной,
# "always" — после каждой проверки, "never" — не присылать.
on = "warning"

# Telegram. Как получить токен бота и chat_id — см. README.
# [notify.telegram]
# bot_token = "123456789:AAE..."
# chat_id = "123456789"

# Почта.
# [notify.email]
# host = "smtp.yandex.ru"
# port = 465
# username = "you@yandex.ru"
# password = "${DOMWARDEN_SMTP_PASSWORD}"   # пароль можно брать из переменной окружения
# from = "you@yandex.ru"
# to = ["you@yandex.ru"]

# Вебхук — блоков может быть несколько.
# [[notify.webhook]]
# url = "https://hooks.slack.com/services/..."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_domain_forms_and_env() {
        // SAFETY: tests in this module don't touch this variable concurrently.
        unsafe { std::env::set_var("DOMWARDEN_TEST_TOKEN", "123:abc") };
        let config = Config::parse(
            r#"
            domains = ["example.com", { name = "example.org", skip = ["mail"] }]

            [[domain]]
            name = "пример.рф"
            hosts = ["www.пример.рф"]

            [settings]
            cert_warning_days = 20

            [notify]
            on = "critical"

            [notify.telegram]
            bot_token = "${DOMWARDEN_TEST_TOKEN}"
            chat_id = 42
            "#,
        )
        .unwrap();
        let names: Vec<_> = config.domain_list().into_iter().map(|d| d.name).collect();
        assert_eq!(names, ["example.com", "example.org", "пример.рф"]);
        assert_eq!(config.domain_list()[1].skip, [Group::Mail]);
        assert_eq!(config.settings.cert_warning_days, 20);
        assert_eq!(config.settings.cert_critical_days, 7);
        let tg = config.notify.telegram.unwrap();
        assert_eq!(tg.bot_token, "123:abc");
        assert_eq!(tg.chat_id, ["42"]);
        assert_eq!(config.notify.on, NotifyOn::Critical);
    }

    #[test]
    fn rejects_typos_and_parses_starters() {
        let err = Config::parse("[settings]\ncert_warn_days = 5").unwrap_err();
        assert!(err.contains("cert_warn_days"), "{err}");
        for lang in [Lang::En, Lang::Ru] {
            let config = Config::parse(starter(lang)).unwrap();
            assert_eq!(config.domain_list().len(), 1);
        }
    }
}
