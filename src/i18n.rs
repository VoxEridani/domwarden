//! Output language: English or Russian.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    /// Picks the language from the operating system locale.
    pub fn detect() -> Lang {
        sys_locale::get_locale()
            .map(|locale| Self::from_locale(&locale))
            .unwrap_or_default()
    }

    fn from_locale(locale: &str) -> Lang {
        if locale.to_ascii_lowercase().starts_with("ru") {
            Lang::Ru
        } else {
            Lang::En
        }
    }
}

impl FromStr for Lang {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "en" | "eng" | "english" => Ok(Lang::En),
            "ru" | "rus" | "russian" | "рус" | "русский" => Ok(Lang::Ru),
            other => Err(format!("unknown language '{other}' (use en or ru)")),
        }
    }
}

impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Lang::En => "en",
            Lang::Ru => "ru",
        })
    }
}

/// Formats a message in the chosen language:
/// `tr!(lang, "{n} days left", "осталось {n} дн.")`.
#[macro_export]
macro_rules! tr {
    ($lang:expr, $en:literal, $ru:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            $crate::i18n::Lang::En => format!($en $(, $arg)*),
            $crate::i18n::Lang::Ru => format!($ru $(, $arg)*),
        }
    };
}

/// Russian plural form: 1 день, 2 дня, 5 дней.
pub fn plural_ru<'a>(n: i64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let n = n.unsigned_abs();
    match (n % 10, n % 100) {
        (_, 11..=14) => many,
        (1, _) => one,
        (2..=4, _) => few,
        _ => many,
    }
}

/// "1 day" / "5 days" / "1 день" / "5 дней".
pub fn days(lang: Lang, n: i64) -> String {
    match lang {
        Lang::En if n.abs() == 1 => format!("{n} day"),
        Lang::En => format!("{n} days"),
        Lang::Ru => format!("{n} {}", plural_ru(n, "день", "дня", "дней")),
    }
}

/// "1 domain" / "3 domains" / "1 домен" / "3 домена".
pub fn domains(lang: Lang, n: usize) -> String {
    match lang {
        Lang::En if n == 1 => "1 domain".to_string(),
        Lang::En => format!("{n} domains"),
        Lang::Ru => format!("{n} {}", plural_ru(n as i64, "домен", "домена", "доменов")),
    }
}

/// "1 problem" / "4 problems" / "1 проблема" / "4 проблемы".
pub fn problems(lang: Lang, n: usize) -> String {
    match lang {
        Lang::En if n == 1 => "1 problem".to_string(),
        Lang::En => format!("{n} problems"),
        Lang::Ru => format!(
            "{n} {}",
            plural_ru(n as i64, "проблема", "проблемы", "проблем")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_plurals() {
        assert_eq!(days(Lang::Ru, 1), "1 день");
        assert_eq!(days(Lang::Ru, 3), "3 дня");
        assert_eq!(days(Lang::Ru, 12), "12 дней");
        assert_eq!(days(Lang::Ru, 21), "21 день");
        assert_eq!(days(Lang::En, 1), "1 day");
        assert_eq!(Lang::from_locale("ru-RU"), Lang::Ru);
        assert_eq!(Lang::from_locale("en-US"), Lang::En);
    }
}
