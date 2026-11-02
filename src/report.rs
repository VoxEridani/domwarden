//! Rendering a report for the terminal.

use std::fmt::Write;

use anstyle::{AnsiColor, Style};

use crate::i18n::{self, Lang};
use crate::model::{Report, Status};
use crate::tr;

pub fn style(status: Status) -> Style {
    let color = match status {
        Status::Ok => AnsiColor::Green,
        Status::Info => AnsiColor::Cyan,
        Status::Unknown => AnsiColor::Magenta,
        Status::Warning => AnsiColor::Yellow,
        Status::Critical => AnsiColor::Red,
    };
    Style::new().fg_color(Some(color.into()))
}

const LABEL_WIDTH: usize = 6;

/// The coloured text report. Print it with `anstream` so colours are dropped
/// when the output isn't a terminal.
pub fn render_text(report: &Report, lang: Lang, quiet: bool) -> String {
    let bold = Style::new().bold();
    let dim = Style::new().dimmed();
    let indent = " ".repeat(2 + 2 + LABEL_WIDTH + 1);
    let mut out = String::new();
    for domain in &report.domains {
        if quiet && !domain.status.is_problem() {
            continue;
        }
        let s = style(domain.status);
        let _ = writeln!(
            out,
            "{bold}{}{bold:#}  {s}{} {}{s:#}",
            domain.domain,
            domain.status.icon(),
            domain.status.label(lang)
        );
        for check in &domain.checks {
            if quiet && !check.status.is_problem() {
                continue;
            }
            let s = style(check.status);
            let label = check.kind.label(lang);
            let prefix = if check.subject == domain.domain {
                String::new()
            } else {
                format!("{}: ", check.subject)
            };
            let _ = writeln!(
                out,
                "  {s}{}{s:#} {label:<LABEL_WIDTH$} {prefix}{}",
                check.status.icon(),
                check.headline()
            );
            for finding in check.details() {
                if quiet && !finding.status.is_problem() {
                    continue;
                }
                let s = style(finding.status);
                let text = if finding.status == Status::Info {
                    format!("{dim}{}{dim:#}", finding.message)
                } else {
                    finding.message.clone()
                };
                let _ = writeln!(out, "{indent}{s}{}{s:#} {text}", finding.status.icon());
            }
        }
        out.push('\n');
    }
    let _ = writeln!(out, "{}", summary_line(report, lang));
    out
}

pub fn summary_line(report: &Report, lang: Lang) -> String {
    let total = i18n::domains(lang, report.domains.len());
    let ok = report.count(|s| !s.is_problem());
    let warn = report.count(|s| matches!(s, Status::Unknown | Status::Warning));
    let crit = report.count(|s| s == Status::Critical);
    let secs = report.duration_ms as f64 / 1000.0;
    let (g, y, r) = (
        style(Status::Ok),
        style(Status::Warning),
        style(Status::Critical),
    );
    tr!(
        lang,
        "Checked {total} in {secs:.1} s: {g}{ok} OK{g:#}, {y}{warn} with warnings{y:#}, {r}{crit} critical{r:#}",
        "Проверено: {total} за {secs:.1} с. {g}В порядке: {ok}{g:#}, {y}с предупреждениями: {warn}{y:#}, {r}критично: {crit}{r:#}"
    )
}
