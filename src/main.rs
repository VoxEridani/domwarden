use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anstream::{eprintln, print, println};
use anstyle::Style;
use clap::{Args, Parser, Subcommand, ValueEnum};

use domwarden::config::{self, Config, DomainConfig};
use domwarden::notify::{self, Message, Notifier};
use domwarden::report::{self, style};
use domwarden::{Checker, Group, Lang, Report, Status, Target, i18n, tr};

const EXAMPLES: &str = "\
Examples:
  domwarden check example.com               check one domain
  domwarden check example.com example.org   check several
  domwarden init                            create a config file
  domwarden check                           check the domains from the config
  domwarden check --only tls,domain         only certificates and registration
  domwarden check --format json             machine-readable report
  domwarden notify-test                     send a test notification

Exit codes: 0 all fine, 1 warnings, 2 critical problems, 3 usage or config error.";

#[derive(Parser)]
#[command(
    name = "domwarden",
    bin_name = "domwarden",
    version,
    about = "Watches your domains: certificates, registration, DNS, email records and site availability.",
    after_help = EXAMPLES
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Config file [default: ./domwarden.toml, then the user config folder]
    #[arg(
        short,
        long,
        global = true,
        env = "DOMWARDEN_CONFIG",
        value_name = "FILE"
    )]
    config: Option<PathBuf>,
    /// Output language: en or ru [default: the system language]
    #[arg(long, global = true, env = "DOMWARDEN_LANG", value_name = "LANG")]
    lang: Option<Lang>,
}

#[derive(Subcommand)]
enum Command {
    /// Check domains and print a report
    Check(CheckArgs),
    /// Create a starter config file
    Init(InitArgs),
    /// Send a test message to every notification channel in the config
    NotifyTest,
}

#[derive(Args)]
struct CheckArgs {
    /// Domains to check [default: the ones from the config]
    domains: Vec<String>,
    /// Run only these checks: dns, domain, tls, http, mail
    #[arg(long, value_delimiter = ',', value_name = "CHECKS")]
    only: Vec<Group>,
    /// Skip these checks
    #[arg(long, value_delimiter = ',', value_name = "CHECKS")]
    skip: Vec<Group>,
    /// Report format
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Show only problems
    #[arg(short, long)]
    quiet: bool,
    /// Send notifications even for domains given on the command line
    #[arg(long, conflicts_with = "no_notify")]
    notify: bool,
    /// Don't send notifications
    #[arg(long)]
    no_notify: bool,
}

#[derive(Args)]
struct InitArgs {
    /// Where to create the file [default: the user config folder]
    path: Option<PathBuf>,
    /// Overwrite an existing file
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(if err.use_stderr() { 3 } else { 0 });
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(3);
        }
    };
    ExitCode::from(runtime.block_on(run(cli)))
}

async fn run(cli: Cli) -> u8 {
    let early_lang = cli.lang.unwrap_or_else(Lang::detect);
    if let Command::Init(args) = &cli.command {
        return init(args, cli.config.as_deref(), early_lang);
    }
    let path = cli.config.clone().or_else(config::find);
    let config = match &path {
        Some(path) => match Config::load(path) {
            Ok(config) => config,
            Err(err) => {
                error(early_lang, &err.to_string());
                return 3;
            }
        },
        None => Config::default(),
    };
    let lang = cli.lang.or(config.lang).unwrap_or_else(Lang::detect);
    match cli.command {
        Command::Check(args) => check(args, config, lang).await,
        Command::NotifyTest => notify_test(config, path, lang).await,
        Command::Init(_) => unreachable!(),
    }
}

fn error(lang: Lang, message: &str) {
    let red = style(Status::Critical);
    eprintln!("{red}{}{red:#} {message}", tr!(lang, "error:", "ошибка:"));
}

async fn check(args: CheckArgs, config: Config, lang: Lang) -> u8 {
    let from_cli = !args.domains.is_empty();
    let known = config.domain_list();
    let specs: Vec<DomainConfig> = if from_cli {
        // Domains named on the command line keep their settings from the config.
        args.domains
            .iter()
            .map(|name| {
                known
                    .iter()
                    .find(|known| known.name.eq_ignore_ascii_case(name))
                    .cloned()
                    .unwrap_or_else(|| DomainConfig::named(name))
            })
            .collect()
    } else {
        known
    };
    if specs.is_empty() {
        error(
            lang,
            &tr!(
                lang,
                "nothing to check. Pass domains (domwarden check example.com) or list them in a config file (domwarden init creates one).",
                "нечего проверять. Укажите домены (domwarden check example.com) или впишите их в файл настроек (его создаёт команда domwarden init)."
            ),
        );
        return 3;
    }
    let mut targets = Vec::with_capacity(specs.len());
    for spec in &specs {
        match Target::from_config(spec) {
            Ok(target) => targets.push(target),
            Err(err) => {
                error(lang, &err);
                return 3;
            }
        }
    }
    let mut groups = if args.only.is_empty() {
        Group::ALL.to_vec()
    } else {
        args.only.clone()
    };
    groups.retain(|group| !args.skip.contains(group));

    let checker = match Checker::new(config.settings.clone(), lang, groups) {
        Ok(checker) => checker,
        Err(err) => {
            error(lang, &err);
            return 3;
        }
    };
    if args.format == Format::Text && std::io::stderr().is_terminal() {
        let dim = Style::new().dimmed();
        let count = i18n::domains(lang, targets.len());
        eprintln!(
            "{dim}{}{dim:#}\n",
            tr!(lang, "Checking {count}…", "Проверяю: {count}…")
        );
    }
    let report = checker.check_all(&targets).await;
    match args.format {
        Format::Text => print!("{}", report::render_text(&report, lang, args.quiet)),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        ),
    }

    if !args.no_notify && (args.notify || !from_cli) {
        if config.notify.is_empty() {
            if args.notify {
                error(
                    lang,
                    &tr!(
                        lang,
                        "--notify: no notification channels in the config",
                        "--notify: в настройках нет ни одного канала оповещений"
                    ),
                );
            }
        } else if config.notify.on.wants(report.status) {
            let message = notify::compose(&report, lang);
            send(&config, &message, Some(&report), lang).await;
        }
    }
    report.exit_code() as u8
}

/// Sends `message` everywhere and prints how it went. True when every channel worked.
async fn send(config: &Config, message: &Message, report: Option<&Report>, lang: Lang) -> bool {
    let notifier = match Notifier::new(config.notify.clone(), config.settings.timeout()) {
        Ok(notifier) => notifier,
        Err(err) => {
            error(lang, &err);
            return false;
        }
    };
    let mut all_sent = true;
    for outcome in notifier.send(message, report).await {
        let channel = outcome.channel;
        match outcome.result {
            Ok(()) => {
                let green = style(Status::Ok);
                eprintln!(
                    "{green}✔{green:#} {}",
                    tr!(
                        lang,
                        "notification sent: {channel}",
                        "оповещение отправлено: {channel}"
                    )
                );
            }
            Err(err) => {
                all_sent = false;
                let red = style(Status::Critical);
                eprintln!(
                    "{red}✘{red:#} {}",
                    tr!(
                        lang,
                        "{channel}: not sent — {err}",
                        "{channel}: не отправлено — {err}"
                    )
                );
            }
        }
    }
    all_sent
}

async fn notify_test(config: Config, path: Option<PathBuf>, lang: Lang) -> u8 {
    if config.notify.is_empty() {
        let place = match path {
            Some(path) => path.display().to_string(),
            None => tr!(lang, "no config file found", "файл настроек не найден"),
        };
        error(
            lang,
            &tr!(
                lang,
                "no notification channels are set up ({place}). Add [notify.telegram], [notify.email] or [[notify.webhook]] to the config.",
                "не настроено ни одного канала оповещений ({place}). Добавьте в настройки [notify.telegram], [notify.email] или [[notify.webhook]]."
            ),
        );
        return 3;
    }
    if send(&config, &notify::test_message(lang), None, lang).await {
        0
    } else {
        1
    }
}

fn init(args: &InitArgs, config_flag: Option<&Path>, lang: Lang) -> u8 {
    let Some(path) = args
        .path
        .clone()
        .or_else(|| config_flag.map(Path::to_path_buf))
        .or_else(config::default_path)
    else {
        error(
            lang,
            &tr!(
                lang,
                "couldn't find the user config folder; pass a path: domwarden init domwarden.toml",
                "не удалось найти папку настроек пользователя; укажите путь: domwarden init domwarden.toml"
            ),
        );
        return 3;
    };
    let shown = path.display();
    if path.exists() && !args.force {
        error(
            lang,
            &tr!(
                lang,
                "{shown} already exists. Add --force to overwrite it.",
                "{shown} уже существует. Чтобы перезаписать его, добавьте --force."
            ),
        );
        return 3;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        error(lang, &format!("{}: {err}", parent.display()));
        return 3;
    }
    if let Err(err) = std::fs::write(&path, config::starter(lang)) {
        error(lang, &format!("{shown}: {err}"));
        return 3;
    }
    let green = style(Status::Ok);
    println!(
        "{green}✔{green:#} {}",
        tr!(lang, "Created {shown}", "Создан файл {shown}")
    );
    println!(
        "{}",
        tr!(
            lang,
            "Open it in a text editor, list your domains and run: domwarden check",
            "Откройте его в текстовом редакторе (например, в Блокноте), впишите свои домены и запустите: domwarden check"
        )
    );
    0
}
