# Domwarden

**Domwarden watches your domains and tells you before something breaks.**

One small program checks, for every domain in your list:

- **TLS certificate** — days until it expires, whether browsers trust it, whether it covers the host name, missing intermediate certificates;
- **domain registration** — when it has to be renewed, and whether the registry suspended or is deleting it (RDAP, plus WHOIS for `.ru`, `.рф`, `.su` and other zones without RDAP);
- **DNS** — name servers and addresses;
- **email records** — MX, SPF (including the 10-lookup limit), DMARC policy, DKIM keys and their strength;
- **the site** — status code, response time, redirect chain, HTTP → HTTPS redirect, HSTS.

Problems go to **Telegram**, **email** or any **webhook** (Slack, Discord, your own system).

```text
$ domwarden check example.com shop.example.org

example.com  ⚠ warnings
  ✔ DNS    name servers: ns1.example.net, ns2.example.net · example.com → 93.184.215.14
  ✔ Domain paid until 2027-08-13 (284 days left) · registrar Example Registrar, Inc.
  ⚠ TLS    valid until 2026-11-12 (10 days left) · issued by Let's Encrypt (R11) · TLS 1.3
           ⚠ the certificate expires in 10 days — check that automatic renewal works
  ✔ HTTP   200 OK · 212 ms · http:// → https://
  ✔ MX     mx.yandex.net (10) · Yandex 360
  ✔ SPF    v=spf1 redirect=_spf.yandex.net · 7 of 10 lookups
  ⚠ DMARC  p=none · reports to dmarc@example.com
           ⚠ policy p=none only collects reports: forged mail is still delivered. …
  ✔ DKIM   keys: mail (RSA 2048)

shop.example.org  ✘ critical
  ✘ TLS    valid until 2027-02-01 (91 days left) · issued by Let's Encrypt (R10) · TLS 1.2
           ✘ the server doesn't send the intermediate certificate: some browsers and most apps and scripts will refuse to connect
  …

Checked 2 domains in 2.4 s: 0 OK, 1 with warnings, 1 critical
```

Why another tool? Certificate lifetimes are shrinking (200 days from March 2026, 47 days by 2029), and
mail providers increasingly reject mail without SPF, DKIM and DMARC. Uptime monitors mostly watch
whether the site answers; web tools like MXToolbox check one domain at a time. Domwarden checks the
whole list in seconds, runs anywhere as a single file, and is made to run on a schedule.

Reports are available in English and Russian (`--lang en|ru`, the system language by default).

## Install

**Ready-made program:** download the archive for your system from
[Releases](https://github.com/VoxEridani/domwarden/releases), unpack it, and run `domwarden` from that folder
(or put it somewhere in your `PATH`).

| System | File |
|---|---|
| Windows | `domwarden-vX.Y.Z-x86_64-pc-windows-msvc.zip` |
| Linux (x86-64 / ARM64) | `…-x86_64-unknown-linux-gnu.tar.gz` / `…-aarch64-unknown-linux-gnu.tar.gz` |
| macOS (Apple silicon / Intel) | `…-aarch64-apple-darwin.tar.gz` / `…-x86_64-apple-darwin.tar.gz` |

**From source** (needs [Rust](https://rustup.rs) 1.89+):

```sh
cargo install --git https://github.com/VoxEridani/domwarden
```

## Quick start

```sh
domwarden check example.com              # check one or more domains right away
domwarden init                           # create a config file with comments
domwarden check                          # check every domain from the config
domwarden notify-test                    # make sure notifications arrive
```

`domwarden init` writes the config to `%APPDATA%\domwarden\domwarden.toml` on Windows,
`~/.config/domwarden/domwarden.toml` on Linux and `~/Library/Application Support/domwarden/domwarden.toml`
on macOS, and prints the path. A `domwarden.toml` in the current folder takes priority; `-c FILE`
or the `DOMWARDEN_CONFIG` variable point to any other file.

Useful options:

| Option | What it does |
|---|---|
| `--only tls,domain` | run only some check groups: `dns`, `domain`, `tls`, `http`, `mail` |
| `--skip mail` | skip groups |
| `-q`, `--quiet` | show only problems |
| `-f json` | machine-readable report ([format](docs/checks.md#json-report)) |
| `--lang ru` | report language |
| `--notify` / `--no-notify` | force or suppress notifications |

**Exit codes:** `0` — all fine, `1` — warnings (or something couldn't be checked), `2` — critical problems,
`3` — usage or config error. This makes Domwarden easy to use from scripts and CI.

## Config

```toml
lang = "en"

domains = [
    "example.com",
    "example.org",
]

# A domain with its own settings.
[[domain]]
name = "shop.example.net"
hosts = ["shop.example.net", "www.shop.example.net"]  # what to check TLS and HTTP on (default: the domain)
skip = ["mail"]                                       # dns, domain, tls, http, mail
dkim_selectors = ["mail"]                             # your DKIM selector, see docs/checks.md

[settings]
cert_warning_days = 14
cert_critical_days = 7
domain_warning_days = 30
domain_critical_days = 7
slow_response_ms = 3000
timeout_secs = 10
concurrency = 8                  # domains checked at the same time
# dns_servers = ["1.1.1.1"]      # instead of the system DNS servers
# dkim_selectors = ["s1"]        # extra selectors for every domain

[notify]
on = "warning"                   # "warning" (any problem), "critical", "always" or "never"
```

Typos in setting names are reported with the line number, so a mistake never goes unnoticed.
Any notification setting can take a value from an environment variable: `password = "${SMTP_PASSWORD}"`.

## Notifications

Notifications are sent when you run `domwarden check` with the domains from the config — the way it
runs on a schedule. Checking domains named on the command line doesn't notify unless you add `--notify`.
Run `domwarden notify-test` after setting a channel up.

### Telegram

1. Open [@BotFather](https://t.me/BotFather), send `/newbot` and follow the steps. You get a token like `123456789:AAE…`.
2. Open the chat with your new bot and press **Start** (bots can't write first).
3. Find your chat id: open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and look for `"chat":{"id":…}`.
   For a group, add the bot to it, send a message there and look again (group ids start with `-`).

```toml
[notify.telegram]
bot_token = "123456789:AAE..."
chat_id = "123456789"            # or a list: ["123", "-100456"]
# thread_id = 42                 # a topic in a forum group
# api_url = "https://my-bot-api.example.com"   # a self-hosted Bot API server
```

### Email

```toml
[notify.email]
host = "smtp.gmail.com"
port = 465                       # 465 — TLS, 587 — STARTTLS
username = "you@gmail.com"       # defaults to `from`
password = "${DOMWARDEN_SMTP_PASSWORD}"
from = "Domwarden <you@gmail.com>"
to = ["you@gmail.com", "admin@example.com"]
# security = "tls"               # "tls", "starttls" or "none"
```

Gmail, Yandex and Mail.ru need an **app password** (created in the account's security settings),
not your usual one. SMTP hosts: Gmail `smtp.gmail.com`, Yandex `smtp.yandex.ru`, Mail.ru `smtp.mail.ru`,
Outlook `smtp-mail.outlook.com` (port 587).

### Webhooks

```toml
[[notify.webhook]]
url = "https://hooks.slack.com/services/T000/B000/XXXX"

[[notify.webhook]]
url = "https://discord.com/api/webhooks/123/abc"

[[notify.webhook]]
url = "https://monitoring.example.com/domwarden"
headers = { Authorization = "Bearer ${MONITORING_TOKEN}" }
# format = "json"                # "json", "slack" or "discord"; guessed from the URL
```

Slack and Discord URLs get a ready-made message. Other URLs receive JSON:
`{"event": "domwarden.report", "title": …, "text": …, "status": …, "report": {…}}`, where `report` is the
full [JSON report](docs/checks.md#json-report).

## Run it every day

**Windows** (Task Scheduler, every day at 09:00):

```bat
schtasks /create /tn "Domwarden" /sc daily /st 09:00 /tr "\"C:\Tools\domwarden\domwarden.exe\" check --quiet"
```

**Linux / macOS** (cron, `crontab -e`):

```cron
0 9 * * * /usr/local/bin/domwarden check --quiet
```

**systemd timer** (`/etc/systemd/system/domwarden.service` and `domwarden.timer`):

```ini
# domwarden.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/domwarden check --quiet -c /etc/domwarden.toml

# domwarden.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl enable --now domwarden.timer`. Exit codes 1 and 2 mark the run as failed, which
also shows up in your system's monitoring.

## Good to know

- **What every message means:** [docs/checks.md](docs/checks.md) lists all checks and codes.
- **DNS:** Domwarden asks every system DNS server at once and takes the first clear answer, so a home
  router that can't handle large answers doesn't break mail checks. Set `dns_servers` to use specific servers.
- **Trust** is checked against the Mozilla root list that browsers use, the same on every system.
- **Bot protection:** sites behind Cloudflare or DDoS-Guard challenges are marked as such instead of failing.
- **Privacy:** Domwarden only talks to your domains, DNS servers, the IANA RDAP directory, registries
  and the notification services you configure. It collects nothing.

## Building

```sh
cargo build --release
cargo test
```

The library (`src/lib.rs`) can be used from other Rust programs: `Checker` runs the checks and returns a `Report`.

## License

[MIT](LICENSE)
