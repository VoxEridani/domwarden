# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-03

First release.

### Checks

- **TLS certificate:** expiry with warning and critical thresholds, trust against the Mozilla root list,
  host name coverage, self-signed and incomplete chains, the Russian Trusted CA, expired intermediates,
  weak RSA keys and SHA-1 signatures, outdated TLS versions.
- **Domain registration:** expiry, registrar and statuses (hold, redemption, pending delete) over RDAP,
  with WHOIS for `.ru`, `.su`, `.рф` and other zones without RDAP.
- **DNS:** name servers and host addresses; queries go to every system DNS server at once, skipping
  the placeholder addresses Windows lists for empty settings.
- **Email:** MX (with mail service detection), SPF (single record, `all` qualifier, the 10-lookup limit,
  broken includes), DMARC (policy, reports, inheritance for subdomains), DKIM (keys and their strength,
  selectors of known mail services).
- **Site:** status, response time, redirect chain and loops, HTTP → HTTPS, HSTS, bot-protection pages.

### Everything else

- `domwarden check`, `domwarden init` and `domwarden notify-test` commands.
- TOML config with short and long domain lists, per-domain hosts, skipped checks and DKIM selectors,
  helpful errors for typos, and `${VAR}` environment variables for secrets.
- Notifications to Telegram, email (SMTP with TLS or STARTTLS) and webhooks (JSON, Slack, Discord).
- Text report in English or Russian, JSON report with stable problem codes, meaningful exit codes.
- Builds for Windows, Linux (x86-64, ARM64) and macOS (Apple silicon, Intel).

[0.1.0]: https://github.com/VoxEridani/domwarden/releases/tag/v0.1.0
