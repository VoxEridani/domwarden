# Checks reference

Every problem Domwarden reports has a stable **code**. You see codes in the JSON report
(`domwarden check --format json`) and in JSON webhooks, so scripts can react to specific problems.

Statuses, from best to worst:

| Status | Meaning | Affects the exit code |
|---|---|---|
| `ok` | All good | no |
| `info` | Advice, not a problem | no |
| `unknown` | The check couldn't finish (timeout, registry offline) | yes — 1 |
| `warning` | Needs attention soon | yes — 1 |
| `critical` | Broken now, or about to break | yes — 2 |

Check groups (for `--only`, `--skip` and `skip = [...]` in the config): `dns`, `domain`, `tls`, `http`, `mail`.

## DNS (`dns`)

Name servers of the registered domain and the IP addresses of every checked host.

| Code | Status | What it means |
|---|---|---|
| `dns.nxdomain` | critical | The domain doesn't exist in DNS: it isn't registered or isn't delegated. Other checks are skipped. |
| `dns.no_ns` | critical | The domain has no name servers. |
| `dns.no_address` | critical | A host has no A/AAAA record, so the site can't be opened. TLS and HTTP checks for it are skipped. |
| `dns.single_ns` | warning | Only one name server; if it fails, everything stops. |
| `dns.lookup_failed` | unknown | The DNS query failed (timeout, server error). |

## Domain registration (`domain`)

Asked over RDAP; zones without RDAP (`.ru`, `.su`, `.рф` and others) over WHOIS.
Thresholds: `domain_warning_days` (30) and `domain_critical_days` (7).

| Code | Status | What it means |
|---|---|---|
| `domain.expired` | critical | The registration has expired. |
| `domain.expiring` | warning / critical | The registration ends within the warning / critical threshold. |
| `domain.not_registered` | critical | Nobody owns the domain. |
| `domain.hold` | critical | The registry or registrar suspended the domain (`clientHold`, `serverHold`). |
| `domain.deleting` | critical | The domain wasn't renewed and is being deleted (`redemptionPeriod`, `pendingDelete`). |
| `domain.not_delegated` | critical | The domain is registered but not delegated (`.ru`/`.рф` state). |
| `domain.no_expiry` | info | The registry doesn't publish the expiry date (common for `.de`, `.eu`). |
| `domain.lookup_failed` | unknown | RDAP and WHOIS didn't answer. |

## Certificate (`tls`)

The certificate is fetched even when it's broken, then checked against the Mozilla root list
that browsers use. Thresholds: `cert_warning_days` (14) and `cert_critical_days` (7).

| Code | Status | What it means |
|---|---|---|
| `tls.expired` | critical | The certificate has expired. |
| `tls.expiring` | warning / critical | It expires within the warning / critical threshold. |
| `tls.not_yet_valid` | critical | Its validity starts in the future (wrong server clock?). |
| `tls.name_mismatch` | critical | The certificate is for other host names. |
| `tls.self_signed` | critical | Self-signed: browsers don't trust it. |
| `tls.incomplete_chain` | critical | The server doesn't send the intermediate certificate. |
| `tls.untrusted` | critical | Issued by an authority browsers don't trust. |
| `tls.russian_ca` | critical | Issued by the Russian Trusted CA: only Yandex Browser and Atom trust it. |
| `tls.chain_expired` | critical | An intermediate certificate in the chain has expired. |
| `tls.revoked` | critical | The certificate has been revoked. |
| `tls.invalid`, `tls.bad_certificate` | critical | Other certificate errors. |
| `tls.connect` | critical | Can't connect to the HTTPS port. |
| `tls.handshake` | critical | The secure connection fails (often: only TLS 1.0/1.1 supported). |
| `tls.weak_key` | warning | RSA key shorter than 2048 bits. |
| `tls.weak_signature` | warning | Signed with SHA-1. |

## Site (`http`)

Opens `https://host/`, follows redirects, and separately checks that `http://` leads to `https://`.

| Code | Status | What it means |
|---|---|---|
| `http.unreachable` | critical | The site doesn't open over HTTPS. |
| `http.server_error` | critical | The site answers 5xx. |
| `http.redirect_loop` | critical | Endless redirect loop. |
| `http.too_many_redirects` | critical | More than 10 redirects. |
| `http.redirect_broken` | critical | A redirect points to an address that doesn't work. |
| `http.client_error` | warning | The home page answers 4xx. |
| `http.bad_redirect` | warning | A 3xx answer without a target. |
| `http.downgrade` | warning | HTTPS redirects to plain HTTP. |
| `http.no_https_redirect` | warning | `http://` opens without switching to `https://`. |
| `http.long_redirects` | warning | More than 3 redirects in a row. |
| `http.slow` | warning | Answer slower than `slow_response_ms` (3000). |
| `http.no_hsts` | info | No `Strict-Transport-Security` header. |
| `http.port80_closed` | info | Port 80 doesn't answer. |
| `http.bot_protection` | info | A bot-protection service (Cloudflare, DDoS-Guard, Qrator…) answered instead of the page. |

## Email (`mail`)

MX, SPF, DMARC and DKIM. A domain without MX records is treated as one that doesn't use email:
missing records then only produce advice. Subdomains without MX skip SPF, DMARC and DKIM.

| Code | Status | What it means |
|---|---|---|
| `mx.unresolvable` | warning / critical | A mail server has no IP address (critical when none of them has). |
| `mx.lookup_failed` | unknown | The MX query failed. |
| `spf.missing` | warning | No SPF record. |
| `spf.missing_parked` | info | No SPF record on a domain that doesn't receive mail; `v=spf1 -all` is suggested. |
| `spf.multiple` | critical | More than one SPF record — receivers treat that as an error. |
| `spf.plus_all` | critical | `+all` lets any server send mail as you. |
| `spf.too_many_lookups` | critical | More than 10 DNS lookups (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`). |
| `spf.broken_include` | critical | An `include:` / `redirect=` target has no SPF record. |
| `spf.neutral_all` | warning | `?all` protects nothing. |
| `spf.no_all` | warning | No final `~all` / `-all`. |
| `spf.ptr` | warning | The deprecated `ptr` mechanism. |
| `spf.syntax` | warning | An unknown term in the record. |
| `spf.lookup_failed` | unknown | The TXT query failed. |
| `dmarc.missing` | warning | No DMARC record. |
| `dmarc.missing_parked` | info | No DMARC on a domain that doesn't receive mail; `p=reject` is suggested. |
| `dmarc.multiple` | critical | More than one DMARC record. |
| `dmarc.invalid` | critical | No or unknown `p=` policy. |
| `dmarc.p_none` | warning | `p=none` only collects reports; forged mail is still delivered. |
| `dmarc.pct` | info | The policy covers less than 100% of mail. |
| `dmarc.no_reports` | info | No `rua=` address for reports. |
| `dmarc.lookup_failed` | unknown | The query failed. |
| `dkim.missing` | warning | No key for the selectors you listed in the config. |
| `dkim.not_found` | info | No key among common selectors; add yours with `dkim_selectors`. |
| `dkim.weak_key` | warning / critical | RSA key under 2048 bits (critical under 1024). |
| `dkim.revoked` | warning | Empty `p=`: the key is revoked. |
| `dkim.bad_key` | warning | The key can't be decoded. |
| `dkim.lookup_failed` | unknown | The query for a configured selector failed. |

### DKIM selectors

A DKIM key lives at `<selector>._domainkey.<domain>`, and the selector name can't be listed
from DNS. Domwarden tries the selectors of the mail service it recognizes from MX records
(Yandex 360 — `mail`, Google Workspace — `google`, Microsoft 365 — `selector1`/`selector2`,
VK WorkSpace — `mailru`, and others) plus common names. If yours isn't found, look it up in your
mail service's settings and add it:

```toml
[[domain]]
name = "example.com"
dkim_selectors = ["mail", "mailchimp"]
```

## JSON report

```json
{
  "version": "0.1.0",
  "checked_at": "2026-11-02T09:00:00Z",
  "duration_ms": 2100,
  "status": "warning",
  "domains": [
    {
      "domain": "example.com",
      "status": "warning",
      "checks": [
        {
          "kind": "tls",
          "subject": "example.com",
          "status": "warning",
          "summary": "valid until 2026-11-12 (10 days left) · issued by Let's Encrypt (R11) · TLS 1.3",
          "findings": [
            { "status": "warning", "code": "tls.expiring", "message": "the certificate expires in 10 days — check that automatic renewal works" }
          ],
          "facts": { "expires": "2026-11-12", "days_left": 10, "issuer": "Let's Encrypt (R11)" }
        }
      ]
    }
  ]
}
```

`message` and `summary` follow the chosen language; `code`, `status` and `facts` don't.
