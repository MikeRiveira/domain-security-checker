# Domain & Email Security Checker

[![Tests](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/tests.yml)
[![CodeQL](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/codeql.yml/badge.svg)](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/codeql.yml)
[![Daily domain check](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/daily-check.yml/badge.svg)](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/daily-check.yml)

**One command checks every domain your company owns for the settings that stop email spoofing and surprise outages:** MX, SPF, DKIM, DMARC, the website's SSL certificate and the domain's registration expiry. Run it on your laptop, or let GitHub Actions run it every morning for free.

```text
$ domaincheck --config domains.toml

demoauto.example  [PASS]
  PASS  MX            1 mail server(s): demoauto-example.mail.protection.outlook.com
  PASS  SPF           Hard fail (-all). 2/10 lookups
  PASS  DMARC         p=reject, with reports
  PASS  DKIM          Key published for selector(s): selector1, selector2
  PASS  SSL           demoauto.example: certificate expires 2027-03-02 (134 days)
  PASS  Registration  Expires 2028-05-14 (572 days)

harborkia.example  [FAIL]
  PASS  MX            1 mail server(s): harborkia-example.mail.protection.outlook.com
  WARN  SPF           Soft fail (~all); -all is stricter. 9/10 lookups
  WARN  DMARC         p=none (monitor only, spoofed mail is still delivered), with reports
  PASS  DKIM          Key published for selector(s): selector1
  FAIL  SSL           www.harborkia.example: certificate expires 2026-10-27 (8 days)
  PASS  Registration  Expires 2027-08-01 (286 days)

seaviewford.example  [FAIL]
  WARN  MX            No MX records: this domain can't receive email
  WARN  SPF           Domain sends no email; publish 'v=spf1 -all' to block spoofing
  FAIL  DMARC         No DMARC record: spoofed email won't be blocked or reported
  INFO  DKIM          Skipped: domain receives no email
  PASS  SSL           seaviewford.example: certificate expires 2027-01-09 (82 days)
  WARN  Registration  Expires 2026-12-01 (43 days); check auto-renew
```

<sub>Example output for the fictional Demo Auto Group. For a live run, open the latest [Daily domain check](https://github.com/MikeRiveira/domain-security-checker/actions/workflows/daily-check.yml) and scroll to its summary.</sub>

---

## Why I built it

I'm the IT Manager for a car dealership group with stores in New York and New Jersey. A group like ours owns a lot of domains: one per rooftop, old names from acquisitions, and parked domains for marketing campaigns. Every one of them can be used to send fake invoices and payoff instructions, and every one has a certificate and a registration that can quietly expire.

Checking them one at a time in MX Toolbox took most of a morning. This tool checks all of them in seconds, explains each problem in plain English, and flags the ones that need attention first.

## What it checks

| Check | Pass | Warning | Fail |
|---|---|---|---|
| **MX** | Mail servers found | No MX records | |
| **SPF** | One record ending in `-all`, 10 or fewer DNS lookups | `~all` or `?all`; a parked domain without `v=spf1 -all` | Missing, duplicated, `+all`, or over the 10-lookup limit |
| **DMARC** | `p=reject` or `p=quarantine` with `rua=` reports | `p=none`, `pct` under 100, or no reports | Missing, duplicated or invalid |
| **DKIM** | A public key at one of your selectors | Only revoked keys, or none at the selectors checked | |
| **MTA-STS** | `mode: enforce` with a TLS-RPT record for failure reports | `mode: testing` or `none`, no TLS-RPT record, or the policy file can't be fetched | |
| **BIMI** | A logo record with an `https://` logo, and DMARC at `p=quarantine` or `p=reject` | A record whose logo isn't HTTPS, or DMARC not enforced (the logo won't show) | |
| **SSL** | Valid certificate, 30+ days left | Under 30 days | Under 14 days, invalid, or unreachable |
| **Registration** | 60+ days until expiry | Under 60 days | Under 30 days |

A few details that matter in practice:

- **SPF lookups are counted recursively.** It follows every `include:` and `redirect=` (and stops at loops), because a record that looks fine can still break the 10-lookup limit once Microsoft 365, a CRM and a marketing platform are all included.
- **Parked domains are held to a stricter standard.** If a domain receives no email, it should say so with `v=spf1 -all` and DMARC `p=reject`, or criminals can send mail as it.
- **A failed DNS lookup is reported as a failed lookup**, not as a missing record, so a network hiccup never looks like a security problem.
- **Registration dates come from RDAP**, the modern replacement for WHOIS, so there's no scraping and no API key.

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/MikeRiveira/domain-security-checker.git
cd domain-security-checker
pip install .

domaincheck example.com example.org          # check a few domains
domaincheck --config domains.example.toml    # or check a list from a file
domaincheck -c domains.toml -f markdown      # Markdown report (also: -f json)
domaincheck -c domains.toml -f csv > report.csv   # spreadsheet: one row per domain and check
```

The exit code is `1` when any domain has a failing check, so it fits into scripts and scheduled tasks. Use `--fail-on warn` to be stricter or `--fail-on never` to always exit `0`.

## Configure your domains

DKIM selectors can't be discovered from DNS, so list the ones your mail platforms use. Microsoft 365 uses `selector1` and `selector2`, and Google Workspace uses `google`.

```toml
[defaults]
dkim_selectors = ["selector1", "selector2"]

[[domain]]
name = "example.com"

[[domain]]
name = "example.net"
https_host = "www.example.net"          # check the website's certificate

[[domain]]
name = "example.org"
dkim_selectors = ["selector1", "s1"]    # add a marketing platform's selector
```

## Run it every day with GitHub Actions

[`daily-check.yml`](.github/workflows/daily-check.yml) runs the checker every morning and posts the Markdown report as the run's summary, with a copy saved as a downloadable file. To use it for your own domains, fork this repo, replace the domains in `domains.toml`, and enable Actions on the fork. The demo in this repo checks a few well-known public domains.

## How it's built

- **Python standard library plus [dnspython](https://www.dnspython.org/).** TLS checks use `ssl` with full certificate verification, and RDAP lookups use `urllib`.
- **Each check is a small pure function** that gets its DNS and network lookups passed in, so the [test suite](tests/test_checks.py) covers every pass, warning and fail rule without touching the network.
- **Domains are checked in parallel**, so a list of 30 domains takes about as long as one.

## Contributing

New checks and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get set up, and the [good first issues](https://github.com/MikeRiveira/domain-security-checker/labels/good%20first%20issue) for ideas. Please report security problems privately, as described in [SECURITY.md](SECURITY.md).

## About me

I'm Michael Riveira, IT Manager for a dealership group across New York and New Jersey. I build IT automation, dealership technology and AI tools. See also my [Dealership IT Dashboard](https://github.com/MikeRiveira/dealership-it-dashboard), whose domain health panel this tool grew out of. [Connect on LinkedIn](https://www.linkedin.com/in/michael-riveira-874a06178/).

MIT licensed.
