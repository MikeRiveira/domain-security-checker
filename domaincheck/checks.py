"""Individual domain and email security checks.

Each check returns a Result. DNS and network access go through small
injectable functions so the checks can be tested without a network.
"""

from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
SEVERITY = {PASS: 0, INFO: 0, WARN: 1, FAIL: 2}

# Selectors used by common mail platforms (Microsoft 365, Google Workspace,
# Mailchimp, generic). DKIM selectors can't be listed from DNS, so we probe.
DEFAULT_DKIM_SELECTORS = ["selector1", "selector2", "google", "k1", "k2", "s1", "s2", "default", "dkim"]

SPF_LOOKUP_LIMIT = 10  # RFC 7208 section 4.6.4


@dataclass
class Result:
    check: str
    status: str
    detail: str


@dataclass
class DomainReport:
    domain: str
    results: list[Result] = field(default_factory=list)

    @property
    def worst(self) -> str:
        return max((r.status for r in self.results), key=SEVERITY.get, default=PASS)


# --- DNS helpers -----------------------------------------------------------

TxtLookup = Callable[[str], list[str]]
MxLookup = Callable[[str], list[tuple[int, str]]]


def dns_txt(name: str) -> list[str]:
    """Return TXT records for name, joining multi-string records. Empty if none."""
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


def dns_mx(name: str) -> list[tuple[int, str]]:
    """Return (preference, host) MX records for name. Empty if none."""
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "MX", lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return sorted((r.preference, r.exchange.to_text().rstrip(".")) for r in answers)


def _spf_records(domain: str, txt: TxtLookup) -> list[str]:
    return [r for r in txt(domain) if r.lower().startswith("v=spf1")]


def _tags(record: str) -> dict[str, str]:
    """Parse 'k=v; k=v' records (DMARC, DKIM) into a lowercase-keyed dict."""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


# --- Checks ----------------------------------------------------------------

def check_mx(domain: str, mx: MxLookup = dns_mx) -> Result:
    records = mx(domain)
    if not records:
        return Result("MX", WARN, "No MX records: this domain can't receive email")
    if records == [(0, "")] or records == [(0, ".")]:
        return Result("MX", INFO, "Null MX: domain is set up to receive no email")
    hosts = ", ".join(host for _, host in records)
    return Result("MX", PASS, f"{len(records)} mail server(s): {hosts}")


def count_spf_lookups(domain: str, txt: TxtLookup, _seen: set[str] | None = None) -> int:
    """Count DNS-querying SPF terms, following include: and redirect=."""
    seen = _seen if _seen is not None else set()
    if domain in seen:
        return 0
    seen.add(domain)
    records = _spf_records(domain, txt)
    if not records:
        return 0
    count = 0
    for term in records[0].split()[1:]:
        term = term.lstrip("+-~?").lower()
        if term.startswith("include:"):
            count += 1 + count_spf_lookups(term.split(":", 1)[1], txt, seen)
        elif term.startswith("redirect="):
            count += 1 + count_spf_lookups(term.split("=", 1)[1], txt, seen)
        elif term in ("a", "mx", "ptr") or term.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count


def check_spf(domain: str, txt: TxtLookup = dns_txt, receives_mail: bool = True) -> Result:
    records = _spf_records(domain, txt)
    if not records:
        return Result("SPF", FAIL, "No SPF record: anyone can send email as this domain")
    if len(records) > 1:
        return Result("SPF", FAIL, f"{len(records)} SPF records found; there must be exactly one")
    record = records[0]
    terms = record.lower().split()
    lookups = count_spf_lookups(domain, txt)
    if lookups > SPF_LOOKUP_LIMIT:
        return Result("SPF", FAIL, f"{lookups} DNS lookups (limit is {SPF_LOOKUP_LIMIT}); receivers will reject it")
    if not receives_mail and terms != ["v=spf1", "-all"]:
        return Result("SPF", WARN, "Domain sends no email; publish 'v=spf1 -all' to block spoofing")
    if "+all" in terms or "all" in terms:
        return Result("SPF", FAIL, "Ends in +all, which lets any server send as this domain")
    if "?all" in terms:
        return Result("SPF", WARN, "Ends in ?all (neutral), which gives no protection")
    if "~all" in terms:
        return Result("SPF", WARN, f"Soft fail (~all); -all is stricter. {lookups}/{SPF_LOOKUP_LIMIT} lookups")
    if "-all" in terms:
        return Result("SPF", PASS, f"Hard fail (-all). {lookups}/{SPF_LOOKUP_LIMIT} lookups")
    if any(t.startswith("redirect=") for t in terms):
        return Result("SPF", PASS, f"Uses redirect. {lookups}/{SPF_LOOKUP_LIMIT} lookups")
    return Result("SPF", WARN, "No 'all' mechanism at the end of the record")


def check_dmarc(domain: str, txt: TxtLookup = dns_txt) -> Result:
    records = [r for r in txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if not records:
        return Result("DMARC", FAIL, "No DMARC record: spoofed email won't be blocked or reported")
    if len(records) > 1:
        return Result("DMARC", FAIL, "More than one DMARC record; receivers will ignore them")
    tags = _tags(records[0])
    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    reports = "with reports" if "rua" in tags else "no aggregate reports (add rua=)"
    if policy == "reject":
        status, text = PASS, "p=reject"
    elif policy == "quarantine":
        status, text = PASS, "p=quarantine"
    elif policy == "none":
        status, text = WARN, "p=none (monitor only, spoofed mail is still delivered)"
    else:
        return Result("DMARC", FAIL, f"Invalid or missing policy: p={policy or '?'}")
    if pct != "100":
        status, text = WARN, f"{text}, but only applied to {pct}% of mail"
    if "rua" not in tags and status == PASS:
        status = WARN
    return Result("DMARC", status, f"{text}, {reports}")


def check_dkim(domain: str, selectors: list[str] | None = None, txt: TxtLookup = dns_txt) -> Result:
    found, revoked = [], []
    for selector in selectors or DEFAULT_DKIM_SELECTORS:
        for record in txt(f"{selector}._domainkey.{domain}"):
            tags = _tags(record)
            if "p" not in tags:
                continue
            (found if tags["p"] else revoked).append(selector)
    if found:
        return Result("DKIM", PASS, "Key published for selector(s): " + ", ".join(found))
    if revoked:
        return Result("DKIM", WARN, "Only revoked keys found: " + ", ".join(revoked))
    return Result("DKIM", WARN, "No key at common selectors; list your selectors in the config")


def fetch_https_text(url: str, timeout: float = 10) -> str:
    """Fetch a small text file over HTTPS with full certificate verification."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read(65536).decode("utf-8", "replace")


def _policy_fields(text: str) -> dict[str, str]:
    """Parse an MTA-STS policy file ('key: value' lines) into a lowercase-keyed dict."""
    fields = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), value.strip())
    return fields


def check_mta_sts(domain: str, txt: TxtLookup = dns_txt, fetch: Callable[[str], str] = fetch_https_text) -> Result:
    """MTA-STS (RFC 8461) makes senders require verified TLS; TLS-RPT (RFC 8460) reports failures."""
    records = [r for r in txt(f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")]
    has_tlsrpt = any(r.lower().startswith("v=tlsrptv1") for r in txt(f"_smtp._tls.{domain}"))
    if not records:
        return Result("MTA-STS", INFO, "Not set up (optional): MTA-STS makes other servers deliver mail only over verified TLS")
    if len(records) > 1:
        return Result("MTA-STS", WARN, f"{len(records)} MTA-STS records found; there must be exactly one")
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        policy = _policy_fields(fetch(url))
    except (OSError, ValueError) as e:
        return Result("MTA-STS", WARN, f"Record found, but the policy at {url} couldn't be fetched ({e.__class__.__name__})")
    mode = policy.get("mode", "").lower()
    if mode == "enforce" and has_tlsrpt:
        return Result("MTA-STS", PASS, "mode: enforce, with TLS-RPT reports")
    if mode == "enforce":
        return Result("MTA-STS", WARN, f"mode: enforce, but no TLS-RPT record at _smtp._tls.{domain} to report failures")
    if mode == "testing":
        return Result("MTA-STS", WARN, "mode: testing (failures are reported but mail is still delivered); switch to enforce")
    if mode == "none":
        return Result("MTA-STS", WARN, "mode: none (policy is switched off)")
    return Result("MTA-STS", WARN, f"Policy has an invalid or missing mode ({mode or '?'})")


def tls_cert_expiry(host: str, port: int = 443, timeout: float = 10) -> dt.datetime:
    """Connect over TLS with full verification and return the cert's expiry (UTC)."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            not_after = tls.getpeercert()["notAfter"]
    return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), dt.timezone.utc)


def check_ssl(host: str, now: dt.datetime, fetch: Callable[[str], dt.datetime] = tls_cert_expiry) -> Result:
    try:
        expires = fetch(host)
    except ssl.SSLCertVerificationError as e:
        return Result("SSL", FAIL, f"{host}: certificate is not valid ({e.verify_message})")
    except OSError as e:
        return Result("SSL", FAIL, f"{host}: could not connect on port 443 ({e.__class__.__name__})")
    days = (expires - now).days
    text = f"{host}: certificate expires {expires:%Y-%m-%d} ({days} days)"
    if days < 14:
        return Result("SSL", FAIL, text)
    if days < 30:
        return Result("SSL", WARN, text)
    return Result("SSL", PASS, text)


def rdap_expiry(domain: str, timeout: float = 15) -> dt.datetime | None:
    """Look up the registration expiry date through RDAP (the modern WHOIS)."""
    request = urllib.request.Request(
        f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.load(response)
    for event in data.get("events", []):
        if event.get("eventAction") == "expiration":
            return dt.datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
    return None


def check_registration(domain: str, now: dt.datetime, fetch: Callable[[str], dt.datetime | None] = rdap_expiry) -> Result:
    try:
        expires = fetch(domain)
    except Exception as e:  # RDAP servers vary a lot; never fail the run on a lookup error
        return Result("Registration", INFO, f"Could not look up expiry ({e.__class__.__name__})")
    if expires is None:
        return Result("Registration", INFO, "Registry doesn't publish an expiry date")
    days = (expires - now).days
    text = f"Expires {expires:%Y-%m-%d} ({days} days)"
    if days < 30:
        return Result("Registration", FAIL, text + "; renew now")
    if days < 60:
        return Result("Registration", WARN, text + "; check auto-renew")
    return Result("Registration", PASS, text)


def _guarded(name: str, check: Callable[..., Result], *args, **kwargs) -> Result:
    """Run a DNS check, reporting a failed lookup instead of a false 'missing record'."""
    import dns.exception

    try:
        return check(*args, **kwargs)
    except dns.exception.DNSException as e:
        return Result(name, WARN, f"DNS lookup failed ({e.__class__.__name__}); try again later")


def check_domain(
    domain: str,
    dkim_selectors: list[str] | None = None,
    https_host: str | None = None,
    now: dt.datetime | None = None,
) -> DomainReport:
    now = now or dt.datetime.now(dt.timezone.utc)
    report = DomainReport(domain)
    mx = _guarded("MX", check_mx, domain)
    receives_mail = mx.status == PASS
    report.results = [
        mx,
        _guarded("SPF", check_spf, domain, receives_mail=receives_mail),
        _guarded("DMARC", check_dmarc, domain),
        _guarded("DKIM", check_dkim, domain, dkim_selectors)
        if receives_mail else Result("DKIM", INFO, "Skipped: domain receives no email"),
        _guarded("MTA-STS", check_mta_sts, domain)
        if receives_mail else Result("MTA-STS", INFO, "Skipped: domain receives no email"),
        check_ssl(https_host or domain, now),
        check_registration(domain, now),
    ]
    return report
