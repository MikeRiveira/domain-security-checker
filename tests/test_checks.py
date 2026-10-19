import datetime as dt
import ssl

from domaincheck import checks
from domaincheck.checks import FAIL, INFO, PASS, WARN
from domaincheck.cli import load_config, main
from domaincheck.report import render_json, render_markdown

NOW = dt.datetime(2026, 10, 19, tzinfo=dt.timezone.utc)


def fake_txt(records):
    return lambda name: records.get(name, [])


# --- MX --------------------------------------------------------------------

def test_mx_pass():
    r = checks.check_mx("d.test", mx=lambda _: [(0, "d-test.mail.protection.outlook.com")])
    assert r.status == PASS and "outlook" in r.detail


def test_mx_missing_warns():
    assert checks.check_mx("d.test", mx=lambda _: []).status == WARN


def test_null_mx_is_info():
    assert checks.check_mx("d.test", mx=lambda _: [(0, "")]).status == INFO


# --- SPF -------------------------------------------------------------------

def test_spf_hard_fail_passes():
    txt = fake_txt({"d.test": ["v=spf1 include:spf.protection.outlook.com -all"],
                    "spf.protection.outlook.com": ["v=spf1 ip4:40.92.0.0/15 -all"]})
    r = checks.check_spf("d.test", txt)
    assert r.status == PASS and "1/10" in r.detail


def test_spf_missing_fails():
    assert checks.check_spf("d.test", fake_txt({})).status == FAIL


def test_spf_duplicate_records_fail():
    txt = fake_txt({"d.test": ["v=spf1 -all", "v=spf1 mx -all"]})
    assert checks.check_spf("d.test", txt).status == FAIL


def test_spf_plus_all_fails():
    assert checks.check_spf("d.test", fake_txt({"d.test": ["v=spf1 +all"]})).status == FAIL


def test_spf_soft_fail_warns():
    assert checks.check_spf("d.test", fake_txt({"d.test": ["v=spf1 mx ~all"]})).status == WARN


def test_spf_too_many_lookups_fails():
    includes = " ".join(f"include:i{n}.test" for n in range(11))
    txt = fake_txt({"d.test": [f"v=spf1 {includes} -all"]})
    r = checks.check_spf("d.test", txt)
    assert r.status == FAIL and "11 DNS lookups" in r.detail


def test_spf_lookup_count_follows_nested_includes_and_loops():
    txt = fake_txt({
        "d.test": ["v=spf1 include:a.test mx -all"],
        "a.test": ["v=spf1 include:b.test a -all"],
        "b.test": ["v=spf1 include:a.test -all"],  # loop back to a.test
    })
    # include:a (1) + mx (1) + include:b (1) + a (1) + include:a again (1, not followed)
    assert checks.count_spf_lookups("d.test", txt) == 5


def test_parked_domain_needs_strict_spf():
    txt = fake_txt({"d.test": ["v=spf1 include:spf.example ~all"]})
    assert checks.check_spf("d.test", txt, receives_mail=False).status == WARN
    txt = fake_txt({"d.test": ["v=spf1 -all"]})
    assert checks.check_spf("d.test", txt, receives_mail=False).status == PASS


# --- DMARC -----------------------------------------------------------------

def test_dmarc_reject_with_reports_passes():
    txt = fake_txt({"_dmarc.d.test": ["v=DMARC1; p=reject; rua=mailto:dmarc@d.test"]})
    assert checks.check_dmarc("d.test", txt).status == PASS


def test_dmarc_without_reports_warns():
    txt = fake_txt({"_dmarc.d.test": ["v=DMARC1; p=reject"]})
    r = checks.check_dmarc("d.test", txt)
    assert r.status == WARN and "rua" in r.detail


def test_dmarc_none_warns():
    txt = fake_txt({"_dmarc.d.test": ["v=DMARC1; p=none; rua=mailto:x@d.test"]})
    assert checks.check_dmarc("d.test", txt).status == WARN


def test_dmarc_partial_pct_warns():
    txt = fake_txt({"_dmarc.d.test": ["v=DMARC1; p=quarantine; pct=25; rua=mailto:x@d.test"]})
    r = checks.check_dmarc("d.test", txt)
    assert r.status == WARN and "25%" in r.detail


def test_dmarc_missing_fails():
    assert checks.check_dmarc("d.test", fake_txt({})).status == FAIL


# --- DKIM ------------------------------------------------------------------

def test_dkim_found():
    txt = fake_txt({"selector1._domainkey.d.test": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"]})
    r = checks.check_dkim("d.test", ["selector1", "selector2"], txt)
    assert r.status == PASS and "selector1" in r.detail


def test_dkim_revoked_only_warns():
    txt = fake_txt({"s1._domainkey.d.test": ["v=DKIM1; p="]})
    assert checks.check_dkim("d.test", ["s1"], txt).status == WARN


def test_dkim_none_warns():
    assert checks.check_dkim("d.test", ["s1"], fake_txt({})).status == WARN


# --- SSL -------------------------------------------------------------------

def test_ssl_thresholds():
    in_days = lambda n: (lambda _: NOW + dt.timedelta(days=n))
    assert checks.check_ssl("d.test", NOW, in_days(90)).status == PASS
    assert checks.check_ssl("d.test", NOW, in_days(20)).status == WARN
    assert checks.check_ssl("d.test", NOW, in_days(5)).status == FAIL


def test_ssl_invalid_cert_fails():
    def bad(_):
        e = ssl.SSLCertVerificationError("bad")
        e.verify_message = "certificate has expired"
        raise e
    r = checks.check_ssl("d.test", NOW, bad)
    assert r.status == FAIL and "expired" in r.detail


def test_ssl_connection_error_fails():
    def refused(_):
        raise ConnectionRefusedError()
    assert checks.check_ssl("d.test", NOW, refused).status == FAIL


# --- Registration ----------------------------------------------------------

def test_registration_thresholds():
    in_days = lambda n: (lambda _: NOW + dt.timedelta(days=n))
    assert checks.check_registration("d.test", NOW, in_days(400)).status == PASS
    assert checks.check_registration("d.test", NOW, in_days(45)).status == WARN
    assert checks.check_registration("d.test", NOW, in_days(10)).status == FAIL


def test_registration_lookup_error_is_info():
    def boom(_):
        raise TimeoutError()
    assert checks.check_registration("d.test", NOW, boom).status == INFO


# --- Reports and CLI -------------------------------------------------------

def sample_report():
    report = checks.DomainReport("d.test")
    report.results = [
        checks.Result("MX", PASS, "ok"), checks.Result("SPF", WARN, "~all"),
        checks.Result("DMARC", FAIL, "missing"), checks.Result("DKIM", PASS, "ok"),
        checks.Result("SSL", PASS, "ok"), checks.Result("Registration", INFO, "n/a"),
    ]
    return report


def test_worst_status():
    assert sample_report().worst == FAIL


def test_markdown_and_json_render():
    md = render_markdown([sample_report()], "now")
    assert "| **d.test** | ✅ | ⚠️ | ❌ |" in md
    assert '"FAIL": 1' in render_json([sample_report()], "now")


def test_load_config(tmp_path):
    path = tmp_path / "domains.toml"
    path.write_text(
        '[defaults]\ndkim_selectors = ["selector1"]\n'
        '[[domain]]\nname = "A.test"\n'
        '[[domain]]\nname = "b.test"\ndkim_selectors = ["s1"]\nhttps_host = "www.b.test"\n'
    )
    assert load_config(str(path)) == [
        {"domain": "a.test", "dkim_selectors": ["selector1"], "https_host": None},
        {"domain": "b.test", "dkim_selectors": ["s1"], "https_host": "www.b.test"},
    ]


def test_cli_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr("domaincheck.cli.check_domain", lambda domain, now, **_: sample_report())
    assert main(["d.test"]) == 1
    assert main(["d.test", "--fail-on", "never"]) == 0
    assert "d.test" in capsys.readouterr().out


def test_dns_failure_is_reported_not_treated_as_missing():
    import dns.resolver

    def broken(*_args, **_kwargs):
        raise dns.resolver.NoNameservers()
    r = checks._guarded("SPF", broken, "d.test")
    assert r.status == WARN and "DNS lookup failed" in r.detail
