import datetime as dt
import ssl

from domaincheck import checks
from domaincheck.checks import FAIL, INFO, PASS, WARN
from domaincheck.cli import load_config, main
from domaincheck.report import render_csv, render_json, render_markdown

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


# --- MTA-STS ---------------------------------------------------------------

STS = {"_mta-sts.d.test": ["v=STSv1; id=20261028"], "_smtp._tls.d.test": ["v=TLSRPTv1; rua=mailto:tls@d.test"]}


def policy(mode):
    return lambda url: f"version: STSv1\nmode: {mode}\nmx: *.mail.protection.outlook.com\nmax_age: 604800\n"


def test_mta_sts_enforce_with_reports_passes():
    urls = []
    r = checks.check_mta_sts("d.test", fake_txt(STS), lambda url: urls.append(url) or policy("enforce")(url))
    assert r.status == PASS
    assert urls == ["https://mta-sts.d.test/.well-known/mta-sts.txt"]


def test_mta_sts_without_tls_rpt_warns():
    txt = fake_txt({"_mta-sts.d.test": STS["_mta-sts.d.test"]})
    r = checks.check_mta_sts("d.test", txt, policy("enforce"))
    assert r.status == WARN and "TLS-RPT" in r.detail


def test_mta_sts_testing_mode_warns():
    assert checks.check_mta_sts("d.test", fake_txt(STS), policy("testing")).status == WARN


def test_mta_sts_missing_is_info():
    r = checks.check_mta_sts("d.test", fake_txt({}), policy("enforce"))
    assert r.status == INFO and "optional" in r.detail


def test_mta_sts_unreachable_policy_warns():
    def unreachable(url):
        raise OSError("connection refused")
    r = checks.check_mta_sts("d.test", fake_txt(STS), unreachable)
    assert r.status == WARN and "couldn't be fetched" in r.detail


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


def test_csv_render_escapes_commas_and_quotes():
    import csv
    import io

    report = sample_report()
    report.results[1] = checks.Result("SPF", WARN, 'Soft fail (~all), "-all" is stricter')
    rows = list(csv.reader(io.StringIO(render_csv([report]))))
    assert rows[0] == ["domain", "check", "status", "detail"]
    assert rows[2] == ["d.test", "SPF", WARN, 'Soft fail (~all), "-all" is stricter']
    assert len(rows) == 1 + len(report.results)


def test_cli_csv_output(monkeypatch, capsys):
    monkeypatch.setattr("domaincheck.cli.check_domain", lambda domain, now, **_: sample_report())
    main(["d.test", "-f", "csv", "--fail-on", "never"])
    assert capsys.readouterr().out.startswith("domain,check,status,detail\nd.test,MX,PASS,ok\n")


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
