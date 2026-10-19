# Contributing

Thanks for helping make domain and email security easier to check. Bug reports, new checks and documentation fixes are all welcome.

## Getting started

```bash
git clone https://github.com/MikeRiveira/domain-security-checker.git
cd domain-security-checker
python -m pip install -e ".[test]"
python -m pytest
```

## Where to start

Issues labeled [good first issue](https://github.com/MikeRiveira/domain-security-checker/labels/good%20first%20issue) are small and well-scoped. Comment on one before you start so nobody duplicates work.

## Adding a check

Each check in [`domaincheck/checks.py`](domaincheck/checks.py) is a small function that returns a `Result(check, status, detail)`:

- Take DNS and network lookups as parameters (see `check_spf` and `check_ssl`), so tests can pass in fake data instead of touching the network.
- Use `PASS`, `WARN`, `FAIL` or `INFO`, and write `detail` in plain English that tells the reader what to fix.
- Add tests in [`tests/test_checks.py`](tests/test_checks.py) for the pass, warning and fail cases.
- Add the check to `check_domain`, the Markdown table in `report.py`, and the "What it checks" table in the README.

## Pull requests

- Keep each pull request to one change, and describe what a user would notice.
- Make sure `python -m pytest` passes; CI runs it on Python 3.11 to 3.13.
- Never include real customer domains, credentials or internal hostnames in code, tests or screenshots. Use `example.com`, `example.net`, `example.org` or `*.test`.
