"""Command-line entry point: domaincheck example.com or domaincheck --config domains.toml"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor

from .checks import FAIL, SEVERITY, WARN, check_domain
from .report import render_json, render_markdown, render_text


def load_config(path: str) -> list[dict]:
    """Read domains from a TOML file. See domains.example.toml for the format."""
    with open(path, "rb") as f:
        config = tomllib.load(f)
    defaults = config.get("defaults", {})
    domains = []
    for entry in config.get("domain", []):
        domains.append({
            "domain": entry["name"].strip().lower(),
            "dkim_selectors": entry.get("dkim_selectors", defaults.get("dkim_selectors")),
            "https_host": entry.get("https_host"),
        })
    return domains


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="domaincheck",
        description="Check MX, SPF, DKIM, DMARC, SSL and registration expiry for your domains.",
    )
    parser.add_argument("domains", nargs="*", help="domains to check (or use --config)")
    parser.add_argument("-c", "--config", help="TOML file listing domains and DKIM selectors")
    parser.add_argument("-f", "--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument(
        "--fail-on", choices=["fail", "warn", "never"], default="fail",
        help="exit non-zero when any check reaches this level (default: fail)",
    )
    args = parser.parse_args(argv)

    targets = [{"domain": d.lower()} for d in args.domains]
    if args.config:
        targets += load_config(args.config)
    if not targets:
        parser.error("give at least one domain or --config")

    now = dt.datetime.now(dt.timezone.utc)
    with ThreadPoolExecutor(max_workers=8) as pool:
        reports = list(pool.map(lambda t: check_domain(now=now, **t), targets))

    generated = now.strftime("%Y-%m-%d %H:%M UTC")
    if args.format == "markdown":
        print(render_markdown(reports, generated))
    elif args.format == "json":
        print(render_json(reports, generated))
    else:
        print(render_text(reports))

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY[FAIL if args.fail_on == "fail" else WARN]
    return 1 if any(SEVERITY[r.worst] >= threshold for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
