"""Render domain reports as text, Markdown, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict

from .checks import FAIL, INFO, PASS, WARN, DomainReport

ICONS = {PASS: "✅", WARN: "⚠️", FAIL: "❌", INFO: "ℹ️"}


def summary_counts(reports: list[DomainReport]) -> dict[str, int]:
    counts = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0}
    for report in reports:
        for result in report.results:
            counts[result.status] += 1
    return counts


def render_text(reports: list[DomainReport]) -> str:
    lines = []
    for report in reports:
        lines.append(f"\n{report.domain}  [{report.worst}]")
        for r in report.results:
            lines.append(f"  {r.status:<5} {r.check:<13} {r.detail}")
    c = summary_counts(reports)
    lines.append(f"\n{len(reports)} domain(s): {c[PASS]} pass, {c[WARN]} warning, {c[FAIL]} fail")
    return "\n".join(lines)


def render_markdown(reports: list[DomainReport], generated: str) -> str:
    c = summary_counts(reports)
    lines = [
        "# Domain & Email Security Report",
        "",
        f"_Generated {generated}_ · {len(reports)} domain(s) · "
        f"{ICONS[PASS]} {c[PASS]} pass · {ICONS[WARN]} {c[WARN]} warning · {ICONS[FAIL]} {c[FAIL]} fail",
        "",
        "| Domain | MX | SPF | DMARC | DKIM | SSL | Registration |",
        "|---|---|---|---|---|---|---|",
    ]
    for report in reports:
        cells = [ICONS[r.status] for r in report.results]
        lines.append(f"| **{report.domain}** | " + " | ".join(cells) + " |")
    for report in reports:
        lines += ["", f"## {ICONS[report.worst]} {report.domain}", ""]
        lines += [f"- {ICONS[r.status]} **{r.check}:** {r.detail}" for r in report.results]
    return "\n".join(lines) + "\n"


def render_json(reports: list[DomainReport], generated: str) -> str:
    payload = {
        "generated": generated,
        "summary": summary_counts(reports),
        "domains": [
            {"domain": r.domain, "status": r.worst, "results": [asdict(x) for x in r.results]}
            for r in reports
        ],
    }
    return json.dumps(payload, indent=2)


def render_csv(reports: list[DomainReport]) -> str:
    """One row per domain and check, ready to open in Excel or attach to a ticket."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["domain", "check", "status", "detail"])
    for report in reports:
        for r in report.results:
            writer.writerow([report.domain, r.check, r.status, r.detail])
    return out.getvalue()
