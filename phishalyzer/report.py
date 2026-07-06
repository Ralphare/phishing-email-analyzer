"""
report.py — Render findings as a clean, analyst-readable console report.

Formatting philosophy: a triage report is read under time pressure, so it
leads with the verdict, groups evidence by category, and explains every
finding inline — no flipping back to documentation.
"""

from __future__ import annotations

import json
import sys
import textwrap

from .eml_parser import ParsedEmail
from .findings import Finding, INFO, LOW, MEDIUM, HIGH, CRITICAL

WIDTH = 78

# ANSI colors — auto-disabled when stdout isn't a terminal (e.g. piped to a file).
COLORS = {
    INFO: "\033[36m",      # cyan
    LOW: "\033[33m",       # yellow
    MEDIUM: "\033[93m",    # bright yellow
    HIGH: "\033[91m",      # bright red
    CRITICAL: "\033[1;91m",  # bold bright red
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def _c(code: str, s: str, enabled: bool) -> str:
    return f"{code}{s}{RESET}" if enabled else s


def _wrap(s: str, indent: int) -> str:
    return textwrap.fill(s, width=WIDTH, initial_indent=" " * indent,
                         subsequent_indent=" " * indent)


def render(parsed: ParsedEmail, findings: list[Finding], urls: list[str],
           attachments: list[str], score_val: int, verdict: str, action: str,
           color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty()

    lines: list[str] = []
    bar = "=" * WIDTH
    lines.append(bar)
    lines.append(_c(BOLD, "  PHISHING EMAIL ANALYSIS REPORT", color))
    lines.append(bar)

    # --- Message summary -------------------------------------------------
    for label, header in (("From", "From"), ("To", "To"), ("Subject", "Subject"),
                          ("Date", "Date"), ("Reply-To", "Reply-To"),
                          ("Return-Path", "Return-Path")):
        value = parsed.header(header)
        if value:
            lines.append(f"  {label + ':':<13}{value[:WIDTH - 16]}")
    lines.append(f"  {'URLs found:':<13}{len(urls)}")
    lines.append(f"  {'Attachments:':<13}{len(attachments)}"
                 + (f"  ({', '.join(attachments[:4])})" if attachments else ""))
    if parsed.parse_warnings:
        lines.append(f"  {'Parse notes:':<13}{'; '.join(parsed.parse_warnings[:3])}")

    # --- Verdict banner ---------------------------------------------------
    sev_for_score = CRITICAL if score_val >= 70 else HIGH if score_val >= 45 \
        else MEDIUM if score_val >= 20 else INFO
    lines.append(bar)
    lines.append(_c(COLORS[sev_for_score] + BOLD,
                    f"  RISK SCORE: {score_val}/100   VERDICT: {verdict}", color))
    lines.append(_wrap(action, 2))
    lines.append(bar)

    # --- Findings by category, most severe first within each ---------------
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    for category in ("Authentication", "URLs", "Attachments", "Body"):
        cat_findings = sorted((f for f in findings if f.category == category),
                              key=lambda f: order.get(f.severity, 5))
        if not cat_findings:
            continue
        lines.append("")
        lines.append(_c(BOLD, f"  [{category.upper()}]", color))
        lines.append("  " + "-" * (WIDTH - 4))
        for f in cat_findings:
            tag = _c(COLORS.get(f.severity, ""), f"[{f.severity}]", color)
            lines.append(f"  {tag} {f.title}")
            lines.append(_wrap(f.detail, 6))
            if f.explanation:
                lines.append(_c(DIM, _wrap("Why it matters: " + f.explanation, 6), color))
            for ev in f.evidence[:4]:
                lines.append(_c(DIM, f"      evidence: {ev[:WIDTH - 18]}", color))
            lines.append("")

    lines.append(bar)
    lines.append(_c(DIM, "  Score is a triage aid — always review findings, not just "
                          "the number.", color))
    lines.append(bar)
    return "\n".join(lines)


def render_json(parsed: ParsedEmail, findings: list[Finding], urls: list[str],
                attachments: list[str], score_val: int, verdict: str,
                action: str) -> str:
    """Machine-readable output — handy for piping into a SIEM or jq."""
    return json.dumps({
        "score": score_val,
        "verdict": verdict,
        "recommended_action": action,
        "summary": {
            "from": parsed.header("From"),
            "subject": parsed.header("Subject"),
            "date": parsed.header("Date"),
            "url_count": len(urls),
            "attachment_count": len(attachments),
        },
        "urls": urls,
        "attachments": attachments,
        "findings": [f.__dict__ for f in findings],
        "parse_warnings": parsed.parse_warnings,
    }, indent=2, ensure_ascii=False)
