#!/usr/bin/env python3
"""
analyze.py — CLI entry point for the phishing email analyzer.

Usage:
    python analyze.py <path-to-eml> [--json] [--no-color] [--online]

The tool is fully offline by default. --online enables optional DNS
lookups (does the sender domain actually publish SPF/DMARC records?)
and degrades gracefully if the network is unavailable.
"""

from __future__ import annotations

import argparse
import sys

from phishalyzer.eml_parser import load_eml
from phishalyzer.auth_checks import analyze_authentication, _extract_domain
from phishalyzer.url_checks import analyze_urls
from phishalyzer.attachment_checks import analyze_attachments
from phishalyzer.body_checks import analyze_body
from phishalyzer.scoring import score
from phishalyzer.report import render, render_json
from phishalyzer.findings import Finding, INFO, MEDIUM


def optional_dns_checks(parsed) -> list[Finding]:
    """
    --online extra: query DNS for the From: domain's SPF and DMARC records.

    Why it's optional: header-based results already reflect the delivery-time
    verdict; this only adds "does the domain even publish a policy?" context.
    It must never break offline analysis, hence the broad exception handling.
    """
    findings: list[Finding] = []
    domain = _extract_domain(parsed.header("From"))
    if not domain:
        return findings
    try:
        import dns.resolver  # dnspython — optional dependency
    except ImportError:
        findings.append(Finding("Authentication", INFO, "Online checks skipped",
                                "dnspython not installed (pip install dnspython).", ""))
        return findings

    def txt(name: str) -> list[str]:
        try:
            return [b"".join(r.strings).decode("utf-8", "replace")
                    for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
        except Exception:
            return []

    spf_records = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
    dmarc_records = [r for r in txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]

    if spf_records:
        findings.append(Finding("Authentication", INFO, "DNS: SPF record published",
                                f"{domain} publishes: {spf_records[0][:100]}",
                                "The domain owner has defined authorized senders."))
    else:
        findings.append(Finding("Authentication", MEDIUM, "DNS: no SPF record",
                                f"{domain} publishes no SPF record.",
                                "Without SPF, any server on the internet can send mail "
                                "claiming this domain and nothing flags it."))
    if dmarc_records:
        findings.append(Finding("Authentication", INFO, "DNS: DMARC policy published",
                                f"_dmarc.{domain}: {dmarc_records[0][:100]}",
                                "The domain enforces (or at least monitors) From: alignment."))
    else:
        findings.append(Finding("Authentication", MEDIUM, "DNS: no DMARC policy",
                                f"{domain} publishes no DMARC record.",
                                "Without DMARC, receivers have no instruction to reject "
                                "spoofed From: headers for this domain — spoofing it is "
                                "trivially easy."))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a .eml file for phishing indicators (defensive triage tool).")
    parser.add_argument("eml_path", help="Path to the .eml file to analyze")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--online", action="store_true",
                        help="Also query DNS for the sender domain's SPF/DMARC records "
                             "(optional; requires network + dnspython)")
    args = parser.parse_args(argv)

    # --- Load (the only place a hard failure is acceptable) -----------------
    try:
        parsed = load_eml(args.eml_path)
    except FileNotFoundError:
        print(f"error: file not found: {args.eml_path}", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"error: permission denied reading: {args.eml_path}", file=sys.stderr)
        return 2
    except Exception as exc:  # truly unexpected — report cleanly, never traceback-spam
        print(f"error: could not read file ({exc.__class__.__name__}: {exc})",
              file=sys.stderr)
        return 2

    # --- Run every analyzer; one failing must not silence the others --------
    findings: list[Finding] = []
    urls: list[str] = []
    attachments: list[str] = []

    for name, runner in (
        ("authentication", lambda: findings.extend(analyze_authentication(parsed))),
        ("urls", lambda: _run_urls(parsed, findings, urls)),
        ("attachments", lambda: _run_attachments(parsed, findings, attachments)),
        ("body", lambda: findings.extend(analyze_body(parsed))),
    ):
        try:
            runner()
        except Exception as exc:
            findings.append(Finding("Body" if name == "body" else name.capitalize(),
                                    INFO, f"{name} analyzer error",
                                    f"Analyzer failed gracefully: {exc.__class__.__name__}: {exc}",
                                    "Malformed input tripped this analyzer; other checks "
                                    "still ran. Consider inspecting the raw file manually."))

    if args.online:
        try:
            findings.extend(optional_dns_checks(parsed))
        except Exception:
            findings.append(Finding("Authentication", INFO, "Online checks unavailable",
                                    "Network/DNS lookup failed; continuing offline.", ""))

    score_val, verdict, action = score(findings)

    if args.json:
        print(render_json(parsed, findings, urls, attachments, score_val, verdict, action))
    else:
        color = False if args.no_color else None
        print(render(parsed, findings, urls, attachments, score_val, verdict, action,
                     color=color))
    return 0


def _run_urls(parsed, findings, urls):
    f, u = analyze_urls(parsed)
    findings.extend(f)
    urls.extend(u)


def _run_attachments(parsed, findings, attachments):
    f, a = analyze_attachments(parsed)
    findings.extend(f)
    attachments.extend(a)


if __name__ == "__main__":
    raise SystemExit(main())
