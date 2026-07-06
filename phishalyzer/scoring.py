"""
scoring.py — Combine findings into a 0–100 risk score.

Design choices, and why:
  * Severity-weighted, not count-weighted. Ten LOW findings shouldn't
    outweigh one CRITICAL — a DMARC fail plus a typosquat link is a phish
    even if the body text is polite.
  * Diminishing returns within a category. The 4th suspicious URL adds
    less than the 1st; otherwise long spam emails with many links would
    max the score for the wrong reason. We halve each successive
    contribution within a category (1, 1/2, 1/4, ...).
  * Hard cap at 100 and a floor at 0 — the score is a triage aid, not a
    probability. Analysts should read the findings, not just the number.
"""

from __future__ import annotations

from .findings import Finding, INFO, LOW, MEDIUM, HIGH, CRITICAL

SEVERITY_POINTS = {
    INFO: 0,
    LOW: 6,
    MEDIUM: 14,
    HIGH: 26,
    CRITICAL: 40,
}

BANDS = [
    (0, 19, "LIKELY BENIGN", "No meaningful phishing indicators. Normal handling."),
    (20, 44, "LOW RISK", "Minor signals present; probably legitimate but worth a second look "
                          "if the sender or request is unusual for the recipient."),
    (45, 69, "SUSPICIOUS", "Multiple phishing indicators. Do not click links or open "
                            "attachments; verify with the sender via a separate channel."),
    (70, 100, "HIGH RISK — LIKELY PHISHING", "Strong, converging indicators of phishing. "
                                              "Quarantine, report to your security team, and "
                                              "hunt for other recipients of the same campaign."),
]


def score(findings: list[Finding]) -> tuple[int, str, str]:
    """Return (score 0-100, verdict label, recommended action)."""
    total = 0.0
    per_category_count: dict[tuple[str, str], int] = {}

    # Sort so the highest-severity findings in each category get full weight
    # and the diminishing-returns halving applies to the lesser ones.
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    for f in sorted(findings, key=lambda f: order.get(f.severity, 5)):
        points = SEVERITY_POINTS.get(f.severity, 0)
        if points == 0:
            continue
        key = (f.category, f.severity)
        n = per_category_count.get(key, 0)
        total += points / (2 ** n)   # 1st full, 2nd half, 3rd quarter...
        per_category_count[key] = n + 1

    final = max(0, min(100, round(total)))
    for lo, hi, label, action in BANDS:
        if lo <= final <= hi:
            return final, label, action
    return final, "UNKNOWN", ""
