"""
findings.py — The shared "Finding" type every analyzer emits.

Keeping one common shape means the scorer and the report renderer don't
need to know anything about *which* module produced a result — a pattern
you'll see in real SIEM/SOAR pipelines (normalized events in, verdict out).
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Severity levels double as scoring weights (see scoring.py).
INFO = "INFO"        # context only, contributes 0 points
LOW = "LOW"          # weak signal on its own
MEDIUM = "MEDIUM"    # meaningful signal
HIGH = "HIGH"        # strong indicator of phishing
CRITICAL = "CRITICAL"  # near-certain malicious indicator


@dataclass
class Finding:
    category: str        # e.g. "Authentication", "URLs", "Attachments", "Body"
    severity: str        # one of the levels above
    title: str           # short human-readable name of the check
    detail: str          # what exactly triggered, with evidence
    explanation: str = ""  # plain-language "why this matters" for the report
    evidence: list[str] = field(default_factory=list)  # raw values (URLs, headers...)
