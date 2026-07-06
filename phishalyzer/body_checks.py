"""
body_checks.py — Social-engineering signals in the message text.

Technical controls (SPF/DKIM/DMARC, URL filters) catch the infrastructure;
these checks catch the *psychology*. Phishing works by short-circuiting the
victim's judgment, and it does so with remarkably consistent language:
manufactured urgency, fear of loss, authority pressure, and a demand for
credentials or money. Pattern-matching that language is crude but effective
— it's the same idea behind the 'suspicious keywords' rules in commercial
secure email gateways.
"""

from __future__ import annotations

import re

from .eml_parser import ParsedEmail
from .findings import Finding, LOW, MEDIUM, HIGH

# Each entry: (regex, finding title, severity, why-it-matters)
# Phrases are matched case-insensitively against text + stripped HTML.
SIGNAL_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r"\b(urgent|immediately|right away|as soon as possible|act now|"
        r"within (24|48) hours?|expires? (today|soon|in \d+)|final (notice|warning)|"
        r"last chance|time.?sensitive|don'?t delay)\b",
        "Urgency / time-pressure language", MEDIUM,
        ("Manufactured deadlines push victims to act before thinking or "
         "verifying through another channel. Real institutions apply far less "
         "pressure — and never over unverifiable email."),
    ),
    (
        r"\b(account (will be|has been|is) (suspend|clos|lock|restrict|deactivat|limit)\w*|"
        r"unusual (sign.?in|activity|login)|suspicious activity|"
        r"verify your (account|identity|information)|confirm your (account|identity|details)|"
        r"reactivate your account|security alert)\b",
        "Account-threat / verification lure", HIGH,
        ("The 'your account is in danger — verify now' framing is the single "
         "most common credential-phishing pretext: it combines fear of loss "
         "with a helpful-looking link that leads to a harvesting page."),
    ),
    (
        r"\b((enter|update|confirm|provide|submit) your (password|credentials|card|"
        r"credit card|banking|ssn|social security|pin)\b|log ?in (below|here|now)|"
        r"click (here|the link below) to (log ?in|sign ?in|verify))\b",
        "Direct credential/payment-detail request", HIGH,
        ("Legitimate services do not ask you to submit passwords, card numbers "
         "or PINs via an emailed link. Any such request is treated as hostile "
         "by definition in SOC triage."),
    ),
    (
        r"\b(wire transfer|payment (is )?(overdue|pending|failed)|invoice (attached|"
        r"is due|#?\d+)|update (your )?(payment|billing) (method|information|details)|"
        r"outstanding (balance|payment)|refund (is )?(pending|waiting|available))\b",
        "Payment / invoice pressure", MEDIUM,
        ("Fake invoices and 'failed payment' notices monetize the phish directly, "
         "or serve as the lure for a malicious attachment (classic BEC and "
         "maldoc pretexts)."),
    ),
    (
        r"\b(you('| ha)ve (won|been selected)|congratulations|claim your (prize|reward|"
        r"gift ?card)|lottery|inheritance|million (usd|dollars|euros))\b",
        "Too-good-to-be-true reward lure", MEDIUM,
        ("Prize and inheritance lures target greed instead of fear — an older "
         "pattern, but it still filters for the most susceptible victims."),
    ),
    (
        r"\b(do not (share|tell|forward|disclose)|keep this (confidential|between us)|"
        r"are you available\??$|quick (favor|task|request)|"
        r"(buy|purchase|get) (some |the )?gift ?cards?)\b",
        "Secrecy / CEO-fraud style request", HIGH,
        ("'Keep this between us, quick favor, buy gift cards' is the fingerprint "
         "of Business Email Compromise: impersonate an executive, isolate the "
         "victim from verification, extract untraceable value."),
    ),
    (
        r"\b(dear (customer|user|client|member|account holder|sir/madam|valued))\b",
        "Generic greeting (sender doesn't know your name)", LOW,
        ("Mass phishing kits blast thousands of addresses and can't personalize. "
         "A real provider that holds your account knows your name. Weak alone, "
         "meaningful in combination."),
    ),
]


def _strip_html(html: str) -> str:
    """Cheap tag stripper — good enough for keyword scanning."""
    return re.sub(r"<[^>]+>", " ", html or "")


def analyze_body(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    text = f"{parsed.text_body}\n{_strip_html(parsed.html_body)}"
    if not text.strip():
        findings.append(Finding("Body", LOW, "Empty or unreadable body",
                                "No text content could be extracted.",
                                "Image-only or empty bodies are themselves a filter-evasion "
                                "technique — the 'text' lives inside a picture."))
        return findings

    lowered = text.lower()
    for pattern, title, severity, why in SIGNAL_PATTERNS:
        matches = re.findall(pattern, lowered, re.IGNORECASE | re.MULTILINE)
        if matches:
            # findall may return tuples for grouped patterns; flatten to strings.
            samples = []
            for m in matches[:3]:
                samples.append(m if isinstance(m, str) else next((x for x in m if x), ""))
            samples = [s for s in samples if s]
            findings.append(Finding(
                "Body", severity, title,
                f"Matched {len(matches)} phrase(s), e.g.: "
                + ", ".join(f"'{s}'" for s in samples[:3]),
                why))

    # --- Sender-identity mismatch: display name claims a brand the domain isn't ---
    # e.g. From: "PayPal Support" <alerts@secure-notify.net>
    from_header = parsed.header("From")
    display = re.sub(r"<[^>]*>", "", from_header).strip(' "\'').lower()
    dom_match = re.search(r"@([A-Za-z0-9.-]+)", from_header)
    from_domain = dom_match.group(1).lower() if dom_match else ""
    if display and from_domain:
        for brand in ("paypal", "microsoft", "apple", "amazon", "google", "netflix",
                      "dhl", "fedex", "ups", "chase", "docusign", "linkedin", "bank"):
            if brand in display and brand not in from_domain:
                findings.append(Finding(
                    "Body", HIGH, "Display name impersonates a brand",
                    f"Display name '{display}' claims '{brand}' but the address is "
                    f"@{from_domain}.",
                    ("Most mail clients — especially on mobile — show only the display "
                     "name, which the sender sets freely. Claiming a brand in the "
                     "display name while sending from an unrelated domain is textbook "
                     "sender spoofing at the human layer."),
                    evidence=[from_header]))
                break

    return findings
