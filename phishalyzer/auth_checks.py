"""
auth_checks.py — SPF, DKIM and DMARC evaluation.

=====================================================================
 Blue-team primer (read this before the code)
=====================================================================
Email has no built-in sender verification — SMTP will happily accept
"MAIL FROM: ceo@yourbank.com" from anyone. Three protocols were bolted
on to fix that, and together they are the single most reliable signal
you have when triaging a suspicious email:

  SPF  (Sender Policy Framework)
      The sending *domain* publishes a DNS record listing which IP
      addresses are allowed to send mail on its behalf. The receiving
      server checks: "did this connection come from an approved IP?"
      Catches: direct spoofing from attacker infrastructure.
      Weakness: only checks the *envelope* sender (Return-Path), which
      the user never sees — so SPF can pass while the visible From: is
      still spoofed. That's why DMARC exists.

  DKIM (DomainKeys Identified Mail)
      The sending server cryptographically signs selected headers and
      the body with a private key; the public key lives in DNS. The
      receiver verifies the signature.
      Catches: tampering in transit, and spoofing (attacker doesn't
      have the private key).
      Weakness: an attacker can DKIM-sign with *their own* domain —
      a valid signature from evil.com proves nothing about paypal.com.
      Alignment matters, which again is DMARC's job.

  DMARC (Domain-based Message Authentication, Reporting & Conformance)
      Ties it together: DMARC passes only if SPF or DKIM passes AND
      the passing domain *aligns* with the visible From: domain — the
      one the user actually sees. It also lets the domain owner publish
      a policy (none / quarantine / reject) telling receivers what to
      do on failure.
      This is the check that most directly answers the triage question:
      "is the From: header trustworthy?"

Where do we read the results from?
      The receiving mail server (Gmail, M365, your gateway) records its
      verdicts in the `Authentication-Results` header. We parse that
      rather than re-doing DNS checks ourselves, because:
        1. It reflects the check done at delivery time, against the
           actual connecting IP — which we can't reconstruct later.
        2. It works fully offline.
      Caveat we handle below: an attacker can pre-insert a *fake*
      Authentication-Results header hoping lazy tools trust it.
=====================================================================
"""

from __future__ import annotations

import re

from .eml_parser import ParsedEmail
from .findings import Finding, INFO, LOW, MEDIUM, HIGH, CRITICAL


def _extract_domain(address_header: str) -> str:
    """Pull the bare domain out of e.g. 'PayPal <service@paypal.com>'."""
    match = re.search(r"@([A-Za-z0-9.-]+)", address_header)
    return match.group(1).lower().rstrip(".") if match else ""


def _find_result(auth_results: str, mechanism: str) -> str | None:
    """
    Extract 'pass' / 'fail' / 'softfail' / 'none' / ... for one mechanism
    from an Authentication-Results header. Returns None if absent.
    """
    match = re.search(rf"\b{mechanism}\s*=\s*([a-zA-Z]+)", auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else None


# Plain-language explanations reused in findings — written for the report
# reader, not for us.
EXPLAIN = {
    "spf_pass": ("SPF pass: the server that delivered this email is on the list of "
                 "servers the sending domain has authorized in DNS. Good sign, but note "
                 "SPF checks the hidden envelope sender, not the From: line you see."),
    "spf_fail": ("SPF fail: the delivering server is NOT authorized to send for this "
                 "domain. Legitimate senders almost never hard-fail SPF — this usually "
                 "means direct spoofing from attacker infrastructure."),
    "spf_softfail": ("SPF softfail (~all): the domain says this server is 'probably not' "
                     "authorized. Weaker than a hard fail, but still suspicious for any "
                     "brand that should have its mail infrastructure in order."),
    "spf_none": ("No SPF record/result: the sending domain publishes no sender policy, "
                 "or the receiving server didn't record one. Anyone can spoof a domain "
                 "with no SPF, so treat the sender address as unverified."),
    "dkim_pass": ("DKIM pass: the message carries a valid cryptographic signature — it "
                  "wasn't altered in transit and was signed by someone holding the "
                  "signing domain's private key. Check alignment: a pass only vouches "
                  "for the *signing* domain, which may not be the From: domain."),
    "dkim_fail": ("DKIM fail: a signature is present but doesn't verify. Either the "
                  "message was modified in transit or the signature was forged/replayed."),
    "dkim_none": ("No DKIM signature: nothing cryptographically ties this message to "
                  "the claimed sender. Common for small senders, but unexpected for any "
                  "major brand — all of them sign their mail."),
    "dmarc_pass": ("DMARC pass: SPF or DKIM passed AND the passing domain matches the "
                   "visible From: domain. This is the strongest available evidence that "
                   "the From: address is genuine."),
    "dmarc_fail": ("DMARC fail: neither SPF nor DKIM passed in alignment with the "
                   "visible From: domain — the address shown to the user could not be "
                   "verified. This is the classic signature of From:-header spoofing."),
    "dmarc_none": ("No DMARC result: the From: domain publishes no DMARC policy (or the "
                   "receiver didn't evaluate it), so nothing enforced alignment between "
                   "the visible sender and the authenticated sender."),
}


def analyze_authentication(parsed: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = _extract_domain(parsed.header("From"))

    auth_headers = parsed.all_headers("Authentication-Results")

    # --- Anti-tampering sanity check -------------------------------------
    # Authentication-Results is added by the *receiving* server. If the header
    # is entirely absent we can't conclude much; but attackers sometimes inject
    # a forged one. A cheap heuristic: a real header names the authserv-id
    # (the evaluating host) before the first semicolon. Multiple conflicting
    # A-R headers is also worth flagging.
    if len(auth_headers) > 1:
        verdicts = {(_find_result(h, "dmarc") or "none") for h in auth_headers}
        if len(verdicts) > 1:
            findings.append(Finding(
                category="Authentication", severity=MEDIUM,
                title="Conflicting Authentication-Results headers",
                detail=f"{len(auth_headers)} Authentication-Results headers with "
                       f"different DMARC verdicts: {sorted(verdicts)}.",
                explanation=("Multiple conflicting results can indicate an attacker "
                             "pre-injected a forged 'pass' header hoping filters trust "
                             "the first one they see. Only the header added by YOUR "
                             "receiving server is trustworthy."),
                evidence=auth_headers,
            ))

    # Use the topmost header (added last, i.e. by the final receiving hop).
    auth = auth_headers[0] if auth_headers else ""

    # Fall back to the older Received-SPF header if needed — some gateways
    # only emit that.
    received_spf = parsed.header("Received-SPF")

    # --- SPF --------------------------------------------------------------
    spf = _find_result(auth, "spf")
    if spf is None and received_spf:
        m = re.match(r"\s*([a-zA-Z]+)", received_spf)
        spf = m.group(1).lower() if m else None

    if spf == "pass":
        findings.append(Finding("Authentication", INFO, "SPF: pass",
                                "Delivering server is authorized by the sender's SPF record.",
                                EXPLAIN["spf_pass"]))
    elif spf == "fail":
        findings.append(Finding("Authentication", HIGH, "SPF: fail",
                                "Delivering server is not authorized for the sender's domain.",
                                EXPLAIN["spf_fail"]))
    elif spf in ("softfail", "neutral"):
        findings.append(Finding("Authentication", MEDIUM, f"SPF: {spf}",
                                f"SPF evaluated as '{spf}' for the envelope sender.",
                                EXPLAIN["spf_softfail"]))
    else:
        findings.append(Finding("Authentication", LOW, "SPF: no result",
                                "No SPF verdict found in headers.",
                                EXPLAIN["spf_none"]))

    # --- DKIM ---------------------------------------------------------------
    dkim = _find_result(auth, "dkim")
    has_signature = bool(parsed.header("DKIM-Signature"))

    if dkim == "pass":
        # Alignment check: which domain actually signed (d= tag)?
        # A valid signature from attacker-domain.com on a mail claiming to be
        # From: paypal.com is a favorite trick — "it says DKIM pass!".
        sig_domain = ""
        m = re.search(r"header\.d\s*=\s*([A-Za-z0-9.-]+)", auth) or \
            re.search(r"\bd\s*=\s*([A-Za-z0-9.-]+)", parsed.header("DKIM-Signature"))
        if m:
            sig_domain = m.group(1).lower()
        if sig_domain and from_domain and not (
                sig_domain == from_domain or sig_domain.endswith("." + from_domain)
                or from_domain.endswith("." + sig_domain)):
            findings.append(Finding(
                "Authentication", MEDIUM, "DKIM: pass, but UNALIGNED",
                f"Signature is valid but was made by '{sig_domain}', while the visible "
                f"From: domain is '{from_domain}'.",
                ("A valid DKIM signature only vouches for the domain that signed it — "
                 "not the From: address you see. Legitimate bulk providers (SendGrid, "
                 "Mailchimp) sometimes sign with their own domain, but attackers use "
                 "the same gap: sign with a domain they control while displaying a "
                 "trusted From:. Without a DMARC pass, treat the From: as unverified."),
                evidence=[f"signing d={sig_domain}", f"From domain={from_domain}"]))
        else:
            findings.append(Finding("Authentication", INFO, "DKIM: pass",
                                    f"Valid signature from '{sig_domain or 'unknown domain'}'.",
                                    EXPLAIN["dkim_pass"]))
    elif dkim in ("fail", "permerror", "temperror"):
        findings.append(Finding("Authentication", HIGH, f"DKIM: {dkim}",
                                "DKIM signature present but failed verification.",
                                EXPLAIN["dkim_fail"]))
    elif has_signature:
        findings.append(Finding("Authentication", LOW, "DKIM: signature present, unverified",
                                "A DKIM-Signature header exists but no verdict was recorded.",
                                "We can see a signature but the receiving server logged no "
                                "result, so we can't confirm it. Treat as unauthenticated."))
    else:
        findings.append(Finding("Authentication", LOW, "DKIM: none",
                                "No DKIM signature on this message.",
                                EXPLAIN["dkim_none"]))

    # --- DMARC ----------------------------------------------------------------
    dmarc = _find_result(auth, "dmarc")
    if dmarc == "pass":
        findings.append(Finding("Authentication", INFO, "DMARC: pass",
                                f"Visible From: domain '{from_domain}' authenticated in alignment.",
                                EXPLAIN["dmarc_pass"]))
    elif dmarc == "fail":
        findings.append(Finding("Authentication", CRITICAL, "DMARC: fail",
                                f"The visible sender '{from_domain}' could NOT be verified.",
                                EXPLAIN["dmarc_fail"]))
    else:
        findings.append(Finding("Authentication", MEDIUM, "DMARC: no result",
                                "No DMARC verdict found in headers.",
                                EXPLAIN["dmarc_none"]))

    # --- Sender-identity coherence checks (header-level spoofing tells) -------
    reply_to_domain = _extract_domain(parsed.header("Reply-To"))
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        findings.append(Finding(
            "Authentication", MEDIUM, "Reply-To domain differs from From domain",
            f"From: @{from_domain} but Reply-To: @{reply_to_domain}.",
            ("Attackers often spoof a trusted From: address but set Reply-To to a "
             "mailbox they control, so replies (and any credentials/invoices the "
             "victim sends back) go straight to them. Legitimate mail rarely does "
             "this across unrelated domains.")))

    return_path_domain = _extract_domain(parsed.header("Return-Path"))
    if return_path_domain and from_domain and return_path_domain != from_domain \
            and not return_path_domain.endswith("." + from_domain):
        findings.append(Finding(
            "Authentication", LOW, "Return-Path domain differs from From domain",
            f"Envelope sender @{return_path_domain} vs visible From @{from_domain}.",
            ("The envelope sender (Return-Path) is what SPF actually checks. A mismatch "
             "is normal for mailing lists and bulk providers, but combined with other "
             "signals it points at spoofing: SPF may 'pass' for the attacker's envelope "
             "domain while the From: line shows the impersonated brand.")))

    return findings
