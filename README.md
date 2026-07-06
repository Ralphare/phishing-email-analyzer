# Phishalyzer — Phishing Email Analyzer

A defensive triage tool that takes a raw `.eml` file and produces a clear,
explained phishing risk report with a weighted 0–100 score. Built for SOC-style
workflows: it doesn't just flag things, it explains *why* each finding matters,
the way a senior analyst would walk a junior through a suspicious email.

100% Python standard library. Runs fully offline. Never crashes on malformed
input — broken MIME, fake charsets and missing headers are absorbed as
findings, not exceptions.

## What it checks

**1. Email authentication (SPF / DKIM / DMARC)**
Parses the `Authentication-Results` header written by the receiving mail
server and interprets the verdicts, including the subtle cases: DKIM that
passes but is *unaligned* with the visible From: domain, conflicting
(possibly attacker-injected) Authentication-Results headers, and
Reply-To / Return-Path domains that diverge from the From: domain.

**2. URLs**
Extracts every link from both the plain-text and HTML bodies (including
defanged `hxxp://` notation), then flags:
- typosquatted lookalikes of ~25 commonly impersonated brands (edit-distance
  based: `paypa1-secure.com` is 1 edit from `paypal`)
- trusted brand names stuffed into subdomains of unrelated domains
  (`paypal.com.account-verify.net`)
- raw-IP links, URL shorteners, `user@host` obfuscation
- HTML anchors whose visible text shows one domain while the href goes to
  another — the trick "hover before you click" exists to catch
- plain-HTTP links to login-style pages

**3. Attachments**
Enumerates all attachments (including ones marked `inline` to dodge naive
scanners) and flags directly executable types (`.exe`, `.scr`, `.js`, …),
double extensions (`invoice.pdf.exe`), macro-enabled Office formats
(`.docm`, `.xlsm`), legacy Office formats, archive/disk-image containers,
HTML attachments, and post-macro-era lures (`.one`, `.xll`, `.chm`).

**4. Body social engineering**
Pattern-matches the language phishing actually uses: urgency and deadlines,
account-suspension threats, direct credential/payment requests, fake
invoices, prize lures, CEO-fraud secrecy ("quick favor", gift cards), generic
greetings — plus display names that claim a brand the sending domain isn't.

**5. Weighted scoring**
Findings carry severities (INFO=0 … CRITICAL=40 points) with diminishing
returns inside each category, so one DMARC fail outweighs ten weak keyword
hits, and a spammy email with 30 links can't max the score for the wrong
reason. Verdict bands: 0–19 likely benign, 20–44 low risk, 45–69 suspicious,
70–100 likely phishing.

## Project layout

```
phishing-analyzer/
├── analyze.py                     # CLI entry point
├── requirements.txt
├── README.md
├── phishalyzer/
│   ├── __init__.py
│   ├── eml_parser.py              # crash-proof .eml loading & decoding
│   ├── findings.py                # shared Finding dataclass
│   ├── auth_checks.py             # SPF / DKIM / DMARC interpretation
│   ├── url_checks.py              # link extraction & lookalike detection
│   ├── attachment_checks.py       # dangerous file-type flagging
│   ├── body_checks.py             # social-engineering language signals
│   ├── scoring.py                 # weighted 0–100 score
│   └── report.py                  # console + JSON report rendering
└── samples/
    ├── benign_newsletter.eml      # scores  0 — LIKELY BENIGN
    ├── subtle_borderline.eml      # scores 55 — SUSPICIOUS
    └── obvious_phishing.eml       # scores 100 — HIGH RISK
```

## Install

Requires Python 3.10+. No dependencies for offline use:

```bash
git clone <your-repo-url> && cd phishing-analyzer
python3 analyze.py samples/obvious_phishing.eml     # that's it
```

Optional — enable `--online` DNS lookups (checks whether the sender domain
even publishes SPF/DMARC records):

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 analyze.py <path-to-eml>              # human-readable report
python3 analyze.py <path-to-eml> --json       # machine-readable (SIEM/jq)
python3 analyze.py <path-to-eml> --no-color   # plain text (files, tickets)
python3 analyze.py <path-to-eml> --online     # + live DNS SPF/DMARC lookups
```

Exit codes: `0` analysis completed, `2` file unreadable.

## Sample output (excerpt, obvious_phishing.eml)

```
==============================================================================
  PHISHING EMAIL ANALYSIS REPORT
==============================================================================
  From:        PayPal Security Team <service@paypal.com>
  Subject:     URGENT: Your account will be suspended within 24 hours
  Reply-To:    recovery-desk@mail-blast-747.xyz
  URLs found:  4
  Attachments: 1  (SecurityForm.pdf.exe)
==============================================================================
  RISK SCORE: 100/100   VERDICT: HIGH RISK — LIKELY PHISHING
  Strong, converging indicators of phishing. Quarantine, report to your
  security team, and hunt for other recipients of the same campaign.
==============================================================================

  [AUTHENTICATION]
  --------------------------------------------------------------------------
  [CRITICAL] DMARC: fail
      The visible sender 'paypal.com' could NOT be verified.
      Why it matters: neither SPF nor DKIM passed in alignment with the
      visible From: domain — the classic signature of From:-header spoofing.

  [URLS]
  --------------------------------------------------------------------------
  [CRITICAL] Likely typosquatted domain
      'paypa1-secure-verification.com' looks like 'paypal.com'
      (token 'paypa1' is 1 edit(s) from 'paypal').
  [CRITICAL] Link text doesn't match real destination
      Visible text shows 'paypal.com' but the link goes to
      'paypa1-secure-verification.com'.
  ...
```

Run all three samples to see the full score range:

```bash
for f in samples/*.eml; do python3 analyze.py "$f"; done
```

## How each check maps to real phishing tactics

| Check | Real-world tactic it catches |
|---|---|
| DMARC fail | From:-header spoofing — displaying `service@paypal.com` while sending from attacker infrastructure. DMARC is the only protocol that verifies the address the *user actually sees*. |
| SPF fail / softfail | Direct spoofing from unauthorized servers; sloppy attacker infra that never bothered with the envelope domain's policy. |
| Unaligned DKIM pass | "Technically signed" mail where the signature belongs to the attacker's own domain — a valid signature from `evil.com` proves nothing about `paypal.com`. |
| Reply-To mismatch | BEC/credential harvest: spoof the From:, but route replies to a mailbox the attacker controls. |
| Typosquat detection | Lookalike domains (`paypa1`, `micros0ft`, `arnazon`) registered specifically because they survive a quick glance. |
| Brand-in-subdomain | `paypal.com.security-check.net` — exploits left-to-right reading; only the rightmost registrable domain identifies the owner. |
| Text/href mismatch | The anchor displays a trusted URL while the href points elsewhere — no legitimate reason exists for this. |
| Shorteners & raw IPs | Destination hiding and reputation-filter evasion; throwaway or compromised hosts with no registered domain. |
| Executable / double-extension attachments | Malware droppers exploiting Windows hiding known extensions (`invoice.pdf.exe` shows as `invoice.pdf`). |
| Macro-enabled Office | The Emotet/Qakbot-era delivery chain: lure text tells the victim to click "Enable Content", which runs the VBA payload. |
| Archives / ISO images | Filter evasion plus Mark-of-the-Web stripping so SmartScreen never warns. |
| Urgency / account-threat / credential-request language | The psychological core of phishing: manufactured deadlines and fear of loss to short-circuit verification. |
| Secrecy + gift-card phrasing | CEO fraud: impersonate authority, isolate the victim from anyone who'd say "that's a scam". |
| Generic greeting | Mass-campaign kits can't personalize; your bank knows your name. |

## Design notes

- **Reads verdicts, doesn't re-verify.** Authentication results come from the
  `Authentication-Results` header written by the receiving server, because the
  delivery-time check (against the actual connecting IP) can't be reproduced
  after the fact — and it keeps the tool fully offline.
- **Trust but verify the header itself.** Multiple conflicting
  Authentication-Results headers are flagged, since attackers pre-inject
  forged "pass" headers hoping tools trust the first one.
- **Score is a triage aid, not a verdict.** The report says so explicitly.
  A clean score doesn't clear a targeted BEC email with no links; analysts
  read findings.

## Next steps to extend it

1. **Attachment content inspection** — hash attachments (SHA-256), extract and
   scan inside ZIPs, detect VBA macros in OLE/OOXML files with `oletools`,
   and optionally query the hashes against a local threat-intel list.
2. **Received-chain hop analysis** — walk the `Received:` headers bottom-up to
   spot geographic/ASN anomalies and forged early hops.
3. **Homoglyph/IDN detection** — extend the typosquat check to punycode
   (`xn--`) domains and Unicode confusables (`pаypal.com` with Cyrillic 'а').
4. **Batch mode + CSV/JSONL export** — analyze a whole mailbox export and feed
   results into your Wazuh instance as custom events for dashboarding.
5. **Local URL reputation cache** — optional offline lists (e.g. a downloaded
   OpenPhish/URLhaus snapshot) consulted before any online lookup.

## Scope & ethics

Defensive analysis only: the tool parses and reports; it never contacts URLs,
detonates attachments, or generates content. The sample "phishing" emails are
inert text fixtures for testing the detector.
