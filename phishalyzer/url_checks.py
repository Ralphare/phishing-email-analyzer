"""
url_checks.py — Extract every URL and flag the classic malicious-link tricks.

Why URLs get their own module: the link is the payload in most credential-
phishing. Headers can be clean (compromised legit mailbox, "BEC"), the body
can be polite — but the victim still has to click *something*. These checks
mirror what a SOC analyst does by hand: hover the link, read the real
domain right-to-left, compare it to the brand being claimed.
"""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .eml_parser import ParsedEmail
from .findings import Finding, LOW, MEDIUM, HIGH, CRITICAL

# --- Reference data ---------------------------------------------------------

# Known URL-shortener domains. Shorteners aren't malicious by themselves,
# but they hide the true destination — which is exactly why phishers love
# them and why corporate mail almost never uses them.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "v.gd",
    "lnkd.in", "tiny.cc", "qr.ae", "soo.gd",
}

# Brands most commonly impersonated in phishing (per APWG / vendor reports).
# We compare every link's registrable domain against these to catch
# typosquats like paypa1.com or micros0ft-login.net.
PROTECTED_BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office": "office.com",
    "google": "google.com", "apple": "apple.com", "amazon": "amazon.com",
    "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "docusign": "docusign.com",
    "outlook": "outlook.com", "icloud": "icloud.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "ups": "ups.com", "whatsapp": "whatsapp.com", "steam": "steampowered.com",
    "github": "github.com", "adobe": "adobe.com", "spotify": "spotify.com",
}

# Common multi-part public suffixes so we can approximate the "registrable
# domain" (e.g. login.paypal.com.evil.co.uk -> evil.co.uk) without pulling
# in the full Public Suffix List. Good enough for a triage tool.
TWO_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.in", "com.br", "com.cn", "com.tr", "com.mx", "co.za",
    "com.sg", "co.kr", "com.hk", "com.az",  # .com.az — relevant for AZ banks
}

URL_REGEX = re.compile(
    r"""\b((?:https?|hxxps?)://[^\s<>"'\)\]]+)""",
    re.IGNORECASE,
)


# --- Small utilities ---------------------------------------------------------

def registrable_domain(host: str) -> str:
    """
    Reduce a hostname to its registrable domain: the part someone actually
    registered. This matters because attackers stack trusted names in
    SUBDOMAINS: 'paypal.com.security-check.net' — the registrable domain,
    read right-to-left, is 'security-check.net'. Users read left-to-right;
    analysts must read right-to-left.
    """
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    """
    Classic edit distance (insert/delete/substitute), implemented in ~10
    lines so we stay dependency-free. Distance 1–2 between a link's domain
    and a big brand's domain is the fingerprint of typosquatting:
    paypal -> paypa1 (1 substitution), microsoft -> micros0ft (1).
    """
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1,          # deletion
                           cur[j - 1] + 1,       # insertion
                           prev[j - 1] + (ca != cb)))  # substitution
        prev = cur
    return prev[-1]


def _normalize_defanged(url: str) -> str:
    """Analysts often share 'defanged' URLs (hxxp, [.]) — re-fang so we can parse."""
    return url.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")


class _AnchorExtractor(HTMLParser):
    """Collect (href, visible_text) pairs from HTML — enables the
    'link text says one thing, destination is another' check."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text_parts = []

    def handle_data(self, data):
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.anchors.append((self._href, "".join(self._text_parts).strip()))
            self._href = None


# --- Main analysis ------------------------------------------------------------

def analyze_urls(parsed: ParsedEmail) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []

    # 1) Gather URLs from both bodies (plain regex) and HTML anchors (parser).
    urls: list[str] = []
    for body in (parsed.text_body, parsed.html_body):
        urls.extend(_normalize_defanged(u) for u in URL_REGEX.findall(body or ""))

    anchors: list[tuple[str, str]] = []
    if parsed.html_body:
        try:
            extractor = _AnchorExtractor()
            extractor.feed(parsed.html_body)
            anchors = extractor.anchors
            urls.extend(href for href, _ in anchors
                        if href and href.lower().startswith(("http://", "https://")))
        except Exception:
            # Broken HTML should never kill the analysis; regex pass above
            # already caught most links anyway.
            pass

    # De-duplicate, preserve order.
    seen: set[str] = set()
    unique_urls = [u for u in urls if not (u in seen or seen.add(u))]

    if not unique_urls:
        findings.append(Finding("URLs", LOW if parsed.html_body else LOW,
                                "No URLs found",
                                "The email contains no hyperlinks.",
                                "Not inherently safe — attachment-based and reply-based "
                                "(BEC) phishing carry no links at all."))
        return findings, unique_urls

    for url in unique_urls:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            findings.append(Finding("URLs", MEDIUM, "Unparseable URL",
                                    f"Could not parse: {url[:120]}",
                                    "Malformed URLs sometimes exploit parser differences "
                                    "between mail filters and browsers."))
            continue
        if not host:
            continue

        # -- Raw IP address instead of a domain --------------------------------
        try:
            ipaddress.ip_address(host)
            findings.append(Finding(
                "URLs", HIGH, "Link points to a raw IP address",
                f"{url}",
                ("Legitimate services link to domain names. A bare IP means no "
                 "registered domain — typical of throwaway attacker servers or "
                 "compromised boxes, and it bypasses domain-reputation filters."),
                evidence=[url]))
            continue
        except ValueError:
            pass  # normal hostname

        reg_dom = registrable_domain(host)

        # -- URL shorteners ------------------------------------------------------
        if reg_dom in SHORTENERS or host in SHORTENERS:
            findings.append(Finding(
                "URLs", MEDIUM, "URL shortener hides destination",
                f"{url}",
                ("Shorteners mask the real destination until after the click, "
                 "defeating the 'hover and check' habit and many reputation "
                 "filters. Businesses rarely use them in transactional mail."),
                evidence=[url]))

        # -- Brand impersonation: typosquats and brand-in-subdomain ---------------
        core = reg_dom.split(".")[0]  # 'paypa1' from 'paypa1-secure.com' -> split hyphens too
        core_tokens = re.split(r"[-_]", core)
        for brand, real_domain in PROTECTED_BRANDS.items():
            if reg_dom == real_domain or reg_dom.endswith("." + real_domain):
                continue  # actually the real brand

            # (a) Typosquat: any hyphen-token of the domain is 1-2 edits from a brand.
            for token in core_tokens:
                dist = levenshtein(token, brand)
                if 0 < dist <= (1 if len(brand) <= 6 else 2):
                    findings.append(Finding(
                        "URLs", CRITICAL, "Likely typosquatted domain",
                        f"'{reg_dom}' looks like '{real_domain}' "
                        f"(token '{token}' is {dist} edit(s) from '{brand}').",
                        ("Typosquatting swaps, drops or adds characters so the domain "
                         "passes a quick glance — paypa1 with a digit one, rn for m. "
                         "The attacker registered this lookalike; it has no relation "
                         "to the real brand."),
                        evidence=[url]))
                    break

            # (b) Exact brand name inside the host, but registrable domain differs:
            #     e.g. paypal.com.account-verify.net or secure-paypal.evil.com
            #     We require the brand as a whole dot/hyphen token to avoid false
            #     positives like 'snapple' containing 'apple'.
            if _brand_is_whole_token(host, brand) and reg_dom != real_domain:
                findings.append(Finding(
                    "URLs", HIGH, "Brand name used on an unrelated domain",
                    f"Host '{host}' contains '{brand}' but is registered under "
                    f"'{reg_dom}', not '{real_domain}'.",
                    ("Stuffing a trusted brand into a subdomain or path exploits "
                     "left-to-right reading: users see 'paypal.com' at the start "
                     "and stop reading. Only the registrable domain — read from "
                     "the right — identifies who owns the site."),
                    evidence=[url]))
                break

        # -- Credentials embedded in URL (user@host trick) -------------------------
        if re.match(r"https?://[^/@\s]+@", url, re.IGNORECASE):
            findings.append(Finding(
                "URLs", HIGH, "URL contains userinfo '@' trick",
                f"{url}",
                ("Everything before '@' in a URL is ignored userinfo — "
                 "'https://paypal.com@evil.net' actually goes to evil.net. A classic "
                 "obfuscation aimed at human readers."),
                evidence=[url]))

        # -- Plain HTTP on a login-looking link --------------------------------------
        if url.lower().startswith("http://") and any(
                k in url.lower() for k in ("login", "signin", "verify", "account", "secure")):
            findings.append(Finding(
                "URLs", MEDIUM, "Unencrypted (HTTP) link to a login-style page",
                f"{url}",
                ("No legitimate service serves authentication pages over plain HTTP "
                 "in the modern era. Attack kits, on the other hand, often skip TLS.")))

    # -- Display-text vs real destination mismatch -----------------------------------
    for href, text in anchors:
        if not href or not text:
            continue
        text_urls = URL_REGEX.findall(text) or (
            [f"http://{text.strip()}"] if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text.strip()) else [])
        if not text_urls:
            continue
        try:
            shown = registrable_domain(urlparse(_normalize_defanged(text_urls[0])).hostname or "")
            actual = registrable_domain(urlparse(href).hostname or "")
        except Exception:
            continue
        if shown and actual and shown != actual:
            findings.append(Finding(
                "URLs", CRITICAL, "Link text doesn't match real destination",
                f"Visible text shows '{shown}' but the link goes to '{actual}'.",
                ("The single most reliable manual phishing check — 'hover before you "
                 "click' — exists because of this trick. Displaying a trusted URL as "
                 "the anchor text while the href points elsewhere is deliberate "
                 "deception; there is no innocent reason for it."),
                evidence=[f"text={text_urls[0]}", f"href={href}"]))

    return findings, unique_urls


def _brand_is_whole_token(host: str, brand: str) -> bool:
    """True if `brand` appears as a full dot/hyphen-delimited token in host."""
    return brand in re.split(r"[.\-_]", host)
