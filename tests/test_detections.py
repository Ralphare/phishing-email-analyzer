"""
Regression tests for phishalyzer.

Run with:  python3 -m unittest discover -s tests -v

Each test builds a tiny .eml in a temp file, runs the real analyzers on it
and checks which findings come out. Several of these are false positives
and misses found during review, so they stay fixed.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishalyzer.eml_parser import load_eml          # noqa: E402
from phishalyzer.url_checks import analyze_urls, typosquat_match  # noqa: E402
from phishalyzer.body_checks import analyze_body      # noqa: E402
from phishalyzer.auth_checks import analyze_authentication  # noqa: E402
from phishalyzer.findings import INFO                 # noqa: E402


def make_email(body: str, sender: str = "Alice <alice@company.com>",
               auth: str = "mx.example.net; spf=pass smtp.mailfrom=company.com; "
                           "dkim=pass header.d=company.com; dmarc=pass",
               content_type: str = "text/plain") -> Path:
    raw = (f"From: {sender}\nTo: bob@example.net\nSubject: test\n"
           f"Authentication-Results: {auth}\n"
           f"Content-Type: {content_type}; charset=utf-8\n\n{body}\n")
    tmp = tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False,
                                      encoding="utf-8", newline="\n")
    tmp.write(raw)
    tmp.close()
    return Path(tmp.name)


def titles(findings) -> list[str]:
    return [f.title for f in findings]


class TyposquatTests(unittest.TestCase):
    def test_real_typosquats_are_caught(self):
        for token, brand in [("paypa1", "paypal"), ("micros0ft", "microsoft"),
                             ("arnazon", "amazon"), ("paypall", "paypal"),
                             ("micorsoft", "microsoft"), ("netflex", "netflix")]:
            with self.subTest(token=token):
                self.assertTrue(typosquat_match(token, brand))

    def test_ordinary_words_are_not_typosquats(self):
        for token, brand in [("us", "ups"), ("stream", "steam"), ("apply", "apple"),
                             ("offices", "office"), ("news", "ups")]:
            with self.subTest(token=token):
                self.assertFalse(typosquat_match(token, brand))

    def test_benign_domains_get_no_typosquat_finding(self):
        for url in ("https://us-news.com/today", "https://stream.com/live",
                    "https://apply-now.com/jobs"):
            with self.subTest(url=url):
                f, _ = analyze_urls(load_eml(make_email(f"Read more at {url}")))
                self.assertNotIn("Likely typosquatted domain", titles(f))

    def test_brand_in_subdomain_still_caught_for_short_brands(self):
        f, _ = analyze_urls(load_eml(make_email("Track: https://ups.delivery-track.net/p")))
        self.assertIn("Brand name used on an unrelated domain", titles(f))


class UrlExtractionTests(unittest.TestCase):
    def test_defanged_url_with_brackets_is_parsed(self):
        f, urls = analyze_urls(load_eml(make_email("IOC: hxxp://evil[.]com/login")))
        self.assertIn("http://evil.com/login", urls)
        self.assertNotIn("Unparseable URL", titles(f))

    def test_no_urls_adds_no_score(self):
        f, _ = analyze_urls(load_eml(make_email("Plain note, no links.")))
        self.assertTrue(all(x.severity == INFO for x in f))

    def test_link_text_mismatch_detected(self):
        html = '<a href="https://evil-site.net/x">https://paypal.com</a>'
        f, _ = analyze_urls(load_eml(make_email(html, content_type="text/html")))
        self.assertIn("Link text doesn't match real destination", titles(f))


class BodyTests(unittest.TestCase):
    def test_are_you_available_ceo_fraud_opener(self):
        for text in ("are you available?", "Are you available"):
            with self.subTest(text=text):
                f = analyze_body(load_eml(make_email(text)))
                self.assertIn("Secrecy / CEO-fraud style request", titles(f))

    def test_are_you_available_with_crlf_line_endings(self):
        # Real .eml files use CRLF. Written as bytes so this runs the same on
        # Linux CI and Windows (text mode on Windows would add \r anyway).
        raw = (b"From: Boss <boss@company.com>\r\nTo: bob@example.net\r\n"
               b"Subject: hi\r\nContent-Type: text/plain\r\n\r\n"
               b"are you available?\r\nThanks.\r\n")
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".eml", delete=False)
        tmp.write(raw)
        tmp.close()
        f = analyze_body(load_eml(tmp.name))
        self.assertIn("Secrecy / CEO-fraud style request", titles(f))

    def test_are_you_available_mid_sentence_not_flagged(self):
        f = analyze_body(load_eml(make_email("Are you available for lunch on Friday with the team?")))
        self.assertNotIn("Secrecy / CEO-fraud style request", titles(f))

    def test_display_name_word_containing_brand_is_not_impersonation(self):
        f = analyze_body(load_eml(make_email("Hello team", sender="Marketing Groups <n@company.com>")))
        self.assertNotIn("Display name impersonates a brand", titles(f))

    def test_display_name_impersonation_still_caught(self):
        f = analyze_body(load_eml(make_email("Hi", sender="PayPal Support <alerts@secure-notify.net>")))
        self.assertIn("Display name impersonates a brand", titles(f))


class AuthTests(unittest.TestCase):
    def test_dmarc_fail_is_critical(self):
        eml = make_email("hi", sender="PayPal <service@paypal.com>",
                         auth="mx.example.net; spf=fail; dkim=none; dmarc=fail")
        f = analyze_authentication(load_eml(eml))
        self.assertIn("DMARC: fail", titles(f))


class SampleScoreTests(unittest.TestCase):
    """The scores documented in the README must stay true."""

    def run_sample(self, name: str) -> int:
        out = subprocess.run([sys.executable, str(ROOT / "analyze.py"),
                              str(ROOT / "samples" / name), "--json"],
                             capture_output=True, text=True, check=True).stdout
        import json
        return json.loads(out)["score"]

    def test_sample_scores(self):
        self.assertEqual(self.run_sample("benign_newsletter.eml"), 0)
        self.assertEqual(self.run_sample("subtle_borderline.eml"), 55)
        self.assertEqual(self.run_sample("obvious_phishing.eml"), 100)

    def test_missing_file_exits_2(self):
        r = subprocess.run([sys.executable, str(ROOT / "analyze.py"), "no-such-file.eml"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
