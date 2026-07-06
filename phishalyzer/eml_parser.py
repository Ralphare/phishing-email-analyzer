"""
eml_parser.py — Safe loading and normalization of .eml files.

Why a dedicated module?
    Real-world phishing emails are frequently *malformed on purpose* —
    attackers break MIME structure, use weird encodings, or omit headers
    to confuse naive parsers and some security tools. Everything downstream
    (auth checks, URL extraction, body scans) depends on this module never
    crashing and always handing back *something* usable.
"""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Optional


@dataclass
class ParsedEmail:
    """A normalized view of one email, safe for the analyzers to consume."""
    message: EmailMessage                 # the underlying parsed object
    raw_bytes: bytes                      # original file content (fallback source)
    text_body: str = ""                   # concatenated text/plain parts
    html_body: str = ""                   # concatenated text/html parts
    parse_warnings: list[str] = field(default_factory=list)

    # Convenience header accessors — always return "" instead of None so
    # downstream code never has to None-check.
    def header(self, name: str) -> str:
        try:
            value = self.message.get(name)
            return str(value) if value is not None else ""
        except Exception:
            # Defective headers (bad encodings) can raise on access.
            # get_all with a failobj is more forgiving.
            try:
                values = self.message.get_all(name, failobj=[])
                return str(values[0]) if values else ""
            except Exception:
                return ""

    def all_headers(self, name: str) -> list[str]:
        try:
            return [str(v) for v in self.message.get_all(name, failobj=[])]
        except Exception:
            return []


def _decode_part(part) -> str:
    """
    Decode one MIME part to text without ever raising.

    Why so paranoid? Attackers deliberately declare a wrong charset
    (e.g. claim utf-8 but send cp1251) hoping scanners give up.
    We try the declared charset, then common fallbacks, then decode
    with errors replaced — worst case we get mojibake, never a crash.
    """
    try:
        payload = part.get_payload(decode=True)  # handles base64 / quoted-printable
    except Exception:
        payload = None
    if payload is None:
        # Payload may already be a str (non-MIME or broken structure)
        try:
            raw = part.get_payload()
            return raw if isinstance(raw, str) else ""
        except Exception:
            return ""

    declared = part.get_content_charset() or "utf-8"
    for charset in (declared, "utf-8", "latin-1"):
        try:
            return payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def load_eml(path: str | Path) -> ParsedEmail:
    """
    Load an .eml file from disk into a ParsedEmail.

    Raises only for genuinely unrecoverable problems (file missing /
    unreadable). Malformed *content* is absorbed into parse_warnings.
    """
    path = Path(path)
    raw = path.read_bytes()  # let FileNotFoundError/PermissionError surface — the CLI handles them

    warnings: list[str] = []

    # policy=default gives us the modern EmailMessage API (walk(), iter_attachments()).
    # message_from_bytes is remarkably tolerant: it records structural problems
    # in .defects instead of raising, which is exactly what we want.
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        # Extremely rare, but possible with pathological input. Fall back to
        # the most permissive policy so we still get a message object.
        warnings.append(f"Strict parse failed ({exc.__class__.__name__}); used compat fallback.")
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    # Surface parser-detected defects as warnings — defects themselves are a
    # weak phishing signal (legit mail clients rarely emit broken MIME).
    for defect in getattr(msg, "defects", []):
        warnings.append(f"MIME defect: {defect.__class__.__name__}")

    parsed = ParsedEmail(message=msg, raw_bytes=raw, parse_warnings=warnings)

    # Walk every part once and bucket text vs html. We deliberately do NOT
    # trust Content-Type alone for attachments here — attachment_checks.py
    # does its own, stricter pass.
    try:
        parts = list(msg.walk())
    except Exception:
        parts = [msg]
        warnings.append("MIME walk failed; treating message as a single part.")

    for part in parts:
        try:
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "").lower()
        except Exception:
            continue
        if "attachment" in disp:
            continue  # handled by attachment_checks.py
        if ctype == "text/plain":
            parsed.text_body += _decode_part(part) + "\n"
        elif ctype == "text/html":
            parsed.html_body += _decode_part(part) + "\n"

    if not parsed.text_body and not parsed.html_body:
        # Non-MIME or single-part message: take whatever body exists.
        parsed.text_body = _decode_part(msg)
        if not parsed.text_body.strip():
            warnings.append("No readable body found (empty or undecodable).")

    return parsed
