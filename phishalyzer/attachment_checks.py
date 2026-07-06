"""
attachment_checks.py — Enumerate attachments and flag dangerous types.

Why attachments matter: link-based phishing steals credentials; attachment-
based phishing usually delivers malware (loaders, RATs, ransomware droppers).
The file *extension* is the first triage signal because Windows executes by
extension — and hides known ones by default, which is exactly what the
double-extension trick ('invoice.pdf.exe') exploits.
"""

from __future__ import annotations

import re

from .eml_parser import ParsedEmail
from .findings import Finding, INFO, LOW, MEDIUM, HIGH, CRITICAL

# Extensions that execute code directly on a double-click. Any one of these
# arriving by email is treated as hostile until proven otherwise — legitimate
# businesses simply do not email executables.
EXECUTABLE_EXTS = {
    ".exe", ".scr", ".pif", ".com", ".cpl", ".msi", ".msp", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".jar", ".reg", ".dll", ".lnk", ".msc",
}

# Macro-enabled Office formats: the 'm' suffix means the file can contain
# VBA macros — the delivery mechanism behind Emotet, Qakbot and countless
# ransomware campaigns. Legacy .doc/.xls can also carry macros, so they get
# a softer flag.
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm"}
LEGACY_OFFICE_EXTS = {".doc", ".xls", ".ppt"}

# Archives and disk images: used to smuggle executables past mail filters,
# and (ISO/IMG in particular) to strip the Mark-of-the-Web so Windows won't
# warn the user when the inner payload runs.
CONTAINER_EXTS = {".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".cab", ".ace", ".gz", ".tar"}

# OneNote and shortcut-style formats surged after Microsoft blocked macros
# from the internet by default in 2022 — attackers adapt fast.
NEWER_LURE_EXTS = {".one", ".onepkg", ".chm", ".xll", ".svg"}


def _filename_of(part) -> str:
    try:
        return part.get_filename() or ""
    except Exception:
        return ""


def analyze_attachments(parsed: ParsedEmail) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    names: list[str] = []

    # iter_attachments() respects Content-Disposition; we also do a manual
    # pass because attackers sometimes mark payloads 'inline' to dodge
    # exactly this kind of enumeration.
    parts = []
    try:
        parts.extend(parsed.message.iter_attachments())
    except Exception:
        pass
    try:
        for part in parsed.message.walk():
            if _filename_of(part) and part not in parts:
                parts.append(part)
    except Exception:
        pass

    if not parts:
        findings.append(Finding("Attachments", INFO, "No attachments",
                                "The email carries no attached files.", ""))
        return findings, names

    for part in parts:
        name = _filename_of(part) or "(unnamed)"
        names.append(name)
        lower = name.lower()
        findings_before = len(findings)  # to detect a fully-benign attachment

        # Split out ALL extensions so 'invoice.pdf.exe' yields ['.pdf', '.exe'].
        exts = ["." + e for e in lower.split(".")[1:]]
        final_ext = exts[-1] if exts else ""

        if final_ext in EXECUTABLE_EXTS:
            findings.append(Finding(
                "Attachments", CRITICAL, "Directly executable attachment",
                f"'{name}' ends in '{final_ext}' — runs code on double-click.",
                ("No legitimate organization emails executables. This is the bluntest "
                 "malware delivery there is; assume it's a dropper/loader and detonate "
                 "only in a sandbox."),
                evidence=[name]))
        if len(exts) >= 2 and final_ext in EXECUTABLE_EXTS | MACRO_EXTS:
            findings.append(Finding(
                "Attachments", HIGH, "Double-extension disguise",
                f"'{name}' shows a decoy extension before the real one ({final_ext}).",
                ("Windows hides known extensions by default, so 'invoice.pdf.exe' "
                 "displays as 'invoice.pdf' with users none the wiser. The visible "
                 "'document' is a costume for an executable."),
                evidence=[name]))
        if final_ext in MACRO_EXTS:
            findings.append(Finding(
                "Attachments", HIGH, "Macro-enabled Office document",
                f"'{name}' is a macro-capable format ({final_ext}).",
                ("The trailing 'm' means embedded VBA macros are allowed — the "
                 "workhorse of maldoc campaigns. The lure text inside typically "
                 "instructs the victim to click 'Enable Content', which runs the "
                 "malicious macro."),
                evidence=[name]))
        if final_ext in LEGACY_OFFICE_EXTS:
            findings.append(Finding(
                "Attachments", MEDIUM, "Legacy Office format (can hide macros)",
                f"'{name}' uses a pre-2007 format that supports embedded macros.",
                ("Unlike modern .docx/.xlsx, legacy formats don't separate "
                 "macro-enabled files by extension, so a .doc can carry VBA "
                 "invisibly. Still common in real campaigns for that reason.")))
        if final_ext in CONTAINER_EXTS:
            findings.append(Finding(
                "Attachments", MEDIUM, "Archive / disk image container",
                f"'{name}' ({final_ext}) can smuggle executables past filters.",
                ("Wrapping a payload in a ZIP/ISO evades attachment-type blocking, "
                 "and ISO/IMG mounts strip Mark-of-the-Web so Windows SmartScreen "
                 "stays silent when the inner file runs. Password-protected archives "
                 "additionally blind AV scanning.")))
        if final_ext in NEWER_LURE_EXTS:
            findings.append(Finding(
                "Attachments", HIGH, "Modern lure file type",
                f"'{name}' ({final_ext}) is a format adopted by campaigns after "
                "Office macro blocking (OneNote, XLL add-ins, HTML-smuggling SVG/CHM).",
                ("When Microsoft blocked internet macros by default, attackers pivoted "
                 "to these formats within weeks. Seeing them emailed from outside the "
                 "org is a strong signal.")))
        if final_ext in (".html", ".htm", ".shtml"):
            findings.append(Finding(
                "Attachments", HIGH, "HTML attachment (credential-harvest classic)",
                f"'{name}' — HTML files open locally in the browser.",
                ("Attached HTML pages render a pixel-perfect login form locally, "
                 "sidestepping URL reputation entirely, then POST the credentials "
                 "to the attacker. One of the most common phish attachments today.")))

        if len(findings) == findings_before:
            findings.append(Finding("Attachments", INFO, "Attachment present",
                                    f"'{name}' — no dangerous extension detected.",
                                    "Extension looks benign, but content-level inspection "
                                    "(hashing, sandboxing) is outside this tool's scope."))

    return findings, names
