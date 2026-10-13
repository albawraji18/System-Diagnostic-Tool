#!/usr/bin/env python3
# -*- coding: ascii -*-
"""
System Security & Drive Diagnostic Tool
=======================================

A single-file desktop utility with three parts:

  1. File & Folder Security Scanner
     Rule-based scanning of a single file or a whole folder (recursive),
     with drag-and-drop, a "Bottom Line" verdict card and a results table.

  2. Storage & Drive Health Diagnostics (CrystalDiskInfo style)
     Drive switcher bar, health / temperature header and a S.M.A.R.T.
     attribute table. Real hardware data is read through smartctl
     (smartmontools) when available, otherwise through Windows WMI /
     Storage cmdlets, otherwise volume information only. A clearly
     labelled "Demo data" mode shows simulated drives for previewing.

  3. Theme engine
     Several cohesive themes applied to every widget, remembered between
     sessions.

Requirements
------------
  * Python 3.8+ with Tkinter (bundled with the python.org installers).
  * Optional: psutil            (better volume detection on Linux/macOS)
  * Optional: tkinterdnd2       (drag-and-drop on Linux/macOS; Windows has
                                 built-in drag-and-drop without it)
  * Optional: smartmontools     (full S.M.A.R.T. data on every platform)

Run as Administrator (Windows) or root (Linux/macOS) for S.M.A.R.T. data.

Command line
------------
  python system_diagnostic_tool.py                 Start the GUI
  python system_diagnostic_tool.py --scan PATH     Console scan (exit 2 = DANGER)
  python system_diagnostic_tool.py --drives        Console drive report
  python system_diagnostic_tool.py --drives --demo Console report, simulated data

SELF-SCAN NOTE
--------------
This file necessarily describes the very patterns it hunts for. To stop the
tool from flagging itself (or a copy of itself, its byte-code cache, or a
report it exported), three independent safeguards are used:

  a) Every content signature is written with "~" split markers, for example
     "vss~admin". The marker is removed only when the regex is compiled, so
     the complete indicator never appears in this source file or its .pyc.
  b) The running script / frozen executable is excluded by real path, and
     any byte-identical copy is excluded by SHA-256.
  c) Indicator text shown in the table and in exported reports is
     "defanged" (e.g. "vss^admin", "hxxp://") so reports never re-trigger.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime
import glob
import hashlib
import json
import os
import queue
import re
import shutil
import string
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # Headless Python: the CLI modes still work.
    tk = None
    tkfont = None
    filedialog = None
    messagebox = None
    ttk = None

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # Optional dependency.
    DND_FILES = None
    TkinterDnD = None

try:
    import psutil
except Exception:  # Optional dependency.
    psutil = None


# ===========================================================================
# Constants
# ===========================================================================

APP_NAME = "System Security & Drive Diagnostic Tool"
APP_VERSION = "1.0.0"

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

DEGREE = "\u00b0"  # Written as an escape so the source stays pure ASCII.

VERDICT_SAFE = "SAFE"
VERDICT_DANGER = "DANGER"
VERDICT_SKIPPED = "SKIPPED"

HEALTH_GOOD = "Good"
HEALTH_CAUTION = "Caution"
HEALTH_BAD = "Bad"
HEALTH_UNKNOWN = "Unknown"


# ===========================================================================
# Generic helpers
# ===========================================================================

def human_bytes(value: Optional[float]) -> str:
    """Format a byte count using decimal units, like drive vendors do."""
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(size) < 1000.0 or unit == "PB":
            if unit == "B":
                return "{:d} B".format(int(size))
            return "{:.1f} {}".format(size, unit)
        size /= 1000.0
    return "{:.1f} PB".format(size)


def fmt_int(value: Optional[int]) -> str:
    """Format an integer with thousands separators, or '-' when missing."""
    if value is None:
        return "-"
    return "{:,}".format(int(value))


def to_int(value, default: Optional[int] = None) -> Optional[int]:
    """Best-effort integer conversion for loosely typed external data."""
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def blend(color_a: str, color_b: str, ratio: float) -> str:
    """Mix two #rrggbb colors. ratio=0 gives color_a, ratio=1 gives color_b."""
    a = color_a.lstrip("#")
    b = color_b.lstrip("#")
    channels = []
    for index in (0, 2, 4):
        start = int(a[index:index + 2], 16)
        end = int(b[index:index + 2], 16)
        channels.append(int(round(start + (end - start) * ratio)))
    return "#{:02x}{:02x}{:02x}".format(*channels)


def run_command(args: List[str], timeout: float = 30.0) -> Tuple[int, str]:
    """Run an external command without a console window; return (rc, stdout)."""
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            **kwargs
        )
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    text = completed.stdout.decode("utf-8", errors="replace")
    return completed.returncode, text


def is_elevated() -> bool:
    """True when running as Administrator (Windows) or root (POSIX)."""
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def settings_path() -> str:
    """Location of the small JSON settings file (theme choice)."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SysSecDriveDiag", "settings.json")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "sys-sec-drive-diag", "settings.json")


def load_settings() -> Dict[str, object]:
    try:
        with open(settings_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data: Dict[str, object]) -> None:
    path = settings_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except OSError:
        pass  # Settings are a convenience; never fail because of them.


# ===========================================================================
# FEATURE 1 - Security scanner engine (rule based)
# ===========================================================================

def _rx(pattern: str) -> "re.Pattern[bytes]":
    """Compile a bytes regex written with '~' split markers (see SELF-SCAN NOTE)."""
    return re.compile(pattern.replace("~", "").encode("ascii"), re.IGNORECASE)


def defang(text: str) -> str:
    """Neutralise an indicator so displayed / exported text never re-triggers.

    URLs become 'hxxp://', every token of 4+ characters gets a caret after
    its third character ('vss^admin', '-en^c'), and finally the text is
    re-checked against every signature until nothing matches any more.
    """
    text = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", text)
    text = re.sub(r"(\S{3})(\S+)", r"\1^\2", text)
    for _ in range(50):
        encoded = text.encode("ascii", errors="replace")
        found = None
        for rule in CONTENT_RULES:
            for pattern in rule.patterns:
                found = pattern.search(encoded)
                if found:
                    break
            if found:
                break
        if not found:
            break
        cut = min(found.start() + 3, len(text) - 1)
        text = text[:cut] + "^" + text[cut:]
    return text


def printable_snippet(raw: bytes, limit: int = 90) -> str:
    """Turn matched bytes into a short, single-line, ASCII-only snippet."""
    text = raw.decode("latin-1", errors="replace")
    text = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit - 3] + "..."
    return defang(text)


@dataclass(frozen=True)
class ContentRule:
    """A content signature: every pattern in `patterns` must match."""

    rule_id: str
    title: str
    explanation: str
    patterns: Tuple["re.Pattern[bytes]", ...]


@dataclass
class RuleHit:
    rule_id: str
    title: str
    indicator: str
    explanation: str


@dataclass
class FileReport:
    path: str
    verdict: str
    hits: List[RuleHit] = field(default_factory=list)
    note: str = ""
    size: Optional[int] = None

    @property
    def name(self) -> str:
        return os.path.basename(self.path) or self.path

    @property
    def rule_text(self) -> str:
        if self.hits:
            extra = len(self.hits) - 1
            suffix = " (+{} more)".format(extra) if extra else ""
            return self.hits[0].title + suffix
        if self.verdict == VERDICT_SKIPPED:
            return "Not scanned"
        if self.note:
            return "Self-exclusion"
        return "No rule matched"

    @property
    def details_text(self) -> str:
        if self.hits:
            return " | ".join(hit.indicator for hit in self.hits)
        return self.note or "No threat indicators found"


# --- Extension groups ------------------------------------------------------

DOCUMENT_MEDIA_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".ods", ".odp", ".rtf", ".txt", ".csv", ".jpg", ".jpeg", ".png",
    ".gif", ".bmp", ".webp", ".tif", ".tiff", ".svg", ".mp3", ".wav",
    ".flac", ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".zip", ".rar",
    ".7z", ".iso",
}

EXECUTABLE_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".ps1", ".msi", ".jar", ".cpl",
    ".reg", ".dll", ".app", ".sh", ".command",
}

MEDIA_ONLY_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    ".mp3", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".avi", ".mov",
    ".wmv", ".iso",
}

BIDI_CONTROL_CHARS = {
    "\u202e": "RIGHT-TO-LEFT OVERRIDE (U+202E)",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE (U+202D)",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING (U+202B)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (U+2066)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (U+2067)",
    "\u2068": "FIRST STRONG ISOLATE (U+2068)",
}

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
LNK_MAGIC = b"L\x00\x00\x00\x01\x14\x02\x00"
ZIP_MAGIC = b"PK\x03\x04"


# --- Content signatures ----------------------------------------------------

CONTENT_RULES: Tuple[ContentRule, ...] = (
    ContentRule(
        "SIG-001",
        "EICAR test signature",
        "The standard anti-malware test string. Real antivirus products treat "
        "this file as infected.",
        (_rx(re.escape("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STAN")
             + "~" + re.escape("DARD-ANTIVIRUS-TEST-FILE!$H+H*")),),
    ),
    ContentRule(
        "PS-001",
        "Encoded PowerShell command",
        "PowerShell launched with a Base64-encoded command hides what it "
        "really runs. This is a hallmark of malware droppers.",
        (_rx(r"power~shell(?:\.exe)?[^\r\n]{0,120}?\s[-/]"
             r"(?:e|ec|en|enc|enco|encodedcommand)\s+['\"]?[a-z0-9+/=]{24,}"),),
    ),
    ContentRule(
        "PS-002",
        "Download-and-execute cradle",
        "Code that downloads a remote script and executes it in memory "
        "(Invoke-Expression + web download).",
        (_rx(r"(?:\bi~ex\b|invoke-expres~sion)[\s\S]{0,300}?"
             r"(?:download~string|download~file|net\.web~client|"
             r"invoke-web~request|\biw~r\b|start-bits~transfer)"
             r"|(?:download~string|net\.web~client|invoke-web~request|\biw~r\b)"
             r"[\s\S]{0,300}?(?:\bi~ex\b|invoke-expres~sion)"),),
    ),
    ContentRule(
        "PS-003",
        "Hidden PowerShell with remote URL",
        "PowerShell started with a hidden window that contacts a remote "
        "address, a common stealth download technique.",
        (_rx(r"power~shell(?:\.exe)?[^\r\n]{0,80}?[-/]w(?:indowstyle)?\s+"
             r"h(?:idden)?\b[^\r\n]{0,300}?https?://"),),
    ),
    ContentRule(
        "LOL-001",
        "LOLBin download / decode (certutil)",
        "certutil is abused to download or decode payloads while bypassing "
        "security controls.",
        (_rx(r"cert~util(?:\.exe)?[^\r\n]{0,80}?(?:[-/]url~cache[^\r\n]{0,80}?"
             r"https?://|[-/]de~code(?:hex)?\b)"),),
    ),
    ContentRule(
        "LOL-002",
        "LOLBin script execution (mshta / regsvr32 / rundll32)",
        "Signed Windows helper programs (mshta, regsvr32, rundll32) abused "
        "to run remote or inline script code.",
        (_rx(r"\bmsh~ta(?:\.exe)?\s+['\"]?(?:https?://|java~script:|vb~script:)"
             r"|regsvr~32(?:\.exe)?[^\r\n]{0,80}?/i:\s*['\"]?https?://"
             r"|rundll~32(?:\.exe)?[^\r\n]{0,60}?java~script:"),),
    ),
    ContentRule(
        "LOL-003",
        "LOLBin transfer (bitsadmin)",
        "bitsadmin used to silently transfer a file from the internet.",
        (_rx(r"bits~admin(?:\.exe)?[^\r\n]{0,40}?/trans~fer[^\r\n]{0,200}?"
             r"https?://"),),
    ),
    ContentRule(
        "RAN-001",
        "Ransomware: backup / shadow copy destruction",
        "Commands that delete Volume Shadow Copies or disable recovery are "
        "run by ransomware right before encrypting files.",
        (_rx(r"vss~admin(?:\.exe)?[^\r\n]{0,40}?delete\s+sha~dows"
             r"|wmic(?:\.exe)?[^\r\n]{0,40}?shadow~copy\s+delete"
             r"|bcd~edit(?:\.exe)?[^\r\n]{0,60}?recovery~enabled\s+(?:no|false)"
             r"|wb~admin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)"),),
    ),
    ContentRule(
        "WSH-001",
        "Script dropper (WScript.Shell + web download)",
        "A script that both downloads data from the web and executes "
        "commands through WScript.Shell.",
        (
            _rx(r"create~object\(\s*['\"]w~script\.shell['\"]\s*\)"),
            _rx(r"msxml2\.(?:server)?xml~http|win~http\.winhttprequest"
                r"|adodb\.str~eam"),
        ),
    ),
    ContentRule(
        "NIX-001",
        "Reverse shell",
        "A shell connected to a remote host, giving an attacker interactive "
        "control of the machine.",
        (_rx(r"\bbash\s+-i\s*>&\s*/dev/~tcp/"
             r"|\bnc(?:at)?\b[^\r\n]{0,40}?\s-e\s+/bin/(?:ba)?sh"
             r"|socket\.socket\([\s\S]{0,200}?\.connect\([\s\S]{0,200}?"
             r"os\.dup~2\("),),
    ),
)

PDF_LAUNCH_RX = _rx(r"/Laun~ch\b")
PDF_SCRIPT_RX = _rx(r"/(?:Java~Script|J~S)\b")
PDF_AUTO_RX = _rx(r"/(?:Open~Action|A~A)\b")
PDF_HEX_NAME_RX = re.compile(rb"#([0-9A-Fa-f]{2})")

LNK_INTERPRETER_RX = _rx(r"power~shell|cmd(?:\.exe)?\s+/c|msh~ta|w~script|"
                         r"c~script|rundll~32")
LNK_SUSPICIOUS_RX = _rx(r"https?://|\s-e(?:nc|c)?\s|from~base64|hid~den|"
                        r"\.(?:ps1|vbs|js|hta)\b")

AUTORUN_RX = re.compile(
    rb"(?im)^\s*(?:open|shellexecute|shell\\[^\r\n=]*\\command)\s*=\s*(\S[^\r\n]*)"
)

OLE_VBA_MARKER = "_VBA_PROJECT".encode("utf-16-le")


def detect_native_binary(head: bytes) -> Optional[str]:
    """Identify native executable formats from the first bytes of a file."""
    if head[:2] == b"MZ":
        if len(head) >= 0x40:
            offset = int.from_bytes(head[0x3C:0x40], "little")
            if 0 < offset <= len(head) - 4 and head[offset:offset + 4] == b"PE\x00\x00":
                return "Windows PE executable (MZ/PE header)"
        return "DOS/Windows executable (MZ header)"
    if head[:4] == b"\x7fELF":
        return "Linux ELF executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macOS Mach-O executable"
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "Mach-O universal / Java class binary"
    return None


def disguise_in_name(name: str) -> Optional[str]:
    """Return a description when a file name hides an executable extension."""
    lowered = name.lower()
    stem, last_ext = os.path.splitext(lowered)
    if last_ext not in EXECUTABLE_EXTS:
        return None
    padded = stem.rstrip(" ._-")
    inner_ext = os.path.splitext(padded)[1]
    if inner_ext in DOCUMENT_MEDIA_EXTS:
        if len(stem) - len(padded) >= 3:
            return "'{}' is padded with blanks to hide '{}'".format(
                inner_ext, last_ext)
        return "'{}' pretends to be '{}' but is '{}'".format(
            name, inner_ext, last_ext)
    return None


class SelfIdentity:
    """Recognises this tool's own files so a self-scan never flags them."""

    def __init__(self) -> None:
        candidates = []
        main_file = globals().get("__file__")
        if main_file:
            candidates.append(main_file)
        if getattr(sys, "frozen", False):
            candidates.append(sys.executable)
        elif sys.argv and sys.argv[0].lower().endswith(".py"):
            candidates.append(sys.argv[0])
        self.paths = set()
        for path in candidates:
            try:
                self.paths.add(self._key(path))
            except OSError:
                continue
        self._digests: Dict[int, str] = {}
        primary = sys.executable if getattr(sys, "frozen", False) else main_file
        if primary and os.path.isfile(primary):
            try:
                size = os.path.getsize(primary)
                self._digests[size] = self.sha256(primary)
            except OSError:
                pass

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))

    @staticmethod
    def sha256(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def matches(self, path: str, size: int) -> bool:
        try:
            if self._key(path) in self.paths:
                return True
            expected = self._digests.get(size)
            return expected is not None and self.sha256(path) == expected
        except OSError:
            return False


class SecurityScanner:
    """Applies all rules to one file and returns a FileReport."""

    HEAD_BYTES = 4096
    MAX_CONTENT_BYTES = 8 * 1024 * 1024

    def __init__(self) -> None:
        self.identity = SelfIdentity()

    # -- public ------------------------------------------------------------

    def scan_file(self, path: str) -> FileReport:
        try:
            info = os.stat(path)
        except OSError as exc:
            return FileReport(path, VERDICT_SKIPPED,
                              note="Cannot access file: {}".format(exc.strerror))

        if self.identity.matches(path, info.st_size):
            return FileReport(
                path, VERDICT_SAFE, size=info.st_size,
                note="This is the diagnostic tool itself - excluded to "
                     "prevent a self-scan false positive")

        name = os.path.basename(path)
        hits = self._check_file_name(name)

        try:
            with open(path, "rb") as handle:
                data = handle.read(self.MAX_CONTENT_BYTES)
        except OSError as exc:
            note = "Cannot read file: {}".format(exc.strerror)
            if hits:
                return FileReport(path, VERDICT_DANGER, hits, note, info.st_size)
            return FileReport(path, VERDICT_SKIPPED, note=note, size=info.st_size)

        hits.extend(self._check_content(path, name, data))
        verdict = VERDICT_DANGER if hits else VERDICT_SAFE
        note = ""
        if info.st_size > self.MAX_CONTENT_BYTES and not hits:
            note = "Large file: first {} inspected".format(
                human_bytes(self.MAX_CONTENT_BYTES))
        return FileReport(path, verdict, hits, note, info.st_size)

    # -- rules ---------------------------------------------------------------

    @staticmethod
    def _check_file_name(name: str) -> List[RuleHit]:
        hits = []
        for char, label in BIDI_CONTROL_CHARS.items():
            if char in name:
                visible = name.replace(char, "[" + label.split(" (")[0] + "]")
                hits.append(RuleHit(
                    "NAME-001", "Hidden text-direction character in file name",
                    "{} in name: {}".format(label, visible.encode(
                        "ascii", "replace").decode("ascii")),
                    "Unicode direction overrides make 'gpj.exe' display as "
                    "'exe.jpg', disguising a program as a harmless file."))
                break
        disguise = disguise_in_name(name)
        if disguise:
            hits.append(RuleHit(
                "NAME-002", "Double extension disguise",
                disguise.encode("ascii", "replace").decode("ascii"),
                "A document/media extension placed before an executable "
                "extension is a classic trick to make a program look safe."))
        return hits

    def _check_content(self, path: str, name: str, data: bytes) -> List[RuleHit]:
        hits: List[RuleHit] = []
        head = data[:self.HEAD_BYTES]
        ext = os.path.splitext(name.lower())[1]
        native = detect_native_binary(head)

        if native and ext in DOCUMENT_MEDIA_EXTS:
            hits.append(RuleHit(
                "BIN-001", "Executable disguised as document/media",
                "Extension '{}' but content is a {}".format(ext, native),
                "The file claims to be a document or picture, but it is "
                "really a program that would run when opened."))

        is_zip = head.startswith(ZIP_MAGIC)
        is_ole = head.startswith(OLE_MAGIC)
        is_pdf = head.startswith(b"%PDF") or ext == ".pdf"

        if is_pdf:
            hits.extend(self._check_pdf(data))
        if is_ole and ext != ".msi":
            hits.extend(self._check_ole(data))
        if is_zip:
            hits.extend(self._check_zip(path))
        if ext == ".lnk" or head.startswith(LNK_MAGIC):
            hits.extend(self._check_lnk(data))
        if name.lower() == "autorun.inf":
            hits.extend(self._check_autorun(data))

        if native is None and not is_zip and not is_ole \
                and ext not in MEDIA_ONLY_EXTS:
            hits.extend(self._check_signatures(data))
        return hits

    @staticmethod
    def _text_views(data: bytes) -> List[bytes]:
        """Raw bytes plus a UTF-16LE decoded view for wide-char scripts."""
        views = [data]
        sample = data[:4096]
        if sample and sample.count(b"\x00") > len(sample) // 5:
            wide = data.decode("utf-16-le", errors="ignore")
            views.append(wide.encode("ascii", errors="ignore"))
        return views

    def _check_signatures(self, data: bytes) -> List[RuleHit]:
        hits = []
        views = self._text_views(data)
        for rule in CONTENT_RULES:
            snippets = []
            for pattern in rule.patterns:
                found = None
                for view in views:
                    found = pattern.search(view)
                    if found:
                        break
                if not found:
                    snippets = []
                    break
                snippets.append(printable_snippet(found.group(0)))
            if snippets:
                hits.append(RuleHit(rule.rule_id, rule.title,
                                    " + ".join(snippets), rule.explanation))
        return hits

    @staticmethod
    def _check_pdf(data: bytes) -> List[RuleHit]:
        normalized = PDF_HEX_NAME_RX.sub(
            lambda m: bytes([int(m.group(1), 16)]), data)
        if PDF_LAUNCH_RX.search(normalized):
            return [RuleHit(
                "PDF-001", "PDF launch action",
                "PDF contains a /Launch action",
                "The PDF tries to start an external program when opened.")]
        if PDF_SCRIPT_RX.search(normalized) and PDF_AUTO_RX.search(normalized):
            return [RuleHit(
                "PDF-002", "Auto-running PDF JavaScript",
                "PDF has embedded JavaScript plus an automatic open action",
                "JavaScript that runs automatically on open is used to "
                "exploit PDF readers.")]
        return []

    @staticmethod
    def _check_ole(data: bytes) -> List[RuleHit]:
        if OLE_VBA_MARKER in data:
            return [RuleHit(
                "DOC-001", "Embedded VBA macros (legacy Office)",
                "Legacy Office document contains a _VBA_PROJECT stream",
                "Macros in documents from outside sources are the most "
                "common Office malware vector. Do not enable editing or "
                "content.")]
        return []

    @staticmethod
    def _check_zip(path: str) -> List[RuleHit]:
        hits = []
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                lowered = [entry.lower() for entry in names]
                if any(entry.endswith("vbaproject.bin") for entry in lowered):
                    hits.append(RuleHit(
                        "DOC-002", "Embedded VBA macros (Office Open XML)",
                        "Document package contains vbaProject.bin",
                        "Macros in documents from outside sources are the "
                        "most common Office malware vector."))
                for entry in names:
                    if not entry.lower().endswith(".rels"):
                        continue
                    info = archive.getinfo(entry)
                    if info.file_size > 512 * 1024:
                        continue
                    content = archive.read(entry)
                    external = re.search(
                        rb"Target=\"(https?://[^\"]+|\\\\[^\"]+)\"[^>]*"
                        rb"TargetMode=\"External\"", content, re.I)
                    if external and (b"attachedTemplate" in content
                                     or b"oleObject" in content
                                     or b"frame" in content):
                        hits.append(RuleHit(
                            "DOC-003", "Remote template / object injection",
                            "External target: " + printable_snippet(
                                external.group(1)),
                            "The document silently loads a template or object "
                            "from a remote server, a known way to deliver "
                            "exploits without macros."))
                        break
                for entry in names:
                    base = entry.replace("\\", "/").rsplit("/", 1)[-1]
                    reason = disguise_in_name(base)
                    has_bidi = any(ch in base for ch in BIDI_CONTROL_CHARS)
                    if reason or has_bidi:
                        detail = reason or "direction override in member name"
                        hits.append(RuleHit(
                            "ARC-001", "Archive contains disguised executable",
                            "Member: " + detail.encode(
                                "ascii", "replace").decode("ascii"),
                            "The archive hides a program behind a fake "
                            "document or picture name."))
                        break
        except (zipfile.BadZipFile, OSError, RuntimeError, KeyError,
                NotImplementedError):
            pass
        return hits

    @staticmethod
    def _check_lnk(data: bytes) -> List[RuleHit]:
        text = data.decode("utf-16-le", errors="ignore")
        text = text.encode("ascii", errors="ignore") + b" " + data
        interpreter = LNK_INTERPRETER_RX.search(text)
        suspicious = LNK_SUSPICIOUS_RX.search(text)
        if interpreter and suspicious:
            return [RuleHit(
                "LNK-001", "Malicious shortcut (.lnk) command line",
                "Shortcut runs {} with {}".format(
                    printable_snippet(interpreter.group(0)),
                    printable_snippet(suspicious.group(0))),
                "Shortcut files are abused to launch hidden script commands "
                "instead of opening a document.")]
        return []

    @staticmethod
    def _check_autorun(data: bytes) -> List[RuleHit]:
        found = AUTORUN_RX.search(data)
        if found:
            return [RuleHit(
                "USB-001", "Autorun.inf launches a program",
                "autorun.inf entry: " + printable_snippet(found.group(0)),
                "Autorun entries are used by USB worms to start themselves "
                "when a drive is opened.")]
        return []


def iter_files(targets: Iterable[str], cancel: threading.Event,
               errors: List[str]) -> Iterator[str]:
    """Yield regular files from files/folders, recursively, skipping links."""
    for target in targets:
        if cancel.is_set():
            return
        if os.path.isfile(target):
            yield target
            continue
        if not os.path.isdir(target):
            errors.append(target)
            continue
        for root, dirs, files in os.walk(
                target, onerror=lambda exc: errors.append(
                    getattr(exc, "filename", "") or str(exc))):
            if cancel.is_set():
                return
            dirs[:] = [d for d in dirs
                       if not os.path.islink(os.path.join(root, d))]
            for file_name in files:
                full = os.path.join(root, file_name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                yield full


# ===========================================================================
# FEATURE 2 - Drive health engine
# ===========================================================================

ATA_ATTRIBUTE_NAMES = {
    0x01: "Read Error Rate", 0x02: "Throughput Performance",
    0x03: "Spin-Up Time", 0x04: "Start/Stop Count",
    0x05: "Reallocated Sectors Count", 0x07: "Seek Error Rate",
    0x08: "Seek Time Performance", 0x09: "Power-On Hours",
    0x0A: "Spin Retry Count", 0x0B: "Recalibration Retries",
    0x0C: "Power Cycle Count", 0xA9: "Remaining Life",
    0xAA: "Available Reserved Space", 0xAB: "Program Fail Count",
    0xAC: "Erase Fail Count", 0xAD: "Wear Leveling Count",
    0xAE: "Unexpected Power Loss Count", 0xB1: "Wear Leveling Count",
    0xB3: "Used Reserved Block Count", 0xB5: "Program Fail Count",
    0xB6: "Erase Fail Count", 0xB7: "Runtime Bad Block",
    0xB8: "End-to-End Error", 0xBB: "Reported Uncorrectable Errors",
    0xBC: "Command Timeout", 0xBD: "High Fly Writes",
    0xBE: "Airflow Temperature", 0xBF: "G-Sense Error Rate",
    0xC0: "Power-off Retract Count", 0xC1: "Load/Unload Cycle Count",
    0xC2: "Temperature", 0xC3: "Hardware ECC Recovered",
    0xC4: "Reallocation Event Count", 0xC5: "Current Pending Sector Count",
    0xC6: "Uncorrectable Sector Count", 0xC7: "UltraDMA CRC Error Count",
    0xC8: "Write Error Rate", 0xE7: "SSD Life Left",
    0xE8: "Available Reserved Space", 0xE9: "Media Wearout Indicator",
    0xF1: "Total Host Writes", 0xF2: "Total Host Reads",
}

# Raw value > 0 on these attributes means the surface is degrading.
CAUTION_ATTRIBUTE_IDS = {
    0x05: "Reallocated Sectors (05)",
    0xC5: "Pending Sectors (C5)",
    0xC6: "Uncorrectable Sectors (C6)",
}

# Normalised values of these attributes express remaining SSD life in %.
SSD_LIFE_ATTRIBUTE_IDS = (0xE7, 0xA9, 0xE9, 0xB1, 0xAD)

TEMPERATURE_ATTRIBUTE_IDS = (0xC2, 0xBE)

NVME_FIELDS = (
    (0x01, "critical_warning", "Critical Warning"),
    (0x02, "temperature", "Composite Temperature"),
    (0x03, "available_spare", "Available Spare"),
    (0x04, "available_spare_threshold", "Available Spare Threshold"),
    (0x05, "percentage_used", "Percentage Used"),
    (0x06, "data_units_read", "Data Units Read"),
    (0x07, "data_units_written", "Data Units Written"),
    (0x08, "host_reads", "Host Read Commands"),
    (0x09, "host_writes", "Host Write Commands"),
    (0x0A, "controller_busy_time", "Controller Busy Time"),
    (0x0B, "power_cycles", "Power Cycles"),
    (0x0C, "power_on_hours", "Power On Hours"),
    (0x0D, "unsafe_shutdowns", "Unsafe Shutdowns"),
    (0x0E, "media_errors", "Media and Data Integrity Errors"),
    (0x0F, "num_err_log_entries", "Error Information Log Entries"),
)


@dataclass
class SmartAttribute:
    attr_id: Optional[int]
    name: str
    current: Optional[int] = None
    worst: Optional[int] = None
    threshold: Optional[int] = None
    raw_value: Optional[int] = None
    raw_text: str = ""
    status: str = "OK"

    @property
    def id_text(self) -> str:
        return "{:02X}".format(self.attr_id) if self.attr_id is not None else "--"


@dataclass
class DriveInfo:
    key: str
    mount: str
    device: str = ""
    fs_type: str = ""
    volume_total: Optional[int] = None
    volume_free: Optional[int] = None
    model: str = "Unknown drive"
    serial: str = "-"
    firmware: str = "-"
    interface: str = "-"
    media: str = "-"
    disk_size: Optional[int] = None
    temperature: Optional[int] = None
    power_on_hours: Optional[int] = None
    power_cycles: Optional[int] = None
    protocol: str = ""
    smart_passed: Optional[bool] = None
    attributes: List[SmartAttribute] = field(default_factory=list)
    health: str = HEALTH_UNKNOWN
    health_percent: Optional[int] = None
    health_reasons: List[str] = field(default_factory=list)
    source: str = "Volume information only"
    notes: List[str] = field(default_factory=list)
    simulated: bool = False

    @property
    def health_label(self) -> str:
        if self.health_percent is not None and self.health != HEALTH_UNKNOWN:
            return "{} {} %".format(self.health, self.health_percent)
        return self.health

    @property
    def temperature_text(self) -> str:
        if self.temperature is None:
            return "-- " + DEGREE + "C"
        return "{} {}C".format(self.temperature, DEGREE)


def evaluate_health(drive: DriveInfo) -> None:
    """Derive the overall status the same way CrystalDiskInfo does."""
    status = HEALTH_GOOD
    reasons: List[str] = []

    def raise_to(level: str, reason: str) -> None:
        nonlocal status
        order = {HEALTH_GOOD: 0, HEALTH_CAUTION: 1, HEALTH_BAD: 2}
        if order[level] > order[status]:
            status = level
        reasons.append(reason)

    if drive.smart_passed is False:
        raise_to(HEALTH_BAD, "Drive self-assessment reports FAILED")

    if drive.protocol == "NVME":
        values = {a.attr_id: a for a in drive.attributes}
        for attr in drive.attributes:
            attr.status = "OK"
        warning = values.get(0x01)
        if warning and warning.raw_value:
            warning.status = HEALTH_BAD
            raise_to(HEALTH_BAD, "NVMe critical warning flag is set")
        spare = values.get(0x03)
        spare_limit = values.get(0x04)
        if spare and spare_limit and spare.raw_value is not None \
                and spare_limit.raw_value is not None \
                and spare.raw_value < spare_limit.raw_value:
            spare.status = HEALTH_BAD
            raise_to(HEALTH_BAD, "Available spare below threshold")
        media = values.get(0x0E)
        if media and media.raw_value:
            media.status = HEALTH_CAUTION
            raise_to(HEALTH_CAUTION, "Media and data integrity errors: {}"
                     .format(media.raw_value))
        used = values.get(0x05)
        if used and used.raw_value is not None:
            drive.health_percent = max(0, 100 - min(100, used.raw_value))
            if used.raw_value >= 100:
                used.status = HEALTH_CAUTION
                raise_to(HEALTH_CAUTION, "Rated endurance fully used")
    elif drive.protocol == "ATA":
        by_id = {}
        for attr in drive.attributes:
            attr.status = "OK"
            if attr.attr_id is not None:
                by_id.setdefault(attr.attr_id, attr)
            failed = (attr.threshold not in (None, 0)
                      and attr.current is not None
                      and attr.current <= attr.threshold)
            if failed:
                attr.status = HEALTH_BAD
                raise_to(HEALTH_BAD, "{} below threshold".format(attr.name))
            elif attr.attr_id in CAUTION_ATTRIBUTE_IDS and attr.raw_value:
                attr.status = HEALTH_CAUTION
                raise_to(HEALTH_CAUTION, "{}: {}".format(
                    CAUTION_ATTRIBUTE_IDS[attr.attr_id], attr.raw_value))
        for attr_id in SSD_LIFE_ATTRIBUTE_IDS:
            attr = by_id.get(attr_id)
            if attr is not None and attr.current is not None \
                    and 0 <= attr.current <= 200:
                drive.health_percent = min(100, attr.current)
                break
        if drive.health_percent is None and status == HEALTH_GOOD \
                and "HDD" in drive.media:
            drive.health_percent = 100
    elif drive.protocol == "STORAGE":
        # Windows Storage reliability counters: status already set upstream.
        status = drive.health if drive.health != HEALTH_UNKNOWN else status
        reasons.extend(drive.health_reasons)
    else:
        status = HEALTH_UNKNOWN
        if drive.smart_passed is False:
            status = HEALTH_BAD

    if status != HEALTH_GOOD and drive.health_percent == 100:
        drive.health_percent = None
    drive.health = status
    drive.health_reasons = reasons


def fill_from_ata_attributes(drive: DriveInfo) -> None:
    """Derive temperature / hours / cycles from attributes when missing."""
    by_id = {a.attr_id: a for a in drive.attributes if a.attr_id is not None}
    if drive.temperature is None:
        for attr_id in TEMPERATURE_ATTRIBUTE_IDS:
            attr = by_id.get(attr_id)
            if attr is not None and attr.raw_value is not None:
                value = attr.raw_value & 0xFF
                if 0 < value < 120:
                    drive.temperature = value
                    break
    if drive.power_on_hours is None and 0x09 in by_id:
        raw = by_id[0x09].raw_value
        drive.power_on_hours = raw & 0xFFFFFFFF if raw is not None else None
    if drive.power_cycles is None and 0x0C in by_id:
        raw = by_id[0x0C].raw_value
        drive.power_cycles = raw & 0xFFFFFFFF if raw is not None else None


# --- smartctl (smartmontools) -----------------------------------------------

def find_smartctl() -> Optional[str]:
    found = shutil.which("smartctl")
    if found:
        return found
    candidates = []
    if IS_WINDOWS:
        for env in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env)
            if base:
                candidates.append(os.path.join(
                    base, "smartmontools", "bin", "smartctl.exe"))
    else:
        candidates += ["/usr/sbin/smartctl", "/usr/local/sbin/smartctl",
                       "/opt/homebrew/bin/smartctl", "/usr/local/bin/smartctl"]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def apply_smartctl_json(drive: DriveInfo, data: Dict) -> bool:
    """Copy smartctl --json output into a DriveInfo. True if SMART data found."""
    if not isinstance(data, dict):
        return False
    device = data.get("device") or {}
    protocol = str(device.get("protocol", "")).upper()
    table = (data.get("ata_smart_attributes") or {}).get("table") or []
    nvme = data.get("nvme_smart_health_information_log")
    model = (data.get("model_name") or data.get("scsi_model_name")
             or data.get("model_family"))
    if not table and not nvme and not model:
        return False

    drive.model = str(model or drive.model)
    drive.serial = str(data.get("serial_number") or drive.serial)
    drive.firmware = str(data.get("firmware_version")
                         or data.get("scsi_revision") or drive.firmware)
    drive.disk_size = to_int((data.get("user_capacity") or {}).get("bytes"),
                             drive.disk_size)

    speed = ((data.get("interface_speed") or {}).get("current") or {})
    sata = (data.get("sata_version") or {}).get("string")
    parts = [protocol or "Unknown"]
    if sata:
        parts.append(str(sata))
    if speed.get("string"):
        parts.append("@ " + str(speed["string"]))
    drive.interface = " ".join(parts)

    status = data.get("smart_status")
    if isinstance(status, dict) and "passed" in status:
        drive.smart_passed = bool(status["passed"])

    drive.temperature = to_int((data.get("temperature") or {}).get("current"))
    drive.power_on_hours = to_int((data.get("power_on_time") or {}).get("hours"))
    drive.power_cycles = to_int(data.get("power_cycle_count"))

    rotation = data.get("rotation_rate")
    if nvme:
        drive.media = "NVMe SSD"
    elif rotation == 0:
        drive.media = "SSD"
    elif isinstance(rotation, int) and rotation > 0:
        drive.media = "HDD ({} RPM)".format(rotation)

    drive.attributes = []
    if nvme:
        drive.protocol = "NVME"
        for attr_id, key, label in NVME_FIELDS:
            if key not in nvme:
                continue
            value = to_int(nvme.get(key))
            text = fmt_int(value)
            if key in ("data_units_read", "data_units_written") and value:
                text += "  ({})".format(human_bytes(value * 512000))
            elif key == "temperature" and value is not None:
                text = "{} {}C".format(value, DEGREE)
            elif key in ("percentage_used", "available_spare",
                         "available_spare_threshold") and value is not None:
                text = "{} %".format(value)
            drive.attributes.append(SmartAttribute(
                attr_id, label, raw_value=value, raw_text=text))
        if drive.temperature is None:
            drive.temperature = to_int(nvme.get("temperature"))
        if drive.power_on_hours is None:
            drive.power_on_hours = to_int(nvme.get("power_on_hours"))
        if drive.power_cycles is None:
            drive.power_cycles = to_int(nvme.get("power_cycles"))
    elif table:
        drive.protocol = "ATA"
        for row in table:
            attr_id = to_int(row.get("id"))
            raw = row.get("raw") or {}
            name = str(row.get("name") or "").replace("_", " ").strip()
            drive.attributes.append(SmartAttribute(
                attr_id,
                ATA_ATTRIBUTE_NAMES.get(attr_id, name or "Vendor Specific"),
                current=to_int(row.get("value")),
                worst=to_int(row.get("worst")),
                threshold=to_int(row.get("thresh")),
                raw_value=to_int(raw.get("value")),
                raw_text=str(raw.get("string") or fmt_int(to_int(raw.get("value")))),
            ))
        fill_from_ata_attributes(drive)
    elif drive.smart_passed is not None:
        # SCSI/SAS or USB bridge: only the overall pass/fail is available.
        drive.protocol = "ATA"
    drive.source = "smartctl (smartmontools)"
    return True


def smartctl_messages(data: Dict) -> List[str]:
    messages = ((data or {}).get("smartctl") or {}).get("messages") or []
    return [str(m.get("string", "")).strip() for m in messages
            if isinstance(m, dict) and m.get("string")]


# --- Windows: WMI / Storage cmdlets -------------------------------------------

# Single quotes only: the script is passed as one -Command argument.
WINDOWS_PS_QUERY = " ; ".join([
    "$ErrorActionPreference = 'SilentlyContinue'",
    "$vol = @(Get-Partition | Where-Object { [string]$_.DriveLetter -match "
    "'^[A-Za-z]$' } | ForEach-Object { [pscustomobject]@{ "
    "Letter = [string]$_.DriveLetter; Disk = [int]$_.DiskNumber } })",
    "$dsk = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { "
    "[pscustomobject]@{ Index = [int]$_.Index; Model = [string]$_.Model; "
    "Serial = [string]$_.SerialNumber; Firmware = [string]$_.FirmwareRevision; "
    "Interface = [string]$_.InterfaceType; Pnp = [string]$_.PNPDeviceID; "
    "Size = [string]$_.Size } })",
    "$smd = @(Get-CimInstance -Namespace root/wmi -ClassName "
    "MSStorageDriver_FailurePredictData | ForEach-Object { [pscustomobject]@{ "
    "Instance = [string]$_.InstanceName; "
    "Data = @($_.VendorSpecific | ForEach-Object { [int]$_ }) } })",
    "$smt = @(Get-CimInstance -Namespace root/wmi -ClassName "
    "MSStorageDriver_FailurePredictThresholds | ForEach-Object { "
    "[pscustomobject]@{ Instance = [string]$_.InstanceName; "
    "Data = @($_.VendorSpecific | ForEach-Object { [int]$_ }) } })",
    "$sms = @(Get-CimInstance -Namespace root/wmi -ClassName "
    "MSStorageDriver_FailurePredictStatus | ForEach-Object { "
    "[pscustomobject]@{ Instance = [string]$_.InstanceName; "
    "Predict = [bool]$_.PredictFailure } })",
    "$rel = @(Get-PhysicalDisk | ForEach-Object { "
    "$r = $_ | Get-StorageReliabilityCounter; [pscustomobject]@{ "
    "Disk = [string]$_.DeviceId; Health = [string]$_.HealthStatus; "
    "Media = [string]$_.MediaType; Bus = [string]$_.BusType; "
    "Temp = $r.Temperature; Hours = $r.PowerOnHours; "
    "ReadErr = $r.ReadErrorsTotal; Wear = $r.Wear; "
    "Starts = $r.StartStopCycleCount } })",
    "[pscustomobject]@{ volumes = $vol; disks = $dsk; smart = $smd; "
    "thresholds = $smt; status = $sms; reliability = $rel } "
    "| ConvertTo-Json -Depth 6 -Compress",
])


def _as_list(value) -> List:
    """Normalise PowerShell JSON quirks (null, single object, value wrapper)."""
    if value is None:
        return []
    if isinstance(value, dict) and isinstance(value.get("value"), list):
        return value["value"]
    if isinstance(value, list):
        return value
    return [value]


def _normalize_pnp(text: str) -> str:
    return re.sub(r"_\d+$", "", str(text or "").strip().upper())


def parse_wmi_smart(vendor: List[int],
                    thresholds: Optional[List[int]]) -> List[SmartAttribute]:
    """Decode the 512-byte ATA SMART block returned by WMI (12-byte entries)."""
    limits: Dict[int, int] = {}
    if thresholds:
        for offset in range(2, len(thresholds) - 11, 12):
            attr_id = thresholds[offset]
            if attr_id:
                limits[attr_id] = thresholds[offset + 1]
    attributes = []
    for offset in range(2, len(vendor) - 11, 12):
        attr_id = vendor[offset]
        if not attr_id:
            continue
        raw = int.from_bytes(bytes(b & 0xFF for b in vendor[offset + 5:offset + 11]),
                             "little")
        if attr_id in TEMPERATURE_ATTRIBUTE_IDS:
            raw_text = "{} {}C".format(raw & 0xFF, DEGREE)
        elif attr_id in (0x09, 0x0C):
            raw_text = fmt_int(raw & 0xFFFFFFFF)
        else:
            raw_text = fmt_int(raw)
        attributes.append(SmartAttribute(
            attr_id,
            ATA_ATTRIBUTE_NAMES.get(attr_id, "Vendor Specific"),
            current=vendor[offset + 3],
            worst=vendor[offset + 4],
            threshold=limits.get(attr_id),
            raw_value=raw,
            raw_text=raw_text,
        ))
    return attributes


def apply_windows_query(drive: DriveInfo, data: Dict) -> bool:
    """Fill a drive from the PowerShell query result. True if data was found."""
    letter = drive.key.rstrip(":\\").upper()
    disk_number = None
    for volume in _as_list(data.get("volumes")):
        if str(volume.get("Letter", "")).upper() == letter:
            disk_number = to_int(volume.get("Disk"))
            break
    if disk_number is None:
        return False

    disk = next((d for d in _as_list(data.get("disks"))
                 if to_int(d.get("Index")) == disk_number), None)
    reliability = next((r for r in _as_list(data.get("reliability"))
                        if str(r.get("Disk")) == str(disk_number)), None)
    if disk:
        drive.model = str(disk.get("Model") or drive.model).strip()
        drive.serial = str(disk.get("Serial") or drive.serial).strip()
        drive.firmware = str(disk.get("Firmware") or drive.firmware).strip()
        drive.interface = str(disk.get("Interface") or drive.interface)
        drive.disk_size = to_int(disk.get("Size"), drive.disk_size)
    if reliability:
        bus = str(reliability.get("Bus") or "")
        media = str(reliability.get("Media") or "")
        if bus:
            drive.interface = bus
        if bus.upper() == "NVME":
            drive.media = "NVMe SSD"
        elif media in ("SSD", "HDD"):
            drive.media = media

    pnp = _normalize_pnp(disk.get("Pnp")) if disk else ""
    smart_row = threshold_row = status_row = None
    if pnp:
        for row in _as_list(data.get("smart")):
            if _normalize_pnp(row.get("Instance")) == pnp:
                smart_row = row
        for row in _as_list(data.get("thresholds")):
            if _normalize_pnp(row.get("Instance")) == pnp:
                threshold_row = row
        for row in _as_list(data.get("status")):
            if _normalize_pnp(row.get("Instance")) == pnp:
                status_row = row

    if smart_row and _as_list(smart_row.get("Data")):
        drive.protocol = "ATA"
        drive.attributes = parse_wmi_smart(
            _as_list(smart_row.get("Data")),
            _as_list(threshold_row.get("Data")) if threshold_row else None)
        if status_row is not None:
            drive.smart_passed = not bool(status_row.get("Predict"))
        if reliability and drive.temperature is None:
            drive.temperature = to_int(reliability.get("Temp"))
        fill_from_ata_attributes(drive)
        if drive.media == "-":
            ids = {a.attr_id for a in drive.attributes}
            drive.media = "SSD" if ids & set(SSD_LIFE_ATTRIBUTE_IDS) else "HDD"
        drive.source = "Windows WMI (MSStorageDriver)"
        return True

    if reliability:
        drive.protocol = "STORAGE"
        drive.temperature = to_int(reliability.get("Temp")) or None
        drive.power_on_hours = to_int(reliability.get("Hours"))
        drive.power_cycles = to_int(reliability.get("Starts"))
        wear = to_int(reliability.get("Wear"))
        read_errors = to_int(reliability.get("ReadErr"))
        health = str(reliability.get("Health") or "")
        drive.health = {"Healthy": HEALTH_GOOD, "Warning": HEALTH_CAUTION,
                        "Unhealthy": HEALTH_BAD}.get(health, HEALTH_UNKNOWN)
        if health and health != "Healthy":
            drive.health_reasons.append("Windows reports: " + health)
        if wear is not None and "SSD" in drive.media:
            drive.health_percent = max(0, 100 - wear)
        rows = [
            ("Temperature", drive.temperature,
             drive.temperature_text if drive.temperature else "-"),
            ("Power-On Hours", drive.power_on_hours, fmt_int(drive.power_on_hours)),
            ("Start/Stop Count", drive.power_cycles, fmt_int(drive.power_cycles)),
            ("Read Errors Total", read_errors, fmt_int(read_errors)),
            ("Wear (% used)", wear, "-" if wear is None else "{} %".format(wear)),
        ]
        drive.attributes = [SmartAttribute(None, name, raw_value=value,
                                           raw_text=text)
                            for name, value, text in rows]
        if read_errors:
            drive.attributes[3].status = HEALTH_CAUTION
        drive.source = "Windows Storage reliability counters"
        drive.notes.append("Full S.M.A.R.T. table unavailable for this drive. "
                           "Install smartmontools or run as Administrator.")
        return True
    return False


# --- Linux sysfs fallback -----------------------------------------------------

def linux_parent_disk(device: str) -> Tuple[str, str]:
    """'/dev/sda1' -> ('/dev/sda', 'sda'); 'nvme0n1p2' -> nvme0n1."""
    name = os.path.basename(os.path.realpath(device))
    sys_path = "/sys/class/block/" + name
    if os.path.exists(os.path.join(sys_path, "partition")):
        parent = os.path.basename(os.path.dirname(os.path.realpath(sys_path)))
        return "/dev/" + parent, parent
    return "/dev/" + name, name


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def apply_linux_sysfs(drive: DriveInfo) -> None:
    _dev, name = linux_parent_disk(drive.device)
    base = "/sys/block/" + name
    model = _read_text(base + "/device/model")
    if model:
        drive.model = model
    serial = _read_text(base + "/device/serial")
    if serial:
        drive.serial = serial
    rotational = _read_text(base + "/queue/rotational")
    if name.startswith("nvme"):
        drive.media = "NVMe SSD"
    elif rotational == "0":
        drive.media = "SSD"
    elif rotational == "1":
        drive.media = "HDD"
    sectors = to_int(_read_text(base + "/size"))
    if sectors:
        drive.disk_size = sectors * 512
    patterns = [base + "/device/hwmon/hwmon*/temp1_input",
                base + "/device/hwmon*/temp1_input",
                base + "/device/device/hwmon/hwmon*/temp1_input"]
    for pattern in patterns:
        for path in glob.glob(pattern):
            milli = to_int(_read_text(path))
            if milli:
                drive.temperature = milli // 1000
                break
        if drive.temperature is not None:
            break
    if model or sectors:
        drive.source = "Linux sysfs (no S.M.A.R.T. access)"


# --- Volume enumeration ---------------------------------------------------------

def _windows_volumes() -> List[DriveInfo]:
    drives = []
    kernel32 = ctypes.windll.kernel32
    kernel32.SetErrorMode(0x0001)  # No "insert disk" dialogs for empty readers.
    mask = kernel32.GetLogicalDrives()
    for index, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << index):
            continue
        root = letter + ":\\"
        drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        if drive_type not in (2, 3):  # DRIVE_REMOVABLE, DRIVE_FIXED
            continue
        free_caller = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        free_total = ctypes.c_ulonglong(0)
        ok = kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(root), ctypes.byref(free_caller),
            ctypes.byref(total), ctypes.byref(free_total))
        if not ok:
            continue
        fs_name = ctypes.create_unicode_buffer(64)
        kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), None, 0, None, None, None, fs_name, 64)
        drives.append(DriveInfo(
            key=letter + ":", mount=root, device=letter + ":",
            fs_type=fs_name.value or "-", volume_total=total.value,
            volume_free=free_total.value))
    return drives


def _posix_mount_entries() -> List[Tuple[str, str, str]]:
    entries = []
    if psutil is not None:
        try:
            for part in psutil.disk_partitions(all=False):
                entries.append((part.device, part.mountpoint, part.fstype))
            return entries
        except Exception:
            entries = []
    if os.path.exists("/proc/mounts"):
        for line in (_read_text("/proc/mounts") or "").splitlines():
            fields = line.split()
            if len(fields) >= 3:
                mount = fields[1].replace("\\040", " ")
                entries.append((fields[0], mount, fields[2]))
    else:
        _rc, output = run_command(["mount"], timeout=10)
        for line in output.splitlines():
            found = re.match(r"^(/dev/\S+) on (.+?) \(([\w-]+)", line)
            if found:
                entries.append(found.groups())
    return entries


def _posix_volumes() -> List[DriveInfo]:
    skip_fs = {"squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660",
               "autofs", "devfs", "nullfs"}
    chosen: Dict[str, Tuple[str, str]] = {}
    for device, mount, fs_type in _posix_mount_entries():
        if not device.startswith("/dev/") or device.startswith("/dev/loop"):
            continue
        if fs_type in skip_fs:
            continue
        if IS_MAC and mount.startswith("/System/Volumes/") \
                and mount != "/System/Volumes/Data":
            continue
        previous = chosen.get(device)
        if previous is None or len(mount) < len(previous[0]):
            chosen[device] = (mount, fs_type)
    drives = []
    for device, (mount, fs_type) in sorted(chosen.items(), key=lambda i: i[1][0]):
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        if usage.total <= 0:
            continue
        drives.append(DriveInfo(
            key=mount, mount=mount, device=device, fs_type=fs_type,
            volume_total=usage.total, volume_free=usage.free))
    return drives


def enumerate_volumes() -> List[DriveInfo]:
    try:
        return _windows_volumes() if IS_WINDOWS else _posix_volumes()
    except Exception:
        return []


# --- Simulated drives (Demo mode) ---------------------------------------------

def simulated_drives() -> List[DriveInfo]:
    """Clearly labelled sample data for previewing the UI without hardware."""

    def ata(rows):
        return [SmartAttribute(i, ATA_ATTRIBUTE_NAMES.get(i, "Vendor Specific"),
                               cur, worst, thr, raw, text)
                for i, cur, worst, thr, raw, text in rows]

    ssd = DriveInfo(
        key="C:", mount="C:\\", device="C:", fs_type="NTFS",
        volume_total=999_560_000_000, volume_free=412_330_000_000,
        model="Samsung SSD 870 EVO 1TB  [SIMULATED]", serial="S6PTNM0R000000X",
        firmware="SVT02B6Q", interface="SATA/600 (SATA 3.3)", media="SSD",
        disk_size=1_000_204_886_016, protocol="ATA", smart_passed=True,
        source="Simulated data (Demo mode)", simulated=True)
    ssd.attributes = ata([
        (0x05, 100, 100, 10, 0, "0"),
        (0x09, 98, 98, 0, 6_412, "6,412"),
        (0x0C, 99, 99, 0, 1_187, "1,187"),
        (0xB1, 98, 98, 0, 31, "31"),
        (0xB3, 100, 100, 10, 0, "0"),
        (0xBB, 100, 100, 0, 0, "0"),
        (0xBE, 66, 52, 0, 34, "34 " + DEGREE + "C"),
        (0xC3, 200, 200, 0, 0, "0"),
        (0xC7, 100, 100, 0, 0, "0"),
        (0xEB, 99, 99, 0, 41, "41"),
        (0xF1, 99, 99, 0, 28_934_552_101, "28,934,552,101"),
    ])

    hdd = DriveInfo(
        key="D:", mount="D:\\", device="D:", fs_type="NTFS",
        volume_total=2_000_381_000_000, volume_free=655_120_000_000,
        model="WDC WD20EZAZ-00GGJB0  [SIMULATED]", serial="WD-WX12D10A0000",
        firmware="80.00A80", interface="SATA/600 (SATA 3.1)",
        media="HDD (5400 RPM)", disk_size=2_000_398_934_016, protocol="ATA",
        smart_passed=True, source="Simulated data (Demo mode)", simulated=True)
    hdd.attributes = ata([
        (0x01, 200, 200, 51, 3, "3"),
        (0x03, 177, 172, 21, 4_133, "4,133"),
        (0x04, 99, 99, 0, 1_502, "1,502"),
        (0x05, 199, 199, 140, 16, "16"),
        (0x07, 200, 200, 0, 0, "0"),
        (0x09, 61, 61, 0, 28_811, "28,811"),
        (0x0C, 99, 99, 0, 1_455, "1,455"),
        (0xC1, 191, 191, 0, 27_340, "27,340"),
        (0xC2, 109, 98, 0, 41, "41 " + DEGREE + "C"),
        (0xC4, 199, 199, 0, 16, "16"),
        (0xC5, 200, 200, 0, 3, "3"),
        (0xC6, 100, 253, 0, 0, "0"),
        (0xC7, 200, 200, 0, 0, "0"),
        (0xC8, 100, 253, 0, 0, "0"),
    ])

    nvme = DriveInfo(
        key="F:", mount="F:\\", device="F:", fs_type="exFAT",
        volume_total=1_999_000_000_000, volume_free=1_534_000_000_000,
        model="WD_BLACK SN850X 2000GB  [SIMULATED]", serial="23170K800000",
        firmware="620361WD", interface="NVMe 4.0 x4", media="NVMe SSD",
        disk_size=2_000_398_934_016, protocol="NVME", smart_passed=True,
        source="Simulated data (Demo mode)", simulated=True)
    nvme_values = {
        "critical_warning": 0, "temperature": 47, "available_spare": 100,
        "available_spare_threshold": 10, "percentage_used": 2,
        "data_units_read": 31_884_210, "data_units_written": 24_190_552,
        "host_reads": 402_119_330, "host_writes": 377_000_154,
        "controller_busy_time": 1_022, "power_cycles": 412,
        "power_on_hours": 2_215, "unsafe_shutdowns": 19, "media_errors": 0,
        "num_err_log_entries": 0,
    }
    apply_smartctl_json(nvme, {
        "device": {"protocol": "NVMe"}, "model_name": nvme.model,
        "serial_number": nvme.serial, "firmware_version": nvme.firmware,
        "smart_status": {"passed": True}, "temperature": {"current": 47},
        "power_on_time": {"hours": 2_215}, "power_cycle_count": 412,
        "nvme_smart_health_information_log": nvme_values,
    })
    nvme.interface = "NVMe 4.0 x4"
    nvme.source = "Simulated data (Demo mode)"

    for drive in (ssd, hdd):
        fill_from_ata_attributes(drive)
    for drive in (ssd, hdd, nvme):
        evaluate_health(drive)
    return [ssd, hdd, nvme]


# --- Orchestration --------------------------------------------------------------

class DriveInspector:
    """Collects volume, identity and S.M.A.R.T. data for every drive."""

    def detect(self, demo: bool = False) -> Tuple[List[DriveInfo], List[str]]:
        if demo:
            return simulated_drives(), [
                "DEMO MODE - the drives below are SIMULATED sample data, "
                "not your hardware. Untick 'Demo data' to read real drives."]

        drives = enumerate_volumes()
        notes: List[str] = []
        smartctl = find_smartctl()
        windows_data: Optional[Dict] = None
        windows_queried = False
        smart_cache: Dict[str, Dict] = {}

        for drive in drives:
            got = False
            if smartctl:
                target = self._smartctl_target(drive)
                if target not in smart_cache:
                    _rc, output = run_command(
                        [smartctl, "-a", "-j", target], timeout=25)
                    try:
                        smart_cache[target] = json.loads(output) if output else {}
                    except ValueError:
                        smart_cache[target] = {}
                result = smart_cache[target]
                got = apply_smartctl_json(drive, result)
                if not got:
                    for message in smartctl_messages(result)[:1]:
                        drive.notes.append("smartctl: " + message)
            if not got and IS_WINDOWS:
                if not windows_queried:
                    windows_queried = True
                    windows_data = self._windows_query()
                if windows_data:
                    got = apply_windows_query(drive, windows_data)
            if not got and IS_LINUX:
                apply_linux_sysfs(drive)
            evaluate_health(drive)
            if drive.health == HEALTH_UNKNOWN and not drive.notes:
                drive.notes.append(
                    "S.M.A.R.T. data could not be read for this drive.")

        if not is_elevated():
            notes.append("Not running as {} - S.M.A.R.T. data may be "
                         "limited or unavailable.".format(
                             "Administrator" if IS_WINDOWS else "root"))
        if not smartctl:
            notes.append("Tip: install smartmontools (smartctl) for the full "
                         "S.M.A.R.T. attribute table on every drive type.")
        return drives, notes

    @staticmethod
    def _smartctl_target(drive: DriveInfo) -> str:
        if IS_WINDOWS:
            return drive.key  # smartctl accepts drive letters such as "C:".
        if IS_LINUX:
            return linux_parent_disk(drive.device)[0]
        if IS_MAC:
            _rc, output = run_command(["diskutil", "info", drive.mount], 10)
            found = re.search(r"Part of Whole:\s+(\S+)", output)
            if found:
                return "/dev/" + found.group(1)
        return drive.device

    @staticmethod
    def _windows_query() -> Optional[Dict]:
        _rc, output = run_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             WINDOWS_PS_QUERY], timeout=60)
        try:
            data = json.loads(output.strip()) if output.strip() else None
        except ValueError:
            return None
        return data if isinstance(data, dict) else None


# ===========================================================================
# FEATURE 3 - Theme engine
# ===========================================================================

def _theme(dark: bool, **colors: str) -> Dict[str, str]:
    """Build a full palette; status colors default per light/dark family."""
    if dark:
        defaults = {
            "safe_bg": "#1f8f4e", "safe_fg": "#ffffff",
            "danger_bg": "#c93636", "danger_fg": "#ffffff",
            "caution_bg": "#d99a1e", "caution_fg": "#1d1400",
            "unknown_bg": "#59616d", "unknown_fg": "#f2f4f7",
            "temp_ok": "#2f6fd6", "safe_text": "#5fe08f",
            "danger_text": "#ff7b7b", "caution_text": "#ffc857",
        }
    else:
        defaults = {
            "safe_bg": "#1e9e55", "safe_fg": "#ffffff",
            "danger_bg": "#d23b3b", "danger_fg": "#ffffff",
            "caution_bg": "#f0b429", "caution_fg": "#2a1c00",
            "unknown_bg": "#8a94a3", "unknown_fg": "#ffffff",
            "temp_ok": "#2563eb", "safe_text": "#15803d",
            "danger_text": "#c62828", "caution_text": "#a15c00",
        }
    defaults.update(colors)
    defaults["dark"] = "1" if dark else ""
    return defaults


THEMES: Dict[str, Dict[str, str]] = {
    "Deep Dark": _theme(
        True, bg="#111316", surface="#191c21", surface_alt="#22262d",
        border="#2f343c", text="#e7e9ec", muted="#949ca7", accent="#3d8bfd",
        accent_text="#ffffff", entry="#0d0f12", select_bg="#284a7a",
        select_fg="#ffffff", row_alt="#16191d", heading="#1f2329"),
    "Cyber Blue": _theme(
        True, bg="#06111e", surface="#0b1b2e", surface_alt="#10263f",
        border="#17426b", text="#d8f4ff", muted="#7ea7c4", accent="#00d0ff",
        accent_text="#001521", entry="#040c16", select_bg="#0a5584",
        select_fg="#ffffff", row_alt="#091828", heading="#0e2540",
        safe_bg="#0c9b74", temp_ok="#0a74c9", safe_text="#3cf2b4"),
    "Nord Slate": _theme(
        True, bg="#2e3440", surface="#3b4252", surface_alt="#434c5e",
        border="#4c566a", text="#eceff4", muted="#a5afc0", accent="#88c0d0",
        accent_text="#232831", entry="#272c36", select_bg="#5e81ac",
        select_fg="#ffffff", row_alt="#373e4d", heading="#434c5e",
        safe_bg="#5f8f4e", danger_bg="#bf616a", caution_bg="#ebcb8b",
        caution_fg="#2e3440", temp_ok="#5e81ac", safe_text="#a3be8c",
        danger_text="#e48a92", caution_text="#ebcb8b"),
    "Light Clean": _theme(
        False, bg="#f3f5f8", surface="#ffffff", surface_alt="#eaeef3",
        border="#d3dae2", text="#1b232b", muted="#5d6975", accent="#2563eb",
        accent_text="#ffffff", entry="#ffffff", select_bg="#cfe0ff",
        select_fg="#0b1f44", row_alt="#f7f9fb", heading="#e6ebf0"),
    "Midnight Amber": _theme(
        True, bg="#15110c", surface="#1f1912", surface_alt="#2a2219",
        border="#3d3123", text="#f4eadc", muted="#b6a48c", accent="#f0a43a",
        accent_text="#1a1105", entry="#110d09", select_bg="#6a4a1f",
        select_fg="#fff6e8", row_alt="#1b1610", heading="#2a2219",
        temp_ok="#3f7fbf"),
}
DEFAULT_THEME = "Deep Dark"


def health_colors(palette: Dict[str, str], health: str) -> Tuple[str, str]:
    if health == HEALTH_GOOD:
        return palette["safe_bg"], palette["safe_fg"]
    if health == HEALTH_CAUTION:
        return palette["caution_bg"], palette["caution_fg"]
    if health == HEALTH_BAD:
        return palette["danger_bg"], palette["danger_fg"]
    return palette["unknown_bg"], palette["unknown_fg"]


def temperature_colors(palette: Dict[str, str],
                       celsius: Optional[int]) -> Tuple[str, str]:
    if celsius is None:
        return palette["unknown_bg"], palette["unknown_fg"]
    if celsius >= 60:
        return palette["danger_bg"], palette["danger_fg"]
    if celsius >= 50:
        return palette["caution_bg"], palette["caution_fg"]
    return palette["temp_ok"], "#ffffff"


# ===========================================================================
# Drag and drop (native Windows implementation, no extra packages)
# ===========================================================================

class WindowsFileDrop:
    """Accept files dropped from Explorer via WM_DROPFILES.

    Works when the tool runs elevated (needed for S.M.A.R.T.), where OLE
    based drag-and-drop from a non-elevated Explorer is blocked by Windows.
    """

    WM_DROPFILES = 0x0233
    WM_COPYDATA = 0x004A
    WM_COPYGLOBALDATA = 0x0049
    GWLP_WNDPROC = -4

    def __init__(self, widget, callback: Callable[[List[str]], None]) -> None:
        from ctypes import wintypes

        self._callback = callback
        self._widget = widget
        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        lresult = ctypes.c_ssize_t

        self._proc_type = ctypes.WINFUNCTYPE(
            lresult, wintypes.HWND, wintypes.UINT,
            wintypes.WPARAM, wintypes.LPARAM)
        user32.CallWindowProcW.argtypes = [
            ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
            wintypes.WPARAM, wintypes.LPARAM]
        user32.CallWindowProcW.restype = lresult
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            set_proc = user32.SetWindowLongPtrW
        else:
            set_proc = user32.SetWindowLongW
        set_proc.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        set_proc.restype = ctypes.c_void_p
        shell32.DragQueryFileW.argtypes = [
            ctypes.c_void_p, wintypes.UINT, ctypes.c_wchar_p, wintypes.UINT]
        shell32.DragQueryFileW.restype = wintypes.UINT
        shell32.DragFinish.argtypes = [ctypes.c_void_p]
        shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
        self._user32 = user32
        self._shell32 = shell32

        widget.update_idletasks()
        hwnd = widget.winfo_id()

        def window_proc(h_wnd, message, w_param, l_param):
            if message == self.WM_DROPFILES:
                try:
                    paths = self._read_drop(w_param)
                    widget.after(0, self._callback, paths)
                except Exception:
                    pass
                return 0
            return user32.CallWindowProcW(
                self._old_proc, h_wnd, message, w_param, l_param)

        self._proc = self._proc_type(window_proc)  # Keep a reference (GC).
        shell32.DragAcceptFiles(hwnd, True)
        try:
            change = user32.ChangeWindowMessageFilterEx
            change.argtypes = [wintypes.HWND, wintypes.UINT,
                               wintypes.DWORD, ctypes.c_void_p]
            for msg in (self.WM_DROPFILES, self.WM_COPYDATA,
                        self.WM_COPYGLOBALDATA):
                change(hwnd, msg, 1, None)  # MSGFLT_ALLOW
        except Exception:
            pass
        self._old_proc = set_proc(hwnd, self.GWLP_WNDPROC,
                                  ctypes.cast(self._proc, ctypes.c_void_p))

    def _read_drop(self, h_drop) -> List[str]:
        query = self._shell32.DragQueryFileW
        count = query(h_drop, 0xFFFFFFFF, None, 0)
        paths = []
        for index in range(count):
            length = query(h_drop, index, None, 0)
            buffer = ctypes.create_unicode_buffer(length + 1)
            query(h_drop, index, buffer, length + 1)
            paths.append(buffer.value)
        self._shell32.DragFinish(h_drop)
        return paths


# ===========================================================================
# GUI
# ===========================================================================

def pick_font_family(root, candidates: List[str], fallback: str) -> str:
    available = set(tkfont.families(root))
    for name in candidates:
        if name in available:
            return name
    return tkfont.nametofont(fallback).actual("family")


class DiagnosticApp:
    """Main window: header, notebook with two tabs, status bar."""

    POLL_MS = 40
    MAX_UI_TASKS_PER_TICK = 400

    def __init__(self, root) -> None:
        self.root = root
        self.settings = load_settings()
        theme = str(self.settings.get("theme", DEFAULT_THEME))
        self.theme_name = theme if theme in THEMES else DEFAULT_THEME
        self.palette = THEMES[self.theme_name]

        self.scanner = SecurityScanner()
        self.inspector = DriveInspector()
        self.ui_queue: "queue.Queue[Tuple[Callable, tuple]]" = queue.Queue()

        self.scan_cancel = threading.Event()
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_targets: List[str] = []
        self.scan_started = 0.0
        self.reports: List[FileReport] = []
        self.report_by_item: Dict[str, FileReport] = {}
        self.verdict_state = {
            "kind": "idle",
            "title": "READY TO SCAN",
            "body": "Choose a file or folder, or drag and drop it anywhere "
                    "on this window. You will get a clear SAFE or DANGER "
                    "verdict here.",
            "meta": "Rule-based scanner: disguised executables, malicious "
                    "scripts, macro documents, ransomware commands and more.",
        }

        self.drives: List[DriveInfo] = []
        self.drive_notes: List[str] = []
        self.selected_drive_key: Optional[str] = None
        self.drive_loading = False
        self.chip_widgets: List[Tuple[object, DriveInfo]] = []
        self.dnd_mode = "none"

        self._build_fonts()
        self.style = ttk.Style(root)
        self.style.theme_use("clam")

        self.root.title("{}  v{}".format(APP_NAME, APP_VERSION))
        self.root.geometry("1220x800")
        self.root.minsize(1000, 660)

        self._build_layout()
        self.apply_theme(self.theme_name)
        self._setup_drag_and_drop()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(self.POLL_MS, self._pump_ui_queue)
        self.root.after(200, self.refresh_drives)

    # ------------------------------------------------------------------
    # Infrastructure
    # ------------------------------------------------------------------

    def post(self, func: Callable, *args) -> None:
        """Thread-safe: schedule func(*args) on the Tk main thread."""
        self.ui_queue.put((func, args))

    def _pump_ui_queue(self) -> None:
        for _ in range(self.MAX_UI_TASKS_PER_TICK):
            try:
                func, args = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                func(*args)
            except Exception as exc:  # Never let a UI task kill the loop.
                self.set_status("Internal UI error: {}".format(exc))
        self.root.after(self.POLL_MS, self._pump_ui_queue)

    def _build_fonts(self) -> None:
        ui_family = pick_font_family(
            self.root,
            ["Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Ubuntu",
             "Cantarell", "Noto Sans", "DejaVu Sans"],
            "TkDefaultFont")
        mono_family = pick_font_family(
            self.root,
            ["Cascadia Mono", "Consolas", "Menlo", "JetBrains Mono",
             "DejaVu Sans Mono"],
            "TkFixedFont")
        self.fonts = {
            "base": tkfont.Font(family=ui_family, size=10),
            "bold": tkfont.Font(family=ui_family, size=10, weight="bold"),
            "small": tkfont.Font(family=ui_family, size=9),
            "small_bold": tkfont.Font(family=ui_family, size=9, weight="bold"),
            "app_title": tkfont.Font(family=ui_family, size=15, weight="bold"),
            "section": tkfont.Font(family=ui_family, size=13, weight="bold"),
            "hero": tkfont.Font(family=ui_family, size=21, weight="bold"),
            "verdict_body": tkfont.Font(family=ui_family, size=11),
            "big_value": tkfont.Font(family=ui_family, size=22, weight="bold"),
            "mid_value": tkfont.Font(family=ui_family, size=15, weight="bold"),
            "mono": tkfont.Font(family=mono_family, size=10),
        }
        tkfont.nametofont("TkDefaultFont").configure(family=ui_family, size=10)

    def set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, style="Header.TFrame", padding=(18, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        self.logo_canvas = tk.Canvas(header, width=34, height=34,
                                     highlightthickness=0, bd=0)
        self.logo_canvas.grid(row=0, column=0, rowspan=2, padx=(0, 12))

        title = ttk.Label(header, text=APP_NAME, style="HeaderTitle.TLabel")
        title.grid(row=0, column=1, sticky="w")
        subtitle = ttk.Label(
            header,
            text="File & folder threat scanning  |  Drive S.M.A.R.T. "
                 "health  |  v" + APP_VERSION,
            style="HeaderMuted.TLabel")
        subtitle.grid(row=1, column=1, sticky="w")

        theme_box = ttk.Frame(header, style="Header.TFrame")
        theme_box.grid(row=0, column=2, rowspan=2, sticky="e")
        ttk.Label(theme_box, text="Theme", style="HeaderMuted.TLabel").pack(
            side="left", padx=(0, 8))
        self.theme_var = tk.StringVar(value=self.theme_name)
        self.theme_combo = ttk.Combobox(
            theme_box, textvariable=self.theme_var, values=list(THEMES),
            state="readonly", width=16)
        self.theme_combo.pack(side="left")
        self.theme_combo.bind("<<ComboboxSelected>>", self._on_theme_selected)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=14, pady=(10, 0))

        self.scan_tab = ttk.Frame(self.notebook, padding=14)
        self.drive_tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(self.scan_tab, text="  Security Scanner  ")
        self.notebook.add(self.drive_tab, text="  Drive Health  ")

        self._build_scan_tab(self.scan_tab)
        self._build_drive_tab(self.drive_tab)

        status_bar = ttk.Frame(self.root, style="Status.TFrame", padding=(14, 6))
        status_bar.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        status_bar.columnconfigure(0, weight=1)
        self.status_label = ttk.Label(status_bar, text="Ready.",
                                      style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="w")
        self.privilege_label = ttk.Label(status_bar, style="StatusMuted.TLabel")
        self.privilege_label.grid(row=0, column=1, sticky="e")
        role = "Administrator" if IS_WINDOWS else "root"
        self.privilege_label.configure(
            text="Running as {}".format(role) if is_elevated()
            else "Standard user (run as {} for S.M.A.R.T.)".format(role))

    # ---------------- Scanner tab -----------------------------------------

    def _build_scan_tab(self, tab) -> None:
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        # The Bottom Line verdict card.
        self.verdict_card = tk.Frame(tab, bd=0, highlightthickness=0)
        self.verdict_card.grid(row=0, column=0, sticky="ew")
        self.verdict_card.columnconfigure(1, weight=1)
        self.verdict_icon = tk.Canvas(self.verdict_card, width=76, height=76,
                                      highlightthickness=0, bd=0)
        self.verdict_icon.grid(row=0, column=0, rowspan=3,
                               padx=(22, 18), pady=18, sticky="n")
        self.verdict_kicker = tk.Label(
            self.verdict_card, text="THE BOTTOM LINE",
            font=self.fonts["small_bold"], anchor="w")
        self.verdict_kicker.grid(row=0, column=1, sticky="ew", pady=(16, 0),
                                 padx=(0, 22))
        self.verdict_title = tk.Label(self.verdict_card, font=self.fonts["hero"],
                                      anchor="w", justify="left")
        self.verdict_title.grid(row=1, column=1, sticky="ew", padx=(0, 22))
        self.verdict_body = tk.Label(
            self.verdict_card, font=self.fonts["verdict_body"], anchor="w",
            justify="left", wraplength=900)
        self.verdict_body.grid(row=2, column=1, sticky="ew", padx=(0, 22))
        self.verdict_meta = tk.Label(
            self.verdict_card, font=self.fonts["small"], anchor="w",
            justify="left", wraplength=900)
        self.verdict_meta.grid(row=3, column=1, sticky="ew",
                               padx=(0, 22), pady=(6, 16))
        self.verdict_card.bind("<Configure>", self._on_verdict_resize)

        # Action row.
        actions = ttk.Frame(tab)
        actions.grid(row=1, column=0, sticky="ew", pady=(12, 8))
        actions.columnconfigure(3, weight=1)
        self.scan_file_btn = ttk.Button(
            actions, text="Scan File...", style="Accent.TButton",
            command=self.choose_file)
        self.scan_file_btn.grid(row=0, column=0, padx=(0, 8))
        self.scan_folder_btn = ttk.Button(
            actions, text="Scan Folder...", style="Accent.TButton",
            command=self.choose_folder)
        self.scan_folder_btn.grid(row=0, column=1, padx=(0, 8))
        self.cancel_btn = ttk.Button(actions, text="Cancel",
                                     command=self.cancel_scan, state="disabled")
        self.cancel_btn.grid(row=0, column=2)
        self.only_threats_var = tk.BooleanVar(value=False)
        only_threats = ttk.Checkbutton(
            actions, text="Show only DANGER results",
            variable=self.only_threats_var, command=self._rebuild_results)
        only_threats.grid(row=0, column=4, padx=(0, 12))
        self.export_btn = ttk.Button(actions, text="Export Report (CSV)",
                                     command=self.export_csv, state="disabled")
        self.export_btn.grid(row=0, column=5)

        # Drop zone.
        self.drop_zone = tk.Canvas(tab, height=64, highlightthickness=0, bd=0,
                                   cursor="hand2")
        self.drop_zone.grid(row=2, column=0, sticky="ew")
        self.drop_zone.bind("<Configure>", lambda _e: self._draw_drop_zone())
        self.drop_zone.bind("<Button-1>", lambda _e: self.choose_file())
        self.drop_hover = False

        # Progress row.
        progress_row = ttk.Frame(tab)
        progress_row.grid(row=3, column=0, sticky="ew", pady=(10, 8))
        progress_row.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_row, mode="determinate",
                                        style="Scan.Horizontal.TProgressbar")
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress_label = ttk.Label(progress_row, text="Idle",
                                        style="Muted.TLabel", width=46,
                                        anchor="e")
        self.progress_label.grid(row=0, column=1, padx=(12, 0))

        # Results table.
        table_frame = ttk.Frame(tab, style="Card.TFrame")
        table_frame.grid(row=4, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = ("name", "verdict", "rule", "details", "path")
        self.results_tree = ttk.Treeview(table_frame, columns=columns,
                                         show="headings", selectmode="browse")
        headings = {
            "name": ("File Name", 210, "w", False),
            "verdict": ("Verdict", 90, "center", False),
            "rule": ("Triggered Rule", 250, "w", False),
            "details": ("Indicator Details", 380, "w", True),
            "path": ("Full Path", 420, "w", True),
        }
        for column, (text, width, anchor, stretch) in headings.items():
            self.results_tree.heading(column, text=text, anchor=anchor)
            self.results_tree.column(column, width=width, minwidth=70,
                                     anchor=anchor, stretch=stretch)
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self.results_tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal",
                                 command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=y_scroll.set,
                                    xscrollcommand=x_scroll.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.results_tree.bind("<Double-1>", self._show_report_details)
        self.results_tree.bind("<Return>", self._show_report_details)
        self.results_tree.bind("<Button-3>", self._show_results_menu)
        self.results_tree.bind("<Button-2>", self._show_results_menu)

        self.results_menu = tk.Menu(self.root, tearoff=False)
        self.results_menu.add_command(label="View details",
                                      command=self._show_report_details)
        self.results_menu.add_command(label="Copy full path",
                                      command=self._copy_selected_path)
        self.results_menu.add_command(label="Show in folder",
                                      command=self._reveal_selected)

        self.summary_label = ttk.Label(tab, style="Muted.TLabel",
                                       text="No scan has been run yet.")
        self.summary_label.grid(row=5, column=0, sticky="w", pady=(8, 0))

    # ---------------- Drive tab ---------------------------------------------

    def _build_drive_tab(self, tab) -> None:
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        toolbar = ttk.Frame(tab)
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(0, weight=1)
        self.chip_bar = ttk.Frame(toolbar)
        self.chip_bar.grid(row=0, column=0, sticky="w")
        controls = ttk.Frame(toolbar)
        controls.grid(row=0, column=1, sticky="e")
        self.demo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Demo data", variable=self.demo_var,
                        command=self.refresh_drives).pack(side="left", padx=(0, 10))
        self.refresh_btn = ttk.Button(controls, text="Refresh (F5)",
                                      command=self.refresh_drives)
        self.refresh_btn.pack(side="left")

        self.drive_banner = tk.Label(tab, anchor="w", justify="left",
                                     font=self.fonts["small"], padx=12, pady=7)
        self.drive_banner.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.drive_banner.bind(
            "<Configure>",
            lambda e: self.drive_banner.configure(wraplength=max(200, e.width - 30)))

        self.drive_title = ttk.Label(tab, text="Detecting drives...",
                                     style="Section.TLabel")
        self.drive_title.grid(row=2, column=0, sticky="w", pady=(12, 8))

        header = ttk.Frame(tab)
        header.grid(row=3, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        gauges = ttk.Frame(header)
        gauges.grid(row=0, column=0, sticky="ns", padx=(0, 14))
        self.health_box = tk.Frame(gauges, width=214, height=132)
        self.health_box.pack(fill="x")
        self.health_box.pack_propagate(False)
        self.health_caption = tk.Label(self.health_box, text="Health Status",
                                       font=self.fonts["small_bold"])
        self.health_caption.pack(pady=(10, 0))
        self.health_value = tk.Label(self.health_box, text="-",
                                     font=self.fonts["big_value"])
        self.health_value.pack()
        self.health_percent = tk.Label(self.health_box, text="",
                                       font=self.fonts["bold"])
        self.health_percent.pack()
        self.health_reason = tk.Label(self.health_box, text="",
                                      font=self.fonts["small"], wraplength=196,
                                      justify="center")
        self.health_reason.pack(padx=8)

        self.temp_box = tk.Frame(gauges, width=214, height=78)
        self.temp_box.pack(fill="x", pady=(10, 0))
        self.temp_box.pack_propagate(False)
        self.temp_caption = tk.Label(self.temp_box, text="Temperature",
                                     font=self.fonts["small_bold"])
        self.temp_caption.pack(pady=(10, 0))
        self.temp_value = tk.Label(self.temp_box, text="--",
                                   font=self.fonts["mid_value"])
        self.temp_value.pack()

        info = ttk.Frame(header, style="Card.TFrame", padding=(16, 12))
        info.grid(row=0, column=1, sticky="nsew")
        for column in (1, 3):
            info.columnconfigure(column, weight=1)
        fields = [
            ("Firmware", "firmware"), ("Serial Number", "serial"),
            ("Interface", "interface"), ("Media Type", "media"),
            ("Drive / Mount", "mount"), ("File System", "fs"),
            ("Disk Capacity", "disk_size"), ("Volume Size", "volume_total"),
            ("Free Space", "volume_free"), ("Power-On Hours", "hours"),
            ("Power-On Count", "cycles"), ("Data Source", "source"),
        ]
        self.info_values: Dict[str, object] = {}
        for index, (label, key) in enumerate(fields):
            row, column = divmod(index, 2)
            ttk.Label(info, text=label, style="CardMuted.TLabel").grid(
                row=row, column=column * 2, sticky="w", padx=(0, 12), pady=2)
            value = ttk.Label(info, text="-", style="CardValue.TLabel")
            value.grid(row=row, column=column * 2 + 1, sticky="w",
                       padx=(0, 24), pady=2)
            self.info_values[key] = value
        usage_row = len(fields) // 2
        ttk.Label(info, text="Space Used", style="CardMuted.TLabel").grid(
            row=usage_row, column=0, sticky="w", pady=(8, 0))
        self.usage_bar = ttk.Progressbar(info, mode="determinate",
                                         style="Usage.Horizontal.TProgressbar")
        self.usage_bar.grid(row=usage_row, column=1, columnspan=2,
                            sticky="ew", pady=(8, 0))
        self.usage_label = ttk.Label(info, text="", style="CardMuted.TLabel")
        self.usage_label.grid(row=usage_row, column=3, sticky="w",
                              padx=(12, 0), pady=(8, 0))

        table_frame = ttk.Frame(tab, style="Card.TFrame")
        table_frame.grid(row=4, column=0, sticky="nsew", pady=(14, 0))
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = ("id", "name", "current", "worst", "threshold", "raw", "status")
        self.attr_tree = ttk.Treeview(table_frame, columns=columns,
                                      show="headings", selectmode="browse")
        specs = {
            "id": ("ID", 60, "center", False),
            "name": ("Attribute Name", 290, "w", True),
            "current": ("Current", 90, "center", False),
            "worst": ("Worst", 90, "center", False),
            "threshold": ("Threshold", 100, "center", False),
            "raw": ("Raw Value", 230, "e", False),
            "status": ("Status", 110, "center", False),
        }
        for column, (text, width, anchor, stretch) in specs.items():
            self.attr_tree.heading(column, text=text, anchor=anchor)
            self.attr_tree.column(column, width=width, minwidth=50,
                                  anchor=anchor, stretch=stretch)
        attr_scroll = ttk.Scrollbar(table_frame, orient="vertical",
                                    command=self.attr_tree.yview)
        self.attr_tree.configure(yscrollcommand=attr_scroll.set)
        self.attr_tree.grid(row=0, column=0, sticky="nsew")
        attr_scroll.grid(row=0, column=1, sticky="ns")

    # ------------------------------------------------------------------
    # Theme engine
    # ------------------------------------------------------------------

    def _on_theme_selected(self, _event=None) -> None:
        name = self.theme_var.get()
        if name in THEMES:
            self.apply_theme(name)
            self.settings["theme"] = name
            save_settings(self.settings)
            self.set_status("Theme changed to {}.".format(name))

    def apply_theme(self, name: str) -> None:
        self.theme_name = name
        p = self.palette = THEMES[name]
        style = self.style
        accent_hover = blend(p["accent"], "#ffffff", 0.15)
        accent_press = blend(p["accent"], "#000000", 0.18)

        self.root.configure(bg=p["bg"])
        style.configure(
            ".", background=p["bg"], foreground=p["text"],
            fieldbackground=p["entry"], bordercolor=p["border"],
            darkcolor=p["surface"], lightcolor=p["surface"],
            troughcolor=p["surface_alt"], focuscolor=p["accent"],
            selectbackground=p["select_bg"], selectforeground=p["select_fg"],
            insertcolor=p["text"], font=self.fonts["base"])
        style.configure("TFrame", background=p["bg"])
        style.configure("Card.TFrame", background=p["surface"])
        style.configure("Header.TFrame", background=p["surface"])
        style.configure("Status.TFrame", background=p["surface"])

        style.configure("TLabel", background=p["bg"], foreground=p["text"])
        style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
        style.configure("Section.TLabel", background=p["bg"],
                        foreground=p["text"], font=self.fonts["section"])
        style.configure("CardMuted.TLabel", background=p["surface"],
                        foreground=p["muted"])
        style.configure("CardValue.TLabel", background=p["surface"],
                        foreground=p["text"], font=self.fonts["bold"])
        style.configure("HeaderTitle.TLabel", background=p["surface"],
                        foreground=p["text"], font=self.fonts["app_title"])
        style.configure("HeaderMuted.TLabel", background=p["surface"],
                        foreground=p["muted"])
        style.configure("Status.TLabel", background=p["surface"],
                        foreground=p["text"], font=self.fonts["small"])
        style.configure("StatusMuted.TLabel", background=p["surface"],
                        foreground=p["muted"], font=self.fonts["small"])

        style.configure("TButton", background=p["surface_alt"],
                        foreground=p["text"], bordercolor=p["border"],
                        lightcolor=p["surface_alt"], darkcolor=p["surface_alt"],
                        padding=(14, 7), relief="flat", focusthickness=0)
        style.map("TButton",
                  background=[("disabled", p["surface"]),
                              ("pressed", p["select_bg"]),
                              ("active", p["border"])],
                  foreground=[("disabled", p["muted"])],
                  bordercolor=[("focus", p["accent"])])
        style.configure("Accent.TButton", background=p["accent"],
                        foreground=p["accent_text"], bordercolor=p["accent"],
                        lightcolor=p["accent"], darkcolor=p["accent"],
                        font=self.fonts["bold"])
        style.map("Accent.TButton",
                  background=[("disabled", p["surface_alt"]),
                              ("pressed", accent_press),
                              ("active", accent_hover)],
                  foreground=[("disabled", p["muted"])],
                  lightcolor=[("active", accent_hover)],
                  darkcolor=[("active", accent_hover)])

        style.configure("TCheckbutton", background=p["bg"], foreground=p["text"],
                        indicatorbackground=p["entry"],
                        indicatorforeground=p["accent_text"],
                        indicatormargin=(0, 0, 6, 0), focusthickness=0)
        style.map("TCheckbutton",
                  background=[("active", p["bg"])],
                  indicatorbackground=[("selected", p["accent"]),
                                       ("active", p["surface_alt"])])

        style.configure("TCombobox", fieldbackground=p["entry"],
                        background=p["surface_alt"], foreground=p["text"],
                        arrowcolor=p["text"], bordercolor=p["border"],
                        lightcolor=p["entry"], darkcolor=p["entry"],
                        padding=(6, 4))
        style.map("TCombobox",
                  fieldbackground=[("readonly", p["entry"])],
                  foreground=[("readonly", p["text"])],
                  selectbackground=[("readonly", p["entry"])],
                  selectforeground=[("readonly", p["text"])],
                  bordercolor=[("focus", p["accent"])])
        self.root.option_add("*TCombobox*Listbox.background", p["entry"])
        self.root.option_add("*TCombobox*Listbox.foreground", p["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", p["select_bg"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", p["select_fg"])
        try:
            popdown = self.root.tk.eval(
                "ttk::combobox::PopdownWindow {}".format(self.theme_combo))
            self.root.tk.call(
                popdown + ".f.l", "configure", "-background", p["entry"],
                "-foreground", p["text"], "-selectbackground", p["select_bg"],
                "-selectforeground", p["select_fg"])
        except tk.TclError:
            pass

        style.configure("TNotebook", background=p["bg"], bordercolor=p["border"],
                        tabmargins=(0, 0, 0, 0), lightcolor=p["bg"],
                        darkcolor=p["bg"])
        style.configure("TNotebook.Tab", background=p["surface"],
                        foreground=p["muted"], padding=(18, 9),
                        bordercolor=p["border"], lightcolor=p["surface"],
                        darkcolor=p["surface"], font=self.fonts["bold"])
        style.map("TNotebook.Tab",
                  background=[("selected", p["bg"]), ("active", p["surface_alt"])],
                  foreground=[("selected", p["accent"]), ("active", p["text"])],
                  lightcolor=[("selected", p["accent"])],
                  expand=[("selected", (0, 0, 0, 0))])

        style.configure("Treeview", background=p["surface"],
                        fieldbackground=p["surface"], foreground=p["text"],
                        bordercolor=p["border"], lightcolor=p["surface"],
                        darkcolor=p["surface"], rowheight=27,
                        font=self.fonts["base"])
        style.map("Treeview",
                  background=[("selected", p["select_bg"])],
                  foreground=[("selected", p["select_fg"])])
        style.configure("Treeview.Heading", background=p["heading"],
                        foreground=p["text"], bordercolor=p["border"],
                        lightcolor=p["heading"], darkcolor=p["heading"],
                        relief="flat", padding=(8, 6), font=self.fonts["bold"])
        style.map("Treeview.Heading",
                  background=[("active", p["surface_alt"])])

        for orient in ("Vertical", "Horizontal"):
            style.configure("{}.TScrollbar".format(orient),
                            background=p["surface_alt"], troughcolor=p["surface"],
                            bordercolor=p["surface"], arrowcolor=p["muted"],
                            lightcolor=p["surface_alt"], darkcolor=p["surface_alt"],
                            gripcount=0)
            style.map("{}.TScrollbar".format(orient),
                      background=[("active", p["border"])])

        style.configure("Scan.Horizontal.TProgressbar", background=p["accent"],
                        troughcolor=p["surface_alt"], bordercolor=p["surface_alt"],
                        lightcolor=p["accent"], darkcolor=p["accent"],
                        thickness=8)
        style.configure("Usage.Horizontal.TProgressbar", background=p["accent"],
                        troughcolor=p["surface_alt"], bordercolor=p["surface_alt"],
                        lightcolor=p["accent"], darkcolor=p["accent"],
                        thickness=10)

        self.results_menu.configure(
            bg=p["surface"], fg=p["text"], activebackground=p["select_bg"],
            activeforeground=p["select_fg"], bd=0)

        self._style_tree_tags()
        self._draw_logo()
        self._render_verdict()
        self._draw_drop_zone()
        self._render_drive_banner()
        self._render_chips()
        self._render_drive_header()

    def _style_tree_tags(self) -> None:
        p = self.palette
        tree = self.results_tree
        tree.tag_configure("odd", background=p["row_alt"])
        tree.tag_configure("even", background=p["surface"])
        tree.tag_configure("danger", background=blend(p["surface"],
                                                      p["danger_bg"], 0.28),
                           foreground=p["text"])
        tree.tag_configure("skipped", foreground=p["muted"])
        tree.tag_configure("safe_text", foreground=p["text"])

        attrs = self.attr_tree
        attrs.tag_configure("odd", background=p["row_alt"])
        attrs.tag_configure("even", background=p["surface"])
        attrs.tag_configure(HEALTH_CAUTION, background=blend(
            p["surface"], p["caution_bg"], 0.30), foreground=p["text"])
        attrs.tag_configure(HEALTH_BAD, background=blend(
            p["surface"], p["danger_bg"], 0.32), foreground=p["text"])

    def _draw_logo(self) -> None:
        p = self.palette
        canvas = self.logo_canvas
        canvas.configure(bg=p["surface"])
        canvas.delete("all")
        canvas.create_polygon(17, 2, 31, 7, 30, 19, 17, 32, 4, 19, 3, 7,
                              fill=p["accent"], outline="")
        canvas.create_line(11, 17, 15, 22, 24, 11, fill=p["accent_text"],
                           width=3, capstyle="round", joinstyle="round")

    # ------------------------------------------------------------------
    # Verdict card
    # ------------------------------------------------------------------

    def _verdict_colors(self, kind: str) -> Tuple[str, str]:
        p = self.palette
        return {
            "idle": (p["surface_alt"], p["text"]),
            "scanning": (p["accent"], p["accent_text"]),
            "safe": (p["safe_bg"], p["safe_fg"]),
            "danger": (p["danger_bg"], p["danger_fg"]),
            "warning": (p["caution_bg"], p["caution_fg"]),
        }.get(kind, (p["surface_alt"], p["text"]))

    def set_verdict(self, kind: str, title: str, body: str, meta: str) -> None:
        self.verdict_state = {"kind": kind, "title": title,
                              "body": body, "meta": meta}
        self._render_verdict()

    def _render_verdict(self) -> None:
        state = self.verdict_state
        bg, fg = self._verdict_colors(state["kind"])
        muted = blend(fg, bg, 0.25)
        self.verdict_card.configure(bg=bg)
        self.verdict_kicker.configure(bg=bg, fg=muted)
        self.verdict_title.configure(bg=bg, fg=fg, text=state["title"])
        self.verdict_body.configure(bg=bg, fg=fg, text=state["body"])
        self.verdict_meta.configure(bg=bg, fg=muted, text=state["meta"])
        self._draw_verdict_icon(state["kind"], bg, fg)

    def _draw_verdict_icon(self, kind: str, bg: str, fg: str) -> None:
        canvas = self.verdict_icon
        canvas.configure(bg=bg)
        canvas.delete("all")
        canvas.create_oval(5, 5, 71, 71, outline=fg, width=4)
        if kind == "safe":
            canvas.create_line(22, 39, 33, 50, 54, 27, fill=fg, width=7,
                               capstyle="round", joinstyle="round")
        elif kind in ("danger", "warning"):
            canvas.create_line(38, 19, 38, 44, fill=fg, width=8,
                               capstyle="round")
            canvas.create_oval(33, 51, 43, 61, fill=fg, outline=fg)
        elif kind == "scanning":
            canvas.create_arc(15, 15, 61, 61, start=90, extent=270,
                              style="arc", outline=fg, width=6)
        else:
            canvas.create_text(38, 39, text="?", fill=fg, font=self.fonts["hero"])

    def _on_verdict_resize(self, event) -> None:
        wrap = max(300, event.width - 160)
        self.verdict_body.configure(wraplength=wrap)
        self.verdict_meta.configure(wraplength=wrap)

    # ------------------------------------------------------------------
    # Drop zone and drag-and-drop
    # ------------------------------------------------------------------

    def _draw_drop_zone(self) -> None:
        p = self.palette
        canvas = self.drop_zone
        width = max(canvas.winfo_width(), 200)
        height = max(canvas.winfo_height(), 40)
        outline = p["accent"] if self.drop_hover else p["border"]
        fill = blend(p["bg"], p["accent"], 0.12) if self.drop_hover else p["bg"]
        canvas.configure(bg=p["bg"])
        canvas.delete("all")
        canvas.create_rectangle(2, 2, width - 3, height - 3, outline=outline,
                                width=2, dash=(7, 5), fill=fill)
        if self.dnd_mode == "none":
            text = ("Click here to choose a file. Drag-and-drop needs the "
                    "optional package:  pip install tkinterdnd2")
        else:
            text = ("Drag & drop files or folders anywhere on this window "
                    "(or click here to browse)")
        canvas.create_text(width // 2, height // 2, text=text,
                           fill=p["accent"] if self.drop_hover else p["muted"],
                           font=self.fonts["bold"])

    def _setup_drag_and_drop(self) -> None:
        if IS_WINDOWS:
            try:
                self._win_drop = WindowsFileDrop(self.root, self.handle_drop)
                self.dnd_mode = "windows"
            except Exception:
                self.dnd_mode = "none"
        if self.dnd_mode == "none" and DND_FILES is not None \
                and hasattr(self.root, "drop_target_register"):
            try:
                for widget in (self.root, self.drop_zone, self.results_tree,
                               self.verdict_card, self.scan_tab):
                    widget.drop_target_register(DND_FILES)
                    widget.dnd_bind("<<Drop>>", self._on_tkdnd_drop)
                    widget.dnd_bind("<<DropEnter>>", self._on_drop_enter)
                    widget.dnd_bind("<<DropLeave>>", self._on_drop_leave)
                self.dnd_mode = "tkdnd"
            except Exception:
                self.dnd_mode = "none"
        self._draw_drop_zone()

    def _on_drop_enter(self, event):
        self.drop_hover = True
        self._draw_drop_zone()
        return event.action

    def _on_drop_leave(self, event):
        self.drop_hover = False
        self._draw_drop_zone()
        return event.action

    def _on_tkdnd_drop(self, event):
        self.drop_hover = False
        self._draw_drop_zone()
        self.handle_drop(list(self.root.tk.splitlist(event.data)))
        return event.action

    def handle_drop(self, paths: List[str]) -> None:
        paths = [p for p in paths if p]
        if not paths:
            return
        self.notebook.select(self.scan_tab)
        self.start_scan(paths)

    # ------------------------------------------------------------------
    # Scanning workflow
    # ------------------------------------------------------------------

    def choose_file(self) -> None:
        if self._scan_running():
            return
        paths = filedialog.askopenfilenames(title="Select file(s) to scan")
        if paths:
            self.start_scan(list(paths))

    def choose_folder(self) -> None:
        if self._scan_running():
            return
        path = filedialog.askdirectory(title="Select a folder to scan",
                                       mustexist=True)
        if path:
            self.start_scan([path])

    def _scan_running(self) -> bool:
        return self.scan_thread is not None and self.scan_thread.is_alive()

    def start_scan(self, targets: List[str]) -> None:
        if self._scan_running():
            messagebox.showinfo(APP_NAME, "A scan is already running.")
            return
        targets = [os.path.abspath(t) for t in targets]
        self.scan_targets = targets
        self.reports = []
        self.report_by_item.clear()
        self.results_tree.delete(*self.results_tree.get_children())
        self.scan_cancel.clear()
        self.scan_started = time.time()

        label = targets[0] if len(targets) == 1 else \
            "{} selected items".format(len(targets))
        self.set_verdict("scanning", "SCANNING...",
                         "Inspecting: {}".format(label),
                         "Please wait. The verdict will appear here when the "
                         "scan finishes.")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.progress_label.configure(text="Collecting files...")
        self._set_scan_controls(running=True)
        self.set_status("Scanning {}".format(label))

        self.scan_thread = threading.Thread(
            target=self._scan_worker, args=(targets,), daemon=True)
        self.scan_thread.start()

    def _set_scan_controls(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.scan_file_btn.configure(state=state)
        self.scan_folder_btn.configure(state=state)
        self.cancel_btn.configure(state="normal" if running else "disabled")
        self.export_btn.configure(
            state="normal" if (not running and self.reports) else "disabled")

    def _scan_worker(self, targets: List[str]) -> None:
        errors: List[str] = []
        files: List[str] = []
        last_update = 0.0
        for path in iter_files(targets, self.scan_cancel, errors):
            files.append(path)
            now = time.time()
            if now - last_update > 0.15:
                last_update = now
                self.post(self.progress_label.configure,
                          {"text": "Collecting files... {:,}".format(len(files))})
        total = len(files)
        self.post(self._begin_determinate, total)
        for index, path in enumerate(files, start=1):
            if self.scan_cancel.is_set():
                break
            report = self.scanner.scan_file(path)
            self.post(self._add_report, report)
            now = time.time()
            if now - last_update > 0.1 or index == total:
                last_update = now
                self.post(self._update_progress, index, total, path)
        self.post(self._finish_scan, total, errors)

    def _begin_determinate(self, total: int) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(total, 1), value=0)

    def _update_progress(self, index: int, total: int, path: str) -> None:
        self.progress.configure(value=index)
        name = os.path.basename(path)
        if len(name) > 28:
            name = name[:25] + "..."
        self.progress_label.configure(
            text="{:,} / {:,} files   {}".format(index, total, name))

    def _add_report(self, report: FileReport) -> None:
        self.reports.append(report)
        if self.only_threats_var.get() and report.verdict != VERDICT_DANGER:
            return
        self._insert_report_row(report)

    def _insert_report_row(self, report: FileReport) -> None:
        index = len(self.report_by_item)
        tags = ["odd" if index % 2 else "even"]
        if report.verdict == VERDICT_DANGER:
            tags = ["danger"]
        elif report.verdict == VERDICT_SKIPPED:
            tags.append("skipped")
        verdict_text = {VERDICT_DANGER: "DANGER", VERDICT_SAFE: "SAFE"}.get(
            report.verdict, "SKIPPED")
        values = (report.name, verdict_text, report.rule_text,
                  report.details_text, report.path)
        position = 0 if report.verdict == VERDICT_DANGER else "end"
        item = self.results_tree.insert("", position, values=values,
                                        tags=tuple(tags))
        self.report_by_item[item] = report

    def _rebuild_results(self) -> None:
        self.results_tree.delete(*self.results_tree.get_children())
        self.report_by_item.clear()
        ordered = sorted(self.reports,
                         key=lambda r: r.verdict != VERDICT_DANGER)
        for report in reversed(ordered):
            if self.only_threats_var.get() and report.verdict != VERDICT_DANGER:
                continue
            self._insert_report_row(report)

    def cancel_scan(self) -> None:
        if self._scan_running():
            self.scan_cancel.set()
            self.cancel_btn.configure(state="disabled")
            self.set_status("Cancelling scan...")

    def _finish_scan(self, total: int, errors: List[str]) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=max(total, 1),
                                value=len(self.reports))
        cancelled = self.scan_cancel.is_set()
        elapsed = time.time() - self.scan_started
        danger = [r for r in self.reports if r.verdict == VERDICT_DANGER]
        skipped = [r for r in self.reports if r.verdict == VERDICT_SKIPPED]
        checked = len(self.reports) - len(skipped)
        self._set_scan_controls(running=False)

        single_file = (len(self.scan_targets) == 1
                       and os.path.isfile(self.scan_targets[0]))
        noun = "file" if single_file else "folder"
        if len(self.scan_targets) > 1:
            noun = "selection"

        if danger:
            self._show_danger_verdict(danger, single_file, noun, cancelled)
        elif cancelled:
            self.set_verdict(
                "warning", "SCAN CANCELLED - RESULT INCOMPLETE",
                "{:,} of {:,} files were checked before the scan was stopped. "
                "No threats were found in those files, but the rest were not "
                "inspected.".format(len(self.reports), total),
                "Run the scan again to get a complete verdict.")
        elif total == 0:
            self.set_verdict(
                "idle", "NOTHING TO SCAN",
                "The selected location contains no readable files.",
                "Empty folders, links and system devices are not scanned.")
        elif checked == 0:
            self.set_verdict(
                "warning", "UNABLE TO VERIFY",
                "None of the selected files could be read, so no verdict can "
                "be given. Check permissions or run the tool elevated.",
                skipped[0].note if skipped else "")
        else:
            target_text = "This file is" if single_file else \
                "This {} is".format(noun)
            body = ("No threat rule matched in {:,} scanned file{}. {} clean "
                    "and safe to open.").format(
                        checked, "" if checked == 1 else "s", target_text)
            if skipped:
                body += (" Note: {:,} file(s) could not be read and were not "
                         "checked.".format(len(skipped)))
            self.set_verdict(
                "safe", "SAFE - CLEAN AND SAFE TO OPEN", body,
                "Rule-based heuristic scan. Keep your antivirus enabled for "
                "full real-time protection.")

        self.summary_label.configure(text=(
            "Scanned: {:,}   |   DANGER: {:,}   |   Not readable: {:,}   |   "
            "Folder errors: {:,}   |   Time: {:.1f} s{}").format(
                len(self.reports), len(danger), len(skipped), len(errors),
                elapsed, "   |   CANCELLED" if cancelled else ""))
        self.progress_label.configure(
            text="Done - {:,} file(s) in {:.1f} s".format(len(self.reports), elapsed))
        self.set_status("Scan finished: {} threat(s) found.".format(len(danger)))
        if danger and self.results_tree.get_children():
            first = self.results_tree.get_children()[0]
            self.results_tree.selection_set(first)
            self.results_tree.see(first)

    def _show_danger_verdict(self, danger: List[FileReport], single_file: bool,
                             noun: str, cancelled: bool) -> None:
        first = danger[0]
        hit = first.hits[0] if first.hits else None
        if single_file and hit:
            title = "DANGER - DO NOT OPEN THIS FILE"
            body = ("Rule triggered: {}.   Detected pattern: {}.   {}"
                    .format(hit.title, hit.indicator, hit.explanation))
            if len(first.hits) > 1:
                body += "   ({} more rule(s) also matched.)".format(
                    len(first.hits) - 1)
        else:
            title = "DANGER - DO NOT OPEN THIS {}".format(noun.upper())
            lines = ["{:,} file(s) matched threat rules.".format(len(danger))]
            for report in danger[:3]:
                top = report.hits[0] if report.hits else None
                if top:
                    indicator = top.indicator
                    if len(indicator) > 60:
                        indicator = indicator[:57] + "..."
                    lines.append("- {}: {} [{}]".format(
                        report.name, top.title, indicator))
            if len(danger) > 3:
                lines.append("- ...and {:,} more (see table below)".format(
                    len(danger) - 3))
            body = "\n".join(lines)
        meta = ("Do NOT open, run or extract the flagged item(s). Delete or "
                "quarantine them and run a full antivirus scan.")
        if cancelled:
            meta += "  (Scan was cancelled - other files may also be unsafe.)"
        self.set_verdict("danger", title, body, meta)

    # ------------------------------------------------------------------
    # Results table actions
    # ------------------------------------------------------------------

    def _selected_report(self) -> Optional[FileReport]:
        selection = self.results_tree.selection()
        return self.report_by_item.get(selection[0]) if selection else None

    def _show_results_menu(self, event) -> None:
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.results_menu.tk_popup(event.x_root, event.y_root)

    def _copy_selected_path(self) -> None:
        report = self._selected_report()
        if report:
            self.root.clipboard_clear()
            self.root.clipboard_append(report.path)
            self.set_status("Path copied to clipboard.")

    def _reveal_selected(self) -> None:
        report = self._selected_report()
        if not report:
            return
        try:
            if IS_WINDOWS:
                subprocess.Popen(["explorer", "/select,", os.path.normpath(report.path)])
            elif IS_MAC:
                subprocess.Popen(["open", "-R", report.path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(report.path)])
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Could not open folder: {}".format(exc))

    def _show_report_details(self, _event=None) -> None:
        report = self._selected_report()
        if not report:
            return
        p = self.palette
        lines = [
            "File      : " + report.name,
            "Path      : " + report.path,
            "Size      : " + human_bytes(report.size),
            "Verdict   : " + report.verdict,
            "",
        ]
        if report.hits:
            for number, hit in enumerate(report.hits, start=1):
                lines += [
                    "[{}] {}  ({})".format(number, hit.title, hit.rule_id),
                    "    Indicator : " + hit.indicator,
                    "    Why       : " + hit.explanation,
                    "",
                ]
        else:
            lines.append(report.note or "No threat indicators found.")
        text = "\n".join(lines)

        window = tk.Toplevel(self.root)
        window.title("Scan details - " + report.name)
        window.configure(bg=p["bg"])
        window.geometry("820x420")
        window.transient(self.root)
        box = tk.Text(window, wrap="word", font=self.fonts["mono"], bd=0,
                      bg=p["surface"], fg=p["text"], insertbackground=p["text"],
                      selectbackground=p["select_bg"], padx=14, pady=12,
                      highlightthickness=0)
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=12, pady=(12, 6))
        buttons = ttk.Frame(window)
        buttons.pack(fill="x", padx=12, pady=(0, 12))

        def copy_text() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        ttk.Button(buttons, text="Copy", command=copy_text).pack(
            side="right", padx=(0, 8))

    def export_csv(self) -> None:
        if not self.reports:
            return
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Export scan report", defaultextension=".csv",
            initialfile="scan_report_{}.csv".format(stamp),
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            write_csv_report(path, self.reports)
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Export failed: {}".format(exc))
            return
        self.set_status("Report exported to {}".format(path))

    # ------------------------------------------------------------------
    # Drive health workflow
    # ------------------------------------------------------------------

    def refresh_drives(self) -> None:
        if self.drive_loading:
            return
        self.drive_loading = True
        self.refresh_btn.configure(state="disabled")
        self.drive_title.configure(text="Detecting drives and reading "
                                        "S.M.A.R.T. data...")
        self.set_status("Reading drive information...")
        demo = self.demo_var.get()
        threading.Thread(target=self._drive_worker, args=(demo,),
                         daemon=True).start()

    def _drive_worker(self, demo: bool) -> None:
        try:
            drives, notes = self.inspector.detect(demo=demo)
        except Exception as exc:
            drives, notes = [], ["Drive detection failed: {}".format(exc)]
        self.post(self._drives_loaded, drives, notes)

    def _drives_loaded(self, drives: List[DriveInfo], notes: List[str]) -> None:
        self.drive_loading = False
        self.refresh_btn.configure(state="normal")
        self.drives = drives
        self.drive_notes = notes
        keys = [d.key for d in drives]
        if self.selected_drive_key not in keys:
            self.selected_drive_key = keys[0] if keys else None
        self._render_drive_banner()
        self._render_chips()
        self._render_drive_header()
        flagged = [d for d in drives if d.health in (HEALTH_CAUTION, HEALTH_BAD)]
        self.set_status("{} drive(s) detected{}.".format(
            len(drives),
            ", {} need attention".format(len(flagged)) if flagged else ""))

    def _selected_drive(self) -> Optional[DriveInfo]:
        for drive in self.drives:
            if drive.key == self.selected_drive_key:
                return drive
        return None

    def select_drive(self, key: str) -> None:
        self.selected_drive_key = key
        self._render_chips()
        self._render_drive_header()

    def _render_drive_banner(self) -> None:
        p = self.palette
        drive = self._selected_drive()
        messages = list(self.drive_notes)
        if drive:
            messages += drive.notes
        if not messages:
            self.drive_banner.grid_remove()
            return
        demo = drive is not None and drive.simulated
        bg = p["accent"] if demo else blend(p["bg"], p["caution_bg"], 0.85)
        fg = p["accent_text"] if demo else p["caution_fg"]
        self.drive_banner.configure(text="   ".join(messages), bg=bg, fg=fg)
        self.drive_banner.grid()

    def _render_chips(self) -> None:
        p = self.palette
        for child in self.chip_bar.winfo_children():
            child.destroy()
        self.chip_widgets = []
        if not self.drives:
            ttk.Label(self.chip_bar, text="No drives detected yet.",
                      style="Muted.TLabel").pack(side="left")
            return
        for drive in self.drives:
            selected = drive.key == self.selected_drive_key
            dot_color = health_colors(p, drive.health)[0]
            bg = p["surface_alt"] if selected else p["surface"]
            border = p["accent"] if selected else p["border"]
            chip = tk.Frame(self.chip_bar, bg=bg, highlightthickness=2,
                            highlightbackground=border, highlightcolor=border,
                            cursor="hand2", padx=10, pady=6)
            chip.pack(side="left", padx=(0, 8))
            dot = tk.Canvas(chip, width=14, height=14, bg=bg,
                            highlightthickness=0, bd=0)
            dot.create_oval(1, 1, 13, 13, fill=dot_color, outline="")
            dot.grid(row=0, column=0, rowspan=2, padx=(0, 8))
            top = tk.Label(chip, bg=bg, fg=p["text"], font=self.fonts["small_bold"],
                           text="{}  {}".format(drive.health, drive.temperature_text))
            top.grid(row=0, column=1, sticky="w")
            name = drive.key if IS_WINDOWS or drive.simulated else drive.mount
            if len(name) > 18:
                name = "..." + name[-15:]
            bottom = tk.Label(chip, bg=bg,
                              fg=p["accent"] if selected else p["muted"],
                              font=self.fonts["bold"],
                              text="Drive " + name)
            bottom.grid(row=1, column=1, sticky="w")
            for widget in (chip, dot, top, bottom):
                widget.bind("<Button-1>",
                            lambda _e, key=drive.key: self.select_drive(key))
            self.chip_widgets.append((chip, drive))

    def _render_drive_header(self) -> None:
        p = self.palette
        drive = self._selected_drive()
        for widget in (self.health_box, self.temp_box):
            widget.configure(bg=p["unknown_bg"])

        if drive is None:
            if not self.drive_loading:
                self.drive_title.configure(text="No drives detected.")
            self._paint_box(self.health_box, p["unknown_bg"], p["unknown_fg"])
            self._paint_box(self.temp_box, p["unknown_bg"], p["unknown_fg"])
            self.health_value.configure(text="-")
            self.health_percent.configure(text="")
            self.health_reason.configure(text="")
            self.temp_value.configure(text="--")
            self.attr_tree.delete(*self.attr_tree.get_children())
            return

        self.drive_title.configure(text="{}   -   {}".format(
            drive.model, human_bytes(drive.disk_size or drive.volume_total)))
        bg, fg = health_colors(p, drive.health)
        self._paint_box(self.health_box, bg, fg)
        self.health_value.configure(text=drive.health)
        percent = "{} %".format(drive.health_percent) \
            if drive.health_percent is not None else ""
        self.health_percent.configure(text=percent)
        reason = ""
        if drive.health in (HEALTH_CAUTION, HEALTH_BAD) and drive.health_reasons:
            reason = drive.health_reasons[0]
            if len(drive.health_reasons) > 1:
                reason += "  (+{} more)".format(len(drive.health_reasons) - 1)
        self.health_reason.configure(text=reason)

        t_bg, t_fg = temperature_colors(p, drive.temperature)
        self._paint_box(self.temp_box, t_bg, t_fg)
        self.temp_value.configure(text=drive.temperature_text)

        used_pct = 0.0
        if drive.volume_total:
            used = drive.volume_total - (drive.volume_free or 0)
            used_pct = 100.0 * used / drive.volume_total
        free_text = human_bytes(drive.volume_free)
        if drive.volume_total and drive.volume_free is not None:
            free_text += "  ({:.1f} %)".format(
                100.0 * drive.volume_free / drive.volume_total)
        values = {
            "firmware": drive.firmware, "serial": drive.serial,
            "interface": drive.interface, "media": drive.media,
            "mount": drive.mount, "fs": drive.fs_type or "-",
            "disk_size": human_bytes(drive.disk_size),
            "volume_total": human_bytes(drive.volume_total),
            "volume_free": free_text,
            "hours": "-" if drive.power_on_hours is None
            else "{:,} hours".format(drive.power_on_hours),
            "cycles": "-" if drive.power_cycles is None
            else "{:,} count".format(drive.power_cycles),
            "source": drive.source,
        }
        for key, value in values.items():
            text = str(value)
            if len(text) > 44:
                text = text[:41] + "..."
            self.info_values[key].configure(text=text)
        self.usage_bar.configure(value=used_pct)
        self.usage_label.configure(text="{:.1f} % used".format(used_pct))
        self._render_drive_banner()

        tree = self.attr_tree
        tree.delete(*tree.get_children())
        if not drive.attributes:
            tree.insert("", "end", values=(
                "--", "S.M.A.R.T. attributes unavailable for this drive",
                "-", "-", "-", "-", "-"), tags=("odd",))
            return
        for index, attr in enumerate(drive.attributes):
            tags = ["odd" if index % 2 else "even"]
            if attr.status in (HEALTH_CAUTION, HEALTH_BAD):
                tags = [attr.status]
            status_text = {"OK": "OK", HEALTH_CAUTION: "CAUTION",
                           HEALTH_BAD: "BAD"}.get(attr.status, attr.status)
            tree.insert("", "end", tags=tuple(tags), values=(
                attr.id_text, attr.name,
                "-" if attr.current is None else attr.current,
                "-" if attr.worst is None else attr.worst,
                "-" if attr.threshold is None else attr.threshold,
                attr.raw_text or fmt_int(attr.raw_value), status_text))

    @staticmethod
    def _paint_box(box, bg: str, fg: str) -> None:
        box.configure(bg=bg)
        for child in box.winfo_children():
            child.configure(bg=bg, fg=fg)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _bind_shortcuts(self) -> None:
        self.root.bind("<Control-o>", lambda _e: self.choose_file())
        self.root.bind("<Control-O>", lambda _e: self.choose_folder())
        self.root.bind("<Escape>", lambda _e: self.cancel_scan())
        self.root.bind("<F5>", lambda _e: self.refresh_drives())

    def _on_close(self) -> None:
        self.scan_cancel.set()
        self.root.destroy()


def write_csv_report(path: str, reports: List[FileReport]) -> None:
    """CSV export; cells are protected against spreadsheet formula injection."""

    def safe(value: str) -> str:
        value = str(value)
        if value[:1] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + value
        return value

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["File Name", "Verdict", "Triggered Rule",
                         "Indicator Details", "Full Path"])
        for report in reports:
            writer.writerow([safe(report.name), report.verdict,
                             safe(report.rule_text), safe(report.details_text),
                             safe(report.path)])


# ===========================================================================
# Command line modes
# ===========================================================================

def cli_scan(paths: List[str]) -> int:
    scanner = SecurityScanner()
    cancel = threading.Event()
    errors: List[str] = []
    danger = 0
    total = 0
    for path in iter_files(paths, cancel, errors):
        total += 1
        report = scanner.scan_file(path)
        if report.verdict == VERDICT_DANGER:
            danger += 1
        print("{:<8} {} | {} | {}".format(report.verdict, report.path,
                                          report.rule_text, report.details_text))
    print("-" * 72)
    if danger:
        print("BOTTOM LINE: DANGER - {} of {} file(s) matched threat rules. "
              "Do NOT open them.".format(danger, total))
        return 2
    print("BOTTOM LINE: SAFE - no threat rule matched in {} file(s).".format(total))
    return 0


def cli_drives(demo: bool) -> int:
    drives, notes = DriveInspector().detect(demo=demo)
    for note in notes:
        print("NOTE:", note)
    for drive in drives:
        print("=" * 72)
        print("{}  {}  [{}]".format(drive.key, drive.model, drive.health_label))
        print("  Temperature: {}   Power-on: {} h   Cycles: {}   Source: {}"
              .format(drive.temperature_text, fmt_int(drive.power_on_hours),
                      fmt_int(drive.power_cycles), drive.source))
        print("  Volume: {} total, {} free".format(
            human_bytes(drive.volume_total), human_bytes(drive.volume_free)))
        for reason in drive.health_reasons:
            print("  ! " + reason)
        for note in drive.notes:
            print("  NOTE: " + note)
        for attr in drive.attributes:
            print("  {:>2}  {:<34} {:>5} {:>5} {:>5}  {:<24} {}".format(
                attr.id_text, attr.name[:34],
                "-" if attr.current is None else attr.current,
                "-" if attr.worst is None else attr.worst,
                "-" if attr.threshold is None else attr.threshold,
                (attr.raw_text or "-").replace(DEGREE, " deg ")[:24],
                attr.status))
    if not drives:
        print("No drives detected.")
    return 0


def enable_windows_dpi_awareness() -> None:
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--scan", nargs="+", metavar="PATH",
                        help="scan files/folders in the console and exit")
    parser.add_argument("--drives", action="store_true",
                        help="print the drive health report and exit")
    parser.add_argument("--demo", action="store_true",
                        help="use simulated drives with --drives")
    args = parser.parse_args(argv)

    # Legacy console code pages cannot print every file name; never crash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    if args.scan:
        return cli_scan(args.scan)
    if args.drives:
        return cli_drives(args.demo)

    if tk is None:
        print("Tkinter is not available in this Python installation. "
              "Install the Tk component, or use --scan / --drives.")
        return 1

    enable_windows_dpi_awareness()
    if TkinterDnD is not None and not IS_WINDOWS:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    DiagnosticApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
