"""Built-in and installed malware protection on Linux and macOS: is anything watching, and is it current?

macOS: XProtect and Gatekeeper are built in; this reports their state and recent XProtect detections.
Linux: nothing is built in; this reports whether ClamAV is installed and how old its signatures are.
Read-only: no scan is triggered and nothing is changed.
"""
from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from ..findings import ModuleResult
from ..osinfo import OS, sh

NAME = "av"
DESCRIPTION = "Malware protection status: XProtect/Gatekeeper (macOS), ClamAV (Linux)"
ORDER = 10
PLATFORMS = ("linux", "macos")


def _linux(res: ModuleResult) -> None:
    scan = shutil.which("clamscan") or shutil.which("clamdscan")
    if not scan:
        res.add(rule_id="AV-NONE", title="No on-host malware scanner is installed", severity="info", evidence="clamscan not found",
                why="Linux ships no antivirus. winsentinel's file scan is on-demand only; nothing watches files as they arrive.",
                confidence=0.9, kind="fact", remediation="Optional: install ClamAV (and clamav-daemon for on-access "
                "scanning) if this machine handles files from other people.", details={"key": "av-none"})
        return
    res.coverage["clamav"] = scan
    newest = 0.0
    for d in ("/var/lib/clamav", "/usr/local/share/clamav", "/opt/homebrew/var/lib/clamav"):
        try:
            for p in Path(d).iterdir():
                if p.suffix in (".cvd", ".cld"):
                    newest = max(newest, p.stat().st_mtime)
        except OSError:
            continue
    if not newest:
        res.add(rule_id="AV-NO-SIGNATURES", title="ClamAV has no signature database", severity="medium",
                evidence="/var/lib/clamav", why="The scanner is installed but cannot detect anything.", confidence=0.8,
                kind="fact", remediation="sudo freshclam.", details={"key": "clamav-nosig"})
        return
    age = (time.time() - newest) / 86400
    res.coverage["clamav_signature_age_days"] = round(age, 1)
    if age > 7:
        res.add(rule_id="AV-STALE", title=f"ClamAV signatures are {age:.0f} days old", severity="medium" if age > 30 else "low",
                evidence="/var/lib/clamav", why="New malware is not detected until signatures are refreshed.", confidence=0.8,
                kind="fact", remediation="sudo freshclam (and enable clamav-freshclam.service).", details={"key": "clamav-stale"})
    rc, out = sh(["systemctl", "is-active", "clamav-daemon", "clamav-freshclam"], timeout=20)
    res.coverage["clamav_services"] = ", ".join(out.split()) or "unknown"


def _macos(res: ModuleResult) -> None:
    rc, out = sh(["spctl", "--status"], timeout=20)
    res.coverage["gatekeeper"] = out.strip() or "unknown"
    for bundle in ("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
                   "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"):
        rc, ver = sh(["defaults", "read", bundle, "CFBundleShortVersionString"], timeout=20)
        if rc == 0 and ver.strip():
            res.coverage["xprotect_version"] = ver.strip()
            try:
                age = (time.time() - os.stat(bundle).st_mtime) / 86400
                res.coverage["xprotect_age_days"] = round(age, 1)
                if age > 60:
                    res.add(rule_id="AV-STALE", title=f"XProtect definitions are {age:.0f} days old", severity="low",
                            evidence=bundle, why="Apple normally updates XProtect every week or two. Old definitions "
                            "usually mean background security updates are switched off.", confidence=0.6, kind="fact",
                            remediation="System Settings > General > Software Update > Automatic Updates: turn on "
                            "'Install Security Responses and system files'.", details={"key": "xprotect-stale"})
            except OSError:
                pass
            break
    else:
        res.note("XProtect bundle not found: definitions version not checked")
    rc, out = sh(["log", "show", "--last", "7d", "--style", "compact", "--predicate",
                  'subsystem == "com.apple.XProtectFramework.PluginAPI" AND eventMessage CONTAINS[c] "detected"'], timeout=180)
    hits = [x for x in out.splitlines() if re.search(r"(?i)detected|remediat", x) and "Timestamp" not in x]
    res.coverage["xprotect_log_window"] = "7 days"
    if hits:
        res.add(rule_id="AV-DETECTION", title=f"XProtect reported {len(hits)} detections in the last 7 days", severity="high",
                evidence="unified log: com.apple.XProtectFramework.PluginAPI", why="; ".join(h[-200:] for h in hits[:5]),
                confidence=0.7, signals=["defender: built-in malware protection reported a detection"],
                remediation="Read the entries (Console.app, search XProtect) and find where the file came from.",
                details={"key": "xprotect-detections", "count": len(hits)})
    rc, out = sh(["sqlite3", "-readonly", str(Path.home() / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"),
                  "select count(*) from LSQuarantineEvent"], timeout=20)
    if rc == 0 and out.strip().isdigit():
        res.coverage["quarantine_events_recorded"] = int(out.strip())


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    (_linux if OS == "linux" else _macos)(res)
    return res
