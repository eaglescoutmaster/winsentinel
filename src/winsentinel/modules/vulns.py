"""Vulnerabilities: outdated software, dependency CVEs, Windows patch state, vulnerable/unsigned drivers.

Network use (package names and versions only, never file contents): winget
source lookup, osv.dev queries by osv-scanner, Trivy database download, and the
Windows Update search in --full.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from ..findings import ModuleResult
from ..pshelper import PSError, ps_json
from ..toolchain import ToolError
from ..winutil import HKCU, HKLM, reg_get, reg_subkeys, reg_values

NAME = "vulns"
DESCRIPTION = "Outdated apps (winget), dependency CVEs (osv-scanner; Trivy in full), Windows updates, vulnerable/unsigned drivers"
ORDER = 70

_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
# Apps where an old version is a direct attack surface (parses untrusted files or network input).
_SENSITIVE_APP = re.compile(
    r"(?i)chrome|firefox|edge|brave|opera|vivaldi|winrar|7-?zip|python|node\.?js|openjdk|java|\.net|dotnet|tailscale|"
    r"anydesk|teamviewer|putty|openssh|openvpn|wireguard|\bgit\b|vlc|docker|visual studio code|vscode|wsl|"
    r"notepad\+\+|adobe|acrobat|zoom|discord|slack|teams|thunderbird|qbittorrent|steam|foxit|libreoffice|office|"
    r"powershell|curl|keepass|bitwarden|1password|virtualbox|vmware|wireshark|nvidia|filezilla|winscp|obs|ollama")
# Small table of widely exploited client-side bugs: (name regex, fixed-in version, CVE, note).
_KNOWN_EXPLOITED = [
    (re.compile(r"(?i)^winrar"), (7, 13), "CVE-2025-8088", "path traversal exploited in the wild via crafted archives"),
    (re.compile(r"(?i)^7-zip"), (24, 9), "CVE-2025-0411", "Mark-of-the-Web bypass exploited in the wild"),
]
_DRIVERS = "Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,PathName,State,StartMode"
_PNP = ("Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverName -and ($_.IsSigned -eq $false) } | "
        "Select-Object DeviceName,DriverVersion,Manufacturer,InfName")
_HOTFIX = ("Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 "
           "HotFixID,@{n='On';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}")
_WU = r"""
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
foreach ($u in $r.Updates) {
  [pscustomobject]@{ Title=$u.Title; Severity="$($u.MsrcSeverity)"; KB=@($u.KBArticleIDs)
    Cats=@($u.Categories | ForEach-Object { $_.Name }) }
}
"""


def _ver(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s or "")[:4])


def _installed() -> list[dict]:
    apps = {}
    for root, view in ((HKLM, 64), (HKLM, 32), (HKCU, 64)):
        for sub in reg_subkeys(root, _UNINSTALL, view):
            v = reg_values(root, f"{_UNINSTALL}\\{sub}", view)
            name = v.get("DisplayName")
            if isinstance(name, str) and name.strip() and not v.get("SystemComponent"):
                apps[(name, str(v.get("DisplayVersion", "")))] = {
                    "name": name, "version": str(v.get("DisplayVersion", "")), "publisher": str(v.get("Publisher", ""))}
    return list(apps.values())


def parse_winget_table(text: str) -> list[dict]:
    """Parse `winget upgrade` output using the header's column offsets."""
    lines = [ln.rstrip("\r") for ln in text.splitlines()]
    hdr = next((i for i, ln in enumerate(lines) if re.search(r"\bId\s+Version\s+Available\b", ln)), None)
    if hdr is None:
        return []
    h = lines[hdr]
    start = h.index("Name") if "Name" in h else 0
    h = h[start:]
    cols = [h.index(c) for c in ("Id", "Version", "Available")]
    src = h.index("Source") if "Source" in h else None
    rows = []
    for ln in lines[hdr + 2:]:
        ln = ln[start:] if len(ln) > start else ln
        if len(ln) <= cols[2] or re.match(r"^\d+ upgrades? available", ln.strip()) or not ln.strip():
            if re.match(r"^\d+ upgrades? available", ln.strip()):
                break
            continue
        row = {"name": ln[: cols[0]].strip(), "id": ln[cols[0]: cols[1]].strip(), "version": ln[cols[1]: cols[2]].strip(),
               "available": (ln[cols[2]: src] if src else ln[cols[2]:]).strip()}
        if row["id"] and " " not in row["id"] and row["available"]:
            rows.append(row)
    return rows


def _software(ctx, res: ModuleResult) -> None:
    apps = _installed()
    res.coverage["installed_apps"] = len(apps)
    for a in apps:
        for pat, fixed, cve, note in _KNOWN_EXPLOITED:
            v = _ver(a["version"])
            if pat.search(a["name"]) and v and v < fixed:
                res.add(rule_id="VULN-KNOWN-EXPLOITED", title=f"{a['name']} is affected by {cve}", severity="high",
                        evidence=f"{a['name']} {a['version']}", why=f"Installed version {a['version']} is older than "
                        f"{'.'.join(map(str, fixed))}: {note}.", confidence=0.9, kind="fact",
                        remediation="Update the application now (winget upgrade or the vendor installer).",
                        signals=[f"version < {'.'.join(map(str, fixed))}", cve],
                        details={"key": cve, "value": a["version"]})
    winget = shutil.which("winget")
    if not winget:
        res.note("winget not found: outdated-application check skipped")
        return
    try:
        p = subprocess.run([winget, "upgrade", "--include-unknown", "--disable-interactivity", "--accept-source-agreements"],
                           capture_output=True, timeout=240, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        res.note(f"winget upgrade failed: {e}")
        return
    rows = parse_winget_table(p.stdout.decode("utf-8", "replace"))
    res.coverage["apps_with_updates"] = len(rows)
    if not rows and p.returncode != 0:
        res.note(f"winget upgrade returned exit {p.returncode} and no parsable table")
    other, sensitive = [], []
    for r in rows:
        label = f"{r['name']} ({r['version']} -> {r['available']})"
        (sensitive if _SENSITIVE_APP.search(r["name"]) or _SENSITIVE_APP.search(r["id"]) else other).append(label)
    if sensitive:
        res.add(rule_id="VULN-OUTDATED-APP", title=f"{len(sensitive)} outdated applications that handle untrusted input",
                severity="medium", evidence="winget upgrade",
                why="Updates are available for browsers, runtimes, archivers, remote-access and similar software: "
                    + "; ".join(sensitive) + ". Old versions of such software are the usual way known CVEs get "
                    "exploited. (winget reports availability only; it does not say which CVEs each update fixes.)",
                confidence=0.6, kind="fact", remediation="winget upgrade --id <Id> for each, or winget upgrade --all.",
                details={"key": "sensitive", "value": str(len(sensitive)), "apps": sensitive})
    if other:
        res.add(rule_id="VULN-OUTDATED-OTHER", title=f"{len(other)} other applications have updates available", severity="low",
                evidence="winget upgrade", why="; ".join(other[:40]) + ("; ..." if len(other) > 40 else ""), confidence=0.5,
                kind="fact", remediation="winget upgrade --all (review the list first).",
                details={"key": "other", "value": str(len(other))})


def _cvss_sev(score: str) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    return "high" if s >= 7 else "medium" if s >= 4 else "low"


def _osv(ctx, res: ModuleResult, targets: list[Path]) -> set[str]:
    seen_ids: set[str] = set()
    if not ctx.tools.path("osv-scanner"):
        res.note("osv-scanner not installed (winsentinel tools install): dependency CVE check skipped")
        return seen_ids
    scanned = 0
    for t in targets:
        with tempfile.TemporaryDirectory(prefix="ws-osv-") as td:
            out = Path(td) / "osv.json"
            try:
                p = ctx.tools.run("osv-scanner", ["scan", "source", "-r", str(t), "--format", "json", "--output-file", str(out)], timeout=900)
            except ToolError as e:
                res.note(f"osv-scanner failed on {t.name}: {e}")
                continue
            if p.returncode == 128:
                continue  # no lockfiles/manifests found
            # Never trust the exit code alone: parse the report and count.
            if not out.exists():
                res.note(f"osv-scanner produced no report for {t.name} (exit {p.returncode}): {p.stderr.decode('utf-8', 'replace')[-200:]}")
                continue
            try:
                data = json.loads(out.read_text("utf-8"))
            except ValueError:
                res.note(f"osv-scanner report for {t.name} is not valid JSON")
                continue
        scanned += 1
        by_src: dict[str, list] = {}
        for result in data.get("results") or []:
            by_src.setdefault(os.path.normpath((result.get("source") or {}).get("path", str(t))), []).extend(result.get("packages") or [])
        for src, packages in by_src.items():
            pk_rows, worst, n_vulns = [], "low", 0
            for pk in packages:
                ids = [v.get("id") for v in pk.get("vulnerabilities") or [] if v.get("id")]
                if not ids:
                    continue
                seen_ids.update(ids)
                for v in pk.get("vulnerabilities") or []:
                    seen_ids.update(v.get("aliases") or [])
                sev = "low"
                for g in pk.get("groups") or []:
                    s = _cvss_sev(g.get("max_severity"))
                    sev = s if ["low", "medium", "high"].index(s) > ["low", "medium", "high"].index(sev) else sev
                worst = sev if ["low", "medium", "high"].index(sev) > ["low", "medium", "high"].index(worst) else worst
                n_vulns += len(ids)
                info = pk.get("package") or {}
                pk_rows.append((sev, f"{info.get('name')}@{info.get('version')} [{sev}] {', '.join(ids[:3])}"))
            if not pk_rows:
                continue
            pk_rows.sort(key=lambda r: ["high", "medium", "low"].index(r[0]))
            res.add(rule_id="VULN-DEPENDENCY", title=f"{len(pk_rows)} vulnerable dependencies in {Path(src).name}", severity=worst,
                    evidence=src, why=f"{n_vulns} known vulnerabilities (OSV). Worst first: " + "; ".join(r[1] for r in pk_rows[:12])
                    + ("; ..." if len(pk_rows) > 12 else "") + ". Reachability is not analysed: a listed CVE may not be exploitable in this project.",
                    confidence=0.7, kind="fact", signals=["osv-scanner"],
                    remediation="Upgrade the listed packages (start with high severity and with direct dependencies).",
                    details={"key": "osv", "source_file": src, "value": f"{len(pk_rows)}|{n_vulns}",
                             "packages": [r[1] for r in pk_rows[:100]]})
    res.coverage["osv_targets_scanned"] = scanned
    return seen_ids


def _trivy(ctx, res: ModuleResult, targets: list[Path], seen_ids: set[str]) -> None:
    if not ctx.tools.path("trivy"):
        res.note("trivy not installed: skipped")
        return
    cache = ctx.cfg.tools_dir / "trivy-cache"
    for t in targets:
        with tempfile.TemporaryDirectory(prefix="ws-trivy-") as td:
            out = Path(td) / "trivy.json"
            try:
                p = ctx.tools.run("trivy", ["fs", "--scanners", "vuln", "--format", "json", "--quiet", "--cache-dir", str(cache),
                                            "--skip-dirs", "**/node_modules", "--skip-dirs", "**/target", "--skip-dirs", "**/.venv",
                                            "--output", str(out), str(t)], timeout=1800)
                data = json.loads(out.read_text("utf-8")) if out.exists() else None
            except (ToolError, ValueError, OSError) as e:
                res.note(f"trivy failed on {t.name}: {e}")
                continue
            if data is None:
                res.note(f"trivy produced no report for {t.name} (exit {p.returncode}): {p.stderr.decode('utf-8', 'replace')[-200:]}")
                continue
        for r in data.get("Results") or []:
            extra = [v for v in r.get("Vulnerabilities") or [] if v.get("VulnerabilityID") not in seen_ids]
            if not extra:
                continue
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            extra.sort(key=lambda v: order.index(v.get("Severity", "UNKNOWN")) if v.get("Severity") in order else 4)
            top = extra[0].get("Severity", "UNKNOWN")
            sev = "high" if top in ("CRITICAL", "HIGH") else "medium" if top == "MEDIUM" else "low"
            res.add(rule_id="VULN-DEPENDENCY-TRIVY", title=f"{len(extra)} more vulnerabilities in {Path(r.get('Target', '')).name} (Trivy)",
                    severity=sev, evidence=str(t / r.get("Target", "")),
                    why="Found by Trivy and not already reported by osv-scanner: " + "; ".join(
                        f"{v.get('PkgName')}@{v.get('InstalledVersion')} {v.get('VulnerabilityID')} [{v.get('Severity')}]" for v in extra[:12]),
                    confidence=0.7, kind="fact", signals=["trivy"], remediation="Upgrade the listed packages.",
                    details={"key": "trivy", "value": str(len(extra))})
    res.coverage["trivy"] = "run"


def _windows_updates(ctx, res: ModuleResult) -> None:
    try:
        rows = ps_json(_HOTFIX, timeout=90)
        if rows:
            on = datetime.strptime(rows[0]["On"], "%Y-%m-%d")
            age = (datetime.now() - on).days
            res.coverage["last_hotfix"] = f"{rows[0]['HotFixID']} on {rows[0]['On']}"
            if age > 45:
                res.add(rule_id="VULN-WU-STALE", title=f"No Windows update installed for {age} days", severity="medium" if age < 120 else "high",
                        evidence=f"{rows[0]['HotFixID']} installed {rows[0]['On']}",
                        why="Microsoft ships security fixes monthly; the newest installed hotfix is older than that cycle.",
                        confidence=0.7, kind="fact", remediation="Settings > Windows Update > Check for updates.",
                        details={"key": "stale", "value": rows[0]["On"]})
    except (PSError, ValueError, KeyError) as e:
        res.note(f"hotfix history unavailable: {e}")
    if not ctx.full:
        res.coverage["windows_update_search"] = "skipped in quick mode"
        return
    try:
        ups = ps_json(_WU, timeout=600)
    except PSError as e:
        res.note(f"Windows Update search failed: {e}")
        return
    res.coverage["missing_updates"] = len(ups)
    for u in ups:
        cats = " ".join(u.get("Cats") or [])
        security = bool(u.get("Severity")) or "Security" in cats
        sev = "high" if u.get("Severity") in ("Critical", "Important") else "medium" if security else "low"
        res.add(rule_id="VULN-WU-MISSING", title=f"Missing Windows update: {u.get('Title', '')[:90]}", severity=sev,
                evidence="KB" + ",".join(u.get("KB") or ["?"]), why=f"Not installed. MSRC severity: {u.get('Severity') or 'n/a'}; "
                f"categories: {cats or 'n/a'}.", confidence=0.9, kind="fact",
                remediation="Install via Settings > Windows Update.", details={"key": ",".join(u.get("KB") or []) or u.get("Title", ""), "value": u.get("Severity", "")})


def _drivers(ctx, res: ModuleResult) -> None:
    lol: dict[str, str] = {}
    for tool, label in (("loldrivers-malicious", "malicious"), ("loldrivers-vulnerable", "vulnerable")):
        p = ctx.tools.path(tool)
        if p:
            for h in p.read_text("ascii", "replace").split():
                lol.setdefault(h.strip().lower(), label)
    if not lol:
        res.note("LOLDrivers hash lists not installed: vulnerable-driver check skipped")
    try:
        rows = ps_json(_DRIVERS, timeout=120)
    except PSError as e:
        res.note(f"driver list unavailable: {e}")
        rows = []
    hashed = unread = 0
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    for d in rows:
        path = str(d.get("PathName") or "").strip('"')
        if path.lower().startswith("\\??\\"):
            path = path[4:]
        if path.lower().startswith("\\systemroot\\"):
            path = os.path.join(sysroot, path[12:])
        if not path or not lol:
            continue
        try:
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            hashed += 1
        except OSError:
            unread += 1
            continue
        label = lol.get(digest)
        if label:
            running = d.get("State") == "Running"
            res.add(rule_id="VULN-LOLDRIVER", title=f"Known {label} driver installed: {d.get('Name')}",
                    severity="high" if label == "malicious" or running else "medium", evidence=path,
                    why=f"SHA256 {digest} is on the LOLDrivers {label} list. Such drivers give kernel access to any "
                        f"admin-level attacker (BYOVD). State: {d.get('State')}, start mode: {d.get('StartMode')}.",
                    confidence=0.9, kind="fact", signals=[f"loldriver: {label}", f"state {d.get('State')}"],
                    remediation="Update or uninstall the product that installed it; enable the Microsoft vulnerable "
                                "driver blocklist (Windows Security > Device security > Core isolation).",
                    details={"path": path, "sha256": digest, "key": str(d.get("Name")), "value": digest})
    res.coverage["drivers_hashed"] = hashed
    if unread:
        res.note(f"{unread} driver files not readable" + ("" if ctx.admin else " without admin"), partial=False)
    try:
        for d in ps_json(_PNP, timeout=120):
            res.add(rule_id="VULN-DRIVER-UNSIGNED", title=f"Unsigned device driver: {d.get('DeviceName')}", severity="medium",
                    evidence=f"{d.get('InfName')} ({d.get('Manufacturer')})", why=f"Windows reports IsSigned=False for driver "
                    f"version {d.get('DriverVersion')}.", confidence=0.7, kind="fact",
                    remediation="Get a signed driver from the manufacturer or Windows Update.",
                    details={"key": str(d.get("InfName")), "value": str(d.get("DriverVersion"))})
    except PSError as e:
        res.note(f"PnP driver signature query failed: {e}")
    if reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1) == 0:
        res.add(rule_id="VULN-DRIVER-BLOCKLIST-OFF", title="Microsoft vulnerable driver blocklist is disabled", severity="medium",
                evidence=r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config :: VulnerableDriverBlocklistEnable",
                why="Known-vulnerable signed drivers can be loaded to gain kernel access.", confidence=1.0, kind="fact",
                remediation="Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist: On.",
                details={"key": "blocklist", "value": "0"})


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    targets = ctx.paths or [d for d in ctx.cfg.code_dirs if d.is_dir()]
    if not ctx.paths:
        _software(ctx, res)
    seen = _osv(ctx, res, targets)
    if ctx.full:
        _trivy(ctx, res, targets, seen)
    else:
        res.coverage["trivy"] = "skipped in quick mode"
    if not ctx.paths:
        _windows_updates(ctx, res)
        _drivers(ctx, res)
    return res
