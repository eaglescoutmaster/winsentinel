"""Autostart and persistence locations. Inventory + heuristics; nothing is modified."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import ModuleResult
from ..pshelper import PSError, check_signatures, ps_json
from ..textrules import SCRIPT_RULES, read_text, scan_text
from ..winutil import (HKCU, HKLM, ROOT_NAME, exe_from_command, in_user_writable, is_script_host,
                       reg_get, reg_subkeys, reg_values, unresolved_target)

NAME = "persistence"
DESCRIPTION = "Run keys, tasks, services, startup folders, WMI subscriptions, IFEO, AppInit, Winlogon, LSA, browser extensions, PS profiles"
ORDER = 20

_CV = r"Software\Microsoft\Windows\CurrentVersion"
_RUN_KEYS = [f"{_CV}\\Run", f"{_CV}\\RunOnce", f"{_CV}\\RunServices", f"{_CV}\\Policies\\Explorer\\Run"]
_NT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_ACCESSIBILITY = {"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"}


@dataclass
class Entry:
    source: str  # run-key | startup-folder | task | service
    location: str  # registry key / folder / task path
    name: str
    command: str
    extra: dict = field(default_factory=dict)


_TASKS = r"""
foreach ($t in @(Get-ScheduledTask)) {
  foreach ($a in @($t.Actions)) {
    if ($a.Execute) {
      [pscustomobject]@{ Path=$t.TaskPath; Name=$t.TaskName; State="$($t.State)"; Author=$t.Author
        User=$t.Principal.UserId; Execute=$a.Execute; Arguments=$a.Arguments }
    }
  }
}
"""
_SERVICES = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State,StartName"
_LNK = r"""
$sh = New-Object -ComObject WScript.Shell
foreach ($q in @([Console]::In.ReadToEnd() | ConvertFrom-Json)) {
  $p = [string]$q
  try { $l = $sh.CreateShortcut($p); [pscustomobject]@{ path=$p; target=$l.TargetPath; args=$l.Arguments } }
  catch { [pscustomobject]@{ path=$p; target=''; args='' } }
}
"""
_WMI = r"""
$ns = 'root\subscription'
foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer)) {
  [pscustomobject]@{ Class=$c.CimClass.CimClassName; Name=$c.Name
    Command="$($c.CommandLineTemplate)$($c.ExecutablePath)"; Script="$($c.ScriptText)".Substring(0, [Math]::Min(400, "$($c.ScriptText)".Length)) }
}
"""
_PROFILES = r"""
$d = [Environment]::GetFolderPath('MyDocuments')
@("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1",
  "$d\WindowsPowerShell\profile.ps1", "$d\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
  "$d\PowerShell\profile.ps1", "$d\PowerShell\Microsoft.PowerShell_profile.ps1",
  "$env:ProgramFiles\PowerShell\7\profile.ps1") | Where-Object { Test-Path -LiteralPath $_ }
"""


def _collect_run_keys() -> list[Entry]:
    out = []
    for root in (HKLM, HKCU):
        for view in (64, 32):
            if root == HKCU and view == 32:
                continue
            for key in _RUN_KEYS:
                loc = f"{ROOT_NAME[root]}\\{key}" + (" (32-bit)" if view == 32 else "")
                for name, val in reg_values(root, key, view).items():
                    if isinstance(val, str) and val.strip():
                        out.append(Entry("run-key", loc, name or "(default)", val))
    return out


def _collect_startup(res: ModuleResult) -> list[Entry]:
    folders = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    files = [p for f in folders if f.is_dir() for p in f.iterdir() if p.is_file() and p.name.lower() != "desktop.ini"]
    lnks = [str(p) for p in files if p.suffix.lower() == ".lnk"]
    targets: dict[str, tuple[str, str]] = {}
    if lnks:
        try:
            for r in ps_json(_LNK, timeout=60, stdin=json.dumps(lnks)):
                targets[r["path"]] = (r.get("target") or "", r.get("args") or "")
        except PSError as e:
            res.note(f"could not resolve startup shortcuts: {e}")
    out = []
    for p in files:
        t, a = targets.get(str(p), (str(p), ""))
        cmd = f'"{t}" {a}'.strip() if t else str(p)
        out.append(Entry("startup-folder", str(p.parent), p.name, cmd))
    return out


_SCRIPT_EXT = (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta")
_SCRIPT_ARG_RE = re.compile(r'(?i)(?:"([^"]+\.(?:ps1|vbs|vbe|js|jse|wsf|bat|cmd|hta))"|(\S+\.(?:ps1|vbs|vbe|js|jse|wsf|bat|cmd|hta))(?=\s|$))')


def _script_target(exe: str | None, args: str) -> str | None:
    """The script an autostart entry runs: the target itself, or the script passed to a script host."""
    if exe and exe.lower().endswith(_SCRIPT_EXT):
        return exe
    if exe and is_script_host(exe):
        m = _SCRIPT_ARG_RE.search(args or "")
        if m:
            p = os.path.expandvars(m.group(1) or m.group(2))
            if os.path.isfile(p):
                return p
    return None


def _analyse(res: ModuleResult, entries: list[Entry], trusted: set[str]) -> None:
    resolved: dict[int, tuple[str | None, str]] = {i: exe_from_command(e.command) for i, e in enumerate(entries)}
    sigs = check_signatures([p for p, _ in resolved.values() if p])
    quiet = 0
    for i, e in enumerate(entries):
        exe, args = resolved[i]
        sig = sigs.get(exe or "", {"status": "Unknown", "signer": "", "os_binary": False})
        signals: list[str] = []
        sev = "info"
        hits = scan_text(e.command, SCRIPT_RULES)
        script = _script_target(exe, args)
        if script:
            try:
                with open(script, "rb") as fh:
                    hits += scan_text(read_text(fh.read(2_000_000)), SCRIPT_RULES)
            except OSError:
                signals.append("script target is unreadable")
        for h in hits:
            signals.append(h.signal)
        if exe is None:
            target = unresolved_target(e.command)
            # Many built-in tasks use COM handlers or %windir% forms we cannot resolve; only report real paths.
            if e.source in ("run-key", "startup-folder", "service") and target and (":" in target or target.startswith("\\\\")):
                signals.append("target file is missing or unreadable")
                sev = "low"
        else:
            trusted_sig = sig["status"] == "Valid" and (sig["os_binary"] or sig["signer"].lower() in trusted)
            if sig["status"] == "Valid" and not hits and not (is_script_host(exe) and args):
                if trusted_sig:
                    quiet += 1
                    continue
            if sig["status"] == "NotSigned" and not exe.lower().endswith(_SCRIPT_EXT):
                signals.append("authenticode: unsigned binary")
            elif sig["status"] == "NotSigned":
                signals.append("autostart target is a script")
            elif sig["status"] in ("HashMismatch", "NotTrusted"):
                signals.append(f"authenticode: {sig['status']}")
            if in_user_writable(exe):
                signals.append("target is in a user-writable location")
            if is_script_host(exe) and args:
                signals.append(f"runs through script host/LOLBin {os.path.basename(exe)}")
        bad_sig = any(s.startswith("authenticode:") for s in signals)
        if hits:
            top = min(hits, key=lambda h: ("high", "medium", "low").index(h.rule.severity)).rule.severity
            multi = len({h.rule.category for h in hits}) >= 2
            sev = "high" if top == "high" or (multi and top == "medium") else "medium" if multi else top
        elif bad_sig and "target is in a user-writable location" in signals:
            sev = "medium"
        elif bad_sig or (exe and is_script_host(exe) and args and in_user_writable(args)):
            sev = "low"
        if "authenticode: HashMismatch" in signals:
            sev = "high"
        why = "; ".join(signals) if signals else "Autostart entry signed by a third party (inventory)."
        res.add(rule_id=f"PERSIST-{e.source.upper()}", title=f"Autostart ({e.source}): {e.name}", severity=sev,
                evidence=f"{e.location} :: {e.name}", why=why, confidence=0.7 if sev != "info" else 0.3,
                signals=signals,
                remediation="If you do not recognise it, disable it with Task Manager > Startup, Task Scheduler, or "
                            "services.msc and inspect the target file before deleting anything.",
                details={"key": e.name, "command": e.command[:500], "path": script or exe or "",
                         "value": e.command[:500],
                         "signer": sig["signer"], "sig_status": sig["status"], **e.extra})
    res.coverage["trusted_signed_entries_not_listed"] = quiet


def _fact(res, rule, title, sev, evidence, why, fix, value=""):
    res.add(rule_id=rule, title=title, severity=sev, evidence=evidence, why=why, confidence=0.9, kind="fact",
            remediation=fix, details={"key": rule, "value": str(value)[:500]})


def _registry_hijacks(res: ModuleResult) -> None:
    for view in (64, 32):
        tag = " (32-bit)" if view == 32 else ""
        base = f"{_NT}\\Image File Execution Options"
        for sub in reg_subkeys(HKLM, base, view):
            dbg = reg_get(HKLM, f"{base}\\{sub}", "Debugger", view=view)
            if dbg:
                crit = sub.lower() in _ACCESSIBILITY
                _fact(res, "PERSIST-IFEO", f"IFEO debugger set for {sub}", "critical" if crit else "high",
                      f"HKLM\\{base}\\{sub}{tag} :: Debugger",
                      f"Launching {sub} runs '{dbg}' instead."
                      + (" This is the classic accessibility-tool logon backdoor." if crit else ""),
                      "Remove the Debugger value unless a debugging tool you installed set it.", dbg)
        spe = f"{_NT}\\SilentProcessExit"
        for sub in reg_subkeys(HKLM, spe, view):
            mon = reg_get(HKLM, f"{spe}\\{sub}", "MonitorProcess", view=view)
            if mon:
                _fact(res, "PERSIST-SPE", f"SilentProcessExit monitor for {sub}", "high",
                      f"HKLM\\{spe}\\{sub}{tag} :: MonitorProcess", f"'{mon}' runs whenever {sub} exits.",
                      "Remove the key if you did not configure it.", mon)
        win = f"{_NT}\\Windows"
        appinit = reg_get(HKLM, win, "AppInit_DLLs", "", view)
        if isinstance(appinit, str) and appinit.strip():
            on = reg_get(HKLM, win, "LoadAppInit_DLLs", 0, view)
            _fact(res, "PERSIST-APPINIT", "AppInit_DLLs is set", "high" if on else "medium",
                  f"HKLM\\{win}{tag} :: AppInit_DLLs",
                  f"'{appinit}' is loaded into every GUI process (LoadAppInit_DLLs={on}; ignored when Secure Boot is on).",
                  "Clear the value unless a product you trust requires it.", appinit)
    wl = f"{_NT}\\Winlogon"
    shell = str(reg_get(HKLM, wl, "Shell", "") or "")
    if shell.strip().lower() not in ("explorer.exe", ""):
        _fact(res, "PERSIST-WINLOGON-SHELL", "Winlogon Shell is not explorer.exe", "high",
              f"HKLM\\{wl} :: Shell", f"Shell='{shell}'.", "Set back to explorer.exe if unexpected.", shell)
    userinit = str(reg_get(HKLM, wl, "Userinit", "") or "")
    parts = [p.strip().lower() for p in userinit.split(",") if p.strip()]
    if parts and not all(p.endswith("\\system32\\userinit.exe") or p == "userinit.exe" for p in parts):
        _fact(res, "PERSIST-WINLOGON-USERINIT", "Winlogon Userinit has extra programs", "high",
              f"HKLM\\{wl} :: Userinit", f"Userinit='{userinit}'.", "Should be only C:\\Windows\\system32\\userinit.exe,", userinit)
    for name in ("Shell", "Userinit"):
        v = reg_get(HKCU, wl, name)
        if v:
            _fact(res, f"PERSIST-WINLOGON-HKCU-{name}", f"Per-user Winlogon {name} override", "high",
                  f"HKCU\\{wl} :: {name}", f"{name}='{v}' runs at this user's logon.", "Delete the value if unexpected.", v)
    lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
    expected = {"Authentication Packages": {"msv1_0"}, "Notification Packages": {"scecli", "rassfm"},
                "Security Packages": {"", '""', "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap"}}
    for name, ok in expected.items():
        val = reg_get(HKLM, lsa, name, [])
        extra = [v for v in (val if isinstance(val, list) else [val]) if isinstance(v, str) and v.strip().lower() not in ok]
        if extra:
            _fact(res, f"PERSIST-LSA-{name.split()[0].upper()}", f"Non-default LSA {name}", "medium",
                  f"HKLM\\{lsa} :: {name}", f"Extra package(s) loaded into LSASS: {', '.join(extra)}.",
                  "Confirm each belongs to software you installed (VPN, smart card, password filter).", ",".join(extra))
    boot = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute", [])
    extra = [v for v in (boot if isinstance(boot, list) else [boot]) if isinstance(v, str) and v.strip()
             and not v.lower().startswith("autocheck autochk")]
    if extra:
        _fact(res, "PERSIST-BOOTEXECUTE", "Non-default BootExecute entry", "high",
              r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager :: BootExecute",
              f"Runs before Windows starts: {', '.join(extra)}.", "Should normally be only 'autocheck autochk *'.", ",".join(extra))


def _wmi(res: ModuleResult) -> None:
    try:
        rows = ps_json(_WMI, timeout=60)
    except PSError as e:
        res.note("WMI event subscriptions not readable" + (" (needs admin)" if "denied" in str(e).lower() else f": {e}"))
        return
    for r in rows:
        cls = r.get("Class", "")
        if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            payload = r.get("Command") or r.get("Script") or ""
            _fact(res, "PERSIST-WMI", f"WMI {cls}: {r.get('Name')}", "high", f"root\\subscription :: {r.get('Name')}",
                  f"Permanent WMI consumer runs: {payload[:300]}",
                  "Rare on home machines. Inspect with Get-CimInstance -Namespace root\\subscription; remove if unknown.",
                  payload)


_EXT_BROWSERS = {
    "Chrome": "Google/Chrome/User Data", "Edge": "Microsoft/Edge/User Data",
    "Brave": "BraveSoftware/Brave-Browser/User Data",
}
_RISKY_PERMS = {"nativeMessaging", "debugger", "proxy", "webRequestBlocking", "management", "privacy"}
_STORE_HOSTS = ("clients2.google.com", "edge.microsoft.com", "brave.com")


def _browser_extensions(res: ModuleResult) -> None:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    count = 0
    for browser, rel in _EXT_BROWSERS.items():
        root = local / rel
        if not root.is_dir():
            continue
        for manifest in root.glob("*/Extensions/*/*/manifest.json"):
            try:
                m = json.loads(manifest.read_text("utf-8-sig", "replace"))
            except (OSError, ValueError):
                continue
            count += 1
            ext_id = manifest.parts[-3]
            name = str(m.get("name", ext_id))
            if name.startswith("__MSG_"):
                name = f"{ext_id} ({m.get('short_name', name)})"
            perms = {p for p in (m.get("permissions") or []) + (m.get("host_permissions") or []) if isinstance(p, str)}
            hosts_all = bool(perms & {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})
            risky = sorted(perms & _RISKY_PERMS)
            upd = str(m.get("update_url", ""))
            sideloaded = not any(h in upd for h in _STORE_HOSTS)
            signals = []
            if sideloaded:
                signals.append(f"not installed from a browser store (update_url='{upd or 'none'}')")
            if risky:
                signals.append("high-risk permissions: " + ", ".join(risky))
            if hosts_all:
                signals.append("can read and change all sites")
            sev = "medium" if sideloaded and (risky or hosts_all) else "low" if (sideloaded or risky) else "info"
            if sev == "info" and not hosts_all:
                continue
            res.add(rule_id="PERSIST-BROWSER-EXT", title=f"{browser} extension: {name}", severity=sev,
                    evidence=str(manifest.parent), why="; ".join(signals), confidence=0.5, signals=signals,
                    remediation=f"Review in {browser} > Extensions; remove extensions you do not use.",
                    details={"key": ext_id, "version": str(m.get("version", "")), "value": ",".join(sorted(perms))[:300]})
    res.coverage["browser_extensions_seen"] = count


def _ps_profiles(res: ModuleResult) -> None:
    try:
        paths = [p for p in ps_json(_PROFILES, timeout=30) if isinstance(p, str)]
    except PSError as e:
        res.note(f"PowerShell profile lookup failed: {e}")
        return
    for p in paths:
        try:
            text = read_text(Path(p).read_bytes()[:2_000_000])
        except OSError:
            continue
        hits = scan_text(text, SCRIPT_RULES)
        signals = [h.signal for h in hits]
        sev = "info"
        if hits:
            sev = "high" if any(h.rule.severity == "high" for h in hits) or len({h.rule.category for h in hits}) >= 2 else "medium"
        res.add(rule_id="PERSIST-PS-PROFILE", title="PowerShell profile script", severity=sev, evidence=p,
                why="; ".join(signals) or "Profile runs in every PowerShell session (inventory).",
                confidence=0.6 if hits else 0.3, signals=signals,
                remediation="Read the profile; remove lines you did not add.",
                details={"path": p, "key": p.lower(), "lines": [h.line for h in hits][:10]})


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    trusted = {s.lower() for s in ctx.cfg.trusted_signers}
    entries = _collect_run_keys() + _collect_startup(res)
    try:
        for t in ps_json(_TASKS, timeout=180):
            cmd = f"{t.get('Execute') or ''} {t.get('Arguments') or ''}".strip()
            entries.append(Entry("task", f"{t.get('Path')}{t.get('Name')}", t.get("Name") or "", cmd,
                                 {"state": t.get("State"), "author": t.get("Author"), "run_as": t.get("User")}))
    except PSError as e:
        res.note(f"scheduled tasks unavailable: {e}")
    try:
        for s in ps_json(_SERVICES, timeout=120):
            path = s.get("PathName") or ""
            if not path:
                continue
            entries.append(Entry("service", f"services\\{s.get('Name')}", s.get("DisplayName") or s.get("Name") or "", path,
                                 {"start": s.get("StartMode"), "state": s.get("State"), "run_as": s.get("StartName")}))
            # Unquoted path with spaces lets a planted C:\Program.exe hijack the service.
            if not path.startswith('"') and " " in path.split(".exe")[0] and ".exe" in path.lower() \
                    and not path.lower().startswith(os.environ.get("SystemRoot", "C:\\Windows").lower()):
                _fact(res, "PERSIST-SVC-UNQUOTED", f"Unquoted service path: {s.get('Name')}", "medium",
                      f"services\\{s.get('Name')} :: ImagePath", f"ImagePath '{path}' contains spaces and is not quoted.",
                      "Reinstall/update the product or ask the vendor; fixing ImagePath needs admin.", path)
    except PSError as e:
        res.note(f"services unavailable: {e}")
    res.coverage["autostart_entries"] = len(entries)
    _analyse(res, entries, trusted)
    _registry_hijacks(res)
    _wmi(res)
    _browser_extensions(res)
    _ps_profiles(res)
    if not ctx.admin:
        res.note("not elevated: other users' HKCU hives and hidden scheduled tasks are not visible")
    return res
