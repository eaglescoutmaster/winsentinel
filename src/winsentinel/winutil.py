"""Small read-only Windows helpers: registry reads, command-line parsing, path heuristics."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil

try:
    import winreg
except ImportError:  # not Windows: registry helpers return their defaults, callers stay importable
    winreg = None

HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else "HKLM"
HKCU = winreg.HKEY_CURRENT_USER if winreg else "HKCU"
_VIEW = {64: winreg.KEY_WOW64_64KEY, 32: winreg.KEY_WOW64_32KEY} if winreg else {64: 0, 32: 0}
ROOT_NAME = {HKLM: "HKLM", HKCU: "HKCU"}


def _open(root, path: str, view: int):
    if winreg is None:
        raise OSError("no registry on this operating system")
    return winreg.OpenKey(root, path, 0, winreg.KEY_READ | _VIEW[view])


def reg_get(root, path: str, name: str, default=None, view: int = 64):
    try:
        with _open(root, path, view) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def reg_values(root, path: str, view: int = 64) -> dict[str, object]:
    out: dict[str, object] = {}
    try:
        with _open(root, path, view) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = val
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(root, path: str, view: int = 64) -> list[str]:
    out: list[str] = []
    try:
        with _open(root, path, view) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


_EXE_EXT = (".exe", ".com", ".scr", ".bat", ".cmd", ".dll", ".sys", ".ps1", ".vbs", ".js", ".msi", ".cpl")
_SYSDIRS = [
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"),
    os.environ.get("SystemRoot", r"C:\Windows"),
]


def _resolve(candidate: str) -> str | None:
    c = os.path.expandvars(candidate.strip().strip('"'))
    if c.lower().startswith("\\??\\"):
        c = c[4:]
    if c.lower().startswith("\\systemroot\\"):
        c = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), c[12:])
    if c.lower().startswith("system32\\"):
        c = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), c)
    tries = [c] if os.path.splitext(c)[1] else [c, c + ".exe"]
    for t in tries:
        if os.path.isabs(t):
            if os.path.isfile(t):
                return os.path.normpath(t)
        else:
            for d in _SYSDIRS:
                p = os.path.join(d, t)
                if os.path.isfile(p):
                    return os.path.normpath(p)
            if "\\" not in t and "/" not in t:
                w = shutil.which(t)
                if w:
                    return os.path.normpath(w)
    return None


def exe_from_command(cmd: str) -> tuple[str | None, str]:
    """Best-effort: return (resolved executable path or None, remaining arguments)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return None, ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 0:
            return _resolve(cmd[1:end]), cmd[end + 1 :].strip()
    # Unquoted: try progressively longer space-separated prefixes ("C:\Program Files\x\y.exe -arg").
    parts = cmd.split(" ")
    for i in range(1, len(parts) + 1):
        cand = " ".join(parts[:i])
        r = _resolve(cand)
        if r and (i == len(parts) or os.path.splitext(r)[1].lower() in _EXE_EXT):
            return r, " ".join(parts[i:]).strip()
    return None, cmd


def unresolved_target(cmd: str) -> str:
    """The path a command appears to name, for 'target missing' reporting."""
    cmd = os.path.expandvars((cmd or "").strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd
    m = re.match(r"(?i)^(.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|com|sys))(?:\s|$)", cmd)
    return m.group(1) if m else cmd.split(" ")[0]


_WRITABLE_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\",
    "\\desktop\\", "\\documents\\", "\\$recycle.bin\\",
)


def in_user_writable(path: str) -> bool:
    """Heuristic: location a standard user can normally write to."""
    if path.startswith("/"):
        from .osinfo import posix_user_writable

        return posix_user_writable(path)
    p = path.lower().replace("/", "\\")
    return any(m in p for m in _WRITABLE_MARKERS)


SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe",
    "regasm.exe", "regsvcs.exe", "conhost.exe", "forfiles.exe", "wmic.exe",
}


def is_script_host(path: str | None) -> bool:
    return bool(path) and os.path.basename(path).lower() in SCRIPT_HOSTS


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    return ip.is_global
