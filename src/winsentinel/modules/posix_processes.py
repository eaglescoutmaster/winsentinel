"""Running processes and network exposure on Linux and macOS. Read-only.

Linux reads /proc directly: executables that were deleted after start, run from temporary
directories, are hidden, or borrow a kernel-thread name. macOS uses ps and checks code signatures
of programs outside the system and /Applications. Both list listening sockets and review hosts,
DNS and proxy settings.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..findings import ModuleResult
from ..osinfo import OS, posix_temp_like, posix_user_writable, sh
from ..trust import check_trust

NAME = "processes"
DESCRIPTION = "Processes run from temp/deleted/hidden files or masquerading, listeners, hosts file, DNS, proxy"
ORDER = 30
PLATFORMS = ("linux", "macos")

_KTHREAD = re.compile(r"^\[?(kworker|kthreadd|ksoftirqd|migration|rcu_|kswapd|watchdog|khugepaged|kdevtmpfs)")
_SHELLS = {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat", "python", "python3", "perl", "ruby"}
_RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 139: "NetBIOS", 445: "SMB", 512: "rexec",
                513: "rlogin", 514: "rsh", 2049: "NFS", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
                6379: "Redis", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB", 2375: "Docker API"}
_OWN = os.getpid()


def _linux_procs(res: ModuleResult) -> list[dict]:
    procs, unreadable = [], 0
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == _OWN:
            continue
        base = f"/proc/{d}"
        try:
            with open(f"{base}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            with open(f"{base}/comm", encoding="utf-8", errors="replace") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            exe = ""
            if cmd:  # kernel threads have no cmdline and no exe; a userland process we cannot read is a gap
                unreadable += 1
        try:
            uid = os.stat(base).st_uid
        except OSError:
            uid = -1
        procs.append({"pid": int(d), "comm": comm, "cmd": cmd, "exe": exe, "uid": uid})
    res.coverage["processes"] = len(procs)
    res.coverage["process_paths_unreadable"] = unreadable
    if unreadable:
        res.note(f"{unreadable} processes owned by other users: executable path not readable without root", partial=False)
    return procs


def _macos_procs(res: ModuleResult) -> list[dict]:
    rc, text = sh(["ps", "-axo", "pid=,uid=,comm="], timeout=60)
    procs = []
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and int(parts[0]) != _OWN:
            procs.append({"pid": int(parts[0]), "uid": int(parts[1]) if parts[1].isdigit() else -1,
                          "comm": os.path.basename(parts[2]), "cmd": parts[2], "exe": parts[2] if parts[2].startswith("/") else ""})
    res.coverage["processes"] = len(procs)
    return procs


def _assess(res: ModuleResult, procs: list[dict], trusted: set[str]) -> None:
    cands = []
    for p in procs:
        exe, signals, sev = p["exe"], [], "info"
        deleted = exe.endswith(" (deleted)")
        path = exe[: -len(" (deleted)")] if deleted else exe
        if deleted and not re.search(r"/(memfd:|\.cache/|snap/|flatpak/)", path):
            # Package upgrades also leave "(deleted)" executables behind for long-running services.
            if posix_temp_like(path) or path.startswith("/memfd") or not path.startswith(("/usr/", "/opt/", "/bin/", "/sbin/", "/lib")):
                signals.append("executable was deleted after the process started")
                sev = "high"
            else:
                res.coverage["processes_on_replaced_binaries"] = res.coverage.get("processes_on_replaced_binaries", 0) + 1
        if path.startswith("/memfd:") or "memfd:" in path:
            signals.append("runs from an anonymous in-memory file (memfd)")
            sev = "high"
        if path and posix_temp_like(path):
            signals.append("runs from a world-writable temporary directory")
            sev = "high" if sev == "high" or os.path.basename(path).startswith(".") else "medium"
        if path and os.path.basename(path).startswith("."):
            signals.append("executable is a hidden file")
            sev = max(sev, "medium", key=["info", "low", "medium", "high"].index)
        if OS == "linux" and path and _KTHREAD.match(p["comm"]):
            signals.append(f"userland process named like a kernel thread ({p['comm']})")
            sev = "high"
        if OS == "linux" and p["cmd"].startswith("[") and path:
            signals.append("command line disguised as a kernel thread")
            sev = "high"
        if signals:
            cands.append((p, path, signals, sev))
        elif OS == "macos" and path and not path.startswith(("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/")):
            cands.append((p, path, [], "info"))
    paths = [c[1] for c in cands if c[1] and os.path.isfile(c[1])]
    sigs = check_trust(paths) if paths else {}
    seen: set[tuple] = set()
    for p, path, signals, sev in cands:
        sig = sigs.get(path)
        if sig:
            if sig["status"] == "NotSigned" and OS == "macos":
                signals.append("code signature: unsigned")
                if posix_user_writable(path):
                    sev = max(sev, "medium", key=["info", "low", "medium", "high"].index)
            elif sig["status"] == "HashMismatch":
                signals.append("code signature: broken (file changed after signing)")
                sev = "high"
            elif sig["status"] == "Valid" and (sig["os_binary"] or sig["signer"].lower() in trusted) and len(signals) <= 1 and sev != "high":
                continue
        if not signals:
            continue
        key = (path, tuple(signals))
        if key in seen:
            continue
        seen.add(key)
        res.add(rule_id="PROC-SUSPICIOUS", title=f"Suspicious process: {p['comm']} (pid {p['pid']})", severity=sev,
                evidence=path or p["cmd"][:200], why="; ".join(signals), confidence=0.6 if len(signals) >= 2 else 0.4,
                signals=signals, remediation="Find what started it (parent process, start-up entries) before killing it; "
                "note the path and hash first.", details={"key": path or p["comm"], "path": path if os.path.isfile(path) else "",
                                                          "cmdline": p["cmd"][:300], "uid": p["uid"]})


def _listeners(res: ModuleResult) -> None:
    rows: list[tuple[str, int, str]] = []  # (address, port, process)
    if OS == "linux":
        rc, text = sh(["ss", "-H", "-tulpn"], timeout=30)
        if rc != 0:
            res.note("ss not available: listening sockets not checked")
            return
        for line in text.splitlines():
            f = line.split()
            if len(f) < 5:
                continue
            addr, _, port = f[4].rpartition(":")
            m = re.search(r'users:\(\("([^"]+)"', line)
            if port.isdigit():
                rows.append((addr.strip("[]"), int(port), m.group(1) if m else "?"))
    else:
        rc, text = sh(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=60)
        if rc not in (0, 1):
            res.note("lsof failed: listening sockets not checked")
            return
        for line in text.splitlines()[1:]:
            f = line.split()
            m = re.search(r"(\S+):(\d+)\s+\(LISTEN\)", line)
            if m and f:
                rows.append((m.group(1).strip("[]"), int(m.group(2)), f[0]))
    res.coverage["listening_sockets"] = len(rows)
    exposed = sorted({(a, p, n) for a, p, n in rows if a in ("0.0.0.0", "*", "::", "") or not a.startswith(("127.", "::1", "fe80", "localhost"))})
    for addr, port, name in exposed:
        if port in _RISKY_PORTS:
            res.add(rule_id="NET-RISKY-LISTENER", title=f"{_RISKY_PORTS[port]} listening on all interfaces (port {port})",
                    severity="medium", evidence=f"{addr or '*'}:{port} ({name})", why=f"{_RISKY_PORTS[port]} is reachable "
                    "from the network. It is often unauthenticated or a common attack target.", confidence=0.7, kind="fact",
                    remediation="Bind it to 127.0.0.1, firewall the port, or stop the service if unused.",
                    details={"key": f"{port}|{name}"})
        elif name in _SHELLS:
            res.add(rule_id="NET-SHELL-LISTENER", title=f"{name} is listening on port {port}", severity="high",
                    evidence=f"{addr or '*'}:{port} ({name})", why="A shell or scripting interpreter holding a listening "
                    "socket is how bind shells look. Development servers (python -m http.server) also match.",
                    confidence=0.4, signals=["interpreter holds a listening socket"],
                    remediation="Identify the process (ps -fp <pid>) and stop it if you did not start it.",
                    details={"key": f"{port}|{name}"})
    if exposed:
        res.add(rule_id="NET-LISTENERS", title=f"{len(exposed)} services listen on network interfaces", severity="info",
                evidence="listening sockets", why=", ".join(f"{n}:{p}" for _, p, n in exposed[:40]), confidence=0.9,
                kind="fact", remediation="Close what you do not need.", details={"key": "listeners"})


def _name_resolution(res: ModuleResult) -> None:
    try:
        hosts = Path("/etc/hosts").read_text("utf-8", "replace")
    except OSError:
        hosts = ""
    odd = []
    for line in hosts.splitlines():
        line = line.split("#")[0].strip()
        f = line.split()
        if len(f) < 2 or f[0].startswith(("127.", "::1", "fe80", "ff0", "255.", "0.0.0.0")) or f[0] in ("::",):
            continue
        for name in f[1:]:
            if re.search(r"(?i)(google|microsoft|apple|github|paypal|bank|amazon|update|antivirus|virustotal|"
                         r"kaspersky|malwarebytes|sophos|symantec|eset|windowsupdate|icloud)\.", name):
                odd.append(f"{name} -> {f[0]}")
    if odd:
        res.add(rule_id="NET-HOSTS", title="Hosts file redirects well-known domains", severity="high", evidence="/etc/hosts",
                why="; ".join(odd[:15]) + ". Redirecting vendor, bank or security-update domains is a classic way to "
                "phish or to block updates.", confidence=0.6, signals=[f"hosts entry: {o}" for o in odd[:5]],
                remediation="Remove the entries unless you added them.", details={"key": "hosts", "path": "/etc/hosts"})
    for var in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        v = os.environ.get(var)
        if v:
            res.add(rule_id="NET-PROXY", title=f"Proxy set in environment ({var})", severity="low", evidence=var,
                    why=f"Traffic is sent through {re.sub(r'//[^@/]+@', '//<credentials>@', v)}.", confidence=0.8,
                    kind="fact", remediation="Unset it if you did not configure a proxy.", details={"key": var})
            break
    if OS == "macos":
        rc, text = sh(["scutil", "--proxy"], timeout=20)
        m = re.search(r"(?:HTTPS?Proxy|ProxyAutoConfigURLString)\s*:\s*(\S+)", text)
        if m and re.search(r"(?:HTTPS?Enable|ProxyAutoConfigEnable)\s*:\s*1", text):
            res.add(rule_id="NET-PROXY", title="System proxy is configured", severity="low", evidence="scutil --proxy",
                    why=f"System traffic is sent through {m.group(1)}.", confidence=0.8, kind="fact",
                    remediation="System Settings > Network > Proxies: clear it if you did not set it.", details={"key": "system-proxy"})


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    procs = _linux_procs(res) if OS == "linux" else _macos_procs(res)
    _assess(res, procs, {s.lower() for s in ctx.cfg.trusted_signers})
    _listeners(res)
    _name_resolution(res)
    return res
