"""Running processes and network posture: signatures, listeners, outbound connections, hosts, DNS, proxy."""
from __future__ import annotations

import os
import re
import subprocess

from ..findings import ModuleResult
from ..pshelper import PSError, check_signatures, ps_json
from ..textrules import SCRIPT_RULES, scan_text
from ..winutil import HKCU, in_user_writable, is_public_ip, is_script_host, reg_get

NAME = "processes"
DESCRIPTION = "Unsigned/masquerading processes, listening ports, outbound connections, hosts file, DNS, proxy"
ORDER = 30

_PROCS = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine"
_TCP = ("Get-NetTCPConnection -State Listen,Established -ErrorAction SilentlyContinue | "
        "Select-Object @{n='State';e={\"$($_.State)\"}},LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess")
_DNS = ("Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,@{n='Servers';e={@($_.ServerAddresses)}}")

# System process names and the only directory they legitimately run from.
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe",
                 "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "explorer.exe",
                 "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe", "lsaiso.exe"}
_EXPOSED_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 2375: "Docker API (no TLS)",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis",
    9200: "Elasticsearch", 27017: "MongoDB", 11434: "Ollama API",
}
_HIGH_RISK_EXPOSED = {23, 2375, 6379, 9200, 27017, 5900}
_ODD_REMOTE_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 6697, 9001, 9030, 5555, 8333}
_KNOWN_DNS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
              "208.67.220.220", "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "100.100.100.100"}
_SECURITY_HOSTS = re.compile(
    r"(?i)(microsoft|windowsupdate|windows\.com|defender|msftncsi|kaspersky|malwarebytes|bitdefender|eset|avast|avg\.|"
    r"symantec|norton|mcafee|sophos|trendmicro|virustotal|crowdstrike|github\.com|google\.com|apple\.com|paypal|bank)")


def _processes(ctx, res: ModuleResult) -> dict[int, dict]:
    try:
        rows = ps_json(_PROCS, timeout=120)
    except PSError as e:
        res.note(f"process list unavailable: {e}")
        return {}
    me = os.getpid()
    procs = {int(r["ProcessId"]): r for r in rows if r.get("ProcessId") is not None}
    # Our own PowerShell helpers use -EncodedCommand; do not report ourselves.
    own = {me} | {pid for pid, r in procs.items() if r.get("ParentProcessId") == me}
    parent = procs.get(me, {}).get("ParentProcessId")
    if parent in procs and (procs[parent].get("Name") or "").lower() == "winsentinel.exe":
        own.add(parent)  # console-script launcher
    for r in procs.values():
        if (r.get("ExecutablePath") or "").startswith("\\\\?\\"):
            r["ExecutablePath"] = r["ExecutablePath"][4:]
    visible = {pid: r for pid, r in procs.items() if pid not in own}
    paths = sorted({r["ExecutablePath"] for r in visible.values() if r.get("ExecutablePath")})
    sigs = check_signatures(paths)
    for r in procs.values():
        r["_sig"] = sigs.get(r.get("ExecutablePath") or "", {"status": "Unknown", "signer": "", "os_binary": False})
    res.coverage["processes"] = len(visible)
    res.coverage["processes_without_readable_path"] = sum(1 for r in visible.values() if not r.get("ExecutablePath"))
    if res.coverage["processes_without_readable_path"] and not ctx.admin:
        res.note("not elevated: image paths of protected/system processes are not readable, so they were not signature-checked")
    sysroot = os.environ.get("SystemRoot", r"C:\Windows").lower()
    seen: set[str] = set()
    for pid, r in visible.items():
        path = r.get("ExecutablePath") or ""
        name = (r.get("Name") or "").lower()
        cmd = r.get("CommandLine") or ""
        sig = r["_sig"]
        signals: list[str] = []
        sev = "info"
        if path:
            pl = path.lower()
            if name in _SYSTEM_NAMES and not pl.startswith(sysroot + "\\"):
                signals += [f"system process name {name} running outside {sysroot}", "name/path masquerade"]
                sev = "high"
            if sig["status"] == "NotSigned":
                signals.append("authenticode: unsigned binary")
                sev = max_sev(sev, "medium" if in_user_writable(path) else "low")
                if in_user_writable(path):
                    signals.append("image is in a user-writable location")
            elif sig["status"] in ("HashMismatch", "NotTrusted"):
                signals.append(f"authenticode: {sig['status']}")
                sev = "high" if sig["status"] == "HashMismatch" else max_sev(sev, "medium")
        hits = scan_text(cmd, SCRIPT_RULES) if cmd else []
        if hits:
            signals += [h.signal for h in hits]
            top = min(hits, key=lambda h: ("high", "medium", "low").index(h.rule.severity)).rule.severity
            multi = len({h.rule.category for h in hits}) >= 2
            sev = max_sev(sev, "high" if top == "high" or (multi and top == "medium") else top)
        if sev == "info":
            continue
        key = f"{path.lower()}|{'|'.join(sorted(h.rule.id for h in hits))}"
        if key in seen:
            continue
        seen.add(key)
        res.add(rule_id="PROC-SUSPECT", title=f"Running process: {r.get('Name')}", severity=sev,
                evidence=path or f"pid {pid} ({r.get('Name')})", why="; ".join(signals), confidence=0.6, signals=signals,
                remediation="Identify the program (publisher, install source). If unknown: note the path, end the "
                            "process in Task Manager and scan the file; do not just delete it.",
                details={"path": path, "pid": pid, "command": cmd[:400], "signer": sig["signer"],
                         "key": os.path.basename(path).lower()})
    return procs


_RANK = ["info", "low", "medium", "high", "critical"]


def max_sev(a: str, b: str) -> str:
    return a if _RANK.index(a) >= _RANK.index(b) else b


def _network(ctx, res: ModuleResult, procs: dict[int, dict]) -> None:
    try:
        conns = ps_json(_TCP, timeout=60)
    except PSError as e:
        res.note(f"TCP connections unavailable: {e}")
        return

    def owner(pid):
        r = procs.get(int(pid or 0), {})
        return r.get("Name") or f"pid {pid}", r.get("ExecutablePath") or "", r.get("_sig", {})

    listeners: dict[tuple, dict] = {}
    for c in conns:
        if c.get("State") != "Listen":
            continue
        addr = str(c.get("LocalAddress"))
        if addr.startswith("127.") or addr == "::1":
            continue
        listeners.setdefault((int(c["LocalPort"]), c.get("OwningProcess")), c)
    res.coverage["non_loopback_tcp_listeners"] = len(listeners)
    for (port, pid), c in sorted(listeners.items()):
        name, path, sig = owner(pid)
        svc = _EXPOSED_PORTS.get(port)
        signals = [f"listening on {c.get('LocalAddress')}:{port}"]
        sev = "info"
        if svc:
            sev = "medium" if port in _HIGH_RISK_EXPOSED else "low"
            signals.append(f"well-known service port ({svc}) reachable from the network if the firewall allows it")
        if sig.get("status") == "NotSigned":
            signals.append("authenticode: unsigned binary")
            sev = max_sev(sev, "low")
        res.add(rule_id="NET-LISTEN", title=f"Listening port {port}/tcp ({svc or name})", severity=sev,
                evidence=f"{c.get('LocalAddress')}:{port} <- {name}", why="; ".join(signals), confidence=0.8,
                kind="fact", signals=signals,
                remediation="If the service is not needed on the network, bind it to 127.0.0.1 or block the port in "
                            "Windows Firewall.",
                details={"key": f"{port}|{name.lower()}", "path": path, "pid": pid})
    out_count = 0
    seen: set[tuple] = set()
    for c in conns:
        if c.get("State") != "Established" or not is_public_ip(str(c.get("RemoteAddress"))):
            continue
        out_count += 1
        name, path, sig = owner(c.get("OwningProcess"))
        rport = int(c.get("RemotePort") or 0)
        signals: list[str] = []
        if is_script_host(path):
            signals.append(f"script host/LOLBin {name} holds an internet connection")
        if sig.get("status") == "NotSigned":
            signals.append("authenticode: unsigned binary")
        if rport in _ODD_REMOTE_PORTS:
            signals.append(f"remote port {rport} is commonly used by C2/IRC/Tor/miners")
        if not signals:
            continue
        key = (name.lower(), c.get("RemoteAddress"), rport)
        if key in seen:
            continue
        seen.add(key)
        sev = "medium" if len(signals) >= 2 or is_script_host(path) else "low"
        res.add(rule_id="NET-OUTBOUND", title=f"Outbound connection from {name}", severity=sev,
                evidence=f"{name} -> {c.get('RemoteAddress')}:{rport}", why="; ".join(signals), confidence=0.4,
                signals=signals,
                remediation="Check what the program is and whether the destination is expected (the IP is not looked "
                            "up online by this tool).",
                details={"key": f"{name.lower()}|{rport}", "path": path, "remote_ip": c.get("RemoteAddress"), "remote_port": rport})
    res.coverage["established_internet_connections"] = out_count


def _hosts(res: ModuleResult) -> None:
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        res.note(f"hosts file unreadable: {e}")
        return
    entries = []
    for ln in lines:
        ln = ln.split("#", 1)[0].strip()
        parts = ln.split()
        if len(parts) >= 2:
            entries += [(parts[0], h) for h in parts[1:]]
    res.coverage["hosts_entries"] = len(entries)
    for ip, host in entries:
        if host.lower() in ("localhost", "kubernetes.docker.internal", "host.docker.internal", "gateway.docker.internal"):
            continue
        sensitive = bool(_SECURITY_HOSTS.search(host))
        blocked = ip in ("0.0.0.0", "127.0.0.1", "::1", "::")
        if sensitive:
            res.add(rule_id="NET-HOSTS-REDIRECT", title=f"hosts file overrides {host}", severity="high" if not blocked else "medium",
                    evidence=f"{path} :: {host}", why=f"{host} is forced to {ip}. Malware redirects or blocks update, "
                    "security and login sites this way; licence-crack tools also block vendor hosts.", confidence=0.7, kind="fact",
                    remediation="Remove the line from the hosts file (needs admin) unless you added it.",
                    details={"key": host.lower(), "value": ip, "path": path})
    custom = [h for ip, h in entries if not _SECURITY_HOSTS.search(h)]
    if custom:
        res.add(rule_id="NET-HOSTS-CUSTOM", title=f"hosts file has {len(custom)} custom entries", severity="info",
                evidence=path, why="Inventory: " + ", ".join(sorted(set(custom))[:15]), confidence=0.3, kind="fact",
                details={"key": "custom", "value": ",".join(sorted(set(custom)))[:400]})


def _dns_proxy(res: ModuleResult) -> None:
    try:
        for row in ps_json(_DNS, timeout=30):
            for s in row.get("Servers") or []:
                if is_public_ip(s) and s not in _KNOWN_DNS:
                    res.add(rule_id="NET-DNS", title=f"Unrecognised public DNS server {s}", severity="low",
                            evidence=f"{row.get('InterfaceAlias')} :: {s}",
                            why="Interface uses a public resolver that is not a well-known provider. DNS hijacking "
                                "malware changes this; ISPs and VPNs also set their own.", confidence=0.3, kind="fact",
                            remediation="Compare with your router/ISP/VPN settings.", details={"key": s, "value": s})
    except PSError as e:
        res.note(f"DNS settings unavailable: {e}")
    inet = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = reg_get(HKCU, inet, "ProxyEnable", 0)
    server = reg_get(HKCU, inet, "ProxyServer", "")
    pac = reg_get(HKCU, inet, "AutoConfigURL", "")
    if enabled and server:
        res.add(rule_id="NET-PROXY", title="User proxy is enabled", severity="medium", evidence=f"HKCU\\{inet} :: ProxyServer",
                why=f"All WinINet traffic goes through '{server}'. Expected for corporate/VPN/debugging tools; also "
                    "used by traffic-intercepting malware.", confidence=0.6, kind="fact",
                remediation="Settings > Network & internet > Proxy: turn off if you did not set it.",
                details={"key": "proxy", "value": str(server)})
    if pac:
        res.add(rule_id="NET-PAC", title="Proxy auto-config script is set", severity="medium",
                evidence=f"HKCU\\{inet} :: AutoConfigURL", why=f"Browser traffic can be routed by '{pac}'.",
                confidence=0.6, kind="fact", remediation="Settings > Network & internet > Proxy: remove the script address if unknown.",
                details={"key": "pac", "value": str(pac)})
    try:
        out = subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, timeout=20,
                             stdin=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
        m = re.search(r"Proxy Server\(s\)\s*:\s*(\S+)", out)
        if m:
            res.add(rule_id="NET-WINHTTP-PROXY", title="System (WinHTTP) proxy is set", severity="medium",
                    evidence="netsh winhttp show proxy", why=f"System services send HTTP through '{m.group(1)}'.",
                    confidence=0.6, kind="fact", remediation="Elevated: netsh winhttp reset proxy (only if you did not set it).",
                    details={"key": "winhttp", "value": m.group(1)})
    except (OSError, subprocess.TimeoutExpired):
        res.note("netsh winhttp query failed")


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    procs = _processes(ctx, res)
    _network(ctx, res, procs)
    _hosts(res)
    _dns_proxy(res)
    return res
