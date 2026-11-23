"""Extract indicators (URLs, IPs, domains, hashes) from files other modules flagged.

Offline by default. With --vt and VT_API_KEY set, the SHA256 of each flagged
file (never the file) is looked up on VirusTotal.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request

from ..findings import SEV_RANK, ModuleResult

NAME = "iocs"
DESCRIPTION = "URLs/IPs/domains/hashes from flagged files; offline unless --vt (hash-only VirusTotal lookup)"
ORDER = 100

_MAX_FILE = 16 * 1024 * 1024
_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\)\]}]{4,200}", re.I)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}\b", re.I)
# Things that look like domains but are file names or code identifiers.
_NOT_TLD = {"exe", "dll", "sys", "ps1", "bat", "cmd", "vbs", "js", "json", "xml", "txt", "log", "dat", "tmp", "ini", "cfg",
            "png", "jpg", "gif", "ico", "css", "html", "htm", "py", "pyc", "rs", "ts", "md", "zip", "pdb", "lib", "obj",
            "cpp", "hpp", "yml", "yaml", "toml", "lock", "bin", "manifest", "resources", "config", "min", "map", "h", "c"}
_COMMON_TLD = {"com", "net", "org", "io", "ru", "cn", "info", "biz", "xyz", "top", "tk", "cc", "co", "me", "dev", "app",
               "site", "online", "club", "live", "pw", "su", "to", "ly", "gg", "onion", "uk", "de", "fr", "nl", "br",
               "in", "jp", "kr", "us", "ca", "au", "eu", "tv", "ws", "link", "click", "shop", "cloud", "ai", "sh"}
_BENIGN_HOSTS = re.compile(
    r"(?i)(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|w3\.org|xmlsoap\.org|digicert\.com|verisign\.com|"
    r"globalsign\.com|sectigo\.com|usertrust\.com|godaddy\.com|letsencrypt\.org|openxmlformats\.org|apache\.org|"
    r"mozilla\.org|github\.com|githubusercontent\.com|python\.org|schemas\.android\.com|purl\.org|example\.com|"
    r"thawte\.com|symantec\.com|symcb\.com|symcd\.com|comodoca\.com|entrust\.net|amazontrust\.com|pki\.goog)$")
_DROP_HOSTS = re.compile(
    r"(?i)webhook\.site|requestbin|pipedream\.net|ngrok|discord(?:app)?\.com/api/webhooks|api\.telegram\.org|"
    r"pastebin\.com|transfer\.sh|duckdns\.org|no-ip\.|\.onion\b|anonfiles|gofile\.io|catbox\.moe")


def defang(s: str) -> str:
    return s.replace("http", "hxxp", 1).replace(".", "[.]") if "://" in s else s.replace(".", "[.]")


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Pure function: indicators found in a blob's ASCII and UTF-16LE strings."""
    chunks = [m.group(0).decode("ascii", "replace") for m in _ASCII.finditer(data)]
    chunks += [m.group(0).decode("utf-16-le", "replace") for m in _UTF16.finditer(data)]
    text = "\n".join(chunks)
    urls: dict[str, None] = {}
    hosts_in_urls: set[str] = set()
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:")
        host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split("@")[-1].split(":")[0].lower()
        hosts_in_urls.add(host)
        if not _BENIGN_HOSTS.search(host):
            urls[u] = None
    ips: dict[str, None] = {}
    for m in IP_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        ctx = text[max(0, m.start() - 12): m.start()].lower()
        if ip.is_global and not re.search(r"(version|ver|v|build)[\s:=]*$", ctx) and not m.group(0).startswith(("1.0.", "2.0.", "0.")):
            ips[str(ip)] = None
    domains: dict[str, None] = {}
    for m in DOMAIN_RE.finditer(URL_RE.sub(" ", text)):
        d = m.group(0).lower()
        tld = d.rsplit(".", 1)[-1]
        if tld in _NOT_TLD or tld not in _COMMON_TLD or d in hosts_in_urls or _BENIGN_HOSTS.search(d):
            continue
        if d.count(".") == 1 and len(d.split(".")[0]) < 4:
            continue
        domains[d] = None
    return {"urls": list(urls)[:200], "ips": list(ips)[:200], "domains": list(domains)[:200]}


def vt_lookup(sha256: str, key: str) -> dict:
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                 headers={"x-apikey": key, "User-Agent": "winsentinel"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            attrs = json.loads(r.read())["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        return {"known": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                "engines": sum(st.values()) if st else 0, "name": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")}
    except urllib.error.HTTPError as e:
        return {"known": False} if e.code == 404 else {"error": f"HTTP {e.code}"}
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        return {"error": type(e).__name__}


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    flagged: dict[str, str] = {}
    for name, r in ctx.results.items():
        if name == NAME:
            continue
        for f in r.findings:
            p = f.details.get("path")
            if p and SEV_RANK[f.severity] <= SEV_RANK["medium"] and os.path.isfile(p):
                flagged.setdefault(p, f.title)
    res.coverage["flagged_files"] = len(flagged)
    if not flagged:
        res.notes.append("no flagged files from other modules in this run")
    from ..keys import get as get_key

    key = get_key("virustotal")[0] if ctx.vt else ""
    if ctx.vt and not key:
        res.note("--vt given but no VirusTotal key is set (winsentinel keys set virustotal): lookup skipped")
    res.coverage["virustotal"] = "hash-only lookups enabled" if key else "off (offline)"
    all_iocs = []
    lookups = 0
    for path, title in flagged.items():
        try:
            if os.path.getsize(path) > _MAX_FILE:
                res.note(f"{path}: larger than 16 MB, IOC extraction skipped", partial=False)
                continue
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            res.note(f"{path}: unreadable (quarantined or locked?)", partial=False)
            continue
        digest = hashlib.sha256(data).hexdigest()
        iocs = extract_iocs(data)
        drops = [u for u in iocs["urls"] if _DROP_HOSTS.search(u)] + [d for d in iocs["domains"] if _DROP_HOSTS.search(d)]
        ip_urls = [u for u in iocs["urls"] if re.match(r"(?i)[a-z]+://\d{1,3}(\.\d{1,3}){3}", u)]
        signals = []
        if drops:
            signals.append(f"contacts data-drop/tunnel endpoint ({defang(drops[0])[:80]})")
        if ip_urls:
            signals.append(f"URL with a raw IP address ({defang(ip_urls[0])[:80]})")
        sev = "medium" if len(signals) >= 2 else "low" if signals else "info"
        entry = {"path": path, "sha256": digest, **iocs}
        if key and lookups < 20:
            if lookups:
                time.sleep(16)  # public API: 4 requests/minute
            vt = vt_lookup(digest, key)
            lookups += 1
            entry["virustotal"] = vt
            if vt.get("malicious", 0) >= 5:
                sev = "high"
                signals.append(f"hash: VirusTotal {vt['malicious']}/{vt['engines']} engines flag this file ({vt.get('name', '')})")
            elif vt.get("known") is False:
                signals.append("VirusTotal has never seen this hash")
        all_iocs.append(entry)
        n = sum(len(v) for v in iocs.values())
        if n == 0 and sev == "info" and "virustotal" not in entry:
            continue
        sample = [defang(x) for x in (iocs["urls"][:5] + iocs["ips"][:5] + iocs["domains"][:5])]
        res.add(rule_id="IOC-EXTRACT", title=f"Indicators in flagged file {os.path.basename(path)}", severity=sev, evidence=path,
                why=f"Flagged as: {title}. {len(iocs['urls'])} URLs, {len(iocs['ips'])} public IPs, {len(iocs['domains'])} domains. "
                    + ("; ".join(signals) + ". " if signals else "") + ("Sample (defanged): " + ", ".join(sample) if sample else ""),
                confidence=0.5, signals=signals,
                remediation="Use the indicators to check firewall/DNS logs; full list is in iocs.json. Do not browse to them.",
                details={"path": path, "sha256": digest, "key": "iocs", "value": str(n)})
    (ctx.report_dir / "iocs.json").write_text(json.dumps(all_iocs, indent=1), "utf-8")
    if key:
        res.coverage["virustotal_lookups"] = lookups
    return res
