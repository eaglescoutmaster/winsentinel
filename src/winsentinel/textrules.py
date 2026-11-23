"""Regex rule engine with decode-then-rescan.

Shared by the ai-tooling module (prompt injection, exfiltration, dangerous
commands) and the files module (Windows script malware traits).

Several patterns are Python ports of rules from MIT-licensed projects; see
NOTICE. All quantifiers are bounded so untrusted input cannot cause runaway
backtracking, and in-file suppression comments are deliberately not honoured.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

MAX_TEXT = 2 * 1024 * 1024
MAX_HITS_PER_RULE = 3
I = re.IGNORECASE


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    title: str
    pattern: re.Pattern
    why: str


@dataclass
class Hit:
    rule: Rule
    line: int
    excerpt: str
    decoded_from: str = ""  # "", "base64", "base64-utf16", "hex"

    @property
    def signal(self) -> str:
        via = f" (inside {self.decoded_from} blob)" if self.decoded_from else ""
        return f"text:{self.rule.id} {self.rule.title}{via}"


def _r(id, cat, sev, title, pat, why, flags=I):
    return Rule(id, cat, sev, title, re.compile(pat, flags), why)


_NET = r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)"
_SENSITIVE = (
    r"(?:\$\{?\w{0,30}(?:TOKEN|SECRET|PASSWORD|API_?KEY)\w{0,10}\}?|\$env:\w{0,30}(?:TOKEN|SECRET|KEY|PASSWORD)"
    r"|\.env\b|\.ssh[\\/]|\.aws[\\/]|id_rsa|id_ed25519|\.credentials\.json|\.claude\.json|\.npmrc|\.netrc)"
)

AI_RULES: list[Rule] = [
    _r("PI-001", "prompt-injection", "high", "Instruction-override phrase",
       r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
       r"(?:instructions?|rules?|guidelines?|constraints?|prompts?)",
       "Text tells an AI agent to drop its earlier instructions."),
    _r("PI-002", "prompt-injection", "medium", "Spoofed system/chat-template token",
       r"<\|(?:system|im_start|im_end|endoftext)\|>|\[INST\]|\[/INST\]|<<SYS>>",
       "Chat-template control tokens inside content can impersonate a system turn."),
    _r("PI-003", "prompt-injection", "high", "Instruction to conceal actions from the user",
       r"\bdo\s+not\s+(?:tell|inform|reveal|disclose|notify|mention\s+(?:this\s+)?to)\s+(?:to\s+)?(?:the\s+)?"
       r"(?:user|human|operator)\b",
       "Text tells an AI agent to hide what it does from the user."),
    _r("PI-004", "prompt-injection", "high", "Remote instruction loading",
       r"\b(?:fetch|load|download|get|read|follow)\s+(?:the\s+)?(?:instructions?|prompts?|rules)\s+(?:from|at)\s+https?://",
       "Agent is told to take instructions from a remote URL, which can change after review."),
    _r("PI-005", "prompt-injection", "medium", "Approval-bypass instruction",
       r"\b(?:without|skip|bypass|don'?t\s+ask\s+for)\s+(?:asking\s+for\s+)?(?:user\s+)?"
       r"(?:confirmation|permission|approval)\b[^\n]{0,60}\b(?:run|execute|delete|send|upload|install)\b",
       "Text pushes an agent to act without user approval."),
    _r("UNI-001", "hidden-unicode", "high", "Unicode tag characters (invisible text)",
       "[\U000E0000-\U000E007F]", "Tag-block characters are invisible to people but read by models.", 0),
    _r("UNI-002", "hidden-unicode", "medium", "Bidirectional override characters",
       "[‪-‮⁦-⁩]", "Bidi controls can make displayed text differ from what is executed.", 0),
    _r("UNI-003", "hidden-unicode", "medium", "Run of zero-width characters",
       "[​‌‍⁠﻿]{3,}", "Runs of zero-width characters can encode hidden data.", 0),
    _r("HID-001", "prompt-injection", "medium", "Hidden HTML comment with agent directive",
       r"<!--[^>]{0,400}\b(?:ignore|system prompt|instructions?|disregard|override|you must)\b[^>]{0,400}-->",
       "Markdown comments are invisible when rendered but read by an agent."),
    _r("EXF-001", "exfiltration", "high", "Network upload of secrets or credential files",
       _NET + r"\b[^\n]{0,300}" + _SENSITIVE + r"|" + _SENSITIVE + r"[^\n]{0,200}\|\s*" + _NET + r"\b",
       "A network client is combined with a secret variable or credential file on one line."),
    _r("EXF-002", "exfiltration", "medium", "Known data-collection endpoint",
       r"webhook\.site|requestbin\.|pipedream\.net|\.ngrok(?:-free)?\.(?:io|app)|discord(?:app)?\.com/api/webhooks"
       r"|api\.telegram\.org/bot|transfer\.sh|\.oast\.(?:fun|live|site|pro)|burpcollaborator\.net|interact\.sh",
       "Endpoint is commonly used to receive exfiltrated data."),
    _r("EXF-003", "exfiltration", "medium", "DNS exfiltration shape",
       r"\b(?:nslookup|dig|Resolve-DnsName)\b[^\n]{0,120}\$\(", "Command output is embedded in a DNS lookup."),
    _r("CMD-001", "dangerous-command", "medium", "Download piped straight into an interpreter",
       _NET + r"\b[^\n|]{0,300}\|\s*(?:(?:ba|z)?sh|python3?|node|iex|Invoke-Expression)\b",
       "Remote content is executed without being saved or reviewed."),
    _r("CMD-002", "dangerous-command", "high", "Destructive command",
       r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/|~|\$HOME)(?:\s|$|\*)"
       r"|\bRemove-Item\b[^\n]{0,80}-Recurse[^\n]{0,80}(?:[A-Z]:\\|\$env:USERPROFILE|\$HOME)[\"']?\s*(?:-Force)?\s*$"
       r"|\bvssadmin(?:\.exe)?\s+delete\s+shadows|\bwbadmin\s+delete\s+catalog|\bformat\s+[a-z]:\s*/",
       "Command deletes a whole home directory, drive or backups.", I | re.M),
    _r("CMD-003", "dangerous-command", "medium", "Agent permission bypass",
       r"--dangerously-skip-permissions|\"defaultMode\"\s*:\s*\"bypassPermissions\"|dangerouslyDisableSandbox",
       "Disables the agent's permission prompts."),
    _r("CMD-004", "defense-evasion", "high", "Defender tampering",
       r"\bSet-MpPreference\b[^\n]{0,200}-Disable\w+\s+\$?true|\bAdd-MpPreference\b[^\n]{0,100}-Exclusion",
       "Command disables Defender protection or adds an exclusion."),
]

SCRIPT_RULES: list[Rule] = [
    _r("PS-ENC", "obfuscation", "medium", "PowerShell encoded command",
       r"\bpowershell(?:\.exe)?\b[^\n]{0,200}\s-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
       "Command line hides its script in base64."),
    _r("PS-DLEXEC", "download-exec", "medium", "PowerShell download-and-execute",
       r"(?:DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|\birm\b|Invoke-RestMethod)[^\n]{0,300}"
       r"(?:\|\s*(?:iex|Invoke-Expression)\b|;\s*(?:iex|Invoke-Expression)\b)"
       r"|(?:\biex\b|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr\b|irm\b|Invoke-WebRequest)",
       "Remote content is fetched and executed in memory."),
    _r("PS-AMSI", "defense-evasion", "high", "AMSI bypass strings",
       r"amsiInitFailed|AmsiScanBuffer|amsiContext|\[Ref\]\.Assembly\.GetType\([^\n]{0,80}Amsi",
       "References internals used to switch off script scanning."),
    _r("PS-HIDDEN", "stealth", "low", "Hidden PowerShell window",
       r"\bpowershell(?:\.exe)?\b[^\n]{0,200}\s-w(?:in|indowstyle)?\s+h(?:idden)?\b",
       "Script runs PowerShell with no visible window."),
    _r("PS-DEFENDER", "defense-evasion", "high", "Defender tampering",
       r"\bSet-MpPreference\b[^\n]{0,200}-Disable\w+\s+\$?true|\bAdd-MpPreference\b[^\n]{0,100}-Exclusion",
       "Script disables Defender protection or adds an exclusion."),
    _r("PS-SOCKET", "c2", "medium", "Raw TCP client in PowerShell",
       r"New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\(", "Typical reverse-shell building block."),
    _r("LOLBIN", "lolbin", "medium", "Living-off-the-land proxy execution",
       r"\bcertutil(?:\.exe)?\s+[^\n]{0,80}-(?:urlcache|decode)\b|\bbitsadmin(?:\.exe)?\s+/transfer"
       r"|\bmshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)"
       r"|\bregsvr32(?:\.exe)?\s+[^\n]{0,80}/i:(?:https?://|\\\\)"
       r"|\brundll32(?:\.exe)?\s+[^\n]{0,80}(?:javascript:|scrobj\.dll)"
       r"|\bmsiexec(?:\.exe)?\s+[^\n]{0,60}https?://|\bwmic\s+process\s+call\s+create",
       "A signed Windows binary is used to download or run code."),
    _r("PERSIST", "persistence", "low", "Persistence command",
       r"\breg(?:\.exe)?\s+add\s+[^\n]{0,200}CurrentVersion\\{1,2}Run|\bschtasks(?:\.exe)?\s+/create"
       r"|\bRegister-ScheduledTask\b|\bNew-ItemProperty\b[^\n]{0,200}CurrentVersion\\{1,2}Run",
       "Script installs something that survives reboot."),
    _r("WSH", "script-host", "low", "Windows Script Host execution object",
       r"CreateObject\(\s*\"(?:WScript\.Shell|MSXML2\.XMLHTTP|ADODB\.Stream|Shell\.Application)\""
       r"|new\s+ActiveXObject\s*\(|GetObject\(\s*\"winmgmts:",
       "Script-host objects that run commands or download files."),
    _r("RANSOM", "impact", "high", "Backup or shadow-copy deletion",
       r"\bvssadmin(?:\.exe)?\s+delete\s+shadows|\bwbadmin\s+delete\s+catalog"
       r"|\bbcdedit\b[^\n]{0,60}recoveryenabled\s+no|\bwmic\s+shadowcopy\s+delete",
       "Removes recovery points, a ransomware precursor."),
    _r("CREDDUMP", "credential-access", "high", "Credential dumping",
       r"sekurlsa::|lsadump::|Invoke-Mimikatz|comsvcs\.dll[^\n]{0,40}MiniDump|\bprocdump(?:64)?\b[^\n]{0,60}lsass",
       "Commands that dump credentials from LSASS."),
    _r("USERADD", "persistence", "medium", "Local account or admin-group change",
       r"\bnet1?\s+user\s+\S+\s+\S+\s+/add\b|\bnet1?\s+localgroup\s+administrators\s+\S+\s+/add\b",
       "Script creates an account or grants local admin."),
]

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,8192}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def decode_blobs(text: str, limit: int = 40) -> list[tuple[str, str]]:
    """Return (kind, decoded_text) for base64/hex blobs that decode to readable text.
    Handles UTF-16LE, which is what powershell -EncodedCommand uses."""
    out: list[tuple[str, str]] = []
    for m in _B64_RE.finditer(text):
        if len(out) >= limit:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < 16:
            continue
        if raw[1:16:2].count(0) >= 6:
            dec, kind = raw.decode("utf-16-le", "replace"), "base64-utf16"
        else:
            dec, kind = raw.decode("utf-8", "replace"), "base64"
        if "�" not in dec[:200] and _printable_ratio(dec) > 0.85:
            out.append((kind, dec))
    for m in _HEX_RE.finditer(text):
        if len(out) >= limit:
            break
        try:
            dec = bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", "replace")
        except ValueError:
            continue
        if _printable_ratio(dec) > 0.85:
            out.append(("hex", dec))
    return out


def _excerpt(text: str, start: int, end: int) -> str:
    a = max(text.rfind("\n", 0, start) + 1, start - 80)
    b = text.find("\n", end)
    b = min(len(text) if b < 0 else b, end + 80)
    s = text[a:b].strip()
    # Make invisible characters visible in reports.
    return "".join(c if c.isprintable() else f"<U+{ord(c):04X}>" for c in s)[:200]


def scan_text(text: str, rules: list[Rule], depth: int = 2, _via: str = "") -> list[Hit]:
    text = text[:MAX_TEXT]
    hits: list[Hit] = []
    for rule in rules:
        n = 0
        for m in rule.pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1 if not _via else 0
            hits.append(Hit(rule, line, _excerpt(text, m.start(), m.end()), _via))
            n += 1
            if n >= MAX_HITS_PER_RULE:
                break
    if depth > 0:
        for kind, dec in decode_blobs(text):
            hits.extend(scan_text(dec, rules, depth - 1, _via or kind))
    return hits


def read_text(data: bytes) -> str:
    """Decode a file's bytes, honouring UTF-16 BOMs (common for .ps1/.reg)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    if len(data) > 16 and data[1:16:2].count(0) >= 6:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")
