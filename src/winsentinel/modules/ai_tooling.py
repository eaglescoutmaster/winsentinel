"""Audit AI-agent tooling: Claude Code skills, plugins, commands, agents, hooks, settings and MCP configs.

Looks for prompt injection, hidden text, obfuscated payloads, exfiltration and
dangerous commands. Session transcripts and history are not read. Suppression
comments inside scanned files are ignored on purpose: the content is untrusted.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from ..config import CODE_SKIP_DIRS, LOCK_FILES
from ..findings import ModuleResult, redact
from ..textrules import AI_RULES, SCRIPT_RULES, read_text, scan_text
from ..winutil import in_user_writable, is_public_ip

NAME = "ai-tooling"
DESCRIPTION = "Claude Code skills/plugins/hooks/MCP configs: prompt injection, obfuscation, exfiltration, dangerous commands"
ORDER = 50

_TEXT_EXT = {".md", ".mdx", ".txt", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".sh", ".bash", ".zsh", ".ps1", ".psm1",
             ".py", ".js", ".mjs", ".cjs", ".ts", ".bat", ".cmd", ".rb", ".xml", ".html", ""}
# Under ~/.claude these hold transcripts, caches and telemetry, not instructions or executable config.
_SKIP_TOP = {"projects", "sessions", "cache", "todos", "shell-snapshots", "file-history", "logs", "statsig",
             "telemetry", "ide", "debug", "paste-cache", "session-env", "backups", "downloads", "tasks"}
_SKIP_EXT = {".jsonl", ".log", ".csv", ".lock", ".map"}
_MAX_TEXT_FILE = 2 * 1024 * 1024
_MAGIC = {b"MZ": "PE", b"\x7fELF": "ELF", b"\xcf\xfa\xed\xfe": "Mach-O", b"\xfe\xed\xfa\xcf": "Mach-O", b"\x00asm": "WASM"}
_SECRET_NAME = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)")
_PLACEHOLDER = re.compile(r"(?i)^(\$\{?\w+\}?|%\w+%|<[^>]+>|x{3,}|your[_-].*|changeme|example.*|\*+|)$")
_NET_CMD = re.compile(r"(?i)\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|nc|ncat|ssh|scp|ftp)\b")
_RANK = ["info", "low", "medium", "high", "critical"]


def _tag_decode(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _iter_files(root: Path, top_skip: set[str], cov: dict):
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            cov["unreadable_dirs"] = cov.get("unreadable_dirs", 0) + 1
            continue
        for e in entries:
            try:
                if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                    cov["links_not_followed"] = cov.get("links_not_followed", 0) + 1
                    continue
                if e.is_dir():
                    if Path(e.path).parent == root and e.name.lower() in top_skip:
                        cov["skipped_data_dirs"] = cov.get("skipped_data_dirs", 0) + 1
                        continue
                    if e.name.lower() in CODE_SKIP_DIRS:
                        cov["skipped_dependency_dirs"] = cov.get("skipped_dependency_dirs", 0) + 1
                        continue
                    stack.append(Path(e.path))
                elif e.is_file():
                    yield Path(e.path)
            except OSError:
                continue


_SURFACE_NAMES = {"skill.md", "claude.md", "agents.md", "memory.md", "settings.json", "settings.local.json", "hooks.json"}
_SURFACE_DIRS = {"skills", "commands", "agents", "hooks", "memory", "output-styles"}
_DOC_CAPPED = {"dangerous-command", "download-exec", "exfiltration", "persistence", "stealth", "lolbin", "obfuscation"}


def _is_agent_surface(path: Path) -> bool:
    """True for files an agent loads as instructions or executes (skills, commands, agents, hooks, memory)."""
    parts = {p.lower() for p in path.parts[:-1]}
    return path.name.lower() in _SURFACE_NAMES or bool(parts & _SURFACE_DIRS)


def _scan_text_file(res: ModuleResult, path: Path, text: str) -> None:
    hits = scan_text(text, AI_RULES + SCRIPT_RULES)
    if not hits:
        return
    surface = _is_agent_surface(path)
    all_signals = list(dict.fromkeys(h.signal for h in hits))
    by_rule: dict[str, list] = {}
    for h in hits:
        by_rule.setdefault(h.rule.id, []).append(h)
    for rid, hs in by_rule.items():
        h = hs[0]
        signals = list(all_signals)
        why = f"{h.rule.why} Match: \"{h.excerpt}\""
        if rid == "UNI-001":
            hidden = _tag_decode(text)
            signals.append(f"hidden text decodes to: {hidden[:120]!r}")
            why += f" Hidden text: {hidden[:200]!r}"
        sev = h.rule.severity
        if h.rule.category == "prompt-injection" and all(x.quoted for x in hs):
            sev = "low"
            why += " Every occurrence is quoted, which usually means an example or a warning about the phrase."
        elif not surface and h.rule.category in _DOC_CAPPED and sev != "info":
            sev = "low"
            why += " File is documentation/test/CI content, not something the agent loads as instructions or runs."
        res.add(rule_id=rid, title=f"{h.rule.title} in {path.name}", severity=sev, evidence=str(path),
                why=why, confidence=0.6 if len(all_signals) > 1 else 0.4, signals=signals,
                remediation="Read the file at the given line. If you did not write it, remove the skill/plugin/config "
                            "entry it belongs to and check where it came from.",
                details={"path": str(path), "line": h.line, "key": rid, "category": h.rule.category,
                         "decoded_from": h.decoded_from, "occurrences": len(hs)})


def _scan_tree(res: ModuleResult, root: Path, top_skip: set[str]) -> None:
    cov = res.coverage
    for path in _iter_files(root, top_skip, cov):
        ext = path.suffix.lower()
        if ext in _SKIP_EXT or path.name.lower() in LOCK_FILES:
            cov["skipped_data_files"] = cov.get("skipped_data_files", 0) + 1
            continue
        try:
            size = path.stat().st_size
            with open(path, "rb") as fh:
                data = fh.read(min(size, _MAX_TEXT_FILE))
        except OSError:
            cov["unreadable_files"] = cov.get("unreadable_files", 0) + 1
            continue
        kind = next((k for m, k in _MAGIC.items() if data.startswith(m)), None)
        if kind:
            res.add(rule_id="AI-NATIVE-BINARY", title=f"Compiled {kind} binary inside agent tooling", severity="medium",
                    evidence=str(path), why="Compiled code shipped with a skill/plugin cannot be reviewed as text and "
                    "runs with your privileges if the skill invokes it.", confidence=0.5,
                    signals=[f"{kind} magic bytes"],
                    remediation="Confirm the plugin's source and why it needs a binary; check its signature.",
                    details={"path": str(path), "key": "binary"})
            continue
        if ext not in _TEXT_EXT or b"\x00\x00\x00" in data[:4096]:
            cov["non_text_files_not_scanned"] = cov.get("non_text_files_not_scanned", 0) + 1
            continue
        if size > _MAX_TEXT_FILE:
            # Fail closed: never report unread content as clean.
            res.add(rule_id="AI-OVERSIZE", title="Text file too large to review fully", severity="low", evidence=str(path),
                    why=f"Only the first 2 MB of {size} bytes were scanned.", confidence=0.3,
                    details={"path": str(path), "key": "oversize"})
        cov["text_files_scanned"] = cov.get("text_files_scanned", 0) + 1
        _scan_text_file(res, path, read_text(data))


def _load_json(path: Path):
    try:
        if path.stat().st_size > 30 * 1024 * 1024:
            return None
        return json.loads(path.read_text("utf-8-sig", "replace"))
    except (OSError, ValueError):
        return None


def _command_findings(res: ModuleResult, source: Path, label: str, command: str, key: str) -> None:
    """Inventory one executable config entry (hook, MCP server, helper) and flag risky traits."""
    hits = scan_text(command, AI_RULES + SCRIPT_RULES)
    signals = list(dict.fromkeys(h.signal for h in hits))
    sev = "info"
    for h in hits:
        if _RANK.index(h.rule.severity) > _RANK.index(sev):
            sev = h.rule.severity
    if _NET_CMD.search(command) and "hook" in label.lower():
        signals.append("hook command uses a network client")
        sev = max(sev, "medium", key=_RANK.index)
    if in_user_writable(command) and re.search(r"(?i)[\\/](temp|tmp|downloads)[\\/]", command):
        signals.append("runs a program from a temp/downloads folder")
        sev = max(sev, "medium", key=_RANK.index)
    res.add(rule_id="AI-EXEC-CONFIG", title=f"{label}", severity=sev, evidence=f"{source} :: {key}",
            why=("; ".join(signals) + ". " if signals else "Inventory: this command runs automatically. ")
            + f"Command: {command[:240]}", confidence=0.6 if signals else 0.3, signals=signals,
            remediation="Confirm you configured this entry; remove it from the file if not.",
            details={"path": str(source), "key": key, "value": command[:500]})


def _env_secrets(res: ModuleResult, source: Path, where: str, env) -> None:
    if not isinstance(env, dict):
        return
    for k, v in env.items():
        if not isinstance(v, str):
            continue
        raw = re.sub(r"(?i)^(bearer|basic|token)\s+", "", v.strip())
        if "${" in raw or raw.startswith(("$", "%")):
            continue  # reference to an environment variable, not a literal
        if (_SECRET_NAME.search(k) or v.strip().lower().startswith(("bearer ", "basic "))) and len(raw) >= 12 \
                and not _PLACEHOLDER.match(raw):
            res.add(rule_id="AI-PLAINTEXT-SECRET", title=f"Plaintext credential in agent config ({k})", severity="medium",
                    evidence=f"{source} :: {where}.env.{k}", why=f"Value {redact(v)} is stored in clear text and is "
                    "readable by every process running as you, including any skill or MCP server.", confidence=0.6, kind="fact",
                    remediation="Move it to an environment variable or credential manager and rotate the key if the file was ever shared.",
                    details={"path": str(source), "key": f"{where}.{k}", "value": redact(v)})


def _audit_settings(res: ModuleResult, path: Path) -> None:
    data = _load_json(path)
    if not isinstance(data, dict):
        return
    res.coverage["settings_files"] = res.coverage.get("settings_files", 0) + 1
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                    cmd = h.get("command") if isinstance(h, dict) else None
                    if isinstance(cmd, str) and cmd.strip():
                        _command_findings(res, path, f"Claude Code hook ({event})", cmd, f"hooks.{event}.{g.get('matcher', '*')}")
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    broad = [a for a in perms.get("allow") or [] if isinstance(a, str) and re.fullmatch(r"(?i)\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|PowerShell|PowerShell\(\*\)", a.strip())]
    if broad:
        res.add(rule_id="AI-PERM-BROAD", title="Agent may run any shell command without asking", severity="medium",
                evidence=f"{path} :: permissions.allow", why=f"Allow rules {broad} pre-approve every shell command, so a "
                "prompt injection in any file or web page the agent reads can execute code.", confidence=0.9, kind="fact",
                remediation="Replace with specific command prefixes.", details={"path": str(path), "key": "allow", "value": ",".join(broad)})
    if perms.get("defaultMode") == "bypassPermissions" or data.get("skipDangerousModePermissionPrompt") is True:
        res.add(rule_id="AI-PERM-BYPASS", title="Agent permission prompts are bypassed by default", severity="medium",
                evidence=f"{path} :: permissions.defaultMode", why="bypassPermissions / skipDangerousModePermissionPrompt "
                "removes the confirmation step for destructive or outward-facing actions.", confidence=0.9, kind="fact",
                remediation="Use the default or acceptEdits mode outside disposable sandboxes.",
                details={"path": str(path), "key": "bypass", "value": str(perms.get("defaultMode"))})
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    _env_secrets(res, path, "settings", env)
    for var in ("ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY"):
        url = env.get(var)
        if isinstance(url, str) and url:
            host = urlparse(url if "://" in url else "http://" + url).hostname or ""
            official = host.endswith(".anthropic.com") or host == "anthropic.com"
            local = host in ("localhost",) or host.startswith("127.") or (re.fullmatch(r"[\d.]+", host) and not is_public_ip(host))
            res.add(rule_id="AI-TRAFFIC-REDIRECT", title=f"Agent traffic is routed via {var}",
                    severity="info" if (official or local) else "high", evidence=f"{path} :: env.{var}",
                    why=f"{var}={url}. " + ("Local or official endpoint." if (official or local) else
                                            "Every prompt, file excerpt and tool result is sent to this third-party host."),
                    confidence=0.8, kind="fact", remediation="Remove the variable unless you set up this gateway yourself.",
                    details={"path": str(path), "key": var, "value": url})
    for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"):
        if isinstance(data.get(key), str):
            _command_findings(res, path, f"Claude Code {key}", data[key], key)
    sl = data.get("statusLine")
    if isinstance(sl, dict) and isinstance(sl.get("command"), str):
        _command_findings(res, path, "Claude Code status line command", sl["command"], "statusLine")
    mk = data.get("extraKnownMarketplaces")
    if isinstance(mk, dict) and mk:
        res.add(rule_id="AI-MARKETPLACES", title=f"{len(mk)} extra plugin marketplace(s) configured", severity="info",
                evidence=f"{path} :: extraKnownMarketplaces", why="Inventory: " + ", ".join(
                    f"{n} ({json.dumps(v.get('source', v))[:80] if isinstance(v, dict) else v})" for n, v in mk.items())[:600],
                confidence=0.3, kind="fact", details={"path": str(path), "key": "marketplaces", "value": ",".join(sorted(mk))})
    _audit_mcp(res, path, data.get("mcpServers"), "mcpServers")


_PINNED = re.compile(r"@\d|==\d|@sha|#[0-9a-f]{7,}|@v\d")


def _audit_mcp(res: ModuleResult, path: Path, servers, where: str) -> None:
    if not isinstance(servers, dict):
        return
    for name, s in servers.items():
        if not isinstance(s, dict):
            continue
        res.coverage["mcp_servers"] = res.coverage.get("mcp_servers", 0) + 1
        key = f"{where}.{name}"
        cmd = s.get("command")
        args = [str(a) for a in (s.get("args") or [])] if isinstance(s.get("args"), list) else []
        if isinstance(cmd, str) and cmd:
            full = " ".join([cmd, *args])
            _command_findings(res, path, f"MCP server '{name}' (local command)", full, key)
            exe = os.path.basename(cmd).lower().removesuffix(".cmd").removesuffix(".exe")
            if exe in ("npx", "uvx", "bunx", "pnpx", "pipx") or (exe in ("uv", "npm", "pnpm") and ("x" in args[:2] or "tool" in args[:2] or "dlx" in args[:2])):
                pkgs = [a for a in args if not a.startswith("-") and a not in ("run", "tool", "x", "dlx", "exec")]
                if pkgs and not _PINNED.search(pkgs[0]):
                    res.add(rule_id="AI-MCP-UNPINNED", title=f"MCP server '{name}' runs an unpinned package", severity="low",
                            evidence=f"{path} :: {key}", why=f"'{full[:160]}' downloads and runs whatever version of "
                            f"'{pkgs[0]}' is current each time. A hijacked release runs with your privileges.",
                            confidence=0.7, kind="fact", remediation="Pin an exact version (pkg@1.2.3) you have reviewed.",
                            details={"path": str(path), "key": key + ".pin", "value": pkgs[0]})
        url = s.get("url")
        if isinstance(url, str) and url:
            u = urlparse(url)
            host = u.hostname or ""
            local = host in ("localhost",) or host.startswith("127.") or host.endswith(".ts.net") or (
                re.fullmatch(r"[\d.]+", host) is not None and not is_public_ip(host))
            if u.scheme == "http" and not local:
                res.add(rule_id="AI-MCP-CLEARTEXT", title=f"MCP server '{name}' uses unencrypted HTTP", severity="medium",
                        evidence=f"{path} :: {key}", why=f"Tool calls and results travel to {host} in clear text.",
                        confidence=0.9, kind="fact", remediation="Use https or remove the server.",
                        details={"path": str(path), "key": key + ".http", "value": host})
            else:
                res.add(rule_id="AI-MCP-REMOTE", title=f"MCP server '{name}' ({'local' if local else 'remote'})", severity="info",
                        evidence=f"{path} :: {key}", why=f"Inventory: connects to {u.scheme}://{host}. A remote MCP server "
                        "sees tool inputs and can return instructions to the agent.", confidence=0.3, kind="fact",
                        details={"path": str(path), "key": key + ".url", "value": f"{u.scheme}://{host}"})
        _env_secrets(res, path, key, s.get("env"))
        _env_secrets(res, path, key + ".headers", s.get("headers"))


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    home = Path.home()
    if ctx.paths:
        for p in ctx.paths:
            if p.is_dir():
                _scan_tree(res, p, set())
            elif p.is_file():
                _scan_text_file(res, p, read_text(p.read_bytes()[:_MAX_TEXT_FILE]))
        return res
    found_any = False
    for d in ctx.cfg.ai_dirs:
        if not d.is_dir():
            continue
        found_any = True
        _scan_tree(res, d, _SKIP_TOP)
        for name in ("settings.json", "settings.local.json"):
            _audit_settings(res, d / name)
        # Auto-memory is instruction-bearing even though it lives under projects/.
        for mem in d.glob("projects/*/memory/*.md"):
            try:
                _scan_text_file(res, mem, read_text(mem.read_bytes()[:_MAX_TEXT_FILE]))
                res.coverage["memory_files_scanned"] = res.coverage.get("memory_files_scanned", 0) + 1
            except OSError:
                pass
        for hooks_json in d.glob("plugins/**/hooks/hooks.json"):
            _audit_settings(res, hooks_json)
        for mcp in list(d.glob("plugins/**/.mcp.json")):
            data = _load_json(mcp)
            if isinstance(data, dict):
                _audit_mcp(res, mcp, data.get("mcpServers", data), "mcpServers")
    for f in ctx.cfg.ai_files:  # ~/.claude.json: only the MCP sections are read
        data = _load_json(f)
        if isinstance(data, dict):
            found_any = True
            _audit_mcp(res, f, data.get("mcpServers"), "mcpServers")
            for proj, pd in (data.get("projects") or {}).items() if isinstance(data.get("projects"), dict) else []:
                if isinstance(pd, dict):
                    _audit_mcp(res, f, pd.get("mcpServers"), f"projects[{proj}].mcpServers")
    import sys

    if sys.platform == "win32":
        desktop = Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
    elif sys.platform == "darwin":
        desktop = Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        desktop = Path.home() / ".config" / "Claude" / "claude_desktop_config.json"
    data = _load_json(desktop)
    if isinstance(data, dict):
        _audit_mcp(res, desktop, data.get("mcpServers"), "mcpServers")
    for proj in ctx.cfg.code_dirs:
        if not proj.is_dir():
            continue
        data = _load_json(proj / ".mcp.json")
        if isinstance(data, dict):
            _audit_mcp(res, proj / ".mcp.json", data.get("mcpServers"), "mcpServers")
        if (proj / ".claude").is_dir():
            _scan_tree(res, proj / ".claude", set())
            for name in ("settings.json", "settings.local.json"):
                _audit_settings(res, proj / ".claude" / name)
        for name in ("CLAUDE.md", "AGENTS.md"):
            p = proj / name
            if p.is_file():
                try:
                    _scan_text_file(res, p, read_text(p.read_bytes()[:_MAX_TEXT_FILE]))
                except OSError:
                    pass
    if not found_any:
        res.status = "skipped"
        res.notes.append(f"no agent tooling found under {home / '.claude'}")
    res.notes.append("session transcripts, history and caches are intentionally not read")
    return res
