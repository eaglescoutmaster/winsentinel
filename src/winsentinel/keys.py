"""API keys and sign-in.

Keys are looked up in the environment first, then in Windows Credential Manager
(via keyring). They are never written to files, reports or persistent environment
variables. The Claude subscription path stores nothing here at all: it uses the
Claude Code CLI's own sign-in (browser login, including "Continue with Google").
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

SERVICE = "winsentinel"
# short name -> (environment variable, what it is for, where to get one)
KEYS = {
    "anthropic": ("ANTHROPIC_API_KEY", "analyze --llm through the Claude API", "https://platform.claude.com/settings/keys"),
    "virustotal": ("VT_API_KEY", "scan --vt hash lookups", "https://www.virustotal.com/gui/my-apikey"),
}


def _keyring():
    try:
        import keyring

        return keyring
    except Exception:
        return None


def get(name: str) -> tuple[str, str]:
    """Return (value, source) where source is 'environment', 'credential manager' or ''."""
    env = KEYS[name][0]
    val = os.environ.get(env, "").strip()
    if val:
        return val, "environment"
    kr = _keyring()
    if kr:
        try:
            val = kr.get_password(SERVICE, name) or ""
        except Exception:
            val = ""
        if val:
            return val, "credential manager"
    return "", ""


def store(name: str, value: str) -> None:
    kr = _keyring()
    if not kr:
        raise RuntimeError("keyring is not available (run uv sync)")
    kr.set_password(SERVICE, name, value.strip())


def remove(name: str) -> bool:
    kr = _keyring()
    if not kr:
        return False
    try:
        kr.delete_password(SERVICE, name)
        return True
    except Exception:
        return False


def claude_cli() -> str | None:
    return shutil.which("claude")


def claude_status() -> dict:
    """Sign-in state of the Claude Code CLI: {installed, logged_in, method}. Never returns account details."""
    exe = claude_cli()
    if not exe:
        return {"installed": False, "logged_in": False, "method": ""}
    try:
        p = subprocess.run([exe, "auth", "status"], capture_output=True, text=True, timeout=30, encoding="utf-8",
                           errors="replace", stdin=subprocess.DEVNULL)
        data = json.loads(p.stdout)
        return {"installed": True, "logged_in": bool(data.get("loggedIn")), "method": str(data.get("authMethod", ""))}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"installed": True, "logged_in": False, "method": ""}


def claude_login(console: bool = False) -> int:
    """Interactive browser sign-in through the Claude Code CLI. Choose 'Continue with Google' on the page."""
    exe = claude_cli()
    if not exe:
        return 127
    return subprocess.call([exe, "auth", "login", "--console" if console else "--claudeai"])
