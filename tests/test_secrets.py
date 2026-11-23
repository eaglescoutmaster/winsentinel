"""secrets module: a planted fake secret must be found, and its value must never reach the output."""
from __future__ import annotations

import base64
import json

import pytest

from winsentinel.findings import redact
from winsentinel.modules import secrets
from winsentinel.report import write_json, write_markdown


def _fake_token() -> str:
    # Random, assembled at runtime: never a real credential and never stored in the repo.
    return "ghp_" + secrets._rand(36)


def test_redact_keeps_only_four_chars():
    assert redact("ghp_abcdefghijklmnop") == "ghp_***(20 chars)"


def test_history_patterns_catch_token_and_redact(tmp_path, monkeypatch):
    tok = _fake_token()
    hist = tmp_path / "AppData" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    hist.mkdir(parents=True)
    (hist / "ConsoleHost_history.txt").write_text(f"git status\ngh auth login --with-token {tok}\n", "utf-8")
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    monkeypatch.setattr(secrets.Path, "home", classmethod(lambda cls: tmp_path))
    res = secrets.ModuleResult("secrets")
    secrets._history(res)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert "github-token" in f.title and f.evidence.endswith(":2")
    assert tok not in json.dumps(f.to_dict())


def test_openssh_passphrase_detection():
    def key(cipher: bytes) -> bytes:
        body = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher + b"\x00" * 16
        return b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(body) + b"\n-----END OPENSSH PRIVATE KEY-----\n"

    assert secrets._openssh_unencrypted(key(b"none")) is True
    assert secrets._openssh_unencrypted(key(b"aes256-ctr")) is False
    assert secrets._openssh_unencrypted(b"not a key") is None


def test_planted_secret_found_by_scanners_and_never_printed(ctx, tmp_path):
    if not (ctx.tools.path("gitleaks") or ctx.tools.path("trufflehog")):
        pytest.skip("gitleaks/trufflehog not installed (winsentinel tools install)")
    proj = tmp_path / "proj"
    (proj / "node_modules" / "dep").mkdir(parents=True)
    tok, tok_ignored = _fake_token(), _fake_token()
    (proj / "deploy.py").write_text(f'GITHUB_TOKEN = "{tok}"\n', "utf-8")
    (proj / "node_modules" / "dep" / "index.js").write_text(f'const t = "{tok_ignored}";\n', "utf-8")
    ctx.paths = [proj]
    res = secrets.run(ctx)
    assert "OK" in res.coverage["tool_preflight"]
    hits = [f for f in res.findings if f.rule_id == "SECRET-CODE"]
    assert len(hits) == 1, [f.evidence for f in hits]
    assert hits[0].evidence.endswith("deploy.py:1")
    # Dependency directories are excluded for the secrets module.
    assert not any("node_modules" in f.evidence for f in res.findings)
    # The secret value must not appear anywhere in the written report.
    meta = {"started": "t", "mode": "quick", "admin": False, "host": "h"}
    write_json(ctx.report_dir / "findings.json", meta, [res], res.findings)
    write_markdown(ctx.report_dir / "report.md", meta, [res], res.findings, {"existed": False})
    for name in ("findings.json", "report.md"):
        text = (ctx.report_dir / name).read_text("utf-8")
        assert tok not in text and tok_ignored not in text
