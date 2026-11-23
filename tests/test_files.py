"""files module: EICAR detection, sniffing, disguise heuristics, end-to-end scan of planted fixtures."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from winsentinel.modules import files
from winsentinel.yaraload import compile_tolerant, load_own

# Built at runtime so no file on disk (including this one) is an EICAR file:
# Defender would quarantine it, and the scanner must never need an AV exclusion.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def test_eicar_is_68_bytes_and_detected_in_memory():
    assert len(EICAR) == 68
    matches = load_own().match(data=EICAR)
    assert [m.rule for m in matches] == ["WS_EICAR_Test_File"]


def test_eicar_result_is_high_with_strong_signal():
    r = {"sha256": "0" * 64, "signals": [], "kind": "script",
         "yara": [{"rule": "WS_EICAR_Test_File", "score": 80, "desc": "EICAR"}]}
    sev, signals, title = files._severity(r, [], r"C:\Users\x\Downloads\eicar.com")
    assert sev == "high"
    assert signals[0].startswith("yara:")
    assert "WS_EICAR_Test_File" in title


def test_clean_bytes_do_not_match():
    assert load_own().match(data=b"hello world " * 50) == []


def test_sniff_by_magic_not_extension():
    assert files.sniff(b"MZ\x90\x00\x03\x00\x00\x00", ".jpg") == "pe"
    assert files.sniff(b"PK\x03\x04abcd", ".docx") == "zip"
    assert files.sniff(b"just text", ".ps1") == "script"
    assert files.sniff(b"just text", ".txt") is None


def test_entropy_bounds():
    assert files.entropy(b"\x00" * 4096) == 0.0
    assert files.entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


def test_name_tricks():
    assert any("double extension" in s for s in files._name_signals(r"C:\Users\x\Downloads\invoice.pdf.exe"))
    assert any("masquerade" in s for s in files._name_signals(r"C:\Users\x\AppData\Local\Temp\svchost.exe"))
    assert files._name_signals(r"C:\Windows\System32\svchost.exe") == []
    assert any("right-to-left" in s for s in files._name_signals("C:\\x\\photo\u202egpj.exe"))


def test_disguised_pe_with_second_signal_is_high():
    r = {"sha256": "0" * 64, "kind": "pe", "yara": [],
         "signals": ["extension mismatch: Windows executable named .jpg", "pe: packer section names (upx0)"]}
    sev, signals, _ = files._severity(r, [], r"C:\Users\x\Downloads\holiday.jpg")
    assert sev == "high" and len(signals) >= 3


def test_single_weak_pe_trait_is_not_reported():
    r = {"sha256": "0" * 64, "kind": "pe", "yara": [], "signals": ["pe: packer section names (upx0)"]}
    assert files._severity(r, [], r"C:\Program Files\Tool\tool.exe")[0] == "none"


def test_analyse_pe_on_real_system_binary():
    data = Path(r"C:\Windows\System32\notepad.exe").read_bytes()
    info = files.analyse_pe(data)
    assert info["imports"] > 10
    assert not any("injection" in s for s in info["signals"])
    assert files.analyse_pe(b"MZ not really a pe") == {}


def test_tolerant_compile_drops_only_unsupported_rules():
    src = ('import "pe"\nrule ok_rule { strings: $a = "winsentinel-marker" condition: $a }\n'
           'rule needs_crypto { condition: pe.number_of_signatures > 0 }\n'
           'rule bad_field { condition: pe.this_field_does_not_exist == 1 }\n'
           'rule ok_two { condition: filesize < 10 }\n')
    rules, kept, dropped = compile_tolerant(src)
    assert (kept, dropped) == (2, 2)
    assert [m.rule for m in rules.match(data=b"xx winsentinel-marker xx")] == ["ok_rule"]


def test_end_to_end_scan_of_planted_fixtures(ctx, tmp_path, monkeypatch):
    """Plant a persistence-style script and a renamed (Microsoft-signed) executable; scan only that folder."""
    target = tmp_path / "planted"
    target.mkdir()
    (target / "updater.vbs").write_text(
        'Set s = CreateObject("WScript.Shell")\n'
        's.Run "schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc onlogon", 0\n'
        's.Run "net user backdoor Passw0rd123 /add", 0\n', "utf-8")
    shutil.copyfile(r"C:\Windows\System32\notepad.exe", target / "holiday.jpg")
    (target / "notes.txt").write_text("nothing to see", "utf-8")
    ctx.paths = [target]
    res = files.run(ctx)
    by_name = {Path(f.evidence).name: f for f in res.findings}
    assert "updater.vbs" in by_name, res.notes
    vbs = by_name["updater.vbs"]
    assert vbs.severity in ("medium", "high")
    assert any("USERADD" in s for s in vbs.signals) and any("PERSIST" in s for s in vbs.signals)
    # The renamed notepad is validly signed by Microsoft: a lone disguise signal must not become a finding.
    assert "holiday.jpg" not in by_name
    assert res.coverage["signed_by_trusted_publisher_not_reported"] == 1
    assert res.coverage["not_deep_scanned_inert_type"] >= 1
    # Second run is served from the resumable cache.
    res2 = files.run(ctx)
    assert res2.coverage["from_cache"] >= 2
    assert {Path(f.evidence).name for f in res2.findings} == set(by_name)
