"""File scan: YARA, hashes, entropy, PE traits, extension tricks, Authenticode.

Every file is sniffed by magic bytes. Executables, scripts, shortcuts, archives
and documents up to max_file_mb are hashed and YARA-scanned; PE files get
static analysis. Nothing is executed, moved or deleted. Results are cached by
(path, size, mtime, rules version) so an interrupted scan resumes and later
scans are incremental. Everything skipped is counted in coverage.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pefile

from ..findings import ModuleResult
from ..pshelper import PSError, check_signatures, ps_json
from ..state import State
from ..textrules import SCRIPT_RULES, read_text, scan_text
from ..winutil import in_user_writable
from ..yaraload import load_own, load_pack

NAME = "files"
DESCRIPTION = "YARA + hash + PE analysis of files (quick: user hot spots; full: all fixed drives), resumable"
ORDER = 90
ENGINE_VERSION = "1"

_SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sct"}
_PE_EXT_OK = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".mui", ".pyd", ".node", ".com", ".ax",
              ".acm", ".tlb", ".winmd", ".xll", ".rll", ".ime", ".tsp", ".vst3", ".aex", ".8bf", ".bin", ".dat",
              ".tmp", ".old", ".bak", ".msi", ".msp", ".olb", ".fon", ".so", ".exe_", ".dll_", ""}
_DECOY_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
              ".txt", ".rtf", ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".csv", ".html", ".htm", ".log", ".ico", ".wav"}
_DOUBLE_EXT = re.compile(
    r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|mp[34]|avi|mkv|zip)\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|ps1)$")
_RLO = "‮"
_FILE_ATTRIBUTE_OFFLINE = 0x1000
_FILE_ATTRIBUTE_RECALL = 0x400000 | 0x40000
_ALWAYS_SKIP_DIRS = {"system volume information", "$windows.~bt", "$windows.~ws", "$sysreset"}
_PACKER_SECTIONS = {"upx0", "upx1", ".themida", ".vmp0", ".vmp1", ".aspack", ".mpress1", ".enigma1", ".petite",
                    ".nsp0", ".upack", ".winlice"}
_INJECT = {"virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
           "queueuserapc", "ntunmapviewofsection", "setthreadcontext", "ntwritevirtualmemory"}
_CRED = {"minidumpwritedump", "lsaretrieveprivatedata", "samconnect", "regsavekeyexw", "regsavekeyw"}
_KEYLOG = {"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate"}
_MAGIC = [
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"Rar!", "archive"), (b"7z\xbc\xaf", "archive"),
    (b"\xd0\xcf\x11\xe0", "ole"), (b"%PDF", "pdf"), (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"MSCF", "archive"),
    (b"\x1f\x8b", "archive"),
]


def sniff(head: bytes, ext: str) -> str | None:
    """Kind of file worth a deep scan, or None."""
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if ext in _SCRIPT_EXT:
        return "script"
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def analyse_pe(data: bytes) -> dict:
    """Static PE traits. Returns {} if the file is not a parseable PE."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, Exception):
        return {}
    info: dict = {"signals": []}
    try:
        names = []
        hi_exec = False
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1").lower()
            names.append(name)
            if s.Characteristics & 0x20000000 and s.SizeOfRawData > 4096:
                if entropy(s.get_data()[: 4 * 1024 * 1024]) > 7.2:
                    hi_exec = True
        packer = sorted(set(names) & _PACKER_SECTIONS)
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        imports = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode("latin-1").lower())
        is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0 if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 else False
        info["imports"] = len(imports)
        info["has_cert_table"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0 if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else False
        if packer:
            info["signals"].append(f"pe: packer section names ({', '.join(packer)})")
        elif hi_exec and len(imports) < 10 and not is_dotnet:
            info["signals"].append("pe: high-entropy code section with almost no imports (packed or encrypted)")
        inj = imports & _INJECT
        if "writeprocessmemory" in inj and len(inj) >= 3:
            info["signals"].append("pe: process-injection import chain (" + ", ".join(sorted(inj)) + ")")
        if imports & _CRED and "openprocess" in imports:
            info["signals"].append("pe: credential-dumping imports (" + ", ".join(sorted(imports & _CRED)) + ")")
        if len(imports & _KEYLOG) >= 2:
            info["signals"].append("pe: keyboard-capture imports")
    finally:
        pe.close()
    return info


class Scanner:
    def __init__(self, ctx, res: ModuleResult):
        self.ctx, self.res = ctx, res
        self.max_bytes = ctx.cfg.max_file_mb * 1024 * 1024
        self.own = load_own()
        self.core = None
        self.rules_tag = ENGINE_VERSION
        core_path = ctx.tools.path("yara-forge-core")
        if core_path:
            try:
                self.core, meta = load_pack(core_path, ctx.cfg.state_dir)
                res.coverage["yara_core_rules"] = meta["rules"]
                res.coverage["yara_core_rules_unsupported"] = meta["dropped_unsupported"]
                self.rules_tag += meta["tag"]
            except Exception as e:
                res.note(f"YARA Forge core pack failed to load, built-in rules only: {e}")
        else:
            res.note("YARA Forge core pack not installed (winsentinel tools install); built-in rules only")
        self.lol: dict[str, str] = {}
        for tool, label in (("loldrivers-malicious", "malicious"), ("loldrivers-vulnerable", "vulnerable")):
            p = ctx.tools.path(tool)
            if p:
                for line in p.read_text("ascii", "replace").split():
                    self.lol.setdefault(line.strip().lower(), label)
        if not self.lol:
            res.note("LOLDrivers hash lists not installed; known-vulnerable driver matching skipped")

    def deep(self, path: str, size: int, kind: str, ext: str) -> dict:
        """Runs in a worker thread. Returns a JSON-serialisable result."""
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            return {"error": type(e).__name__}
        out: dict = {"sha256": hashlib.sha256(data).hexdigest(), "signals": [], "yara": [], "kind": kind}
        for rules in (self.own, self.core):
            if rules is None:
                continue
            try:
                for m in rules.match(data=data, timeout=60):
                    out["yara"].append({"rule": m.rule, "score": int(m.meta.get("score", 60) or 60),
                                        "desc": str(m.meta.get("description", ""))[:200]})
            except Exception as e:
                out.setdefault("notes", []).append(f"yara: {type(e).__name__}")
        label = self.lol.get(out["sha256"])
        if label:
            out["loldriver"] = label
        if kind == "pe":
            pe = analyse_pe(data)
            out["signals"] += pe.get("signals", [])
            out["has_cert_table"] = pe.get("has_cert_table", False)
            if ext in _DECOY_EXT:
                out["signals"].append(f"extension mismatch: Windows executable named {ext}")
        elif kind == "script" and size <= 2 * 1024 * 1024:
            hits = scan_text(read_text(data), SCRIPT_RULES)
            out["text"] = [{"id": h.rule.id, "sev": h.rule.severity, "cat": h.rule.category, "signal": h.signal,
                            "line": h.line} for h in hits]
        return out


def _roots(ctx) -> list[Path]:
    if ctx.paths:
        return ctx.paths
    if not ctx.full:
        return [p for p in ctx.cfg.quick_paths if p.exists()]
    try:
        rows = ps_json('Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID', timeout=30)
        return [Path(r["DeviceID"] + "\\") for r in rows]
    except PSError:
        return [Path(os.environ.get("SystemDrive", "C:") + "\\")]


def _walk(roots: list[Path], excludes: list[str], cov: Counter, deadline: float | None):
    """Yield (path, DirEntry stat) for regular files; never follows links or recalls cloud files."""
    stack = [str(r) for r in roots if r.is_dir()]
    for r in roots:
        if r.is_file():
            yield str(r), r.stat()
    while stack:
        if deadline and time.monotonic() > deadline:
            cov["time_budget_hit"] = 1
            cov["dirs_not_reached"] += len(stack)
            return
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            cov["unreadable_dirs"] += 1
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink() or e.is_junction():
                        cov["links_not_followed"] += 1
                        continue
                    if e.is_dir(follow_symlinks=False):
                        low = e.path.lower()
                        if e.name.lower() in _ALWAYS_SKIP_DIRS or any(low == x or low.startswith(x + "\\") for x in excludes):
                            cov["excluded_dirs"] += 1
                            continue
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        if st.st_file_attributes & (_FILE_ATTRIBUTE_OFFLINE | _FILE_ATTRIBUTE_RECALL):
                            cov["cloud_placeholders_skipped"] += 1
                            continue
                        yield e.path, st
                except OSError:
                    cov["unreadable_entries"] += 1


_SYSROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()
_SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe", "wininit.exe",
                    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "explorer.exe", "runtimebroker.exe",
                    "wmiprvse.exe", "dllhost.exe", "sihost.exe", "ctfmon.exe", "rundll32.exe", "lsaiso.exe",
                    "searchindexer.exe", "wudfhost.exe", "fontdrvhost.exe"}
_TRICKS = ("extension mismatch", "double extension", "right-to-left", "masquerade")


def _name_signals(path: str) -> list[str]:
    name = os.path.basename(path)
    out = []
    if _DOUBLE_EXT.search(name):
        out.append("double extension disguises an executable as a document")
    if _RLO in name:
        out.append("right-to-left override character in file name")
    if name.lower() in _SYSTEM_BINARIES and not path.lower().startswith(_SYSROOT + "\\"):
        out.append(f"masquerade: Windows system binary name {name} outside {_SYSROOT}")
    return out


def _severity(r: dict, name_sigs: list[str], path: str) -> tuple[str, list[str], str]:
    """Combine evidence into (severity, signals, title). 'none' means not reportable."""
    signals: list[str] = []
    sev_rank = 0  # 0 none, 1 low, 2 medium, 3 high
    title = "Suspicious file"
    for y in r.get("yara", []):
        signals.append(f"yara: {y['rule']} (score {y['score']}) {y['desc']}".strip())
        sev_rank = max(sev_rank, 3 if y["score"] >= 80 else 2 if y["score"] >= 60 else 1)
        title = f"YARA match: {y['rule']}"
    if r.get("loldriver"):
        signals.append(f"loldriver: SHA256 is on the LOLDrivers {r['loldriver']} list")
        sev_rank = max(sev_rank, 3 if r["loldriver"] == "malicious" else 2)
        title = f"Known {r['loldriver']} driver"
    heur = list(r.get("signals", [])) + name_sigs
    text = r.get("text", [])
    if text:
        top = max({"low": 1, "medium": 2, "high": 3}[t["sev"]] for t in text)
        multi = len({t["cat"] for t in text}) >= 2
        sev_rank = max(sev_rank, 3 if top == 3 or (multi and top == 2) else 2 if multi else top)
        signals += list(dict.fromkeys(t["signal"] for t in text))
        if title == "Suspicious file":
            title = "Script with malware-like behaviour"
    if heur:
        writable = in_user_writable(path)
        strong_trick = any(s.startswith(_TRICKS) for s in heur)
        n = len(heur) + (1 if writable else 0)
        h = 2 if strong_trick else 3 if n >= 3 else 2 if n >= 2 else 0
        if strong_trick and (len(heur) >= 2 or sev_rank >= 2):
            h = 3  # a disguise plus any other evidence
        if h:
            signals += heur + (["file is in a user-writable location"] if writable else [])
            if title == "Suspicious file":
                title = "Disguised executable" if strong_trick else "Executable with malware-like traits"
        sev_rank = max(sev_rank, h)
    return ["none", "low", "medium", "high"][sev_rank], signals, title


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    sc = Scanner(ctx, res)
    roots = _roots(ctx)
    if not roots:
        res.status = "skipped"
        res.notes.append("no scan roots exist")
        return res
    res.coverage["roots"] = ", ".join(str(r) for r in roots)
    excludes = [str(p).lower().rstrip("\\") for p in ctx.cfg.default_excludes()]
    cov: Counter = Counter()
    deadline = None
    if not ctx.full and not ctx.paths:
        deadline = time.monotonic() + ctx.cfg.quick_files_budget_s
    state = State(ctx.cfg.state_dir / "files.db")
    results: list[tuple[str, int, dict]] = []
    pending = []
    last_log = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=max(1, ctx.cfg.threads)) as pool:
            for path, st in _walk(roots, excludes, cov, deadline):
                cov["files_seen"] += 1
                size = st.st_size
                if size < 4:
                    continue
                ext = os.path.splitext(path)[1].lower()
                cached = state.get(path, size, st.st_mtime_ns, sc.rules_tag)
                if cached is not None:
                    cov["from_cache"] += 1
                    results.append((path, size, cached))
                    continue
                try:
                    with open(path, "rb") as fh:
                        head = fh.read(8)
                except OSError:
                    cov["unreadable_files"] += 1
                    continue
                kind = sniff(head, ext)
                if kind is None:
                    cov["not_deep_scanned_inert_type"] += 1
                    continue
                if size > sc.max_bytes:
                    cov["not_deep_scanned_oversize"] += 1
                    cov["oversize_bytes"] += size
                    continue
                pending.append((path, size, st.st_mtime_ns, pool.submit(sc.deep, path, size, kind, ext)))
                if len(pending) >= 256:
                    _drain(pending, results, state, sc.rules_tag, cov)
                if time.monotonic() - last_log > 30:
                    last_log = time.monotonic()
                    ctx.log(f"[files] {cov['files_seen']} files seen, {cov['deep_scanned']} deep-scanned")
            _drain(pending, results, state, sc.rules_tag, cov)
    except KeyboardInterrupt:
        res.note("interrupted: partial results; rerun to resume from the cache")
        _drain(pending, results, state, sc.rules_tag, cov, wait=False)
    finally:
        state.close()

    # Build findings; batch signature checks for PE candidates only.
    cands = []
    for path, size, r in results:
        if "error" in r:
            continue
        sev, signals, title = _severity(r, _name_signals(path), path)
        if sev != "none":
            cands.append((path, size, r, sev, signals, title))
    pe_paths = [c[0] for c in cands if c[2].get("kind") == "pe" and os.path.isfile(c[0])]
    sigs = check_signatures(pe_paths) if pe_paths else {}
    trusted = {s.lower() for s in ctx.cfg.trusted_signers}
    dropped_signed = 0
    for path, size, r, sev, signals, title in cands:
        sig = sigs.get(path)
        strong = any(s.startswith(("yara:", "loldriver:")) for s in signals)
        if sig:
            if sig["status"] == "Valid" and (sig["os_binary"] or sig["signer"].lower() in trusted) and not strong:
                dropped_signed += 1
                continue
            if sig["status"] == "Valid" and not strong:
                sev = "low"
                signals.append(f"validly signed by {sig['signer']}")
            elif sig["status"] == "NotSigned":
                signals.append("authenticode: unsigned")
            elif sig["status"] in ("HashMismatch", "NotTrusted"):
                signals.append(f"authenticode: {sig['status']}")
                sev = "high"
        res.add(rule_id="FILE-" + (r["yara"][0]["rule"] if r.get("yara") else "HEURISTIC"), title=f"{title}: {os.path.basename(path)}",
                severity=sev, evidence=path, why="; ".join(signals), confidence=0.8 if strong else 0.5, signals=signals,
                remediation="Do not open or run it. Check where it came from; upload the SHA256 (not the file) to "
                            "VirusTotal or let Defender scan it; delete it yourself only once you are sure.",
                details={"path": path, "sha256": r["sha256"], "size": size, "key": "file", "kind": r.get("kind"),
                         "line": (r.get("text") or [{}])[0].get("line", 0)})
    cov["signed_by_trusted_publisher_not_reported"] = dropped_signed
    cov["read_errors"] = sum(1 for _, _, r in results if "error" in r)
    res.coverage.update({k: v for k, v in cov.items()})
    res.coverage["max_file_mb"] = ctx.cfg.max_file_mb
    if cov.get("time_budget_hit"):
        res.note(f"quick-scan time budget ({ctx.cfg.quick_files_budget_s}s) reached with {cov['dirs_not_reached']} "
                 "directories not visited; rerun (cache makes it faster) or use --full")
    if cov.get("unreadable_dirs") and not ctx.admin:
        res.note(f"{cov['unreadable_dirs']} directories not readable without admin", partial=False)
    if cov.get("not_deep_scanned_oversize"):
        res.note(f"{cov['not_deep_scanned_oversize']} scannable files over {ctx.cfg.max_file_mb} MB were not scanned", partial=False)
    return res


def _drain(pending: list, results: list, state: State, tag: str, cov: Counter, wait: bool = True) -> None:
    for path, size, mtime_ns, fut in pending:
        if not wait and not fut.done():
            fut.cancel()
            continue
        try:
            r = fut.result()
        except Exception as e:  # one bad file must not stop the scan
            r = {"error": type(e).__name__}
        cov["deep_scanned"] += 1
        if "error" not in r:
            state.put(path, size, mtime_ns, tag, r)
        results.append((path, size, r))
    pending.clear()
