"""Static analysis of your own projects with Semgrep.

Semgrep is run from an isolated, version-pinned environment via `uv tool run`
(nothing is installed system-wide). Rule packs come from the Semgrep registry;
metrics are off, so no code or findings leave the machine.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import CODE_SKIP_DIRS, LOCK_FILES
from ..findings import ModuleResult

NAME = "code"
DESCRIPTION = "Semgrep (security-audit + OWASP Top 10 packs) over your project directories; --full only unless selected"
ORDER = 80

SEMGREP_VERSION = "1.186.0"
SEMGREP_PYTHON = "3.13"
_PACKS = ["p/security-audit", "p/owasp-top-ten"]
_TESTY = re.compile(r"(?i)(^|[\\/])(tests?|__tests__|fixtures?|examples?|samples?|benches|fuzz|docs?)[\\/]|[._]test\.|_test\.|\.spec\.")


def _semgrep_cmd() -> list[str] | None:
    uv = shutil.which("uv")
    if not uv:
        return None
    return [uv, "tool", "run", "--python", SEMGREP_PYTHON, "--from", f"semgrep=={SEMGREP_VERSION}", "semgrep"]


def run_semgrep(target: Path, timeout: int = 3600) -> tuple[list[dict], list[str]]:
    base = _semgrep_cmd()
    if base is None:
        raise RuntimeError("uv not found on PATH")
    args = [*base, "scan", "--metrics=off", "--json", "--quiet", "--disable-version-check", "--timeout", "20",
            "--max-target-bytes", "1000000"]
    for p in _PACKS:
        args += ["--config", p]
    for d in sorted(CODE_SKIP_DIRS):
        args += ["--exclude", d]
    for f in sorted(LOCK_FILES):
        args += ["--exclude", f]
    args.append(str(target))
    env = dict(os.environ, PYTHONUTF8="1", SEMGREP_SEND_METRICS="off")
    p = subprocess.run(args, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env)
    out = p.stdout.decode("utf-8", "replace")
    start = out.find("{")
    if start < 0:
        raise RuntimeError(f"semgrep exit {p.returncode}: {p.stderr.decode('utf-8', 'replace')[-400:]}")
    data = json.loads(out[start:])
    errors = [str(e.get("message", e))[:200] for e in data.get("errors") or []]
    return data.get("results") or [], errors


def summarise(res: ModuleResult, target: Path, results: list[dict]) -> None:
    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(r.get("check_id", "?"), []).append(r)
    for check, items in groups.items():
        extra = items[0].get("extra") or {}
        meta = extra.get("metadata") or {}
        level = str(extra.get("severity", "WARNING")).upper()
        conf = str(meta.get("confidence", "")).upper()
        impact = str(meta.get("impact", "")).upper()
        sev = {"ERROR": "medium", "WARNING": "low", "INFO": "info"}.get(level, "low")
        if level == "ERROR" and conf == "HIGH" and impact == "HIGH":
            sev = "high"
        real = [i for i in items if not _TESTY.search(i.get("path", ""))]
        signals = [f"semgrep: {check}", f"rule severity {level}, confidence {conf or 'n/a'}, impact {impact or 'n/a'}"]
        if not real:
            sev = "low" if sev != "info" else "info"
            signals.append("all matches are in test/example/doc paths")
        locs = [f"{Path(i.get('path', '')).as_posix()}:{(i.get('start') or {}).get('line', 0)}" for i in (real or items)]
        cwe = meta.get("cwe")
        cwe = ", ".join(cwe) if isinstance(cwe, list) else str(cwe or "")
        first = (real or items)[0]
        res.add(rule_id="CODE-" + check.split(".")[-1][:60], title=f"{check.split('.')[-1]} ({len(items)}x) in {target.name}",
                severity=sev, evidence=f"{first.get('path')}:{(first.get('start') or {}).get('line', 0)}",
                why=f"{str(extra.get('message', '')).strip()[:300]} {('[' + cwe[:80] + '] ') if cwe else ''}"
                    f"Locations: {', '.join(locs[:6])}" + (f" (+{len(locs) - 6} more)" if len(locs) > 6 else ""),
                confidence={"HIGH": 0.8, "MEDIUM": 0.6}.get(conf, 0.4), signals=signals,
                remediation="Open the first location, confirm untrusted input can reach it, and apply the rule's "
                            "suggested fix. Static analysis reports patterns, not proven exploits.",
                details={"key": f"{target.name}|{check}", "source_file": first.get("path", ""),
                         "line": (first.get("start") or {}).get("line", 0), "value": str(len(items)), "check_id": check})


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    if not ctx.full and NAME not in ctx.explicit:
        res.status = "skipped"
        res.notes.append("code analysis runs in --full, or with --module code")
        return res
    if _semgrep_cmd() is None:
        res.status = "skipped"
        res.notes.append("uv not found: Semgrep cannot be run")
        return res
    # Canary: a scanner that silently finds nothing would look like clean code.
    try:
        with tempfile.TemporaryDirectory(prefix="ws-sg-") as td:
            (Path(td) / "canary.py").write_text(
                "import subprocess, sys\nsubprocess.call('ls ' + sys.argv[1], shell=True)\n", "utf-8")
            canary, _ = run_semgrep(Path(td), timeout=900)
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        canary = []
        res.note(f"semgrep preflight error: {str(e)[:300]}")
    if not canary:
        res.status = "error"
        res.notes.append("semgrep BROKEN: it did not flag the planted canary (rule download blocked?); projects NOT analysed")
        return res
    res.coverage["tool_preflight"] = "semgrep=OK"
    targets = ctx.paths or [d for d in ctx.cfg.code_dirs if d.is_dir()]
    done = 0
    for t in targets:
        ctx.log(f"[code] semgrep {t}")
        try:
            results, errors = run_semgrep(t)
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            res.note(f"semgrep failed on {t.name}: {str(e)[:300]}")
            continue
        done += 1
        if errors:
            res.note(f"{t.name}: {len(errors)} files/rules had semgrep errors (first: {errors[0]})", partial=False)
        summarise(res, t, results)
    res.coverage["projects_scanned"] = done
    res.coverage["semgrep"] = f"{SEMGREP_VERSION} ({', '.join(_PACKS)}), metrics off"
    if targets and done == 0:
        res.status = "error"
    return res
