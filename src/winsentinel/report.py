"""report.md, findings.json and SARIF 2.1.0 writers."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import __version__
from .findings import SEV_RANK, SEVERITIES, Finding, ModuleResult

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SCORE = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "0.0"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEV_RANK[f.severity], -f.confidence, f.module, f.evidence))


def _md(s: object) -> str:
    return str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def write_json(path: Path, meta: dict, results: list[ModuleResult], findings: list[Finding]) -> None:
    doc = {
        "meta": meta,
        "modules": [
            {
                "name": r.name,
                "status": r.status,
                "notes": r.notes,
                "coverage": r.coverage,
                "duration_s": round(r.duration_s, 1),
                "findings": len(r.findings),
            }
            for r in results
        ],
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    path.write_text(json.dumps(doc, indent=1, default=str), "utf-8")


def write_sarif(path: Path, findings: list[Finding]) -> None:
    rules: dict[str, dict] = {}
    results = []
    for f in sort_findings(findings):
        rid = f"{f.module}/{f.rule_id}"
        rules.setdefault(
            rid,
            {
                "id": rid,
                "shortDescription": {"text": f.title},
                "properties": {"security-severity": _SARIF_SCORE[f.severity]},
            },
        )
        res = {
            "ruleId": rid,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.why}"},
            "partialFingerprints": {"winsentinel/v1": f.fingerprint},
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "status": f.status,
                "verification": f.verification,
            },
        }
        p = f.details.get("path")
        if p:
            loc = {"artifactLocation": {"uri": Path(p).as_uri() if Path(p).is_absolute() else str(p)}}
            if f.details.get("line"):
                loc["region"] = {"startLine": int(f.details["line"])}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "winsentinel", "version": __version__, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=1, default=str), "utf-8")


def _finding_md(f: Finding) -> list[str]:
    lines = [
        f"### [{f.severity.upper()}] {f.title}",
        "",
        f"- **Module / rule:** `{f.module}` / `{f.rule_id}` ({f.status})",
        f"- **Evidence:** `{f.evidence}`",
        f"- **Why flagged:** {f.why}",
        f"- **Confidence:** {f.confidence:.2f} ({f.kind})",
    ]
    if f.signals:
        lines.append(f"- **Signals:** {'; '.join(f.signals)}")
    if f.verification:
        lines.append(f"- **Verification:** {f.verification}")
    if f.remediation:
        lines.append(f"- **Suggested manual remediation:** {f.remediation}")
    lines.append("")
    return lines


def write_markdown(
    path: Path, meta: dict, results: list[ModuleResult], findings: list[Finding], baseline: dict
) -> None:
    fs = sort_findings(findings)
    fresh = [f for f in fs if f.status != "known"]
    known = [f for f in fs if f.status == "known"]
    out: list[str] = [
        "# winsentinel report",
        "",
        f"- **Generated:** {meta['started']}  |  **Mode:** {meta['mode']}  |  **Admin:** {meta['admin']}",
        f"- **Host:** {meta['host']}  |  **winsentinel:** {__version__}",
        "",
        "> Read-only scan. Nothing was deleted, quarantined or changed. This tool is not a "
        "replacement for antivirus or EDR; absence of findings is not proof of a clean machine.",
        "",
        "## Summary",
        "",
        "| Severity | New / changed | Known (baseline) |",
        "|---|---|---|",
    ]
    for s in SEVERITIES:
        out.append(f"| {s} | {sum(f.severity == s for f in fresh)} | {sum(f.severity == s for f in known)} |")
    out.append("")
    if not baseline.get("existed"):
        out.append("No baseline existed; this run created it. Later runs show only new or changed findings in detail.")
    else:
        out.append(
            f"Compared with baseline: {len(fresh)} new or changed, {len(known)} known, "
            f"{baseline.get('resolved', 0)} no longer present."
            + (" Baseline updated." if baseline.get("written") else " Baseline not modified (use --update-baseline).")
        )
    out += ["", "## Coverage", "", "| Module | Status | Findings | Time | Notes |", "|---|---|---|---|---|"]
    for r in results:
        notes = "; ".join(n.splitlines()[0] for n in r.notes) or "-"
        out.append(f"| {r.name} | {r.status} | {len(r.findings)} | {r.duration_s:.0f}s | {_md(notes)} |")
    out.append("")
    for r in results:
        if r.coverage:
            cov = ", ".join(f"{k}={v}" for k, v in r.coverage.items())
            out.append(f"- **{r.name}:** {_md(cov)}")
    skipped = [m for m in meta.get("not_run", [])]
    if skipped:
        out.append(f"- **Not selected this run:** {', '.join(skipped)}")
    out += ["", "## New and changed findings", ""]
    if not fresh:
        out.append("None.")
    detailed = [f for f in fresh if f.severity != "info"]
    for f in detailed:
        out += _finding_md(f)
    info = [f for f in fresh if f.severity == "info"]
    if info:
        out += ["### Informational", "", "| Module | Title | Evidence |", "|---|---|---|"]
        out += [f"| {f.module} | {_md(f.title)} | `{_md(f.evidence)}` |" for f in info]
        out.append("")
    if known:
        out += ["## Known findings (unchanged since baseline)", "", "| Severity | Module | Title | Evidence |", "|---|---|---|---|"]
        out += [f"| {f.severity} | {f.module} | {_md(f.title)} | `{_md(f.evidence)}` |" for f in known]
        out.append("")
    path.write_text("\n".join(out) + "\n", "utf-8")


def new_report_dir(root: Path) -> Path:
    d = root / datetime.now().strftime("%Y%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    return d
