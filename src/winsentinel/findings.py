"""Finding model, fingerprints and baseline diffing."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def downgrade(sev: str, steps: int = 1) -> str:
    return SEVERITIES[min(SEV_RANK[sev] + steps, len(SEVERITIES) - 1)]


def cap(sev: str, ceiling: str) -> str:
    """Return sev, but never more severe than ceiling."""
    return sev if SEV_RANK[sev] >= SEV_RANK[ceiling] else ceiling


def redact(secret: str) -> str:
    """Never store a secret value: keep the first 4 characters and the length."""
    s = secret.strip()
    return f"{s[:4]}***({len(s)} chars)"


@dataclass
class Finding:
    module: str
    rule_id: str
    title: str
    severity: str
    evidence: str  # file path, registry key, port, package ...
    why: str
    confidence: float = 0.5
    remediation: str = ""
    # "fact" = deterministic state read directly from the system;
    # "heuristic" = inferred, subject to the verification pass.
    kind: str = "heuristic"
    signals: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    verification: str = ""
    status: str = "new"  # new | changed | known (relative to baseline)

    def __post_init__(self) -> None:
        if self.severity not in SEV_RANK:
            raise ValueError(f"bad severity {self.severity!r}")

    @property
    def fingerprint(self) -> str:
        key = "|".join(
            [self.module, self.rule_id, self.evidence.lower(), str(self.details.get("key", ""))]
        )
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]

    @property
    def content_hash(self) -> str:
        blob = json.dumps(
            [self.severity, self.why, self.details.get("sha256", ""), self.details.get("value", "")],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:20]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class ModuleResult:
    name: str
    status: str = "ok"  # ok | partial | skipped | error
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    duration_s: float = 0.0

    def note(self, msg: str, partial: bool = True) -> None:
        self.notes.append(msg)
        if partial and self.status == "ok":
            self.status = "partial"

    def add(self, **kw) -> Finding:
        f = Finding(module=self.name, **kw)
        self.findings.append(f)
        return f


def apply_baseline(findings: list[Finding], baseline_path: Path, update: bool) -> dict:
    """Mark findings new/changed/known. Baseline is created on the first run and
    afterwards only rewritten when update=True."""
    existed = baseline_path.exists()
    base: dict[str, str] = {}
    if existed:
        try:
            base = json.loads(baseline_path.read_text("utf-8")).get("findings", {})
        except (OSError, ValueError):
            base = {}
    current: dict[str, str] = {}
    for f in findings:
        current[f.fingerprint] = f.content_hash
        if f.fingerprint not in base:
            f.status = "new"
        elif base[f.fingerprint] != f.content_hash:
            f.status = "changed"
        else:
            f.status = "known"
    resolved = sorted(set(base) - set(current))
    wrote = False
    if update or not existed:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps({"findings": current}, indent=1), "utf-8")
        wrote = True
    return {"existed": existed, "written": wrote, "resolved": len(resolved)}
