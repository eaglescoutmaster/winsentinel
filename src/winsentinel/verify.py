"""Second look at every high/critical heuristic finding before it is reported.

Deterministic checks only:
  1. A heuristic high/critical needs at least two independent signals.
  2. If the finding points at a file, its Authenticode signature (embedded or
     catalog) is re-checked; a valid signature from a trusted signer or an OS
     catalog binary downgrades it, any other valid signature caps it at medium
     unless a signature-grade signal (YARA/hash/Defender) is present.
  3. Evidence under test/fixture/sample directories is capped at medium.
  4. A matching Microsoft Defender detection confirms the finding.
"fact" findings are direct reads of system state and are not second-guessed.
"""
from __future__ import annotations

import os
import re

from .findings import SEV_RANK, Finding, cap, downgrade
from .trust import check_trust

_FIXTURE_RE = re.compile(r"[\\/](tests?|fixtures?|testdata|examples?|samples?|testskills|__tests__|pytest-of-[^\\/]+)[\\/]", re.I)
STRONG_PREFIXES = ("yara:", "hash:", "defender:", "loldriver:")


def _has_strong(f: Finding) -> bool:
    return any(s.startswith(STRONG_PREFIXES) for s in f.signals)


def verify_findings(findings: list[Finding], trusted_signers: list[str],
                    defender_paths: set[str] | None = None, sigcheck=check_trust) -> int:
    """Mutates findings in place. Returns how many were downgraded."""
    targets = [f for f in findings if SEV_RANK[f.severity] <= SEV_RANK["high"]]
    for f in targets:
        if f.kind == "fact":
            f.verification = "fact: read directly from system state"
    heur = [f for f in targets if f.kind != "fact"]
    paths = [f.details["path"] for f in heur if f.details.get("path") and os.path.isfile(f.details["path"])]
    sigs = sigcheck(paths) if paths else {}
    trusted = {s.lower() for s in trusted_signers}
    defender_paths = {p.lower() for p in (defender_paths or set())}
    changed = 0
    for f in heur:
        before = f.severity
        notes: list[str] = []
        path = f.details.get("path", "")
        if path and path.lower() in defender_paths:
            f.signals.append("defender: Microsoft Defender detected this path")
            notes.append("confirmed by Defender detection")
        strong = _has_strong(f)
        if len(f.signals) < 2 and not strong:
            f.severity = cap(f.severity, "medium")
            notes.append("single weak signal")
        sig = sigs.get(path)
        if sig:
            f.details["signature"] = sig
            if sig["status"] == "Valid":
                if sig["os_binary"] or sig["signer"].lower() in trusted:
                    f.severity = cap(f.severity, "low")
                    notes.append(f"valid signature from trusted signer ({sig['signer'] or 'OS catalog'})")
                elif not strong:
                    f.severity = cap(f.severity, "medium")
                    notes.append(f"validly signed by {sig['signer']}")
                else:
                    notes.append(f"validly signed by {sig['signer']} but signature-grade signal present")
            elif sig["status"] in ("HashMismatch", "NotTrusted"):
                f.signals.append(f"authenticode: {sig['status']}")
                notes.append(f"signature status {sig['status']}")
            elif sig["status"] == "NotSigned":
                notes.append("unsigned")
        if path and _FIXTURE_RE.search(path) and not (path.lower() in defender_paths):
            f.severity = cap(f.severity, "medium")
            notes.append("located in a test/fixture/example directory")
        if f.severity != before:
            changed += 1
            f.confidence = round(f.confidence * 0.6, 2)
            f.verification = f"downgraded from {before}: " + "; ".join(notes)
        else:
            f.verification = "kept: " + ("; ".join(notes) or f"{len(f.signals)} independent signals")
    return changed


__all__ = ["verify_findings", "downgrade"]
