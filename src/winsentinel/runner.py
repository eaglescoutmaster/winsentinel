"""Scan context and module runner."""
from __future__ import annotations

import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .findings import ModuleResult
from .toolchain import Toolchain


@dataclass
class Context:
    cfg: Config
    mode: str  # quick | full
    admin: bool
    tools: Toolchain
    report_dir: Path
    paths: list[Path] = field(default_factory=list)  # --path overrides
    vt: bool = False
    defender_scan: bool = False
    explicit: set[str] = field(default_factory=set)  # modules named with --module
    results: dict[str, ModuleResult] = field(default_factory=dict)

    @property
    def full(self) -> bool:
        return self.mode == "full"

    def log(self, msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)


def run_modules(ctx: Context, names: list[str]) -> list[ModuleResult]:
    from .modules import REGISTRY

    out: list[ModuleResult] = []
    for name in names:
        mod = REGISTRY[name]
        ctx.log(f"[{name}] start")
        t0 = time.monotonic()
        try:
            res = mod.run(ctx)
        except KeyboardInterrupt:
            res = ModuleResult(name, status="partial", notes=["interrupted by user"])
            res.duration_s = time.monotonic() - t0
            ctx.results[name] = res
            out.append(res)
            ctx.log(f"[{name}] interrupted; writing partial report")
            break
        except Exception as e:  # a broken module must not kill the scan
            tb = traceback.format_exc(limit=3)
            res = ModuleResult(name, status="error", notes=[f"{type(e).__name__}: {e}", tb])
        res.duration_s = time.monotonic() - t0
        ctx.results[name] = res
        out.append(res)
        ctx.log(f"[{name}] {res.status}: {len(res.findings)} findings in {res.duration_s:.1f}s")
    return out
