from __future__ import annotations

from pathlib import Path

import pytest

from winsentinel.config import Config
from winsentinel.runner import Context
from winsentinel.toolchain import Toolchain

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def ctx(tmp_path):
    """A scan context whose state/reports live in tmp_path but which reuses the repo's installed tools."""
    cfg = Config(data_dir=tmp_path)
    cfg.code_dirs = []
    cfg.quick_paths = []
    report_dir = tmp_path / "reports" / "t"
    report_dir.mkdir(parents=True)
    return Context(cfg=cfg, mode="quick", admin=False, tools=Toolchain(REPO / "tools"), report_dir=report_dir)


def no_sigcheck(paths, chunk=200):
    return {p: {"status": "NotSigned", "signer": "", "os_binary": False} for p in paths}
