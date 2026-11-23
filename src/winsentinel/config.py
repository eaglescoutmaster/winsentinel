"""Configuration: defaults merged with an optional winsentinel.toml."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path.home()
REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories never descended into by the code/secrets modules (the files module
# still scans them for malware).
CODE_SKIP_DIRS = {"node_modules", "target", ".venv", "venv", "dist", "build", "__pycache__", ".git"}
LOCK_FILES = {
    "cargo.lock", "package-lock.json", "yarn.lock", "pdm.lock", "poetry.lock",
    "pnpm-lock.yaml", "uv.lock", "composer.lock", "gemfile.lock",
}


def _env(name: str, default: str = "") -> Path:
    return Path(os.environ.get(name, default))


@dataclass
class Config:
    data_dir: Path = REPO_ROOT
    code_dirs: list[Path] = field(
        default_factory=lambda: [HOME / "agentroom", HOME / "TwoAI", HOME / "OpenManus", HOME / "AI Coder"]
    )
    # files module
    exclude_paths: list[Path] = field(default_factory=list)
    max_file_mb: int = 64
    quick_paths: list[Path] = field(
        default_factory=lambda: [
            HOME / "Downloads",
            HOME / "Desktop",
            _env("TEMP", str(HOME / "AppData/Local/Temp")),
            _env("APPDATA", str(HOME / "AppData/Roaming")) / "Microsoft/Windows/Start Menu/Programs/Startup",
            _env("PROGRAMDATA", "C:/ProgramData") / "Microsoft/Windows/Start Menu/Programs/Startup",
            _env("PUBLIC", "C:/Users/Public"),
        ]
    )
    quick_files_budget_s: int = 180
    threads: int = 6
    # ai-tooling module
    ai_dirs: list[Path] = field(default_factory=lambda: [HOME / ".claude"])
    ai_files: list[Path] = field(default_factory=lambda: [HOME / ".claude.json"])
    # secrets module: extra dotfiles / history checked for plaintext credentials
    trusted_signers: list[str] = field(
        default_factory=lambda: ["Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher"]
    )

    @property
    def tools_dir(self) -> Path:
        return self.data_dir / "tools"

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def default_excludes(self) -> list[Path]:
        # Own tools/reports/state hold signatures and evidence that would self-match.
        return [self.tools_dir, self.reports_dir, self.state_dir, *self.exclude_paths]


def load_config(path: Path | None = None) -> Config:
    cfg = Config()
    path = path or (REPO_ROOT / "winsentinel.toml")
    if not path.exists():
        return cfg
    raw = tomllib.loads(path.read_text("utf-8"))
    for key in ("code_dirs", "exclude_paths", "quick_paths", "ai_dirs", "ai_files"):
        if key in raw:
            setattr(cfg, key, [Path(os.path.expandvars(p)).expanduser() for p in raw[key]])
    for key in ("max_file_mb", "quick_files_budget_s", "threads"):
        if key in raw:
            setattr(cfg, key, int(raw[key]))
    if "trusted_signers" in raw:
        cfg.trusted_signers = list(raw["trusted_signers"])
    if "data_dir" in raw:
        cfg.data_dir = Path(os.path.expandvars(raw["data_dir"])).expanduser()
    return cfg
