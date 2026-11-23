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


def default_quick_paths() -> list[Path]:
    """Hot spots the quick file scan covers: where downloads land and where things start from."""
    import sys

    if sys.platform == "win32":
        return [
            HOME / "Downloads",
            HOME / "Desktop",
            _env("TEMP", str(HOME / "AppData/Local/Temp")),
            _env("APPDATA", str(HOME / "AppData/Roaming")) / "Microsoft/Windows/Start Menu/Programs/Startup",
            _env("PROGRAMDATA", "C:/ProgramData") / "Microsoft/Windows/Start Menu/Programs/Startup",
            _env("PUBLIC", "C:/Users/Public"),
        ]
    common = [HOME / "Downloads", HOME / "Desktop", Path("/tmp"), Path("/var/tmp")]
    if sys.platform == "darwin":
        return common + [HOME / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"),
                         Path("/Users/Shared"), HOME / "Library/Application Support/com.apple.backgroundtaskmanagementagent"]
    return common + [Path("/dev/shm"), HOME / ".config/autostart", HOME / ".local/bin", Path("/usr/local/bin"),
                     Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly")]


def discover_code_dirs(limit: int = 12) -> list[Path]:
    """Default code directories: the most recently modified git repositories directly under the
    usual project folders. Override with code_dirs in winsentinel.toml."""
    roots = [HOME, HOME / "source" / "repos", HOME / "Documents" / "GitHub", HOME / "projects", HOME / "code",
             HOME / "dev", HOME / "repos", HOME / "src"]
    out: list[Path] = []
    for root in roots:
        try:
            for d in sorted(root.iterdir()):
                if d.is_dir() and not d.name.startswith(".") and (d / ".git").exists() and d.resolve() != REPO_ROOT and d not in out:
                    out.append(d)
        except OSError:
            continue

    def mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0

    return sorted(out, key=mtime, reverse=True)[:limit]


@dataclass
class Config:
    data_dir: Path = REPO_ROOT
    code_dirs: list[Path] = field(default_factory=lambda: discover_code_dirs())
    # files module
    exclude_paths: list[Path] = field(default_factory=list)
    max_file_mb: int = 64
    quick_paths: list[Path] = field(default_factory=lambda: default_quick_paths())
    quick_files_budget_s: int = 180
    threads: int = field(default_factory=lambda: min(16, os.cpu_count() or 4))
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
