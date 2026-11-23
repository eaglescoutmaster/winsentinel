"""Which operating system this is, and small read-only helpers that differ between them."""
from __future__ import annotations

import os
import platform
import subprocess
import sys

OS = "windows" if sys.platform == "win32" else "macos" if sys.platform == "darwin" else "linux"
_M = platform.machine().lower()
ARCH = "arm64" if _M in ("arm64", "aarch64") else "x64"
POSIX = OS != "windows"


def is_admin() -> bool:
    if OS == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def is_wsl() -> bool:
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def sh(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    """Run a read-only command. Returns (exit code, stdout); (127, '') when the program is missing."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 127, ""
    except (OSError, subprocess.TimeoutExpired):
        return 124, ""
    return p.returncode, p.stdout.decode("utf-8", "replace")


_POSIX_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/", "/users/shared/",
                   "/home/", "/users/", "/root/", "/run/user/")


def posix_user_writable(path: str) -> bool:
    """Heuristic: a location an ordinary user can normally write to."""
    p = path.lower()
    return any(p.startswith(m) for m in _POSIX_WRITABLE)


def posix_temp_like(path: str) -> bool:
    p = path.lower()
    return p.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/", "/users/shared/"))
