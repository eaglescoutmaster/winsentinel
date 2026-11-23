"""Who vouches for a file, per operating system.

Every backend returns {path: {"status", "signer", "os_binary"}} so callers stay the same:
  Windows  Authenticode (embedded or catalog).
  macOS    codesign: Valid / NotSigned / HashMismatch; os_binary when Apple signed it.
  Linux    there is no code signing, so the nearest thing is package ownership: a file owned by an
           installed dpkg/rpm package is "Valid" with os_binary True. This proves where the path came
           from, not that the bytes are unchanged; package integrity is checked separately in vulns.
"""
from __future__ import annotations

import re
import shutil

from .osinfo import OS, sh

_UNKNOWN = {"status": "Unknown", "signer": "", "os_binary": False}


def _linux(paths: list[str]) -> dict[str, dict]:
    out = {p: dict(_UNKNOWN, status="Unpackaged") for p in paths}
    if shutil.which("dpkg-query"):
        for i in range(0, len(paths), 100):
            part = paths[i: i + 100]
            _, text = sh(["dpkg-query", "-S", *part], timeout=120)
            for line in text.splitlines():
                pkg, _, path = line.partition(": ")
                if path in out:
                    out[path] = {"status": "Valid", "signer": "dpkg:" + pkg.split(":")[0].split(",")[0], "os_binary": True}
    elif shutil.which("rpm"):
        for p in paths:
            rc, text = sh(["rpm", "-qf", "--qf", "%{NAME}\n", p], timeout=30)
            if rc == 0 and text.strip():
                out[p] = {"status": "Valid", "signer": "rpm:" + text.split()[0], "os_binary": True}
    else:
        out = {p: dict(_UNKNOWN) for p in paths}
    return out


_AUTH = re.compile(r"(?m)^Authority=(.+)$")
_TEAM = re.compile(r"(?m)^TeamIdentifier=(.+)$")


def _macos(paths: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in paths:
        # codesign prints its details on stderr; -v verifies the seal as well as showing it.
        import subprocess

        try:
            r = subprocess.run(["codesign", "-dv", "--verbose=2", p], capture_output=True, timeout=30,
                               stdin=subprocess.DEVNULL)
            v = subprocess.run(["codesign", "--verify", p], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            out[p] = dict(_UNKNOWN)
            continue
        info = r.stderr.decode("utf-8", "replace")
        if r.returncode != 0 or "not signed" in info:
            out[p] = {"status": "NotSigned", "signer": "", "os_binary": False}
            continue
        auth = _AUTH.findall(info)
        signer = auth[0] if auth else ("adhoc" if "Signature=adhoc" in info else "")
        team = _TEAM.search(info)
        apple = bool(auth) and auth[0] == "Software Signing" or (team and team.group(1).strip() == "not set" and
                                                                  "Apple" in " ".join(auth))
        status = "Valid" if v.returncode == 0 else "HashMismatch"
        if signer == "adhoc":
            status = "NotSigned"  # ad-hoc signatures identify nobody
        out[p] = {"status": status, "signer": signer, "os_binary": bool(apple)}
    return out


def check_trust(paths: list[str], chunk: int = 200) -> dict[str, dict]:
    uniq = list(dict.fromkeys(paths))
    if not uniq:
        return {}
    if OS == "windows":
        from .pshelper import check_signatures

        return check_signatures(uniq, chunk)
    return _macos(uniq) if OS == "macos" else _linux(uniq)


def trust_label() -> str:
    return {"windows": "Authenticode", "macos": "code signature", "linux": "package ownership"}[OS]
