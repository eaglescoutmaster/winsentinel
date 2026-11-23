"""Pinned external tools and signature data.

Everything is downloaded from the vendor's official GitHub release (or a pinned
commit), checked against the SHA256 recorded here, and unpacked into
<data_dir>/tools/<name>/<version>/. Nothing is installed system-wide and
nothing is fetched at scan time.
"""
from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

_GH = "https://github.com"
_LOL = "39c70ca64ae9b66650e2c50e011eec6f7354e9cf"
_LOL_RAW = f"https://raw.githubusercontent.com/magicsword-io/LOLDrivers/{_LOL}/detections/hashes"


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    url: str
    sha256: str
    kind: str  # zip | tgz | raw
    member: str  # archive member (suffix match) or "" for raw
    filename: str  # name on disk


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool("gitleaks", "8.30.1",
             f"{_GH}/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
             "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
             "zip", "gitleaks.exe", "gitleaks.exe"),
        Tool("trufflehog", "3.100.0",
             f"{_GH}/trufflesecurity/trufflehog/releases/download/v3.100.0/trufflehog_3.100.0_windows_amd64.tar.gz",
             "e3e854ded5b19ce1312fd103f3ca898f367e99f24f27c1170a711e0e9288f86d",
             "tgz", "trufflehog.exe", "trufflehog.exe"),
        Tool("osv-scanner", "2.7.1",
             f"{_GH}/google/osv-scanner/releases/download/v2.7.1/osv-scanner_windows_amd64.exe",
             "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800",
             "raw", "", "osv-scanner.exe"),
        # Trivy >= 0.70 required: earlier release channels were hit by CVE-2026-33634.
        Tool("trivy", "0.76.2",
             f"{_GH}/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_windows-64bit.zip",
             "691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6",
             "zip", "trivy.exe", "trivy.exe"),
        Tool("yara-forge-core", "20261122",
             f"{_GH}/YARAHQ/yara-forge/releases/download/20261122/yara-forge-rules-core.zip",
             "f88eb4ea361a4636021513dd71c3dfde0ca7af8d51e43ac9ccdfec9530dc3737",
             "zip", "yara-rules-core.yar", "yara-rules-core.yar"),
        Tool("loldrivers-vulnerable", _LOL[:12], f"{_LOL_RAW}/samples_vulnerable.sha256",
             "51c5529853d1bd343ea4039c6aba7ad4e33fcfb27855bb3a0cbcf1d54fb399eb",
             "raw", "", "samples_vulnerable.sha256"),
        Tool("loldrivers-malicious", _LOL[:12], f"{_LOL_RAW}/samples_malicious.sha256",
             "d64991526a7ac497970a0d9c23cdcfc9a1a6a81df11247926d86061fdee933ec",
             "raw", "", "samples_malicious.sha256"),
    ]
}

_ALLOWED_HOSTS = ("https://github.com/", "https://raw.githubusercontent.com/")
_MAX_DOWNLOAD = 400 * 1024 * 1024


class ToolError(RuntimeError):
    pass


class Toolchain:
    def __init__(self, tools_dir: Path):
        self.dir = tools_dir

    def path(self, name: str) -> Path | None:
        t = TOOLS[name]
        p = self.dir / t.name / t.version / t.filename
        return p if p.is_file() else None

    def status(self) -> dict[str, str]:
        return {n: (str(self.path(n)) if self.path(n) else "missing") for n in TOOLS}

    def install(self, name: str, log=print) -> Path:
        t = TOOLS[name]
        existing = self.path(name)
        if existing:
            return existing
        if not t.url.startswith(_ALLOWED_HOSTS):
            raise ToolError(f"{name}: download host not allowed")
        log(f"downloading {name} {t.version}")
        req = urllib.request.Request(t.url, headers={"User-Agent": "winsentinel"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read(_MAX_DOWNLOAD + 1)
        if len(data) > _MAX_DOWNLOAD:
            raise ToolError(f"{name}: download too large")
        digest = hashlib.sha256(data).hexdigest()
        if digest != t.sha256:
            raise ToolError(f"{name}: SHA256 mismatch (got {digest}, pinned {t.sha256}); not installed")
        payload = self._extract(t, data)
        dest = self.dir / t.name / t.version / t.filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)  # fixed destination name: archive paths are never trusted
        log(f"installed {dest}")
        return dest

    @staticmethod
    def _extract(t: Tool, data: bytes) -> bytes:
        if t.kind == "raw":
            return data
        if t.kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = [n for n in z.namelist() if n.replace("\\", "/").split("/")[-1] == t.member]
                if len(names) != 1:
                    raise ToolError(f"{t.name}: expected one {t.member} in archive, found {len(names)}")
                return z.read(names[0])
        if t.kind == "tgz":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                members = [m for m in tf.getmembers() if m.isfile() and m.name.split("/")[-1] == t.member]
                if len(members) != 1:
                    raise ToolError(f"{t.name}: expected one {t.member} in archive, found {len(members)}")
                f = tf.extractfile(members[0])
                assert f is not None
                return f.read()
        raise ToolError(f"{t.name}: unknown archive kind {t.kind}")

    def run(self, name: str, args: list[str], timeout: int = 600, cwd: Path | None = None,
            env: dict | None = None) -> subprocess.CompletedProcess:
        exe = self.path(name)
        if not exe:
            raise ToolError(f"{name} not installed (run: winsentinel tools install)")
        try:
            return subprocess.run(
                [str(exe), *args], capture_output=True, timeout=timeout, cwd=cwd, env=env,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as e:
            raise ToolError(f"{name}: timeout after {timeout}s") from e
