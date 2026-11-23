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

from .osinfo import ARCH, OS

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


_GL = f"{_GH}/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_"
_TH = f"{_GH}/trufflesecurity/trufflehog/releases/download/v3.100.0/trufflehog_3.100.0_"
_OSV = f"{_GH}/google/osv-scanner/releases/download/v2.7.1/osv-scanner_"
# Trivy >= 0.70 required: earlier release channels were hit by CVE-2026-33634.
_TV = f"{_GH}/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_"

# (name, version) -> {(os, arch): (url, sha256, kind)}. Digests are the ones GitHub publishes for each asset.
_BINARIES: dict[tuple[str, str], dict[tuple[str, str], tuple[str, str, str]]] = {
    ("gitleaks", "8.30.1"): {
        ("windows", "x64"): (_GL + "windows_x64.zip", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e", "zip"),
        ("linux", "x64"): (_GL + "linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", "tgz"),
        ("linux", "arm64"): (_GL + "linux_arm64.tar.gz", "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080", "tgz"),
        ("macos", "x64"): (_GL + "darwin_x64.tar.gz", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709", "tgz"),
        ("macos", "arm64"): (_GL + "darwin_arm64.tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5", "tgz"),
    },
    ("trufflehog", "3.100.0"): {
        ("windows", "x64"): (_TH + "windows_amd64.tar.gz", "e3e854ded5b19ce1312fd103f3ca898f367e99f24f27c1170a711e0e9288f86d", "tgz"),
        ("linux", "x64"): (_TH + "linux_amd64.tar.gz", "b2d85eba59865e98f45c9fc9f77d2c6d62df529fdd5755af121304ea5a7cecbb", "tgz"),
        ("linux", "arm64"): (_TH + "linux_arm64.tar.gz", "aa61657049229ae523e8455fcbba87dff57b0a2ba6bdb391a38cf75e6d4016dd", "tgz"),
        ("macos", "x64"): (_TH + "darwin_amd64.tar.gz", "e69972286bf313d551ad976b75da5395dc660ff316e2db9660e841e328c96210", "tgz"),
        ("macos", "arm64"): (_TH + "darwin_arm64.tar.gz", "fb326527959216a858636640adcfb93720bb09a7d7e727237c1244cdb3af4ac3", "tgz"),
    },
    ("osv-scanner", "2.7.1"): {
        ("windows", "x64"): (_OSV + "windows_amd64.exe", "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800", "raw"),
        ("linux", "x64"): (_OSV + "linux_amd64", "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8", "raw"),
        ("linux", "arm64"): (_OSV + "linux_arm64", "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81", "raw"),
        ("macos", "x64"): (_OSV + "darwin_amd64", "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b", "raw"),
        ("macos", "arm64"): (_OSV + "darwin_arm64", "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3", "raw"),
    },
    ("trivy", "0.76.2"): {
        ("windows", "x64"): (_TV + "windows-64bit.zip", "691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6", "zip"),
        ("linux", "x64"): (_TV + "Linux-64bit.tar.gz", "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf", "tgz"),
        ("linux", "arm64"): (_TV + "Linux-ARM64.tar.gz", "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3", "tgz"),
        ("macos", "x64"): (_TV + "macOS-64bit.tar.gz", "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b", "tgz"),
        ("macos", "arm64"): (_TV + "macOS-ARM64.tar.gz", "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8", "tgz"),
    },
}
_EXE = ".exe" if OS == "windows" else ""


def _binary_tools() -> list[Tool]:
    out = []
    for (name, version), builds in _BINARIES.items():
        build = builds.get((OS, ARCH))
        if not build:
            continue  # no pinned build for this platform: the tool reports as missing and its checks are skipped
        url, sha, kind = build
        out.append(Tool(name, version, url, sha, kind, "" if kind == "raw" else name + _EXE, name + _EXE))
    return out


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        *_binary_tools(),
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
        t = TOOLS.get(name)
        if t is None:  # not pinned for this OS/architecture
            return None
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
        if OS != "windows" and t.filename == t.name:
            dest.chmod(0o755)
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
