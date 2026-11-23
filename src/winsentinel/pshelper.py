"""Run read-only PowerShell 5.1 snippets and get JSON back.

Scripts are passed with -EncodedCommand so no quoting can alter them. Every
snippet in this project must be read-only: Get-* / registry reads / CIM queries.
"""
from __future__ import annotations

import base64
import json
import subprocess

_PREFIX = (
    "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
)


class PSError(RuntimeError):
    pass


def run_ps(script: str, timeout: int = 120, stdin: str | None = None) -> str:
    full = _PREFIX + script
    enc = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
            capture_output=True,
            timeout=timeout,
            input=(stdin.encode("utf-8") if stdin is not None else None),
            stdin=(None if stdin is not None else subprocess.DEVNULL),
        )
    except subprocess.TimeoutExpired as e:
        raise PSError(f"timeout after {timeout}s") from e
    except OSError as e:
        raise PSError(f"cannot start powershell: {e}") from e
    out = p.stdout.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace").strip()
        if err.startswith("#< CLIXML"):
            err = err[:600]
        raise PSError((err or out or f"exit {p.returncode}")[:800])
    return out


def ps_json(script: str, timeout: int = 120, stdin: str | None = None) -> list:
    """Run a snippet whose pipeline output is converted to a JSON array."""
    wrapped = f"$__r = & {{ {script} }}; ConvertTo-Json -InputObject @($__r) -Depth 5 -Compress"
    out = run_ps(wrapped, timeout=timeout, stdin=stdin).lstrip("﻿")
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError as e:
        raise PSError(f"bad JSON from powershell: {out[:200]}") from e
    return data if isinstance(data, list) else [data]


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


_SIG_SCRIPT = r"""
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
foreach ($q in @($paths)) {
  $p = [string]$q
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
    [pscustomobject]@{ path=$p; status="$($s.Status)"; subject=$subj; catalog=[bool]$s.IsOSBinary }
  } catch {
    [pscustomobject]@{ path=$p; status='Error'; subject=''; catalog=$false }
  }
}
"""


def signer_name(subject: str) -> str:
    """Extract the CN from an X.500 subject string."""
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('"')
    return ""


def check_signatures(paths: list[str], chunk: int = 200) -> dict[str, dict]:
    """Authenticode status (embedded or catalog) for each path.
    Returns {path: {status, signer, os_binary}}; status 'Unknown' when the check failed."""
    result: dict[str, dict] = {}
    uniq = list(dict.fromkeys(paths))
    for i in range(0, len(uniq), chunk):
        part = uniq[i : i + chunk]
        try:
            rows = ps_json(_SIG_SCRIPT, timeout=60 + 2 * len(part), stdin=json.dumps(part))
        except PSError:
            rows = []
        for r in rows:
            status = r.get("status", "Unknown")
            # Store (MSIX) apps are signed at package level; per-file Authenticode says NotSigned.
            if status == "NotSigned" and "\program files\windowsapps\\" in r["path"].lower():
                status = "PackageSigned"
            result[r["path"]] = {
                "status": status,
                "signer": signer_name(r.get("subject") or ""),
                "os_binary": bool(r.get("catalog")),
            }
    for p in uniq:
        result.setdefault(p, {"status": "Unknown", "signer": "", "os_binary": False})
    return result
