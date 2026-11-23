"""Linux and macOS halves of the vulns module: pending updates, kernel modules/extensions, package integrity.

Read-only. Package lists are read from the local cache (no `apt update`, no sudo), so results are as
fresh as the last refresh; the report says so.
"""
from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from .findings import ModuleResult
from .osinfo import OS, sh

_SENSITIVE = re.compile(
    r"(?i)^(openssl|libssl|openssh|sudo|polkit|glibc|libc6|linux-image|kernel|systemd|curl|libcurl|git|bash|"
    r"firefox|chromium|chrome|thunderbird|docker|containerd|runc|python3|nodejs|node|nginx|apache2|httpd|"
    r"samba|bind9|cups|ghostscript|imagemagick|libxml2|zlib|xz|liblzma|gnupg|ca-certificates|dbus|pam|libpam|"
    r"wget|rsync|tar|unzip|p7zip|vim|ffmpeg|libwebp|expat|sqlite|postgresql|mysql|mariadb|redis|wireshark|"
    r"virtualbox|vlc|zoom|slack|teams|safari|macos)")


def _report(res: ModuleResult, source: str, pkgs: list[str], security: list[str], fix: str) -> None:
    res.coverage["pending_updates"] = len(pkgs)
    if not pkgs:
        return
    sens = sorted({p for p in pkgs if _SENSITIVE.match(p)} | set(security))
    if sens:
        res.add(rule_id="VULN-OUTDATED-SENSITIVE", title=f"{len(sens)} security-relevant packages have updates pending",
                severity="medium", evidence=source,
                why="; ".join(sens[:40]) + ("; ..." if len(sens) > 40 else "") + ". These handle untrusted input or "
                    "run with privilege. (The package manager reports availability only, not which CVEs are fixed.)",
                confidence=0.6, kind="fact", remediation=fix, details={"key": "outdated-sensitive", "packages": sens[:200]})
    other = sorted(set(pkgs) - set(sens))
    if other:
        res.add(rule_id="VULN-OUTDATED", title=f"{len(other)} other packages have updates pending", severity="low",
                evidence=source, why="; ".join(other[:40]) + ("; ..." if len(other) > 40 else ""), confidence=0.5,
                kind="fact", remediation=fix, details={"key": "outdated-other", "count": len(other)})


def _age_days(path: str) -> float | None:
    try:
        return (time.time() - os.stat(path).st_mtime) / 86400
    except OSError:
        return None


def updates(ctx, res: ModuleResult) -> None:
    if OS == "macos":
        rc, text = sh(["softwareupdate", "-l"], timeout=300)  # asks Apple's update server; sends no file data
        if rc not in (0, 1) and not text:
            res.note("softwareupdate -l failed: macOS update check skipped")
        else:
            labels = re.findall(r"(?m)^\s*\*\s*(?:Label:\s*)?(.+)$", text)
            if labels:
                sec = [x for x in labels if re.search(r"(?i)macos|security|safari|xprotect", x)]
                res.add(rule_id="VULN-OS-UPDATES", title=f"{len(labels)} Apple software updates pending",
                        severity="medium" if sec else "low", evidence="softwareupdate -l", why="; ".join(labels[:20]),
                        confidence=0.8, kind="fact", remediation="System Settings > General > Software Update.",
                        details={"key": "macos-updates"})
            res.coverage["macos_update_check"] = "done"
        brew = shutil.which("brew")
        if brew:
            rc, text = sh([brew, "outdated", "--quiet"], timeout=180)
            _report(res, "brew outdated", [x.split()[0] for x in text.splitlines() if x.strip()], [],
                    "brew upgrade (review the list first).")
        else:
            res.coverage["homebrew"] = "not installed"
        return
    if shutil.which("apt"):
        rc, text = sh(["apt", "list", "--upgradable"], timeout=120)
        pkgs, security = [], []
        for line in text.splitlines():
            if "/" not in line or "upgradable" not in line:
                continue
            name = line.split("/")[0]
            pkgs.append(name)
            if "-security" in line.split()[0]:
                security.append(name)
        age = _age_days("/var/lib/apt/periodic/update-success-stamp") or _age_days("/var/lib/apt/lists")
        if age is not None:
            res.coverage["apt_lists_age_days"] = round(age, 1)
            if age > 14:
                res.note(f"apt package lists were last refreshed {age:.0f} days ago; the pending-update list is "
                         "stale (run: sudo apt update)", partial=False)
        _report(res, "apt list --upgradable", pkgs, security, "sudo apt update && sudo apt upgrade (review the list first).")
    elif shutil.which("dnf"):
        rc, text = sh(["dnf", "-q", "-C", "check-update"], timeout=180)  # -C: cache only, no network, no root
        pkgs = [x.split()[0].rsplit(".", 1)[0] for x in text.splitlines() if re.match(r"^\S+\.\S+\s+\S+\s+\S+", x)]
        _report(res, "dnf check-update (cached)", pkgs, [], "sudo dnf upgrade (review the list first).")
    elif shutil.which("pacman"):
        rc, text = sh(["pacman", "-Qu"], timeout=120)
        _report(res, "pacman -Qu", [x.split()[0] for x in text.splitlines() if x.strip()], [], "sudo pacman -Syu.")
    else:
        res.note("no supported package manager (apt, dnf, pacman): pending-update check skipped")
    if Path("/var/run/reboot-required").exists():
        res.add(rule_id="VULN-REBOOT", title="Reboot required to finish installed updates", severity="low",
                evidence="/var/run/reboot-required", why="Updated kernel or libraries are not in use until the machine restarts.",
                confidence=0.9, kind="fact", remediation="Restart when convenient.", details={"key": "reboot"})


def kernel_extensions(ctx, res: ModuleResult) -> None:
    if OS == "macos":
        rc, text = sh(["systemextensionsctl", "list"], timeout=60)
        third = [x.strip() for x in text.splitlines() if "[activated enabled]" in x and "com.apple." not in x]
        if third:
            res.add(rule_id="VULN-SYSEXT", title=f"{len(third)} third-party system extensions active", severity="info",
                    evidence="systemextensionsctl list", why="; ".join(x[:140] for x in third[:15]), confidence=0.8,
                    kind="fact", remediation="Remove the owning app if you do not recognise an extension.",
                    details={"key": "sysext"})
        rc, text = sh(["kmutil", "showloaded", "--list-only", "--variant-suffix", "release"], timeout=60)
        ids = re.findall(r"(?m)\s([A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+)\s+\(", text)
        res.coverage["kernel_extensions_loaded"] = len(set(ids))
        kexts = sorted({i for i in ids if not i.startswith("com.apple.")})
        if kexts:
            res.add(rule_id="VULN-KEXT", title=f"{len(kexts)} third-party kernel extensions loaded", severity="medium",
                    evidence="kmutil showloaded", why="; ".join(kexts[:20]) + ". Kernel extensions run with full "
                    "kernel privilege and are deprecated by Apple.", confidence=0.7, kind="fact",
                    remediation="Update or remove the software that installed them.", details={"key": "kext"})
        return
    try:
        lines = Path("/proc/modules").read_text("ascii", "replace").splitlines()
    except OSError:
        res.note("/proc/modules not readable: kernel module check skipped")
        return
    res.coverage["kernel_modules"] = len(lines)
    # Taint letters in parentheses: O = out-of-tree, E = unsigned, P = proprietary.
    flagged = []
    for line in lines:
        m = re.search(r"\(([A-Z]+)\)\s*$", line)
        if m and set(m.group(1)) & {"O", "E"}:
            flagged.append(f"{line.split()[0]} ({m.group(1)})")
    if flagged:
        res.add(rule_id="VULN-KMOD", title=f"{len(flagged)} out-of-tree or unsigned kernel modules loaded",
                severity="medium" if any("E" in f.split("(")[-1] for f in flagged) else "low", evidence="/proc/modules",
                why="; ".join(flagged[:30]) + ". O = built outside the kernel tree, E = unsigned. Usually GPU, "
                    "VirtualBox or ZFS drivers; a kernel rootkit would also appear here unless it hides itself.",
                confidence=0.5, kind="fact", remediation="Confirm each belongs to software you installed (modinfo <name>).",
                details={"key": "kmod", "modules": flagged[:100]})


def package_integrity(ctx, res: ModuleResult) -> None:
    """Files that differ from what their package installed. Slow; full mode only."""
    if OS != "linux":
        return
    if shutil.which("dpkg"):
        rc, text = sh(["dpkg", "--verify"], timeout=1800)
        cmd = "dpkg --verify"
    elif shutil.which("rpm"):
        rc, text = sh(["rpm", "-Va", "--nomtime", "--nouser", "--nogroup", "--nomode"], timeout=1800)
        cmd = "rpm -Va"
    else:
        return
    changed = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or "5" not in parts[0]:
            continue  # only checksum mismatches
        path = parts[-1]
        if " c " in f" {line} " or not re.match(r"^/(usr/)?(s?bin|lib(64|exec)?)/", path):
            continue  # config files change legitimately; only programs and libraries matter
        changed.append(path)
    res.coverage["package_integrity"] = f"{cmd}: {len(changed)} modified program files"
    if changed:
        res.add(rule_id="VULN-PKG-MODIFIED", title=f"{len(changed)} packaged programs or libraries were modified",
                severity="high", evidence=cmd, why="; ".join(changed[:25]) + ". The file on disk no longer matches "
                "the checksum its package recorded. Causes: manual patching, disk corruption, or a trojanised binary.",
                confidence=0.6, signals=[f"hash: package checksum mismatch ({len(changed)} files)"],
                remediation="Reinstall the owning package (apt install --reinstall <pkg>) and investigate how it changed.",
                details={"key": "pkg-modified", "files": changed[:200]})
