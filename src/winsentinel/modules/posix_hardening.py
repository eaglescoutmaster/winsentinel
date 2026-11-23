"""Hardening posture on Linux and macOS. Every finding is a fact read from system state. Read-only.

Linux: firewall, SSH daemon settings, kernel sysctls, disk encryption, SELinux/AppArmor, Secure Boot,
accounts with uid 0 or empty passwords, unexpected setuid programs, automatic updates.
macOS: SIP, Gatekeeper, FileVault, firewall, automatic updates, remote login, sharing, guest account.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

from ..findings import ModuleResult
from ..osinfo import OS, is_wsl, sh
from ..trust import check_trust

NAME = "hardening"
DESCRIPTION = "Firewall, SSH, kernel settings, disk encryption, MAC/SIP/Gatekeeper, Secure Boot, accounts, setuid files"
ORDER = 40
PLATFORMS = ("linux", "macos")


def _fact(res, rule, title, sev, evidence, why, fix, **details):
    res.add(rule_id=rule, title=title, severity=sev, evidence=evidence, why=why, confidence=0.9, kind="fact",
            remediation=fix, details={"key": rule, **details})


def _read(path: str) -> str:
    try:
        return Path(path).read_text("utf-8", "replace")
    except OSError:
        return ""


def _sshd(res: ModuleResult) -> None:
    files = [Path("/etc/ssh/sshd_config")]
    try:
        files += sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf"))
    except OSError:
        pass
    text = "\n".join(_read(str(f)) for f in files)
    if not text.strip():
        res.coverage["sshd"] = "no readable sshd_config (server not installed or not readable)"
        return
    res.coverage["sshd"] = "config read"

    def opt(name: str) -> str:
        m = re.search(rf"(?im)^\s*{name}\s+(\S+)", text)
        return m.group(1).lower() if m else ""

    if opt("PermitRootLogin") == "yes":
        _fact(res, "HARD-SSH-ROOT", "SSH allows root login with a password", "medium", "/etc/ssh/sshd_config",
              "PermitRootLogin yes lets attackers guess the one account name every machine has.",
              "Set PermitRootLogin prohibit-password (or no) and restart sshd.")
    if opt("PasswordAuthentication") == "yes":
        _fact(res, "HARD-SSH-PASSWORD", "SSH accepts password logins", "low", "/etc/ssh/sshd_config",
              "Passwords can be guessed or sprayed; keys cannot.", "Use keys and set PasswordAuthentication no.")
    if opt("PermitEmptyPasswords") == "yes":
        _fact(res, "HARD-SSH-EMPTY", "SSH permits empty passwords", "high", "/etc/ssh/sshd_config",
              "Any account with no password can log in remotely.", "Set PermitEmptyPasswords no.")


def _linux(ctx, res: ModuleResult) -> None:
    wsl = is_wsl()
    if wsl:
        res.note("WSL: firewall, disk encryption and Secure Boot belong to the Windows host and are not judged here", partial=False)
    # Firewall
    if not wsl:
        state = ""
        if shutil.which("ufw"):
            state = _read("/etc/ufw/ufw.conf")
            active = bool(re.search(r"(?im)^\s*ENABLED\s*=\s*yes", state))
            res.coverage["firewall"] = "ufw " + ("enabled" if active else "disabled")
        else:
            rc, out = sh(["systemctl", "is-active", "firewalld", "nftables"], timeout=20)
            active = "active" in [x.strip() for x in out.splitlines()]
            res.coverage["firewall"] = "firewalld/nftables " + ("active" if active else "not active")
        if not active:
            _fact(res, "HARD-FIREWALL", "No host firewall is enabled", "medium", "ufw / firewalld / nftables",
                  "Every listening service is reachable from the network the machine is on.",
                  "sudo ufw enable (or enable firewalld); allow only the ports you need.")
    _sshd(res)
    # Kernel settings
    sysctls = {
        "kernel/randomize_va_space": ("2", "low", "Address space layout randomisation is not fully on"),
        "kernel/kptr_restrict": ("1", "low", "Kernel pointers are exposed to unprivileged users"),
        "kernel/dmesg_restrict": ("1", "info", "Kernel log is readable by unprivileged users"),
        "kernel/yama/ptrace_scope": ("1", "low", "Any process can trace other processes of the same user"),
        "fs/protected_symlinks": ("1", "low", "Symlink protection in world-writable directories is off"),
        "fs/suid_dumpable": ("0", "low", "Setuid programs may write core dumps"),
    }
    for key, (want, sev, title) in sysctls.items():
        val = _read(f"/proc/sys/{key}").strip()
        if val and (int(val) < int(want) if key != "fs/suid_dumpable" else val not in ("0",)):
            _fact(res, "HARD-SYSCTL-" + key.split("/")[-1].upper(), title, sev, f"/proc/sys/{key} = {val}",
                  f"Recommended value is {want}.", f"sudo sysctl -w {key.replace('/', '.')}={want} and persist it in /etc/sysctl.d/.")
    # Mandatory access control
    selinux = _read("/sys/fs/selinux/enforce").strip()
    apparmor = _read("/sys/module/apparmor/parameters/enabled").strip()
    if selinux == "0":
        _fact(res, "HARD-SELINUX", "SELinux is permissive", "medium", "/sys/fs/selinux/enforce = 0",
              "Policy violations are logged but not blocked.", "sudo setenforce 1 and set SELINUX=enforcing in /etc/selinux/config.")
    elif not selinux and apparmor != "Y" and not wsl:
        _fact(res, "HARD-MAC", "Neither SELinux nor AppArmor is active", "low", "/sys/fs/selinux, /sys/module/apparmor",
              "No mandatory access control confines services if they are compromised.", "Enable the one your distribution ships.")
    # Disk encryption and Secure Boot
    if not wsl:
        rc, out = sh(["lsblk", "-rno", "TYPE,MOUNTPOINT"], timeout=20)
        if rc == 0:
            encrypted = any(x.startswith("crypt") for x in out.splitlines())
            res.coverage["disk_encryption"] = "LUKS volume present" if encrypted else "no encrypted volume found"
            if not encrypted:
                _fact(res, "HARD-DISK-ENC", "No encrypted disk volume found", "medium", "lsblk",
                      "Anyone with physical access to the disk can read it.", "Full-disk encryption (LUKS) is set up at install time; "
                      "at least encrypt your home directory or sensitive folders.")
        sb = shutil.which("mokutil")
        if sb:
            rc, out = sh([sb, "--sb-state"], timeout=20)
            if "disabled" in out.lower():
                _fact(res, "HARD-SECUREBOOT", "Secure Boot is disabled", "low", "mokutil --sb-state",
                      "Boot-time malware is not blocked by firmware.", "Enable Secure Boot in firmware setup.")
        else:
            res.coverage["secure_boot"] = "mokutil not installed: not checked"
    # Accounts
    uid0 = [x.split(":")[0] for x in _read("/etc/passwd").splitlines() if len(x.split(":")) > 2 and x.split(":")[2] == "0"]
    if len(uid0) > 1:
        _fact(res, "HARD-UID0", "More than one account has uid 0", "high", "/etc/passwd",
              f"Accounts with full root rights: {', '.join(uid0)}. Extra uid-0 accounts are a common backdoor.",
              "Remove or renumber every uid-0 account except root.")
    shadow = _read("/etc/shadow")
    if shadow:
        empty = [x.split(":")[0] for x in shadow.splitlines() if len(x.split(":")) > 1 and x.split(":")[1] == ""]
        if empty:
            _fact(res, "HARD-EMPTY-PASSWORD", "Accounts with an empty password", "high", "/etc/shadow",
                  f"{', '.join(empty)} can log in with no password.", "Set a password (passwd <user>) or lock the account (passwd -l).")
    else:
        res.note("/etc/shadow not readable without root: empty-password check skipped", partial=False)
    # Automatic updates
    if shutil.which("apt"):
        auto = _read("/etc/apt/apt.conf.d/20auto-upgrades")
        if not re.search(r'Unattended-Upgrade\s+"1"', auto):
            _fact(res, "HARD-AUTO-UPDATE", "Automatic security updates are not enabled", "low",
                  "/etc/apt/apt.conf.d/20auto-upgrades", "Security fixes wait until someone runs apt upgrade.",
                  "sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades.")
    _setuid(ctx, res)


def _setuid(ctx, res: ModuleResult) -> None:
    """Setuid-root programs that no installed package owns."""
    roots = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin", "/opt", "/tmp", "/var/tmp",
             "/dev/shm", str(Path.home())]
    found: list[str] = []
    seen_dirs: set[str] = set()
    budget = 200_000
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            real = os.path.realpath(dirpath)
            if real in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(real)
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "proc", "snap", ".cache")]
            for name in filenames:
                budget -= 1
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID and st.st_uid == 0:
                    found.append(p)
            if budget <= 0:
                break
        if budget <= 0:
            res.note("setuid search stopped at its file budget; some directories were not checked", partial=False)
            break
    found = sorted(set(found))
    res.coverage["setuid_root_files"] = len(found)
    if not found:
        return
    sigs = check_trust(found)
    orphan = [p for p in found if sigs.get(p, {}).get("status") == "Unpackaged"]
    for p in orphan:
        risky = p.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", str(Path.home())))
        res.add(rule_id="HARD-SETUID-ORPHAN", title=f"Setuid-root program not owned by any package: {os.path.basename(p)}",
                severity="high" if risky else "medium", evidence=p,
                why="It runs as root for whoever starts it, and no installed package accounts for it."
                    + (" It sits in a user-writable location." if risky else ""), confidence=0.6,
                signals=["setuid root", "not owned by any package"] + (["user-writable location"] if risky else []),
                remediation="Find out what installed it. Remove the setuid bit (chmod u-s) only once you are sure.",
                details={"key": p, "path": p})


def _macos(ctx, res: ModuleResult) -> None:
    def check(cmd, pattern, rule, title, sev, why, fix, want_match=True):
        rc, out = sh(cmd, timeout=30)
        if rc == 127 or (not out and rc != 0):
            res.note(f"{' '.join(cmd)} failed: {title.lower()} not checked", partial=False)
            return
        if bool(re.search(pattern, out, re.I)) == want_match:
            _fact(res, rule, title, sev, " ".join(cmd), why, fix)

    check(["csrutil", "status"], r"disabled", "HARD-SIP", "System Integrity Protection is disabled", "high",
          "System files and processes are not protected from modification, even by root.",
          "Restart into Recovery and run: csrutil enable.")
    check(["spctl", "--status"], r"disabled", "HARD-GATEKEEPER", "Gatekeeper is disabled", "high",
          "Unsigned and un-notarised apps open without a warning.", "sudo spctl --master-enable.")
    check(["fdesetup", "status"], r"FileVault is Off", "HARD-FILEVAULT", "FileVault disk encryption is off", "medium",
          "Anyone with physical access to the Mac can read the disk.", "System Settings > Privacy & Security > FileVault.")
    check(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], r"disabled", "HARD-FIREWALL",
          "Application firewall is off", "low", "Incoming connections to any listening app are allowed.",
          "System Settings > Network > Firewall.")
    check(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"],
          r"^\s*1\s*$", "HARD-AUTO-UPDATE", "Automatic macOS updates are not enabled", "low",
          "Security fixes wait until you install them by hand.", "System Settings > General > Software Update > Automatic Updates.",
          want_match=False)
    check(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], r"^\s*1\s*$",
          "HARD-GUEST", "Guest account is enabled", "low", "Anyone can log in without a password.",
          "System Settings > Users & Groups > Guest User: turn it off.")
    check(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"], r"\S",
          "HARD-AUTOLOGIN", "Automatic login is enabled", "medium", "The Mac logs in without a password at start-up.",
          "System Settings > Users & Groups > Automatically log in as: Off.")
    rc, out = sh(["launchctl", "print-disabled", "system"], timeout=30)
    if rc == 0:
        for svc, label in (("com.openssh.sshd", "Remote Login (SSH)"), ("com.apple.screensharing", "Screen Sharing"),
                           ("com.apple.smbd", "File Sharing (SMB)")):
            if re.search(rf'"{re.escape(svc)}"\s*=>\s*(?:false|enabled)', out):
                _fact(res, "HARD-SHARING-" + svc.split(".")[-1].upper(), f"{label} is turned on", "low",
                      "launchctl print-disabled system", f"{label} accepts connections from the network.",
                      "System Settings > General > Sharing: turn it off if you do not use it.")
    _sshd(res)
    rc, out = sh(["system_profiler", "SPInstallHistoryDataType"], timeout=120)
    m = re.findall(r"XProtectPlistConfigData[^\n]*\n(?:.*\n){0,6}?\s*Install Date:\s*(.+)", out)
    if m:
        res.coverage["xprotect_last_update"] = m[-1].strip()


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    (_linux if OS == "linux" else _macos)(ctx, res)
    if not ctx.admin:
        res.note("not root: some settings (shadow file, other users' data) were not readable", partial=False)
    return res
