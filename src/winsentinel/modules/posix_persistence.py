"""Persistence on Linux and macOS: everything that starts by itself at boot, login or on a schedule.

Linux: systemd units and timers (system and user), cron, rc.local, init.d, XDG autostart, shell
start-up files, ld.so.preload, authorized_keys, sudoers drop-ins.
macOS: LaunchAgents and LaunchDaemons, login items (background task database), cron, periodic
scripts, configuration profiles, shell start-up files, authorized_keys.

Each entry's command is resolved to the program or script it runs. Scripts are scanned by content,
binaries are checked for who vouches for them (package ownership on Linux, code signature on macOS).
Read-only: nothing is disabled or removed.
"""
from __future__ import annotations

import os
import plistlib
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..findings import ModuleResult
from ..osinfo import OS, posix_temp_like, posix_user_writable, sh
from ..shellrules import SHELL_RULES
from ..textrules import SCRIPT_RULES, read_text, scan_text
from ..trust import check_trust

NAME = "persistence"
DESCRIPTION = "systemd, cron, autostart, launchd, login items, shell start-up files, preload hooks, SSH keys, sudoers"
ORDER = 20
PLATFORMS = ("linux", "macos")

_RANK = ["info", "low", "medium", "high"]
_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "python2", "perl", "ruby", "node",
                 "osascript", "env", "nohup", "sudo", "exec", "nice", "ionice", "setsid", "timeout", "open"}
_SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/System/", "/Library/Apple/",
                "/Applications/", "/snap/", "/nix/")


@dataclass
class Entry:
    source: str      # e.g. "systemd unit", "cron", "LaunchAgent"
    location: str    # file that defines it
    name: str
    command: str
    user_owned: bool = False  # definition lives somewhere the user can write


def _read(p: Path, limit: int = 1_000_000) -> str:
    try:
        if p.is_file() and p.stat().st_size <= limit:
            return read_text(p.read_bytes())
    except OSError:
        pass
    return ""


def resolve_command(cmd: str) -> tuple[str | None, str | None]:
    """Return (program, script) for a command line: the binary that runs and, if an interpreter is used,
    the script file it is given. Either may be None when it cannot be resolved to a file."""
    cmd = re.sub(r"^[@\-+!:|]+", "", cmd.strip())  # systemd ExecStart prefixes
    try:
        parts = shlex.split(cmd, posix=True)
    except ValueError:
        parts = cmd.split()
    parts = [p for p in parts if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", p)]  # leading VAR=value
    if not parts:
        return None, None
    prog = parts[0]
    path = prog if prog.startswith("/") else shutil.which(prog)
    script = None
    i = 0
    while i < len(parts) and os.path.basename(parts[i]).rstrip("0123456789.") in _INTERPRETERS:
        i += 1
        while i < len(parts) and parts[i].startswith("-") and parts[i] not in ("-c", "-e"):
            i += 1
        if i < len(parts) and parts[i] in ("-c", "-e"):
            return path, None  # inline code: the command text itself is scanned
    if i > 0 and i < len(parts):
        cand = os.path.expanduser(parts[i])
        if cand.startswith("/") and os.path.isfile(cand):
            script = cand
    return (path if path and os.path.isfile(path) else None), script


def _systemd_entries(res: ModuleResult) -> list[Entry]:
    out: list[Entry] = []
    home = Path.home()
    dirs = [(Path("/etc/systemd/system"), False), (Path("/usr/local/lib/systemd/system"), False),
            (Path("/run/systemd/system"), False), (home / ".config/systemd/user", True),
            (Path("/etc/systemd/user"), False)]
    seen = 0
    for d, user in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.suffix not in (".service", ".timer", ".socket", ".path") or p.is_symlink() and not p.exists():
                continue
            text = _read(p)
            if not text:
                continue
            seen += 1
            for m in re.finditer(r"(?m)^\s*Exec(?:Start|StartPre|StartPost|Stop|Reload)\s*=\s*(.+)$", text):
                out.append(Entry("systemd unit", str(p), p.name, m.group(1).strip(), user))
    res.coverage["systemd_unit_files"] = seen
    return out


def _cron_entries(res: ModuleResult) -> list[Entry]:
    out: list[Entry] = []
    files: list[Path] = [Path("/etc/crontab")]
    for d in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs", "/usr/lib/cron/tabs", "/var/at/tabs"):
        try:
            files += [p for p in sorted(Path(d).iterdir()) if p.is_file()]
        except OSError:
            if Path(d).exists():
                res.note(f"{d} not readable without root: other users' cron jobs not checked", partial=False)
    rc, text = sh(["crontab", "-l"], timeout=20)
    blobs = [("crontab -l (current user)", text, True)] if rc == 0 else []
    blobs += [(str(f), _read(f), False) for f in files]
    n = 0
    for loc, text, user in blobs:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or re.match(r"^[A-Za-z_]+\s*=", line):
                continue
            m = re.match(r"^(?:@\w+|(?:\S+\s+){5})\s*(.+)$", line)
            if not m:
                continue
            cmd = m.group(1)
            if loc.startswith(("/etc/crontab", "/etc/cron.d")):
                cmd = cmd.split(None, 1)[1] if len(cmd.split(None, 1)) == 2 else cmd  # drop the user column
            n += 1
            out.append(Entry("cron", loc, cmd[:60], cmd, user))
    for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/periodic/daily",
              "/etc/periodic/weekly", "/etc/periodic/monthly", "/etc/init.d"):
        try:
            for p in sorted(Path(d).iterdir()):
                if p.is_file() and not p.name.startswith("."):
                    n += 1
                    out.append(Entry("scheduled script" if "init.d" not in d else "init script", str(p), p.name, str(p)))
        except OSError:
            pass
    if Path("/etc/rc.local").is_file():
        out.append(Entry("rc.local", "/etc/rc.local", "rc.local", "/etc/rc.local"))
    res.coverage["cron_entries"] = n
    return out


def _autostart_entries(res: ModuleResult) -> list[Entry]:
    out: list[Entry] = []
    for d, user in ((Path.home() / ".config/autostart", True), (Path("/etc/xdg/autostart"), False)):
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.desktop")):
            text = _read(p)
            m = re.search(r"(?m)^\s*Exec\s*=\s*(.+)$", text)
            if m and not re.search(r"(?mi)^\s*Hidden\s*=\s*true", text):
                out.append(Entry("XDG autostart", str(p), p.name, re.sub(r"\s%[a-zA-Z]", "", m.group(1).strip()), user))
    res.coverage["autostart_entries"] = len(out)
    return out


def _launchd_entries(res: ModuleResult) -> list[Entry]:
    out: list[Entry] = []
    home = Path.home()
    dirs = [(home / "Library/LaunchAgents", "LaunchAgent (user)", True), (Path("/Library/LaunchAgents"), "LaunchAgent", False),
            (Path("/Library/LaunchDaemons"), "LaunchDaemon", False)]
    n = 0
    for d, label, user in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.plist")):
            try:
                with open(p, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                res.add(rule_id="PERSIST-UNREADABLE", title=f"{label} could not be parsed: {p.name}", severity="low",
                        evidence=str(p), why="The property list is malformed or unreadable, so what it starts is unknown.",
                        confidence=0.4, signals=["unparseable launchd plist"], remediation="Inspect it: plutil -p <file>.",
                        details={"key": p.name, "path": str(p)})
                continue
            n += 1
            args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
            if not args:
                continue
            cmd = " ".join(shlex.quote(str(a)) for a in args)
            e = Entry(label, str(p), str(pl.get("Label", p.stem)), cmd, user)
            out.append(e)
            if pl.get("RunAtLoad") and pl.get("KeepAlive") and user and not str(pl.get("Label", "")).startswith("com.apple."):
                e.name += " [RunAtLoad+KeepAlive]"
    res.coverage["launchd_plists"] = n
    rc, text = sh(["sfltool", "dumpbtm"], timeout=60)
    if rc == 0 and text:
        items = re.findall(r"(?m)^\s*Name:\s*(.+)$", text)
        res.coverage["login_items_listed"] = len(items)
    else:
        res.note("login items (sfltool dumpbtm) need root or Full Disk Access: not listed", partial=False)
    return out


def _analyse(res: ModuleResult, entries: list[Entry], trusted: set[str]) -> None:
    resolved = [(e, *resolve_command(e.command)) for e in entries]
    bins = [prog for _, prog, _ in resolved if prog]
    sigs = check_trust(bins) if bins else {}
    listed = 0
    for e, prog, script in resolved:
        signals: list[str] = []
        sev = "info"
        text_hits = scan_text(e.command, SCRIPT_RULES + SHELL_RULES)
        target = script or (prog if prog and _looks_like_script(prog) else None)
        if target:
            text_hits += scan_text(_read(Path(target)), SCRIPT_RULES + SHELL_RULES)
        for h in text_hits:
            signals.append(h.signal)
            sev = max(sev, h.rule.severity, key=_RANK.index)
        if len({h.rule.category for h in text_hits}) >= 2 and sev == "medium":
            sev = "high"
        run_path = target or prog
        if run_path:
            if posix_temp_like(run_path):
                signals.append("runs from a world-writable temporary directory")
                sev = max(sev, "high", key=_RANK.index)
            elif os.path.basename(run_path).startswith("."):
                signals.append("target is a hidden file")
                sev = max(sev, "medium", key=_RANK.index)
            elif posix_user_writable(run_path) and not e.user_owned:
                signals.append("system-level entry runs a file from a user-writable location")
                sev = max(sev, "medium", key=_RANK.index)
        elif not re.search(r"\s-(c|e)\s", " " + e.command + " ") and e.command.strip().startswith("/"):
            first = e.command.split()[0]
            if not os.path.exists(first):
                signals.append("target file does not exist")
                sev = max(sev, "low", key=_RANK.index)
        sig = sigs.get(prog or "")
        if sig and not target:
            if sig["status"] == "Valid" and (sig["os_binary"] or sig["signer"].lower() in trusted) and not signals:
                continue  # vouched-for program with nothing odd about it: not listed
            if sig["status"] in ("NotSigned", "HashMismatch"):
                signals.append(f"code signature: {sig['status']}")
                sev = max(sev, "medium" if sig["status"] == "NotSigned" else "high", key=_RANK.index)
            elif sig["status"] == "Unpackaged" and not prog.startswith(_SYSTEM_DIRS):
                signals.append("program is not owned by any installed package")
        listed += 1
        res.add(rule_id="PERSIST-" + e.source.split()[0].upper(), title=f"{e.source}: {e.name}"[:120], severity=sev,
                evidence=e.location, why="; ".join(dict.fromkeys(signals)) or "Starts automatically; nothing suspicious found.",
                confidence=0.6 if len(signals) >= 2 else 0.4, signals=list(dict.fromkeys(signals)),
                remediation="If you do not recognise it, find what installed it before disabling it "
                            + ("(systemctl disable / crontab -e)." if OS == "linux" else "(launchctl bootout / remove the plist)."),
                details={"key": e.name, "command": e.command[:400], "path": run_path or "", "source": e.source})
    res.coverage["autostart_entries_total"] = len(entries)
    res.coverage["autostart_entries_listed"] = listed


def _looks_like_script(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def _fact(res, rule, title, sev, evidence, why, fix, key, signals=None):
    res.add(rule_id=rule, title=title, severity=sev, evidence=evidence, why=why, confidence=0.8, kind="fact",
            signals=signals or [], remediation=fix, details={"key": key, "path": evidence.split(":")[0]})


def _hooks(res: ModuleResult) -> None:
    """Places that change how every process or login behaves."""
    pre = _read(Path("/etc/ld.so.preload")).strip()
    if pre:
        _fact(res, "PERSIST-LD-PRELOAD", "Library forced into every process (/etc/ld.so.preload)", "high",
              "/etc/ld.so.preload", f"Lists: {pre[:200]}. Almost no legitimate software uses this file; userland "
              "rootkits do.", "Find which package owns each listed library (dpkg -S / rpm -qf) before removing the entry.", "ld.so.preload")
    home = Path.home()
    rc_files = [home / n for n in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
                                   ".zprofile", ".zlogin", ".config/fish/config.fish")]
    rc_files += [Path("/etc/profile"), Path("/etc/bash.bashrc"), Path("/etc/zshrc"), Path("/etc/zprofile")]
    try:
        rc_files += sorted(Path("/etc/profile.d").glob("*.sh"))
    except OSError:
        pass
    n = 0
    for f in rc_files:
        text = _read(f)
        if not text:
            continue
        n += 1
        hits = [h for h in scan_text(text, SHELL_RULES) if h.rule.id != "SH-PERSIST"]
        if hits:
            sev = max((h.rule.severity for h in hits), key=_RANK.index)
            res.add(rule_id="PERSIST-SHELLRC", title=f"Suspicious command in shell start-up file {f.name}", severity=sev,
                    evidence=f"{f}:{hits[0].line}", why="; ".join(dict.fromkeys(h.signal for h in hits)),
                    confidence=0.5, signals=list(dict.fromkeys(h.signal for h in hits)),
                    remediation="Read the line; remove it if you did not add it.",
                    details={"key": f.name, "path": str(f), "line": hits[0].line})
    res.coverage["shell_startup_files"] = n
    ak = home / ".ssh" / "authorized_keys"
    keys = [x for x in _read(ak).splitlines() if x.strip() and not x.strip().startswith("#")]
    if keys:
        forced = [k for k in keys if re.match(r'^\s*(?:[a-z\-]+(?:="[^"]*")?,)*command="', k)]
        res.add(rule_id="PERSIST-SSH-KEYS", title=f"{len(keys)} SSH keys can log in as you", severity="info",
                evidence=str(ak), why="Comments: " + ", ".join(sorted({k.split()[-1][:40] for k in keys if len(k.split()) >= 3})[:12])
                + (f". {len(forced)} run a forced command." if forced else ""), confidence=0.9, kind="fact",
                remediation="Remove any key you do not recognise.", details={"key": "authorized_keys", "count": len(keys)})
    for d in ("/etc/sudoers.d",):
        try:
            for p in sorted(Path(d).iterdir()):
                text = _read(p)
                m = re.search(r"(?m)^\s*([^#\s]\S*)\s+ALL\s*=\s*\(?[^)]*\)?\s*NOPASSWD:\s*ALL\b", text)
                if m:
                    _fact(res, "PERSIST-SUDOERS", f"Passwordless sudo for {m.group(1)}", "medium", str(p),
                          "This account can become root without a password, so anything running as it can too.",
                          "Remove the NOPASSWD rule unless it is deliberate (cloud images add one for the default user).",
                          f"{p.name}|{m.group(1)}")
        except OSError:
            res.note(f"{d} not readable without root: sudoers drop-ins not checked", partial=False)
    if OS == "macos":
        rc, text = sh(["profiles", "list"], timeout=30)
        n = len(re.findall(r"profileIdentifier", text))
        if n:
            res.add(rule_id="PERSIST-PROFILES", title=f"{n} configuration profiles installed", severity="low",
                    evidence="profiles list", why="Profiles can set proxies, trusted certificates and login items. "
                    "Expected on a managed Mac; unexpected on a personal one.", confidence=0.6, kind="fact",
                    remediation="System Settings > Privacy & Security > Profiles: remove any you do not recognise.",
                    details={"key": "profiles", "count": n})


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    entries = _cron_entries(res)
    entries += _launchd_entries(res) if OS == "macos" else _systemd_entries(res) + _autostart_entries(res)
    _analyse(res, entries, {s.lower() for s in ctx.cfg.trusted_signers})
    _hooks(res)
    if not ctx.admin:
        res.note("not root: root-only cron spools and other users' start-up files were not readable", partial=False)
    return res
