"""OS hardening posture. Every finding is a direct read of configuration ("fact")."""
from __future__ import annotations

import os
import re
import subprocess

from ..findings import ModuleResult
from ..pshelper import PSError, ps_json
from ..winutil import HKLM, reg_get

NAME = "hardening"
DESCRIPTION = "UAC, BitLocker, firewall, RDP, SMBv1, LSA protection, Secure Boot, local admins, guest, password policy"
ORDER = 40
PLATFORMS = ("windows",)

_BITLOCKER = r"""
$sh = New-Object -ComObject Shell.Application
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
  $v = $null
  try { $v = $sh.NameSpace($d.DeviceID).Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
  [pscustomobject]@{ Drive=$d.DeviceID; Protection=$v }
}
"""
_FIREWALL = ("Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}},"
             "@{n='Inbound';e={\"$($_.DefaultInboundAction)\"}}")
_USERS = ("Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,@{n='SID';e={$_.SID.Value}},"
          "@{n='LastLogon';e={if ($_.LastLogon) {$_.LastLogon.ToString('yyyy-MM-dd')} else {''}}}")
_ADMINS = ("Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,@{n='Class';e={$_.ObjectClass}},"
           "@{n='Source';e={\"$($_.PrincipalSource)\"}}")
_POLICIES = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    passed: list[str] = []

    def bad(rule, title, sev, evidence, why, fix, value=""):
        res.add(rule_id=rule, title=title, severity=sev, evidence=evidence, why=why, confidence=1.0, kind="fact",
                remediation=fix, details={"key": rule, "value": str(value)})

    # UAC
    lua = reg_get(HKLM, _POLICIES, "EnableLUA", 1)
    consent = reg_get(HKLM, _POLICIES, "ConsentPromptBehaviorAdmin", 5)
    if lua == 0:
        bad("HARD-UAC-OFF", "UAC is disabled", "high", f"HKLM\\{_POLICIES} :: EnableLUA",
            "Every program an admin runs gets full administrator rights without a prompt.",
            "Set EnableLUA=1 (Control Panel > User Accounts > Change User Account Control settings) and reboot.", lua)
    elif consent == 0:
        bad("HARD-UAC-NOPROMPT", "UAC elevates without prompting", "medium", f"HKLM\\{_POLICIES} :: ConsentPromptBehaviorAdmin",
            "Elevation requests from an admin account are approved silently.", "Raise the UAC slider to the default level.", consent)
    else:
        passed.append("UAC")
    if lua != 0 and reg_get(HKLM, _POLICIES, "PromptOnSecureDesktop", 1) == 0:
        bad("HARD-UAC-DESKTOP", "UAC prompt is not on the secure desktop", "low", f"HKLM\\{_POLICIES} :: PromptOnSecureDesktop",
            "Other programs can interact with the elevation prompt.", "Raise the UAC slider to the default level.", 0)

    # BitLocker (shell property works without admin: 1/3/5 = on or encrypting, 2 = off)
    try:
        sysdrive = (os.environ.get("SystemDrive") or "C:").upper()
        for row in ps_json(_BITLOCKER, timeout=60):
            v, drive = row.get("Protection"), str(row.get("Drive"))
            if v is None:
                res.note(f"BitLocker state for {drive} not readable without admin")
            elif int(v) in (2, 4, 6):
                is_sys = drive.upper() == sysdrive
                bad("HARD-BITLOCKER", f"Drive {drive} is not BitLocker-protected", "medium" if is_sys else "low",
                    f"{drive} (System.Volume.BitLockerProtection={v})",
                    "Anyone with physical access to the disk can read its contents"
                    + (" including saved credentials and tokens." if is_sys else "."),
                    "Settings > Privacy & security > Device encryption / BitLocker: turn on and store the recovery key safely.", v)
            else:
                passed.append(f"BitLocker {drive}")
    except PSError as e:
        res.note(f"BitLocker check failed: {e}")

    # Firewall
    try:
        for p in ps_json(_FIREWALL, timeout=60):
            if not p.get("Enabled"):
                bad("HARD-FW-OFF", f"Windows Firewall {p.get('Name')} profile is off", "high",
                    f"Firewall profile {p.get('Name')}", "Listening services are reachable from that network type.",
                    "Windows Security > Firewall & network protection: turn the profile on.", p.get("Name"))
            elif str(p.get("Inbound")) == "Allow":
                bad("HARD-FW-INBOUND", f"Firewall {p.get('Name')} profile allows inbound by default", "high",
                    f"Firewall profile {p.get('Name')}", "Default inbound action is Allow.",
                    "Set default inbound action back to Block.", p.get("Name"))
            else:
                passed.append(f"Firewall {p.get('Name')}")
    except PSError as e:
        res.note(f"firewall profiles unavailable: {e}")

    # RDP
    if reg_get(HKLM, _TS, "fDenyTSConnections", 1) == 0:
        nla = reg_get(HKLM, _TS + r"\WinStations\RDP-Tcp", "UserAuthentication", 1)
        bad("HARD-RDP-ON", "Remote Desktop is enabled", "high" if nla == 0 else "medium", f"HKLM\\{_TS} :: fDenyTSConnections",
            "RDP accepts connections" + (" and Network Level Authentication is off." if nla == 0 else
                                           " (NLA is on). Exposed RDP is a top ransomware entry point."),
            "Settings > System > Remote Desktop: turn off if unused; never forward 3389 from the internet.", f"nla={nla}")
    else:
        passed.append("RDP off")

    # SMBv1
    smb1 = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    mrx = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    if smb1 == 1:
        bad("HARD-SMB1-SERVER", "SMBv1 server is enabled", "high", r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters :: SMB1",
            "SMBv1 is the protocol exploited by EternalBlue/WannaCry.", "Elevated: Set-SmbServerConfiguration -EnableSMB1Protocol $false", 1)
    elif mrx is not None and mrx != 4:
        bad("HARD-SMB1-CLIENT", "SMBv1 client driver is installed and enabled", "medium",
            r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10 :: Start", f"mrxsmb10 Start={mrx}.",
            "Turn off 'SMB 1.0/CIFS File Sharing Support' in Windows Features.", mrx)
    else:
        passed.append("SMBv1 off")

    # LSA / credential protection
    ppl = reg_get(HKLM, _LSA, "RunAsPPL")
    if not ppl:
        bad("HARD-LSA-PPL", "LSA protection (RunAsPPL) is not enabled", "low" if ppl is None else "medium", f"HKLM\\{_LSA} :: RunAsPPL",
            "LSASS is not a protected process, so admin-level malware can dump credentials from it.",
            "Windows Security > Device security > Core isolation > Local Security Authority protection: On.", ppl)
    else:
        passed.append("LSA protection")
    if reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0) == 1:
        bad("HARD-WDIGEST", "WDigest stores plaintext credentials in memory", "high",
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest :: UseLogonCredential",
            "UseLogonCredential=1 keeps logon passwords in LSASS in clear text; attackers set this deliberately.",
            "Set UseLogonCredential to 0 (elevated) and find out what changed it.", 1)

    # Secure Boot
    sb = reg_get(HKLM, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    if sb == 0:
        bad("HARD-SECUREBOOT", "Secure Boot is off", "medium", r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "Boot-level malware (bootkits) is not blocked by firmware.", "Enable Secure Boot in UEFI setup.", 0)
    elif sb is None:
        res.note("Secure Boot state not present (legacy BIOS boot?)", partial=False)
    else:
        passed.append("Secure Boot")

    # Accounts
    try:
        users = ps_json(_USERS, timeout=60)
        for u in users:
            sid = str(u.get("SID", ""))
            if not u.get("Enabled"):
                continue
            if sid.endswith("-501"):
                bad("HARD-GUEST", "Guest account is enabled", "medium", f"Local user {u.get('Name')}",
                    "Anyone can log on without a password.", "Elevated: Disable-LocalUser -Name Guest", u.get("Name"))
            elif sid.endswith("-500"):
                bad("HARD-BUILTIN-ADMIN", "Built-in Administrator account is enabled", "low", f"Local user {u.get('Name')}",
                    "The well-known RID-500 account is not subject to UAC by default and is a brute-force target.",
                    "Disable it if you have another admin account.", u.get("Name"))
            if u.get("PasswordRequired") is False:
                bad("HARD-NO-PASSWORD-REQ", f"Account {u.get('Name')} does not require a password", "medium",
                    f"Local user {u.get('Name')}", "PasswordRequired=False: the account may have a blank password.",
                    "Set a password; elevated: Set-LocalUser -Name <name> -PasswordNotRequired $false", u.get("Name"))
        passed.append("local accounts enumerated")
    except PSError as e:
        res.note(f"local users unavailable: {e}")
    try:
        admins = ps_json(_ADMINS, timeout=60)
        names = [a.get("Name") for a in admins]
        res.add(rule_id="HARD-ADMINS", title=f"Local Administrators group has {len(names)} member(s)",
                severity="low" if len(names) > 3 else "info", evidence="BUILTIN\\Administrators",
                why="Members: " + ", ".join(str(n) for n in names), confidence=1.0, kind="fact",
                remediation="Remove accounts that do not need admin; use a standard account day to day.",
                details={"key": "admins", "value": ",".join(sorted(str(n) for n in names))})
    except PSError as e:
        res.note(f"Administrators group membership unavailable: {e}")

    # Password / lockout policy
    try:
        out = subprocess.run(["net", "accounts"], capture_output=True, timeout=20, stdin=subprocess.DEVNULL).stdout.decode("utf-8", "replace")
        m = re.search(r"Minimum password length:\s*(\d+)", out)
        if m and int(m.group(1)) < 8:
            bad("HARD-PW-LENGTH", f"Minimum password length is {m.group(1)}", "low", "net accounts",
                "Local policy allows short or blank passwords.", "Elevated: net accounts /minpwlen:12", m.group(1))
        m = re.search(r"Lockout threshold:\s*(\S+)", out)
        if m and m.group(1).lower() == "never":
            bad("HARD-LOCKOUT", "No account lockout threshold", "low", "net accounts",
                "Unlimited password guesses are allowed (matters most if RDP or SMB is reachable).",
                "Elevated: net accounts /lockoutthreshold:10", "never")
        if not out.strip():
            res.note("net accounts returned nothing")
    except (OSError, subprocess.TimeoutExpired):
        res.note("net accounts failed")

    # Misc policy
    if reg_get(HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0) == 1:
        bad("HARD-WU-OFF", "Automatic Windows Update is disabled by policy", "medium",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU :: NoAutoUpdate", "Security patches are not installed automatically.",
            "Remove the policy value or enable automatic updates.", 1)
    if str(reg_get(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "")).lower() == "off":
        bad("HARD-SMARTSCREEN", "SmartScreen for apps and files is off", "low",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer :: SmartScreenEnabled",
            "Downloaded executables are not reputation-checked.", "Windows Security > App & browser control.", "Off")
    if reg_get(HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 0) == 1:
        bad("HARD-DEFENDER-POLICY", "Policy value DisableAntiSpyware is set", "high",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender :: DisableAntiSpyware",
            "A registry policy tries to turn Defender off; malware and 'debloat' scripts set this.",
            "Delete the value (elevated) unless a third-party AV manages it.", 1)

    res.coverage["checks_passed"] = ", ".join(passed)
    return res
