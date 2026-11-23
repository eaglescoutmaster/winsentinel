"""Microsoft Defender: status, exclusions, tamper protection, detection history, optional scan."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..findings import ModuleResult
from ..pshelper import PSError, ps_json

NAME = "defender"
DESCRIPTION = "Defender status, exclusions, tamper protection, threat history; triggers a quick scan in --full"
ORDER = 10
PLATFORMS = ("windows",)

_STATUS = r"""
$s = Get-MpComputerStatus
[pscustomobject]@{
  AMServiceEnabled=$s.AMServiceEnabled; AntivirusEnabled=$s.AntivirusEnabled
  RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled; BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled
  IoavProtectionEnabled=$s.IoavProtectionEnabled; OnAccessProtectionEnabled=$s.OnAccessProtectionEnabled
  IsTamperProtected=$s.IsTamperProtected; AMRunningMode="$($s.AMRunningMode)"
  SignatureAgeDays=$s.AntivirusSignatureAge; QuickScanAgeDays=$s.QuickScanAge; FullScanAgeDays=$s.FullScanAge
}
"""
_PREFS = r"""
$p = Get-MpPreference
[pscustomobject]@{
  ExclusionPath=@($p.ExclusionPath); ExclusionProcess=@($p.ExclusionProcess)
  ExclusionExtension=@($p.ExclusionExtension); ExclusionIpAddress=@($p.ExclusionIpAddress)
  DisableRealtimeMonitoring=$p.DisableRealtimeMonitoring; DisableScriptScanning=$p.DisableScriptScanning
  DisableIOAVProtection=$p.DisableIOAVProtection; DisableBehaviorMonitoring=$p.DisableBehaviorMonitoring
  MAPSReporting=$p.MAPSReporting; PUAProtection=$p.PUAProtection; EnableControlledFolderAccess=$p.EnableControlledFolderAccess
}
"""
_THREATS = r"""
$names = @{}
foreach ($t in @(Get-MpThreat)) { $names["$($t.ThreatID)"] = @($t.ThreatName, $t.SeverityID, $t.IsActive) }
foreach ($d in @(Get-MpThreatDetection)) {
  $n = $names["$($d.ThreatID)"]
  [pscustomobject]@{
    ThreatID=$d.ThreatID; Name=$(if ($n) {$n[0]} else {''}); SeverityID=$(if ($n) {$n[1]} else {0})
    IsActive=$(if ($n) {[bool]$n[2]} else {$false})
    Time=$(if ($d.InitialDetectionTime) { $d.InitialDetectionTime.ToUniversalTime().ToString('o') } else {''})
    Resources=@($d.Resources); ActionSuccess=$d.ActionSuccess; StatusID=$d.ThreatStatusID
    Process=$d.ProcessName; User=$d.DomainUser
  }
}
"""
_BROAD_EXT = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "msi", "com"}
_REMEDIATION_EXCL = "Review in Windows Security > Virus & threat protection > Exclusions; remove any you did not add."


def _is_broad_path(p: str) -> bool:
    q = p.rstrip("\\/").lower()
    return len(q) <= 2 or q.count("\\") <= 2 and ("\\users\\" in q + "\\" or q.endswith(("\\windows", "\\temp", "\\programdata")))


def run(ctx) -> ModuleResult:
    res = ModuleResult(NAME)
    try:
        st = ps_json(_STATUS, timeout=60)[0]
    except (PSError, IndexError) as e:
        res.status = "skipped"
        res.notes.append(f"Defender cmdlets unavailable (third-party AV or module missing): {e}")
        return res
    res.coverage["running_mode"] = st.get("AMRunningMode")

    def fact(rule, title, sev, why, fix, value=""):
        res.add(rule_id=rule, title=title, severity=sev, evidence="Microsoft Defender", why=why,
                confidence=1.0, kind="fact", remediation=fix, details={"key": rule, "value": value})

    if not st.get("AntivirusEnabled") or not st.get("AMServiceEnabled"):
        fact("DEF-AV-OFF", "Defender antivirus is disabled", "high",
             f"AntivirusEnabled={st.get('AntivirusEnabled')}, running mode {st.get('AMRunningMode')}. "
             "Expected only if another AV product is registered.",
             "Confirm a third-party AV is installed and active, or re-enable Defender in Windows Security.")
    elif not st.get("RealTimeProtectionEnabled"):
        fact("DEF-RTP-OFF", "Defender real-time protection is off", "high",
             "Files are not scanned on access.", "Turn on Real-time protection in Windows Security.")
    for key, label in (("BehaviorMonitorEnabled", "behaviour monitoring"), ("IoavProtectionEnabled", "download/attachment scanning")):
        if st.get("AntivirusEnabled") and st.get(key) is False:
            fact(f"DEF-{key}", f"Defender {label} is off", "medium", f"{key}=False.",
                 "Re-enable in Windows Security or check for a policy/registry override.")
    if st.get("IsTamperProtected") is False:
        fact("DEF-TAMPER-OFF", "Defender tamper protection is off", "medium",
             "Malware or scripts running as admin can switch Defender off or add exclusions silently.",
             "Windows Security > Virus & threat protection settings > Tamper Protection: On.")
    age = st.get("SignatureAgeDays")
    if isinstance(age, int) and age > 7:
        fact("DEF-SIG-OLD", "Defender signatures are out of date", "medium",
             f"Signatures are {age} days old.", "Run Windows Update or 'Check for updates' in Windows Security.", str(age))

    try:
        pr = ps_json(_PREFS, timeout=60)[0]
        hidden = False
        for kind in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress"):
            for v in pr.get(kind) or []:
                v = str(v)
                if v.startswith("N/A"):
                    hidden = True
                    continue
                broad = (kind == "ExclusionPath" and _is_broad_path(v)) or (
                    kind == "ExclusionExtension" and v.lstrip(".").lower() in _BROAD_EXT
                )
                res.add(rule_id=f"DEF-EXCL-{kind}", title=f"Defender exclusion ({kind[9:].lower()})",
                        severity="high" if broad else "medium", evidence=v,
                        why=("Very broad exclusion: " if broad else "") + "Defender does not scan this "
                        "location/process/type. Exclusions are a common malware hiding place.",
                        confidence=1.0, kind="fact", remediation=_REMEDIATION_EXCL, details={"key": kind})
        if hidden:
            res.note("Defender exclusions are hidden from non-admin users; run elevated to audit them")
        for key in ("DisableRealtimeMonitoring", "DisableScriptScanning", "DisableIOAVProtection", "DisableBehaviorMonitoring"):
            if pr.get(key) is True:
                fact(f"DEF-PREF-{key}", f"Defender preference {key} is set", "high", f"{key}=True in Get-MpPreference.",
                     "Unset with Set-MpPreference (elevated) after confirming you did not configure it.")
        if pr.get("PUAProtection") == 0:
            fact("DEF-PUA-OFF", "Potentially unwanted app blocking is off", "low", "PUAProtection=0.",
                 "Windows Security > App & browser control > Reputation-based protection.")
    except (PSError, IndexError) as e:
        res.note(f"Get-MpPreference failed: {e}")

    if ctx.defender_scan:
        ctx.log("[defender] starting Defender quick scan (can take several minutes)")
        try:
            ps_json("Start-MpScan -ScanType QuickScan", timeout=3600)
            res.coverage["quick_scan_triggered"] = True
        except PSError as e:
            res.note(f"Start-MpScan failed: {e}")
    else:
        res.coverage["quick_scan_triggered"] = False

    try:
        dets = ps_json(_THREATS, timeout=120)
    except PSError as e:
        res.note(f"threat history unavailable: {e}")
        dets = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=3650 if ctx.full else 90)
    paths: list[str] = []
    seen = set()
    for d in dets:
        try:
            when = datetime.fromisoformat(d["Time"].replace("Z", "+00:00")) if d.get("Time") else None
        except ValueError:
            when = None
        if when and when < cutoff:
            continue
        files = [r.split(":_", 1)[1] if ":_" in r else r for r in (d.get("Resources") or [])]
        paths += files
        ev = files[0] if files else f"ThreatID {d.get('ThreatID')}"
        key = (d.get("ThreatID"), ev.lower())
        if key in seen:
            continue
        seen.add(key)
        active = bool(d.get("IsActive")) or d.get("ActionSuccess") is False
        res.add(rule_id="DEF-DETECTION", title=f"Defender detection: {d.get('Name') or d.get('ThreatID')}",
                severity="high" if active else "medium", evidence=ev,
                why=(f"Defender detected this on {d.get('Time', '?')[:10]}; "
                     + ("the threat is still active or the action failed." if active
                        else "Defender reports the action succeeded.")),
                confidence=0.9, kind="fact",
                remediation="Open Windows Security > Protection history, confirm the item is removed or quarantined, "
                            "and work out how it arrived (download, archive, repo clone).",
                signals=[f"defender: {d.get('Name')}"],
                details={"key": str(d.get("ThreatID")), "resources": files[:10], "process": d.get("Process"),
                         "value": str(active)})
    res.coverage["detections_in_window"] = len(seen)
    res.coverage["_detected_paths"] = paths
    return res
