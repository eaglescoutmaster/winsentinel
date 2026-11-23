# winsentinel

Defensive, **read-only** security scanner for a Windows 11 machine. It looks for malware, persistence,
vulnerabilities, leaked secrets and risky configuration, and writes a report. It never deletes, quarantines or
changes anything: v1 has no remediation code paths at all.

> **Not a replacement for antivirus or EDR.** winsentinel is a second opinion and an audit aid. It runs
> point-in-time, in user mode, with static heuristics. A clean report does not prove a clean machine. Keep
> Microsoft Defender (or your AV) on.

## Install

Requires Windows 10/11, Python 3.14 and [uv](https://docs.astral.sh/uv/). PowerShell 5.1 is used for read-only queries.

```powershell
cd C:\Users\mwhite8\winsentinel
uv sync
uv run winsentinel tools install
```

`tools install` downloads pinned releases of the external scanners into `tools\` (git-ignored), from the vendors'
official GitHub releases only, and refuses any file whose SHA256 does not match the value pinned in
`src/winsentinel/toolchain.py`. Nothing is installed system-wide. Semgrep is run on demand from an isolated,
version-pinned environment through `uv tool run`.

## Usage

```powershell
uv run winsentinel scan                 # same as --quick
uv run winsentinel scan --quick         # triage, a few minutes
uv run winsentinel scan --full          # all fixed drives, git history, Semgrep, Trivy, Windows Update search
uv run winsentinel scan --module persistence --module hardening
uv run winsentinel scan --module files --path D:\Downloads
uv run winsentinel scan --full --vt     # opt in: hash-only VirusTotal lookups (needs VT_API_KEY)
uv run winsentinel scan --update-baseline
uv run winsentinel tools status
uv run winsentinel modules
```

Run from an elevated terminal for full coverage. Without admin the scan still completes; every check that was
skipped is listed under **Coverage** in the report.

### Output

`reports\<timestamp>\` contains:

| File | Content |
|---|---|
| `report.md` | Summary, coverage per module, new/changed findings in detail, known findings as a table |
| `findings.json` | Every finding with evidence, signals, confidence, verification note, fingerprint |
| `findings.sarif` | SARIF 2.1.0 for editors and code-scanning viewers |
| `iocs.json` | URLs, IPs, domains and SHA256 extracted from flagged files |

Each finding has a severity (critical / high / medium / low / info), the evidence path, why it was flagged, a
confidence value and a suggested **manual** remediation.

**Verification pass.** Before reporting, every high/critical heuristic finding gets a second look: it needs two
independent signals (or one signature-grade signal: YARA, known hash, Defender detection); the file's
Authenticode signature is re-checked; test/fixture paths are capped. Findings that fail are downgraded and say
why. Findings of kind `fact` are direct reads of system state and are not second-guessed.

**Baseline.** The first full-module run writes `state\baseline.json`. Later runs mark each finding new, changed or
known, and only new/changed ones are shown in detail. `--update-baseline` accepts the current state. Runs limited
with `--module` or `--path` use a separate baseline so they cannot hide findings from modules that did not run.

## Modules

| Module | What it checks | Tools | Quick | Full adds | Needs admin for |
|---|---|---|---|---|---|
| `defender` | Defender status, tamper protection, exclusions, detection history | Defender cmdlets | collect only | `Start-MpScan` quick scan | viewing exclusions |
| `persistence` | Run keys, startup folders, tasks, services, WMI subscriptions, IFEO, AppInit, Winlogon, LSA, BootExecute, browser extensions, PowerShell profiles | registry, CIM | yes | | WMI subscriptions, other users' hives |
| `processes` | Unsigned or masquerading processes, listeners, outbound connections, hosts file, DNS, proxy | CIM, NetTCPIP | yes | | image paths of protected processes |
| `hardening` | UAC, BitLocker, firewall, RDP, SMBv1, LSA protection, WDigest, Secure Boot, local admins, guest, password policy | registry, cmdlets | yes | | |
| `ai-tooling` | `~/.claude` skills, plugins, commands, agents, hooks, settings, memory, MCP configs: prompt injection, hidden Unicode, encoded payloads, exfiltration, dangerous commands, broad permissions, unpinned MCP packages | built-in rules | yes | | |
| `secrets` | Secrets in code dirs; plaintext credentials in dotfiles, persistent env vars, shell history | Gitleaks, TruffleHog | working tree | git history | |
| `vulns` | Outdated apps, known-exploited app versions, dependency CVEs, patch age, vulnerable/unsigned drivers | winget, osv-scanner, Trivy, LOLDrivers | winget, osv, drivers | Trivy, Windows Update search | some driver files |
| `code` | Static analysis of your projects | Semgrep | skipped | yes (or `--module code`) | |
| `files` | YARA (built-in + YARA Forge core), SHA256, PE traits, disguised executables, known-vulnerable drivers | yara-python, pefile | Downloads, Desktop, Temp, Startup, Public (3-minute budget) | all fixed drives | protected directories |
| `iocs` | Indicators from files flagged above | built-in; VirusTotal with `--vt` | yes | | |

### Scan time

Quick: roughly 5 to 10 minutes. Full: hours on first run (every file on every fixed drive is sniffed; executables,
scripts, archives and documents up to 64 MB are hashed and YARA-scanned). The `files` module caches results by
path, size, mtime and rules version, so an interrupted scan resumes and later full scans only read what changed.

## Configuration

Optional `winsentinel.toml` in the repo root (git-ignored):

```toml
code_dirs = ['C:\Users\mwhite8\agentroom', 'C:\Users\mwhite8\TwoAI']
exclude_paths = ['D:\VMs', 'E:\Epic Games']   # files module only
quick_paths = ['%USERPROFILE%\Downloads']
max_file_mb = 64
quick_files_budget_s = 180
threads = 8
trusted_signers = ['Microsoft Corporation', 'Microsoft Windows']
```

`node_modules`, `target`, `.venv`, `dist`, `build`, `__pycache__` and lock files are skipped by the `secrets`,
`code` and `ai-tooling` modules. The `files` module still scans them for malware.

## Privacy and network use

- No file contents or personal data leave the machine.
- TruffleHog always runs with `--no-verification`, so found credentials are never sent to a provider.
- Secret values are never written to reports: type, location and at most the first 4 characters.
- Network is used only for: tool/rule/signature downloads (`tools install`, Semgrep rule packs, Trivy DB),
  `winget upgrade` source lookups, osv.dev queries (package names and versions), the Windows Update search in
  `--full`, and VirusTotal **hash** lookups if you pass `--vt`. Files are never uploaded.
- Suspicious files are never executed. There is no dynamic analysis.

## Limitations

- User-mode and static only: no kernel visibility, no memory scanning, no behaviour monitoring, no rootkit detection.
- Heuristics produce false positives (unsigned hobby software, security tools, admin scripts) and false
  negatives (novel or well-packed malware, anything that hides from a user-mode enumeration).
- Without admin: Defender exclusions, WMI subscriptions, protected process paths, other users' registry hives and
  some directories are not visible. The report lists what was skipped.
- `files` does not unpack archives or parse Office macros; it YARA-scans the container file as stored.
- The YARA build has no OpenSSL, so a small number of YARA Forge rules that inspect PE signatures are dropped
  (the count is in the report).
- "Outdated application" comes from `winget upgrade` and does not map to specific CVEs, apart from a small
  built-in table of widely exploited versions. Dependency CVEs are not checked for reachability.
- Browser extension checks cover Chrome, Edge and Brave manifests only.
- Signature validity is necessary, not sufficient: malware can be validly signed, so a valid non-trusted
  signature only caps severity rather than clearing a finding.

## Tests

```powershell
uv run pytest
```

Tests use an in-memory EICAR string (never written to disk, so no Defender exclusion is needed), fake persistence
entries, and a randomly generated fake token planted in a temp project.

## Credits

Detection patterns were ported from MIT-licensed projects listed in `NOTICE`.
