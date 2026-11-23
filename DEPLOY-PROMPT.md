# Deploy prompt

## Windows

Paste everything in the block below into Claude Code on any Windows 10/11 machine.

```text
Install and run winsentinel, a defensive, read-only Windows security scanner, on this machine, then show me
the top findings. Work through every step without asking me questions unless a rule below says to stop.

RULES
- Report only. Do not delete, quarantine, move, disable, uninstall or change any file, setting, service,
  registry key or account, even if the scan finds something serious. Tell me and let me decide.
- Do not elevate or ask for admin. A non-admin scan is expected; the report lists what it could not see.
- Do not run, open or upload any file the scan flags.
- Use Windows PowerShell 5.1 syntax (no `&&`). Git is not required.
- The only downloads allowed are the ones bootstrap.ps1 makes itself (uv, Python 3.13, PyPI wheels, pinned
  SHA256-verified tools from GitHub).

STEP 1: get the code (skip the download if %USERPROFILE%\winsentinel\bootstrap.ps1 already exists)

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $ProgressPreference = 'SilentlyContinue'
  $dst = "$env:USERPROFILE\winsentinel"
  $tmp = Join-Path $env:TEMP ("ws-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force $tmp | Out-Null
  Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/eaglescoutmaster/winsentinel/archive/refs/tags/v0.3.0.zip' -OutFile "$tmp\ws.zip"
  Expand-Archive -LiteralPath "$tmp\ws.zip" -DestinationPath $tmp -Force
  Move-Item -LiteralPath "$tmp\winsentinel-0.3.0" -Destination $dst
  Remove-Item -LiteralPath $tmp -Recurse -Force

  If $dst exists but has no bootstrap.ps1, stop and tell me rather than overwriting it.

STEP 2: bootstrap (installs uv if missing, Python 3.13, dependencies, pinned tools; runs tests and a quick scan)

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\winsentinel\bootstrap.ps1"

  This takes 10 to 25 minutes. Run it in the background or with the longest timeout you have, and wait for it
  to finish. Do not start a second copy. It is safe to re-run after a failure: downloads and the file scan
  resume from cache.

  If it fails:
  - Network error or timeout: wait a minute and re-run the same command, up to 3 times.
  - "tools install" or "tests" warnings: these do not stop the run; carry on and mention them at the end.
  - uv not found after install: open a new PowerShell process and re-run; the script also checks
    %USERPROFILE%\.local\bin\uv.exe directly.
  - The scan itself exits non-zero: re-run only the scan with
      cd "$env:USERPROFILE\winsentinel"; uv run winsentinel scan --quick
    If it fails again, show me the last 40 lines of output and stop. Do not edit the scanner's code.

STEP 3: report
  The last line of the bootstrap prints `REPORT: <path>\report.md`. Read that file (and findings.json beside
  it if you need detail). Then tell me, in this order:
  1. Counts by severity.
  2. Every critical and high finding: what, where, why it was flagged, suggested manual fix.
  3. The most important medium findings (at most 10).
  4. What the scan could not cover (the Coverage section, skipped modules, missing tools).
  Never print secret values. Finish by reminding me this is not a replacement for antivirus or EDR.
```

Later scans on the same machine:

```powershell
cd $env:USERPROFILE\winsentinel
uv run winsentinel scan --quick     # or --full from an elevated terminal
```

## Linux and macOS

Paste everything in the block below into Claude Code on a Linux or macOS machine.

```text
Install and run winsentinel, a defensive, read-only security scanner, on this machine, then show me the top
findings. Work through every step without asking me questions unless a rule below says to stop.

RULES
- Report only. Do not delete, quarantine, move, disable, uninstall or change any file, setting, service,
  account, cron job or launch item, even if the scan finds something serious. Tell me and let me decide.
- Do not use sudo and do not ask for my password. A non-root scan is expected; the report lists what it
  could not see.
- Do not run, open or upload any file the scan flags.
- The only downloads allowed are the ones bootstrap.sh makes itself (uv, Python 3.13, PyPI wheels, pinned
  SHA256-verified tools from GitHub). Do not install system packages.

STEP 1: get the code (skip the download if ~/winsentinel/bootstrap.sh already exists)

  dst="$HOME/winsentinel"
  tmp=$(mktemp -d)
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/ws.tar.gz" https://github.com/eaglescoutmaster/winsentinel/archive/refs/tags/v0.4.0.tar.gz
  else
    wget -q -O "$tmp/ws.tar.gz" https://github.com/eaglescoutmaster/winsentinel/archive/refs/tags/v0.4.0.tar.gz
  fi
  tar -xzf "$tmp/ws.tar.gz" -C "$tmp"
  mv "$tmp/winsentinel-0.4.0" "$dst"
  rm -rf "$tmp"

  If ~/winsentinel exists but has no bootstrap.sh, stop and tell me rather than overwriting it.
  If neither curl nor wget is installed, stop and tell me which one to install.

STEP 2: bootstrap (installs uv if missing, Python 3.13, dependencies, pinned tools; runs tests and a quick scan)

  sh "$HOME/winsentinel/bootstrap.sh"

  This takes 5 to 20 minutes. Run it in the background or with the longest timeout you have, and wait for it
  to finish. Do not start a second copy. It is safe to re-run after a failure: downloads and the file scan
  resume from cache.

  If it fails:
  - Network error or timeout: wait a minute and re-run the same command, up to 3 times.
  - "tools install" or "tests" warnings: these do not stop the run; carry on and mention them at the end.
  - uv not found after install: re-run; the script also checks ~/.local/bin/uv directly.
  - The scan itself exits non-zero: re-run only the scan with
      cd "$HOME/winsentinel" && ~/.local/bin/uv run winsentinel scan --quick
    If it fails again, show me the last 40 lines of output and stop. Do not edit the scanner's code.

STEP 3: report
  The bootstrap prints `REPORT: <path>/report.md`. Read that file (and findings.json beside it if you need
  detail). Then tell me, in this order:
  1. Counts by severity.
  2. Every critical and high finding: what, where, why it was flagged, suggested manual fix.
  3. The most important medium findings (at most 10).
  4. What the scan could not cover (the Coverage section, skipped modules, missing tools, root-only checks).
  Never print secret values. Finish by reminding me this is not a replacement for antivirus or EDR.
```

Later scans:

```sh
cd ~/winsentinel
uv run winsentinel scan --quick     # or: sudo "$(command -v uv)" run winsentinel scan --full
```
