<#
  winsentinel bootstrap: from a fresh Windows 10/11 install to a finished quick scan.
  Windows PowerShell 5.1 compatible. Safe to re-run. Changes nothing outside this folder
  except installing uv (per-user) when it is missing.

  Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 [-SkipTests] [-SkipScan]
#>
param([switch]$SkipTests, [switch]$SkipScan)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-Location -LiteralPath $PSScriptRoot

function Step($msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }

function Find-Uv {
    $c = Get-Command uv -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:USERPROFILE\.local\bin\uv.exe", "$env:USERPROFILE\.cargo\bin\uv.exe",
                     "$env:LOCALAPPDATA\Microsoft\WinGet\Links\uv.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

Step 'uv'
$uv = Find-Uv
if (-not $uv) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host 'installing uv with winget'
        & $winget.Source install --id astral-sh.uv -e --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Host
    }
    $uv = Find-Uv
    if (-not $uv) {
        Write-Host 'installing uv with the official installer (astral.sh)'
        $installer = Join-Path $env:TEMP 'uv-install.ps1'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://astral.sh/uv/install.ps1' -OutFile $installer
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer | Out-Host
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
        $uv = Find-Uv
    }
}
if (-not $uv) { throw 'uv could not be installed. Install it from https://docs.astral.sh/uv/ and re-run.' }
Write-Host "uv: $uv ($(& $uv --version))"

# Native tools write progress to stderr; under 'Stop' PowerShell 5.1 would treat that as a failure.
$ErrorActionPreference = 'Continue'

function Invoke-Uv {
    param([string]$What, [string[]]$UvArgs, [switch]$AllowFail)
    Step $What
    & $uv @UvArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        if ($AllowFail) { Write-Host "WARNING: '$What' exited with $code; continuing" -ForegroundColor Yellow }
        else { Write-Host "FAILED: '$What' exited with $code" -ForegroundColor Red; exit $code }
    }
    return
}

Invoke-Uv 'Python 3.13 + dependencies (prebuilt wheels, no compiler needed)' @('sync')
# A tool that fails to download is reported by the scan as skipped; it must not stop the bootstrap.
Invoke-Uv 'pinned external tools (SHA256 verified)' @('run', 'winsentinel', 'tools', 'install') -AllowFail
Invoke-Uv 'tool status' @('run', 'winsentinel', 'tools', 'status') -AllowFail
if (-not $SkipTests) { Invoke-Uv 'tests' @('run', 'pytest', '-q') -AllowFail }
if (-not $SkipScan) {
    Invoke-Uv 'quick scan (read-only, about 5 minutes)' @('run', 'winsentinel', 'scan', '--quick')
    $latest = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'reports') -Directory | Sort-Object Name | Select-Object -Last 1
    if ($latest) { Write-Host "`nREPORT: $(Join-Path $latest.FullName 'report.md')" -ForegroundColor Green }
}
Write-Host "`nOptional, for 'analyze --llm' and 'scan --vt':"
Write-Host '  uv run winsentinel login                 # Claude subscription, browser sign-in (Google works)'
Write-Host '  uv run winsentinel keys set anthropic    # or a Claude API key'
Write-Host '  uv run winsentinel keys set virustotal   # VirusTotal hash lookups'
exit 0
