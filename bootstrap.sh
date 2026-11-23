#!/bin/sh
# winsentinel bootstrap for Linux and macOS: from a fresh install to a finished quick scan.
# Safe to re-run. Changes nothing outside this folder except installing uv (per-user) when missing.
# No sudo. Usage: sh bootstrap.sh [--skip-tests] [--skip-scan]
set -u
cd "$(dirname "$0")" || exit 1

SKIP_TESTS=0; SKIP_SCAN=0
for a in "$@"; do
  case "$a" in
    --skip-tests) SKIP_TESTS=1 ;;
    --skip-scan) SKIP_SCAN=1 ;;
  esac
done

step() { printf '\n== %s\n' "$1"; }

find_uv() {
  if command -v uv >/dev/null 2>&1; then command -v uv; return; fi
  for p in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; do
    [ -x "$p" ] && { echo "$p"; return; }
  done
}

step uv
UV=$(find_uv)
if [ -z "$UV" ]; then
  echo "installing uv with the official installer (astral.sh)"
  if command -v curl >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- https://astral.sh/uv/install.sh | sh
  else
    echo "FAILED: neither curl nor wget is installed. Install one (or uv itself) and re-run." >&2
    exit 1
  fi
  UV=$(find_uv)
fi
if [ -z "$UV" ]; then
  echo "FAILED: uv could not be installed. See https://docs.astral.sh/uv/ and re-run." >&2
  exit 1
fi
echo "uv: $UV ($("$UV" --version))"

run() {  # run <fatal 0|1> <title> <uv args...>
  fatal=$1; title=$2; shift 2
  step "$title"
  "$UV" "$@"
  code=$?
  if [ $code -ne 0 ]; then
    if [ "$fatal" = 1 ]; then echo "FAILED: '$title' exited with $code" >&2; exit $code; fi
    echo "WARNING: '$title' exited with $code; continuing"
  fi
}

run 1 'Python 3.13 + dependencies (prebuilt wheels, no compiler needed)' sync
# A tool that fails to download is reported by the scan as skipped; it must not stop the bootstrap.
run 0 'pinned external tools (SHA256 verified)' run winsentinel tools install
run 0 'tool status' run winsentinel tools status
[ $SKIP_TESTS = 1 ] || run 0 tests run pytest -q
if [ $SKIP_SCAN = 0 ]; then
  run 1 'quick scan (read-only, about 5 minutes)' run winsentinel scan --quick
  latest=$(ls -d reports/2* 2>/dev/null | sort | tail -n 1)
  [ -n "$latest" ] && printf '\nREPORT: %s/%s/report.md\n' "$(pwd)" "$latest"
fi
printf '\nOptional, for "analyze --llm" and "scan --vt":\n'
echo '  uv run winsentinel login                 # Claude subscription, browser sign-in (Google works)'
echo '  uv run winsentinel keys set anthropic    # or a Claude API key'
echo '  uv run winsentinel keys set virustotal   # VirusTotal hash lookups'
echo 'For fuller coverage, re-run the scan as root: sudo "$(command -v uv)" run winsentinel scan --quick'
exit 0
