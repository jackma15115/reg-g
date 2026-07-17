#!/usr/bin/env bash
# Download browser binaries used by the local Turnstile solver.
#
# Default: fetch whatever the installed camoufox/patchright packages want
# (no hard-coded browser version in this repo).
#
# Cache locations (override via env):
#   XDG_CACHE_HOME          -> camoufox cache parent (default: /data/cache or ~/.cache)
#   PLAYWRIGHT_BROWSERS_PATH-> chromium binaries (default: $XDG_CACHE_HOME/ms-playwright)
#
# Optional:
#   TURNSTILE_BROWSER_TYPE=camoufox|chromium|chrome|msedge  (default camoufox)
#   TURNSTILE_BROWSER_FORCE_FETCH=1   re-download even if present
#   TURNSTILE_FETCH_CHROMIUM=1        also fetch chromium when primary is camoufox
set -euo pipefail

PY="${TURNSTILE_PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/resolve_browser_cache.sh"
# If caller already exported XDG_CACHE_HOME, keep it; else shared resolve.
if [[ -z "${XDG_CACHE_HOME:-}" ]]; then
  apply_browser_cache_env "${REPO_DIR}"
else
  export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$XDG_CACHE_HOME/ms-playwright}"
  mkdir -p "$XDG_CACHE_HOME" "$PLAYWRIGHT_BROWSERS_PATH"
fi

BROWSER_TYPE="$(echo "${TURNSTILE_BROWSER_TYPE:-camoufox}" | tr '[:upper:]' '[:lower:]')"
FORCE="$(echo "${TURNSTILE_BROWSER_FORCE_FETCH:-0}" | tr '[:upper:]' '[:lower:]')"
FORCE_ON=0
if [[ "$FORCE" == "1" || "$FORCE" == "true" || "$FORCE" == "yes" || "$FORCE" == "on" ]]; then
  FORCE_ON=1
fi

need_camoufox=0
need_chromium=0
case "$BROWSER_TYPE" in
  camoufox) need_camoufox=1 ;;
  chromium|chrome|msedge) need_chromium=1 ;;
  *) need_camoufox=1 ;;
esac
if [[ "${TURNSTILE_FETCH_CHROMIUM:-0}" == "1" ]]; then
  need_chromium=1
fi

camoufox_ready() {
  "$PY" - <<'PY' 2>/dev/null
from camoufox.pkgman import INSTALL_DIR, Version
from pathlib import Path
p = Path(INSTALL_DIR)
if not p.exists() or not any(p.iterdir()):
    raise SystemExit(1)
try:
    # installed version must be within package-supported range
    if not Version.from_path().is_supported():
        raise SystemExit(2)
except Exception:
    raise SystemExit(3)
raise SystemExit(0)
PY
}

chromium_ready() {
  # Presence of any chromium-* dir under PLAYWRIGHT_BROWSERS_PATH is good enough.
  local root="${PLAYWRIGHT_BROWSERS_PATH}"
  [[ -d "$root" ]] || return 1
  compgen -G "$root/chromium-*" >/dev/null 2>&1 || compgen -G "$root/chromium_headless_shell-*" >/dev/null 2>&1
}

echo "[fetch-browsers] cache=$XDG_CACHE_HOME playwright=$PLAYWRIGHT_BROWSERS_PATH type=$BROWSER_TYPE"

if [[ "$need_camoufox" == "1" ]]; then
  if [[ "$FORCE_ON" != "1" ]] && camoufox_ready; then
    ver="$("$PY" - <<'PY'
from camoufox.pkgman import installed_verstr
print(installed_verstr())
PY
)"
    echo "[fetch-browsers] camoufox already present: v${ver}"
  else
    echo "[fetch-browsers] downloading camoufox (version selected by installed camoufox package)..."
    # No hard-coded browser version: package resolves the matching release.
    if ! "$PY" -m camoufox fetch; then
      echo "[fetch-browsers] WARN: camoufox fetch failed" >&2
    else
      ver="$("$PY" - <<'PY'
from camoufox.pkgman import installed_verstr
print(installed_verstr())
PY
)" || ver="unknown"
      echo "[fetch-browsers] camoufox ready: v${ver}"
    fi
  fi
fi

if [[ "$need_chromium" == "1" ]]; then
  if [[ "$FORCE_ON" != "1" ]] && chromium_ready; then
    echo "[fetch-browsers] chromium already present under $PLAYWRIGHT_BROWSERS_PATH"
  else
    echo "[fetch-browsers] downloading chromium via patchright (package-selected revision)..."
    if ! "$PY" -m patchright install chromium; then
      echo "[fetch-browsers] WARN: patchright chromium install failed" >&2
    else
      echo "[fetch-browsers] chromium ready"
    fi
  fi
fi

echo "[fetch-browsers] done"
