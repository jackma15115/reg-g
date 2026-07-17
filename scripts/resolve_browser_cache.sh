#!/usr/bin/env bash
# Shared browser-cache resolution for local + Docker.
# Source this file:  source "$ROOT/scripts/resolve_browser_cache.sh"
# Or call:           bash scripts/resolve_browser_cache.sh   (prints path)
#
# Priority (same on every host):
#   1) existing XDG_CACHE_HOME if it already has camoufox
#   2) $GROK_REGISTER_LITE_DATA_DIR/cache  (Docker: /data/cache)
#   3) /opt/browser-cache                  (image bake)
#   4) <repo>/data/register_lite/cache     (source checkout)
#   5) $HOME/.cache
#
# Always sets:
#   XDG_CACHE_HOME
#   PLAYWRIGHT_BROWSERS_PATH=$XDG_CACHE_HOME/ms-playwright

_resolve_browser_cache_has_camoufox() {
  local root="$1"
  [[ -n "$root" ]] || return 1
  [[ -d "${root}/camoufox/browsers/official" ]] && return 0
  compgen -G "${root}/camoufox/browsers/official/*" >/dev/null 2>&1 && return 0
  # package install layouts (camoufox dir present with any content)
  [[ -d "${root}/camoufox" ]] && return 0
  return 1
}

resolve_browser_cache() {
  local repo_dir="${1:-}"
  local cand

  # 1) honor pre-set env if usable
  if [[ -n "${XDG_CACHE_HOME:-}" ]] && _resolve_browser_cache_has_camoufox "${XDG_CACHE_HOME}"; then
    echo "${XDG_CACHE_HOME}"
    return 0
  fi

  # 2) data dir (container /data or explicit)
  if [[ -n "${GROK_REGISTER_LITE_DATA_DIR:-}" ]]; then
    cand="${GROK_REGISTER_LITE_DATA_DIR}/cache"
    if _resolve_browser_cache_has_camoufox "$cand" || [[ -d "${GROK_REGISTER_LITE_DATA_DIR}" ]]; then
      echo "$cand"
      return 0
    fi
  fi

  # 3) image bake path
  if _resolve_browser_cache_has_camoufox "/opt/browser-cache" || [[ -d /opt/browser-cache/camoufox ]]; then
    echo "/opt/browser-cache"
    return 0
  fi

  # 4) source-tree data dir (local checkout)
  if [[ -n "$repo_dir" ]]; then
    cand="${repo_dir}/data/register_lite/cache"
    echo "$cand"
    return 0
  fi

  # 5) home cache
  echo "${HOME:-/root}/.cache"
}

apply_browser_cache_env() {
  local repo_dir="${1:-}"
  local chosen
  chosen="$(resolve_browser_cache "$repo_dir")"
  export XDG_CACHE_HOME="$chosen"
  export PLAYWRIGHT_BROWSERS_PATH="${XDG_CACHE_HOME}/ms-playwright"
  mkdir -p "${XDG_CACHE_HOME}" "${PLAYWRIGHT_BROWSERS_PATH}"
}

# When executed directly, print resolved path
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  REPO="$(cd "$(dirname "$0")/.." && pwd)"
  apply_browser_cache_env "$REPO"
  echo "$XDG_CACHE_HOME"
fi
