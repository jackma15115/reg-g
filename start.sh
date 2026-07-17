#!/usr/bin/env bash
# Start the local registration/import console backed only by SQLite.
set -euo pipefail

cd "$(dirname "$0")"

# Prefer project venv so system Python (PEP 668) doesn't break startup.
if [[ -n "${PYTHON:-}" ]]; then
  PY="$PYTHON"
elif [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="python3"
fi

if ! command -v "$PY" >/dev/null 2>&1 && [[ ! -x "$PY" ]]; then
  echo "ERROR: Python 3.10+ is required." >&2
  exit 1
fi

if ! "$PY" -c "import fastapi, uvicorn, httpx, curl_cffi" 2>/dev/null; then
  if [[ "$PY" == ".venv/bin/python" || "$PY" == *"/venv/"* || "$PY" == *".venv/"* ]]; then
    "$PY" -m pip install -r requirements.txt
  else
    echo "ERROR: missing deps for $PY. Create .venv and install requirements, or set PYTHON=..." >&2
    exit 1
  fi
fi

export PYTHONPATH="$(pwd)/grok-build-auth${PYTHONPATH:+:$PYTHONPATH}"
export GROK_REGISTER_LITE=1
export GROK2API_STORE_BACKEND=file
export GROK2API_REQUIRE_SHARED_STORES=0

# Align with Docker/server layout: host data dir contents == container /data
# Server: /opt/grok-register-data/register_lite.sqlite3  (mounted at /data)
# Local:  ./data/register_lite/register_lite.sqlite3
export GROK_REGISTER_LITE_DATA_DIR="${GROK_REGISTER_LITE_DATA_DIR:-$(pwd)/data/register_lite}"
export GROK_REGISTER_LITE_DB="${GROK_REGISTER_LITE_DB:-${GROK_REGISTER_LITE_DATA_DIR}/register_lite.sqlite3}"
export GROK_REGISTER_LITE_OUTPUT_DIR="${GROK_REGISTER_LITE_OUTPUT_DIR:-${GROK_REGISTER_LITE_DATA_DIR}/outputs}"
mkdir -p "${GROK_REGISTER_LITE_DATA_DIR}" \
  "${GROK_REGISTER_LITE_OUTPUT_DIR}" \
  "${GROK_REGISTER_LITE_DATA_DIR}/backups" \
  "${GROK_REGISTER_LITE_DATA_DIR}/register_sso" \
  "${GROK_REGISTER_LITE_DATA_DIR}/cache"

echo "注册机: http://127.0.0.1:8788/admin/accounts"
echo "数据目录: ${GROK_REGISTER_LITE_DATA_DIR}"
echo "数据库:   ${GROK_REGISTER_LITE_DB}"
exec "$PY" register_lite_app.py
