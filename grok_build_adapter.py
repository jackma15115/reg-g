"""Adapter: grok-build-auth -> grok-register-lite account pool.

Drives the vendored ``grok-build-auth/xconsole_client`` protocol client to:

1. register an x.ai account with MoeMail + YesCaptcha
2. extract SSO/session cookies
3. convert SSO via sso_to_auth_json into a local auth.json entry
4. import that entry into the multi-account pool

Import of ``xconsole_client`` is deferred so the main API can start even when
optional deps are missing. Registration endpoints then return a clear error
instead of crashing process startup.

``grok-build-auth`` is vendored in-tree (not a git submodule).
Legacy browser (DrissionPage) and grpc-session registration engines were removed.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
GBA = ROOT / "grok-build-auth"
ADAPTER_BUILD = "2026-07-21-success-target-ti-domain-pool-1"
# Newly registered accounts often need a short settle window before probe.
REGISTER_PROBE_DELAY_SEC = float(
    os.environ.get("GROK2API_REG_PROBE_DELAY_SEC", "30") or 30
)

YESCAPTCHA_KEY = (
    os.environ.get("GROK2API_YESCAPTCHA_KEY")
    or os.environ.get("YESCAPTCHA_API_KEY")
    or ""
).strip()

CAPTCHA_PROVIDER = (
    os.environ.get("GROK2API_CAPTCHA_PROVIDER")
    or os.environ.get("CAPTCHA_PROVIDER")
    or "local"
).strip().lower()
if CAPTCHA_PROVIDER not in {"local", "yescaptcha"}:
    CAPTCHA_PROVIDER = "local"

LOCAL_SOLVER_URL = (
    os.environ.get("GROK2API_LOCAL_SOLVER_URL")
    or os.environ.get("LOCAL_SOLVER_URL")
    or os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")
    or os.environ.get("YESCAPTCHA_ENDPOINT")
    or "http://127.0.0.1:5072"
).strip().rstrip("/")

# Hard cap for multi-thread registration concurrency only (captcha + xAI rate limits).
# Batch count is intentionally uncapped — only concurrency bounds parallelism.
MAX_CONCURRENCY = int(os.environ.get("GROK2API_REG_MAX_CONCURRENCY", "50") or 50)
DEFAULT_CONCURRENCY = int(os.environ.get("GROK2API_REG_CONCURRENCY", "1") or 1)
# Local multi-browser captcha pool size (turnstile-solver --thread).
DEFAULT_CAPTCHA_CONCURRENCY = int(os.environ.get("GROK2API_CAPTCHA_CONCURRENCY", "1") or 1)
MAX_CAPTCHA_CONCURRENCY = int(os.environ.get("GROK2API_CAPTCHA_MAX_CONCURRENCY", "50") or 50)

# When captcha_provider=local, registration must wait for the inline Turnstile
# Solver HTTP to answer before spawning workers. Prevents "already running but
# captcha always fails because solver is still booting / restarting".
LOCAL_SOLVER_WAIT_SEC = float(
    os.environ.get("GROK2API_LOCAL_SOLVER_WAIT_SEC", "120") or 120
)
LOCAL_SOLVER_POLL_SEC = float(
    os.environ.get("GROK2API_LOCAL_SOLVER_POLL_SEC", "1.0") or 1.0
)

# --------------------------------------------------------------------------- #
# session state
# --------------------------------------------------------------------------- #
_sessions: dict[str, dict[str, Any]] = {}
_batches: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
# batch_id -> True while a local ThreadPool spawner is alive in THIS process.
_active_batch_runners: dict[str, bool] = {}
# Local captcha: multi-browser pool (like grok_reg TabPool — one browser lane
# per captcha worker). Controlled by registration_config.captcha_concurrency and
# TURNSTILE_THREAD. Use a semaphore so N solves can run in parallel.
_local_captcha_limit = max(1, min(MAX_CAPTCHA_CONCURRENCY, DEFAULT_CAPTCHA_CONCURRENCY))
_local_captcha_sem = threading.Semaphore(_local_captcha_limit)
_local_captcha_active = 0
_local_captcha_active_lock = threading.Lock()


def get_local_captcha_concurrency() -> int:
    return int(_local_captcha_limit)


def get_local_captcha_active() -> int:
    with _local_captcha_active_lock:
        return int(_local_captcha_active)


def set_local_captcha_concurrency(value: int | str | None) -> int:
    """Set how many local Camoufox captcha solves may run at once (1..50)."""
    global _local_captcha_limit, _local_captcha_sem
    try:
        n = int(value if value is not None else DEFAULT_CAPTCHA_CONCURRENCY)
    except (TypeError, ValueError):
        n = DEFAULT_CAPTCHA_CONCURRENCY
    n = max(1, min(MAX_CAPTCHA_CONCURRENCY, n))
    _local_captcha_limit = n
    # Replace semaphore; in-flight tasks keep old slots until release.
    _local_captcha_sem = threading.Semaphore(n)
    return n


class _CaptchaSlot:
    """Context manager: acquire one captcha lane from the pool."""

    def __enter__(self):
        global _local_captcha_active
        _local_captcha_sem.acquire()
        with _local_captcha_active_lock:
            _local_captcha_active += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        global _local_captcha_active
        with _local_captcha_active_lock:
            _local_captcha_active = max(0, int(_local_captcha_active) - 1)
        _local_captcha_sem.release()
        return False

# Cross-batch in-flight registration jobs. Configurable from UI
# (registration_config.global_inflight); env is only the boot default.
try:
    _GLOBAL_REG_INFLIGHT_MAX = max(
        1,
        min(
            64,
            int(os.environ.get("GROK2API_REG_GLOBAL_INFLIGHT", "1") or 1),
        ),
    )
except (TypeError, ValueError):
    _GLOBAL_REG_INFLIGHT_MAX = 1
# Dynamic admission (limit can change without restart).
_global_reg_inflight_limit = int(_GLOBAL_REG_INFLIGHT_MAX)
_global_reg_inflight_active = 0
_global_reg_inflight_cond = threading.Condition()
# Soft rate-limit signal: after device-flow / captcha storms, temporarily reduce
# new job admission without killing already-running workers.
_reg_soft_pause_until = 0.0
_reg_soft_pause_lock = threading.Lock()
_xconsole_ready = False
_xconsole_error: str | None = None


def get_global_reg_inflight_limit() -> int:
    with _global_reg_inflight_cond:
        return int(_global_reg_inflight_limit)


def get_global_reg_inflight_active() -> int:
    with _global_reg_inflight_cond:
        return int(_global_reg_inflight_active)


def set_global_reg_inflight_limit(value: int | str | None) -> int:
    """Update cross-batch admission cap at runtime (1..64)."""
    global _global_reg_inflight_limit
    try:
        n = int(value if value is not None else _GLOBAL_REG_INFLIGHT_MAX)
    except (TypeError, ValueError):
        n = int(_GLOBAL_REG_INFLIGHT_MAX)
    n = max(1, min(64, n))
    with _global_reg_inflight_cond:
        _global_reg_inflight_limit = n
        _global_reg_inflight_cond.notify_all()
    return n


def _immediate_auto_upload_emails(emails: list[str]) -> dict[str, Any] | None:
    """Upload probe-passed emails immediately — no grouping / waiting for batch end."""
    clean: list[str] = []
    seen: set[str] = set()
    for email in emails or []:
        key = str(email or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        clean.append(key)
    if not clean:
        return None
    try:
        import register_lite_store as _store

        # One-shot upload of this session's probe-passed accounts.
        return _store.sync_accounts_after_probe(clean, batch_size=max(1, len(clean)))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:240], "total": len(clean), "emails": clean}


def _note_reg_pressure(reason: str = "", *, pause_sec: float | None = None) -> None:
    """Backoff new admissions briefly when upstream rate-limits hit."""
    global _reg_soft_pause_until
    try:
        sec = float(
            pause_sec
            if pause_sec is not None
            else (os.environ.get("GROK2API_REG_SOFT_PAUSE_SEC", "8") or 8)
        )
    except (TypeError, ValueError):
        sec = 8.0
    sec = max(1.0, min(60.0, sec))
    with _reg_soft_pause_lock:
        _reg_soft_pause_until = max(_reg_soft_pause_until, time.time() + sec)
    if reason:
        print(f"[registration] soft-pause {sec:.0f}s ({reason})")


def _wait_reg_admission(*, check_cancel=None) -> None:
    """Block until global inflight slot is free and soft-pause window ends."""
    global _global_reg_inflight_active
    while True:
        if check_cancel is not None:
            try:
                check_cancel()
            except Exception:
                raise
        with _reg_soft_pause_lock:
            wait = _reg_soft_pause_until - time.time()
        if wait > 0:
            time.sleep(min(1.0, wait))
            continue
        with _global_reg_inflight_cond:
            if _global_reg_inflight_active < _global_reg_inflight_limit:
                _global_reg_inflight_active += 1
                return
            _global_reg_inflight_cond.wait(timeout=0.15)


def _release_reg_admission() -> None:
    global _global_reg_inflight_active
    with _global_reg_inflight_cond:
        _global_reg_inflight_active = max(0, int(_global_reg_inflight_active) - 1)
        _global_reg_inflight_cond.notify_all()

# How many jobs may be pre-created (mailbox + session) beyond the live concurrency
# cap. Keep small so stop/cancel doesn't waste dozens of mailboxes.
REG_PREFETCH_SLOTS = int(os.environ.get("GROK2API_REG_PREFETCH_SLOTS", "1") or 1)


def _now() -> float:
    return time.time()


def _reg_redis() -> bool:
    """The registration-only server has no Redis dependency."""
    return False


# Kept for the local batch heartbeat loop (full multi-worker stack used Redis TTL).
# Lite mode only sleeps on this interval; ownership is process-local.
try:
    REG_BATCH_RUNNER_LOCK_TTL = max(
        15,
        min(600, int(os.environ.get("GROK2API_REG_RUNNER_LOCK_TTL", "90") or 90)),
    )
except (TypeError, ValueError):
    REG_BATCH_RUNNER_LOCK_TTL = 90


def _renew_batch_runner(_batch_id: str, _token: str | None) -> None:
    """Local batch ownership lives for the lifetime of this process."""


def _try_acquire_batch_runner(batch_id: str) -> tuple[bool, str | None]:
    """Claim exclusive spawner ownership for one local process."""
    bid = str(batch_id or "").strip()
    if not bid:
        return False, None
    with _lock:
        if _active_batch_runners.get(bid):
            return False, None
        _active_batch_runners[bid] = True
    return True, f"{uuid.uuid4().hex}|{os.getpid()}|{_now():.0f}"


def _release_batch_runner(batch_id: str, _token: str | None) -> None:
    bid = str(batch_id or "").strip()
    with _lock:
        _active_batch_runners.pop(bid, None)


def _snapshot_reg_config(
    *,
    captcha_provider: str,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None,
    moemail_base_url: str | None,
    prefix: str | None,
    domain: str | None,
    expiry_ms: int | None,
    concurrency: int,
    stagger_ms: int,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
) -> dict[str, Any]:
    """Config snapshot kept with the in-memory/Redis batch while it is running."""
    return {
        "captcha_provider": captcha_provider,
        "yescaptcha_key": yescaptcha_key if captcha_provider == "yescaptcha" else "",
        "proxy": proxy or "",
        "moemail_api_key": moemail_api_key or "",
        "moemail_base_url": moemail_base_url or "",
        "prefix": prefix or "",
        "domain": domain or "",
        "expiry_ms": expiry_ms,
        "concurrency": concurrency,
        "stagger_ms": stagger_ms,
        "local_solver_url": "http://127.0.0.1:5072",
        "mail_provider": (mail_provider or "moemail").strip().lower() or "moemail",
        "mailbox_mode": (mailbox_mode or "maindomain").strip().lower() or "maindomain",
    }


class _RegCancelled(Exception):
    """Cooperative cancel for in-flight registration workers."""


_TERMINAL_STATUSES = frozenset(
    {
        "imported",
        "success",
        "completed",
        "error",
        "failed",
        "probe_failed",
        "expired",
        "protocol_error",
        "protocol_blocked",
        "cancelled",
        "stopped",
    }
)


def _is_cancel_status(status: str | None) -> bool:
    return str(status or "").lower() in ("cancelled", "stopped", "stopping")


def _session_cancel_requested(sess: dict[str, Any] | None) -> bool:
    if not isinstance(sess, dict):
        return False
    if sess.get("cancel_requested"):
        return True
    return _is_cancel_status(sess.get("status"))


def _mirror_reg_sess(_sid: str, _sess: dict[str, Any] | None) -> None:
    """Compatibility hook retained for local in-memory sessions only."""


def _mirror_reg_batch(_batch_id: str, _batch: dict[str, Any] | None) -> None:
    """Compatibility hook retained for local in-memory batches only."""


def _record_register_task(
    *,
    task_id: str | None,
    summary: str,
    status: str,
    ok: bool | None = None,
    progress_done: int = 0,
    progress_total: int = 0,
    finished: bool = True,
    detail: dict[str, Any] | None = None,
) -> None:
    # The lite UI reads live registration session and batch state directly.
    return None


def _session_task_log_payload(sess: dict[str, Any] | None) -> dict[str, Any]:
    s = sess if isinstance(sess, dict) else {}
    st = str(s.get("status") or "done").lower() or "done"
    ok: bool | None
    if st in ("imported", "success", "completed", "done"):
        ok = True
    elif st in ("error", "failed", "probe_failed", "expired", "protocol_error", "protocol_blocked"):
        ok = False
    elif st in ("cancelled", "stopped"):
        ok = False
    else:
        ok = None
    email = str(s.get("email") or "").strip()
    summary = str(s.get("message") or "").strip()
    if not summary:
        summary = f"协议注册 {email or s.get('id') or ''}".strip()
    return {
        "task_id": str(s.get("id") or ""),
        "summary": summary,
        "status": st,
        "ok": ok,
        "progress_done": 1 if st in _TERMINAL_STATUSES else 0,
        "progress_total": 1,
        "finished": st in _TERMINAL_STATUSES,
        "detail": {
            "session_id": s.get("id"),
            "batch_id": s.get("batch_id"),
            "email": email or None,
            "status": st,
            "error": s.get("error"),
            "imported_account_ids": list(s.get("imported_account_ids") or [])[:20],
            "adapter_build": s.get("adapter_build") or ADAPTER_BUILD,
        },
    }


def _load_reg_sess(sid: str) -> dict[str, Any] | None:
    with _lock:
        return _sessions.get(sid)


def _load_reg_batch(batch_id: str) -> dict[str, Any] | None:
    with _lock:
        return _batches.get(batch_id)


def _clean_old_sessions() -> None:
    cutoff = _now() - 6 * 3600
    for sid in list(_sessions.keys()):
        sess = _sessions.get(sid) or {}
        if float(sess.get("updated_at") or 0) < cutoff:
            _sessions.pop(sid, None)
            _mirror_reg_sess(sid, None)


def _compact_session(sess: dict[str, Any]) -> dict[str, Any]:
    out = dict(sess)
    out.pop("_client", None)
    out.pop("_oauth_client", None)
    out.pop("password", None)
    out.pop("yescaptcha_key", None)
    # Prefer explicit imported ids; fall back to auth_json summary for UI/logs.
    imported_ids = list(out.get("imported_account_ids") or [])
    imported_accounts = list(out.get("imported_accounts") or [])
    aj = out.get("auth_json")
    if isinstance(aj, dict):
        rows = [x for x in (aj.get("imported") or []) if isinstance(x, dict)]
        out["auth_json_count"] = len(rows)
        if not imported_ids:
            imported_ids = [str(x.get("id")) for x in rows if x.get("id")]
        if not imported_accounts:
            imported_accounts = [
                {"id": x.get("id"), "email": x.get("email")}
                for x in rows
                if x.get("id") or x.get("email")
            ]
    elif aj is not None:
        try:
            out["auth_json_count"] = len(aj)  # type: ignore[arg-type]
        except Exception:
            out["auth_json_count"] = 0
    if imported_ids:
        out["imported_account_ids"] = imported_ids
    if imported_accounts:
        out["imported_accounts"] = imported_accounts
    # Drop full auth payload from list/poll responses (secrets).
    out.pop("auth_json", None)
    return out


def ensure_xconsole() -> None:
    """Ensure vendored grok-build-auth/xconsole_client is importable.

    Raises RuntimeError with actionable message when unavailable.
    Safe to call multiple times.
    """
    global _xconsole_ready, _xconsole_error
    if _xconsole_ready:
        return
    if _xconsole_error:
        raise RuntimeError(_xconsole_error)

    if not GBA.is_dir():
        _xconsole_error = (
            "grok-build-auth 目录不存在。请确认仓库完整检出，"
            "或重新 clone 本项目。"
        )
        raise RuntimeError(_xconsole_error)

    xc = GBA / "xconsole_client"
    if not xc.is_dir():
        _xconsole_error = (
            "grok-build-auth/xconsole_client 不存在。"
            "请确认仓库完整检出（该目录已内置，不再使用 git submodule）。"
        )
        raise RuntimeError(_xconsole_error)

    # Put vendored package root on sys.path so `import xconsole_client` works.
    gba_str = str(GBA.resolve())
    if gba_str not in sys.path:
        sys.path.insert(0, gba_str)

    try:
        # Import side-effect: validate package is loadable.
        import xconsole_client  # noqa: F401
        from xconsole_client import (  # noqa: F401
            XConsoleAuthClient,
            YesCaptchaSolver,
            create_solver,
            xai_oauth_login_protocol,
        )
        from xconsole_client.oauth_protocol import (  # noqa: F401
            extract_cookies_from_auth_client,
        )
        from xconsole_client.xai_oauth import (  # noqa: F401
            CLIPROXYAPI_GROK_HEADERS,
            build_cliproxyapi_auth_record,
        )
    except ModuleNotFoundError as e:
        missing = getattr(e, "name", None) or str(e)
        if missing in ("curl_cffi", "requests") or "curl_cffi" in str(e) or "requests" in str(e):
            _xconsole_error = (
                f"注册机依赖缺失: {missing}。请执行: pip install -r requirements.txt"
            )
        else:
            _xconsole_error = (
                f"无法导入 xconsole_client ({e})。请执行: pip install -r requirements.txt"
            )
        raise RuntimeError(_xconsole_error) from e
    except Exception as e:  # noqa: BLE001
        _xconsole_error = f"加载 grok-build-auth 失败: {e}"
        raise RuntimeError(_xconsole_error) from e

    _xconsole_ready = True
    _xconsole_error = None


def _local_solver_base_url(url: str | None = None) -> str:
    """Always pin local captcha to the in-container inline solver."""
    raw = (
        (url or "").strip()
        or (LOCAL_SOLVER_URL or "").strip()
        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")
        or os.environ.get("LOCAL_SOLVER_URL")
        or "http://127.0.0.1:5072"
    ).strip().rstrip("/")
    # Registration must never hit an external "local" URL; force loopback.
    if (
        not raw
        or "127.0.0.1" not in raw
        and "localhost" not in raw
    ):
        return "http://127.0.0.1:5072"
    return raw


def probe_local_solver(
    url: str | None = None,
    *,
    timeout: float = 2.0,
) -> dict[str, Any]:
    """Probe inline Turnstile Solver readiness.

    HTTP up is enough to accept createTask (lazy browser mode warms on first
    solve). We prefer ``/health`` but also accept ``/`` returning any HTTP body.
    """
    base = _local_solver_base_url(url)
    out: dict[str, Any] = {
        "ok": False,
        "ready": False,
        "url": base,
        "http_up": False,
        "lazy": None,
        "pool_ready": None,
        # Live pool size fields from /health (critical for power-mode hot-apply).
        "thread": None,
        "threads": None,
        "owned": None,
        "queue": None,
        "in_flight": None,
        "browser_type": None,
        "error": None,
        "status_code": None,
    }
    try:
        import urllib.error
        import urllib.request
    except Exception as e:  # noqa: BLE001
        out["error"] = f"urllib unavailable: {e}"
        return out

    def _absorb_health(data: dict[str, Any]) -> None:
        """Copy structured /health fields so callers can compare pool size."""
        out["lazy"] = data.get("lazy")
        out["pool_ready"] = data.get("pool_ready")
        out["browser_type"] = data.get("browser_type")
        for key in ("thread", "threads", "owned", "queue", "in_flight"):
            if key not in data:
                continue
            try:
                out[key] = int(data.get(key))
            except (TypeError, ValueError):
                out[key] = data.get(key)

    # 1) /health — structured
    try:
        req = urllib.request.Request(
            f"{base}/health",
            headers={"Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:
            out["status_code"] = int(getattr(resp, "status", 200) or 200)
            body = resp.read().decode("utf-8", errors="replace")
        out["http_up"] = True
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            _absorb_health(data)
            # Solver process is ready when /health answers ok=true.
            # pool_ready may still be false under TURNSTILE_LAZY=1 — that is OK;
            # browsers warm on the first captcha task.
            if data.get("ok") is False:
                out["error"] = f"solver health ok=false body={body[:200]}"
            else:
                out["ok"] = True
                out["ready"] = True
                return out
        else:
            out["ok"] = True
            out["ready"] = True
            return out
    except Exception as e:  # noqa: BLE001
        out["error"] = f"health: {e}"

    # 2) fallback: any response from /
    try:
        req = urllib.request.Request(f"{base}/", method="GET")
        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:
            out["status_code"] = int(getattr(resp, "status", 200) or 200)
            _ = resp.read(256)
        out["http_up"] = True
        out["ok"] = True
        out["ready"] = True
        out["error"] = None
        return out
    except Exception as e:  # noqa: BLE001
        if not out.get("error"):
            out["error"] = f"root: {e}"
        else:
            out["error"] = f"{out['error']}; root: {e}"
        return out


def resize_local_solver(
    thread: int | str | None,
    url: str | None = None,
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Ask a live Turnstile Solver to resize its browser pool in-process.

    Prefers ``POST /resize`` (no process kill). Returns ok=False when the
    endpoint is missing/unreachable so callers can fall back to process restart.
    """
    base = _local_solver_base_url(url)
    try:
        n = max(1, min(MAX_CAPTCHA_CONCURRENCY, int(thread if thread is not None else 1)))
    except (TypeError, ValueError):
        n = 1
    out: dict[str, Any] = {
        "ok": False,
        "url": base,
        "thread": n,
        "method": "http_resize",
        "error": None,
    }
    try:
        import urllib.error
        import urllib.request
    except Exception as e:  # noqa: BLE001
        out["error"] = f"urllib unavailable: {e}"
        return out

    body = json.dumps({"thread": n}).encode("utf-8")
    last_err = ""
    for path in ("/resize", "/resize/"):
        try:
            req = urllib.request.Request(
                f"{base}{path}",
                data=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=max(1.0, float(timeout))) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                raw = resp.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {"raw": raw[:200]}
            out["status_code"] = status
            out["response"] = data
            if data.get("ok") is False:
                out["error"] = str(data.get("error") or data.get("errorDescription") or raw[:200])
                return out
            # Prefer reported thread from solver.
            try:
                reported = int(data.get("thread") or data.get("threads") or n)
            except (TypeError, ValueError):
                reported = n
            out["ok"] = True
            out["thread"] = reported
            out["previous_thread"] = data.get("previous_thread")
            out["resized"] = bool(data.get("resized", True))
            out["pool_ready"] = data.get("pool_ready")
            return out
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            # 404/405 → try next path or give up for process-restart fallback.
            continue
    out["error"] = last_err or "resize endpoint unavailable"
    return out


def wait_for_local_solver(
    url: str | None = None,
    *,
    timeout_sec: float | None = None,
    poll_sec: float | None = None,
    progress: Any | None = None,
) -> dict[str, Any]:
    """Block until local Turnstile Solver is HTTP-ready, or fail.

    Used by registration start so workers never race a still-booting solver.
    """
    base = _local_solver_base_url(url)
    try:
        wait_s = float(
            timeout_sec
            if timeout_sec is not None
            else LOCAL_SOLVER_WAIT_SEC
        )
    except (TypeError, ValueError):
        wait_s = 120.0
    wait_s = max(1.0, min(wait_s, 600.0))
    try:
        every = float(
            poll_sec if poll_sec is not None else LOCAL_SOLVER_POLL_SEC
        )
    except (TypeError, ValueError):
        every = 1.0
    every = max(0.2, min(every, 5.0))

    deadline = time.time() + wait_s
    last: dict[str, Any] = {
        "ok": False,
        "ready": False,
        "url": base,
        "waited_sec": 0.0,
        "error": "not started",
    }
    started = time.time()
    attempt = 0
    while True:
        attempt += 1
        last = probe_local_solver(base, timeout=min(2.0, every + 0.5))
        last["waited_sec"] = round(time.time() - started, 2)
        last["attempts"] = attempt
        last["url"] = base
        if last.get("ready"):
            last["ok"] = True
            if progress:
                try:
                    progress(
                        f"本地过盾已就绪 url={base} waited={last['waited_sec']}s"
                    )
                except Exception:
                    pass
            return last
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        msg = (
            f"等待本地过盾就绪… url={base} "
            f"attempt={attempt} left={remaining:.0f}s "
            f"err={last.get('error') or 'down'}"
        )
        if progress:
            try:
                progress(msg)
            except Exception:
                pass
        if attempt == 1 or attempt % 5 == 0:
            print(f"[grok-build-auth] {msg}")
        time.sleep(min(every, max(0.2, remaining)))

    last["ok"] = False
    last["ready"] = False
    last["error"] = (
        f"本地过盾服务未在 {wait_s:.0f}s 内就绪 "
        f"(url={base}; last={last.get('error') or 'unreachable'}). "
        f"请确认 inline Turnstile Solver 已启动（entrypoint / TURNSTILE_PORT），"
        f"或稍后重试注册。"
    )
    return last


def registration_available() -> dict[str, Any]:
    """Non-raising health probe for admin UI / startup logs."""
    moemail_configured = bool(
        os.environ.get("GROK2API_MOEMAIL_API_KEY")
        or os.environ.get("MOEMAIL_API_KEY")
    )
    try:
        from register_lite_config import MOEMAIL_API_KEY as _cfg_moemail

        moemail_configured = moemail_configured or bool(_cfg_moemail)
    except Exception:
        pass
    provider = (
        CAPTCHA_PROVIDER
        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
        or os.environ.get("CAPTCHA_PROVIDER")
        or "local"
    ).strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    local_url = _local_solver_base_url(
        LOCAL_SOLVER_URL
        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")
        or os.environ.get("LOCAL_SOLVER_URL")
        or ""
    )
    captcha_ready = bool(local_url) if provider == "local" else bool(YESCAPTCHA_KEY)
    local_solver_live: dict[str, Any] | None = None
    if provider == "local":
        local_solver_live = probe_local_solver(local_url, timeout=1.2)
        captcha_ready = bool(local_solver_live.get("ready"))
    try:
        ensure_xconsole()
        out = {
            "ok": True,
            "available": True,
            "engine": "dongguatanglinux/grok-build-auth",
            "path": str(GBA),
            "vendored": True,
            "adapter_build": ADAPTER_BUILD,
            "captcha_provider": provider,
            "local_solver_url": local_url,
            "local_solver_configured": bool(local_url),
            "local_solver_ready": (
                bool(local_solver_live.get("ready")) if local_solver_live else None
            ),
            "local_solver_probe": local_solver_live,
            "yescaptcha_configured": (
                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)
            ),
            "moemail_configured": moemail_configured,
        }
        return out
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "available": False,
            "engine": "dongguatanglinux/grok-build-auth",
            "path": str(GBA),
            "vendored": True,
            "adapter_build": ADAPTER_BUILD,
            "error": str(e),
            "captcha_provider": provider,
            "local_solver_url": local_url,
            "local_solver_configured": bool(local_url),
            "local_solver_ready": (
                bool(local_solver_live.get("ready")) if local_solver_live else None
            ),
            "local_solver_probe": local_solver_live,
            "yescaptcha_configured": (
                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)
            ),
            "moemail_configured": moemail_configured,
        }


def relogin_with_password(
    *,
    email: str,
    password: str,
    captcha_provider: str,
    yescaptcha_key: str = "",
    local_solver_url: str = "",
    proxy: str = "",
    on_progress=None,
) -> dict[str, Any]:
    """Protocol password relogin: captcha → CreateSession → new SSO → OAuth.

    Must mint a **new** SSO via password CreateSession (not reuse stored SSO).
    Browser/Camoufox only solves Turnstile; login is pure gRPC-web protocol.
    One Turnstile token is single-use — each outer pass re-solves captcha.
    """
    def progress(message: str) -> None:
        if callable(on_progress):
            on_progress(str(message))

    ensure_xconsole()
    email = str(email or "").strip().lower()
    password = str(password or "")
    if not email or not password:
        raise ValueError("账号或密码为空")

    from xconsole_client import XConsoleAuthClient, YesCaptchaSolver
    from xconsole_client import config as C

    progress("访问 xAI 登录页")
    # debug=True so CreateSession rejection reason lands in app log.
    client = XConsoleAuthClient(debug=True, proxy=proxy or "")
    client.visit_home()
    # Warm accounts host + scrape sitekey (same scraper registration uses).
    client.load_signup_page()
    sitekey = str(getattr(client, "turnstile_sitekey", None) or C.TURNSTILE_SITEKEY or "").strip()
    if not sitekey:
        raise RuntimeError("无法获取 x.ai Turnstile sitekey")
    signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
    provider = str(captcha_provider or "local").strip().lower()
    if provider == "local":
        progress("等待本地过盾服务")
        endpoint = _local_solver_base_url(local_solver_url)
        ready = wait_for_local_solver(endpoint, timeout_sec=min(60.0, LOCAL_SOLVER_WAIT_SEC))
        if not ready.get("ready"):
            raise RuntimeError(ready.get("error") or "本地过盾未就绪")
        solver = YesCaptchaSolver(
            "local",
            endpoint=endpoint,
            timeout=120,
            poll_interval=1.0,
            on_progress=lambda _message: progress("正在过盾"),
        )
    elif provider == "yescaptcha":
        key = str(yescaptcha_key or YESCAPTCHA_KEY).strip()
        if not key:
            raise ValueError("YesCaptcha 模式缺少 Key")
        solver = YesCaptchaSolver(
            key,
            timeout=120,
            poll_interval=2.0,
            on_progress=lambda _message: progress("正在过盾"),
        )
    else:
        raise ValueError(f"未知过盾方式: {provider}")

    def _solve_turnstile(*, premium: bool = False) -> str:
        # Original behavior: local Camoufox is Proxyless (server egress).
        # Protocol login still uses job proxy; only captcha is direct.
        use_premium = bool(premium) and provider != "local"
        return solver.solve_turnstile(
            signin_url,
            sitekey,
            premium=use_premium,
            fallback_non_premium=True,
            proxy=None,
        )

    def _attempt_login(*, pass_label: str, premium: bool) -> str | None:
        # Fresh captcha every pass. CreateSession retries=1: rejected token is dead.
        progress(f"正在过盾（{pass_label}）")
        turnstile = _solve_turnstile(premium=premium)
        if not turnstile:
            raise RuntimeError("过盾返回空 token")
        progress(f"过盾通过，协议密码登录 CreateSession（{pass_label}）")
        return client.obtain_session_via_password(
            email=email,
            password=password,
            turnstile_token=turnstile,
            referer=signin_url,
            retries=1,
        )

    # Up to 3 independent password-login passes, each with a fresh token.
    # Local Camoufox: hold captcha lock across solve + CreateSession so the
    # token is consumed immediately (no queue aging).
    max_passes = 3
    sso: str | None = None
    last_diag = ""

    def _run_passes() -> str | None:
        nonlocal last_diag
        out: str | None = None
        for i in range(1, max_passes + 1):
            premium = provider != "local" and i == 1
            out = _attempt_login(pass_label=f"第{i}轮", premium=premium)
            last_diag = str(getattr(client, "last_session_diagnostic", "") or "")
            if out:
                return out
            if i < max_passes:
                progress(f"第{i}轮 CreateSession 未拿到新 SSO，重新过盾再登录")
                time.sleep(0.8 * i)
        return out

    if provider == "local":
        # Original serial strategy: one local captcha/login flight at a time.
        with _CaptchaSlot():
            sso = _run_passes()
    else:
        sso = _run_passes()

    if not sso:
        raise RuntimeError(last_diag or client.last_session_diagnostic or "账号密码登录未取得 SSO")

    import sso_to_auth_json as sso_import

    progress("已取得新 SSO，正在换取 OAuth 凭证")
    token = sso_import.sso_to_token(sso)
    if not token or not token.get("access_token"):
        raise RuntimeError("已取得新 SSO，但 OAuth 凭证转换失败")
    _key, entry = sso_import.token_to_auth_entry(token, email=email)
    return {
        "email": email,
        "sso": sso,
        "access_token": token.get("access_token") or "",
        "refresh_token": token.get("refresh_token") or "",
        "id_token": token.get("id_token") or "",
        "expires_at": entry.get("expires_at") or "",
        "oidc_issuer": entry.get("oidc_issuer") or "https://auth.x.ai",
        "oidc_client_id": entry.get("oidc_client_id") or "",
    }


# --------------------------------------------------------------------------- #
# mail provider: moemail / yyds / gptmail / cfmail / duckmail / ti-temp-mail
# --------------------------------------------------------------------------- #
def _make_email_receiver(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
):
    from moemail import create_mailbox, fetch_messages, normalize_mail_provider
    from register_lite_config import MOEMAIL_API_KEY, MOEMAIL_BASE_URL, MOEMAIL_DOMAIN, MOEMAIL_EXPIRY_MS

    candidate_base = (base_url or MOEMAIL_BASE_URL or "").rstrip("/")
    prov = normalize_mail_provider(mail_provider, base_url=candidate_base)
    # Historical MOEMAIL_* fallbacks belong only to MoeMail. Reusing them for
    # another provider can leak a MoeMail admin key in an unrelated auth header.
    key = (api_key or (MOEMAIL_API_KEY if prov == "moemail" else "") or "").strip()
    base = (
        candidate_base
        if base_url or prov == "moemail" or not (mail_provider or "").strip()
        else ""
    )
    # DuckMail and TI Temp Mail can work without a create API key.
    if prov not in {"duckmail", "ti-temp-mail"} and not key:
        raise ValueError(
            "Mail API key missing. Set GROK2API_MOEMAIL_API_KEY or pass api_key."
        )
    # Non-MoeMail providers: empty domain means provider-side auto/random pick.
    # Never bleed MoeMail's MOEMAIL_DOMAIN (default example.com) into them.
    if prov == "ti-temp-mail":
        # Preserve the full pool. TI Temp Mail selects once while constructing
        # the actual POST /mailbox payload, so logs and the request agree.
        dom = str(domain or "").strip()
    elif prov in {"yyds", "gptmail", "cfmail", "duckmail"}:
        dom = _pick_domain_from_pool(domain)
    else:
        dom = _pick_domain_from_pool(domain) or (MOEMAIL_DOMAIN or "").strip().lstrip("@").strip(".")
    # Random local-part only (no "grok-" brand prefix). Admin UI no longer exposes
    # a custom prefix field; ignore leftover config values for new mailboxes.
    pre = secrets.token_hex(5).lower()

    if prov == "ti-temp-mail":
        domain_count = len(_domain_pool(dom))
        print(
            f"[ti-temp-mail] create mailbox: base={base or 'https://keldie.cyou'} "
            f"mode={mailbox_mode or 'maindomain'} domain_pool={domain_count or '<auto>'} "
            f"create_auth={'set' if key else 'unset'}",
            flush=True,
        )
    try:
        mailbox = create_mailbox(
            provider=prov,
            name=pre,
            domain=dom or None,
            expiry_ms=expiry_ms if expiry_ms is not None else MOEMAIL_EXPIRY_MS,
            api_key=key or None,
            base_url=base or None,
            mailbox_mode=mailbox_mode,
        )
    except Exception as exc:
        if prov == "ti-temp-mail":
            print(
                f"[ti-temp-mail] create mailbox failed: {type(exc).__name__}: {exc}",
                flush=True,
            )
        raise
    email_id = mailbox["id"]
    address = mailbox["email"]
    token = str(mailbox.get("token") or "")
    if prov == "ti-temp-mail":
        print(
            f"[ti-temp-mail] mailbox created: address={address} "
            f"selected_domain={mailbox.get('selected_domain') or address.rpartition('@')[2]} "
            f"mode={mailbox.get('mailbox_mode') or mailbox_mode or 'maindomain'} "
            f"mailbox_token={'set' if token else 'missing'}",
            flush=True,
        )

    class _MailReceiver:
        def __init__(
            self,
            email: str,
            email_id: str,
            api_key: str | None,
            base_url: str | None,
            *,
            provider: str,
            token: str = "",
            mailbox_mode: str = "",
        ):
            self.email = email
            self.email_id = email_id
            self.api_key = api_key
            if provider == "yyds":
                default_base = "https://maliapi.215.im"
            elif provider == "gptmail":
                default_base = "https://mail.chatgpt.org.uk"
            elif provider == "cfmail":
                default_base = "https://temp-email-api.awsl.uk"
            elif provider == "duckmail":
                default_base = "https://api.duckmail.sbs"
            elif provider == "ti-temp-mail":
                default_base = "https://keldie.cyou"
            else:
                default_base = "https://moemail.521884.xyz"
            self.base_url = base_url or default_base
            self.provider = provider
            self.token = token
            self.mailbox_mode = mailbox_mode or "maindomain"

        def wait_for_code(
            self,
            timeout: float = 120,
            *,
            should_cancel=None,
            poll_interval: float | None = None,
            on_progress=None,
        ) -> str:
            import re as _re

            deadline = time.time() + float(timeout or 120)
            # Keep polls short so cooperative cancel can land quickly.
            poll = float(poll_interval if poll_interval is not None else 1.0)
            poll = max(0.4, min(poll, 2.0))
            started_at = time.time()
            attempt = 0
            last_message_count = -1
            last_error = ""
            last_detail_error = ""
            next_log_at = started_at

            def _emit(message: str) -> None:
                if self.provider != "ti-temp-mail":
                    return
                print(f"[ti-temp-mail] {message}", flush=True)
                if callable(on_progress):
                    on_progress(message)

            _emit(
                f"开始收信：address={self.email} base={self.base_url} "
                f"mode={self.mailbox_mode} 超时={float(timeout or 120):.0f}秒 "
                f"mailbox_token={'set' if self.token else 'missing'}"
            )
            while time.time() < deadline:
                if callable(should_cancel) and should_cancel():
                    raise _RegCancelled("cancelled while waiting for email code")
                attempt += 1
                request_started = time.time()
                request_log_due = self.provider == "ti-temp-mail" and (
                    attempt == 1 or request_started >= next_log_at
                )
                if request_log_due:
                    _emit(
                        f"轮询 #{attempt} 请求中：GET {self.base_url.rstrip('/')}/messages"
                    )
                try:
                    messages = fetch_messages(
                        self.email_id,
                        provider=self.provider,
                        api_key=self.api_key,
                        base_url=self.base_url,
                        include_details=True,
                        address=self.email,
                        token=self.token or None,
                    )
                    now = time.time()
                    message_count = len(messages)
                    detail_errors = [
                        str(item.get("_detail_error") or "")
                        for item in messages
                        if isinstance(item, dict) and item.get("_detail_error")
                    ]
                    detail_error = detail_errors[0][:160] if detail_errors else ""
                    recovered = bool(last_error)
                    detail_recovered = bool(last_detail_error and not detail_error)
                    log_snapshot = (
                        self.provider == "ti-temp-mail"
                        and (
                            attempt == 1
                            or request_log_due
                            or message_count != last_message_count
                            or now >= next_log_at
                            or recovered
                            or detail_recovered
                            or detail_error != last_detail_error
                        )
                    )
                    if log_snapshot:
                        status = (
                            f"轮询 #{attempt}：耗时={now - started_at:.0f}秒 "
                            f"请求耗时={now - request_started:.1f}秒 邮件={message_count}"
                        )
                        if recovered:
                            status += "，接口已恢复"
                        if detail_recovered:
                            status += "，详情接口已恢复"
                        if detail_error:
                            status += f"，详情失败={detail_error}"
                        _emit(status)
                        next_log_at = now + 5.0
                    last_message_count = message_count
                    last_error = ""
                    last_detail_error = detail_error
                    for item in messages:
                        # Prefer xAI AAA-BBB codes first.
                        text = "\n".join(
                            str(item.get(k) or "")
                            for k in (
                                "subject",
                                "content",
                                "text",
                                "textBody",
                                "html",
                                "htmlBody",
                                "body",
                                "from_address",
                                "from",
                                "verificationCode",
                            )
                        )
                        match = _re.search(
                            r"\b([A-Z0-9]{3})-([A-Z0-9]{3})\b", text, flags=_re.I
                        )
                        if match:
                            _emit(
                                f"找到验证码：轮询={attempt} 耗时={time.time() - started_at:.0f}秒 "
                                f"message_id={item.get('id') or item.get('_id') or '?'}"
                            )
                            return "".join(match.groups()).upper()
                        # Also accept plain 6-char alnum codes from xAI mails.
                        match2 = _re.search(
                            r"\b([A-Z0-9]{6})\b", text, flags=_re.I
                        )
                        if match2 and "x.ai" in text.lower():
                            _emit(
                                f"找到验证码：轮询={attempt} 耗时={time.time() - started_at:.0f}秒 "
                                f"message_id={item.get('id') or item.get('_id') or '?'}"
                            )
                            return match2.group(1).upper()
                        extracted = item.get("extracted") or {}
                        codes = extracted.get("codes") or []
                        for code in codes:
                            clean = str(code).replace("-", "").strip().upper()
                            if len(clean) == 6 and _re.fullmatch(r"[A-Z0-9]{6}", clean):
                                _emit(
                                    f"找到验证码：轮询={attempt} 耗时={time.time() - started_at:.0f}秒 "
                                    f"message_id={item.get('id') or item.get('_id') or '?'}"
                                )
                                return clean
                    if self.provider == "ti-temp-mail" and messages and log_snapshot:
                        subjects = ", ".join(
                            str(item.get("subject") or "<no subject>")
                            .replace("\r", " ")
                            .replace("\n", " ")[:80]
                            for item in messages[:3]
                            if isinstance(item, dict)
                        )
                        _emit(f"收到邮件但未识别验证码：subjects={subjects or '<empty>'}")
                except _RegCancelled:
                    raise
                except Exception as exc:
                    now = time.time()
                    error = f"{type(exc).__name__}: {exc}"[:240]
                    if self.provider == "ti-temp-mail" and (
                        error != last_error or now >= next_log_at
                    ):
                        _emit(
                            f"轮询 #{attempt} 异常：耗时={now - started_at:.0f}秒 "
                            f"请求耗时={now - request_started:.1f}秒 {error}"
                        )
                        next_log_at = now + 5.0
                    last_error = error
                # Sleep in small slices so stop can interrupt mid-wait.
                slept = 0.0
                while slept < poll:
                    if callable(should_cancel) and should_cancel():
                        raise _RegCancelled("cancelled while waiting for email code")
                    step = min(0.25, poll - slept)
                    time.sleep(step)
                    slept += step
                poll = min(2.0, poll + 0.15)
            if self.provider == "ti-temp-mail":
                timeout_message = (
                    f"TI Temp Mail 收信超时：耗时={time.time() - started_at:.0f}秒 "
                    f"轮询={attempt} 最后邮件数={max(0, last_message_count)} "
                    f"最后错误={last_error or '<none>'}"
                )
                _emit(timeout_message)
                raise RuntimeError(timeout_message)
            raise RuntimeError("timeout waiting for xAI email verification code")

    return address, _MailReceiver(
        address,
        email_id,
        api_key=key,
        base_url=base,
        provider=prov,
        token=token,
        mailbox_mode=str(mailbox.get("mailbox_mode") or mailbox_mode or "maindomain"),
    )


def _proxy_url() -> str:
    """Pick one proxy from the configured pool (env / registration config)."""
    try:
        from proxy_pool import resolve_proxy_for_request

        return resolve_proxy_for_request(fallback_env=True) or ""
    except Exception:
        try:
            from moemail import normalize_proxy_config
            from register_lite_config import XAI_PROXY

            cfg = normalize_proxy_config(XAI_PROXY or None)
            return cfg["proxy"] if cfg else ""
        except Exception:
            return ""


def _proxy_pool(
    proxy_text: str | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
) -> list[str]:
    """Parse multi-line proxy text into full proxy URLs."""
    try:
        from proxy_pool import parse_proxy_pool

        pool = parse_proxy_pool(
            proxy_text,
            username=username,
            password=password,
            fallback_env=True,
        )
        if pool:
            return pool
    except Exception:
        pass
    # Fallback: treat as single proxy via classic normalizer.
    one = (proxy_text or "").strip() or _proxy_url()
    return [one] if one else []


def _pick_proxy_from_pool(
    pool: list[str],
    *,
    strategy: str | None = None,
    index: int | None = None,
) -> str:
    try:
        from proxy_pool import pick_proxy, normalize_proxy_strategy

        strat = strategy
        if not strat:
            try:
                from register_lite_config import XAI_PROXY_STRATEGY as _strat
            except Exception:
                _strat = "round_robin"
            strat = _strat
        return pick_proxy(pool, strategy=normalize_proxy_strategy(strat), index=index) or ""
    except Exception:
        return pool[0] if pool else ""


def _domain_pool(domain: str | None) -> list[str]:
    raw = str(domain or "")
    if not raw.strip():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in re.split(r"[\s,;|]+", raw):
        dom = item.strip().lstrip("@").strip(".").lower()
        if not dom or dom in seen:
            continue
        seen.add(dom)
        out.append(dom)
    return out


def _pick_domain_from_pool(domain: str | None) -> str:
    pool = _domain_pool(domain)
    if not pool:
        return ""
    if len(pool) == 1:
        return pool[0]
    return secrets.choice(pool)


# --------------------------------------------------------------------------- #
# registration flow
# --------------------------------------------------------------------------- #
def _prepare_registration_session(
    *,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
    batch_id: str | None = None,
    batch_index: int | None = None,
    batch_total: int | None = None,
    start_delay: float = 0.0,
) -> dict[str, Any]:
    """Create mailbox + session record. Does NOT start the registration worker."""
    if start_delay > 0:
        time.sleep(start_delay)

    try:
        email, receiver = _make_email_receiver(
            api_key=moemail_api_key,
            base_url=moemail_base_url,
            prefix=prefix,
            domain=domain,
            expiry_ms=expiry_ms,
            mail_provider=mail_provider,
            mailbox_mode=mailbox_mode,
        )
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    # xAI password rules: mix upper/lower/digit/symbol.
    password = f"Aa{os.urandom(5).hex()}9!xZ"
    sid = f"gba_{uuid.uuid4().hex[:16]}"

    receiver_provider = str(getattr(receiver, "provider", "") or "")
    receiver_mode = str(getattr(receiver, "mailbox_mode", "") or "")
    mail_logs: list[dict[str, Any]] = []
    if receiver_provider == "ti-temp-mail":
        mail_logs.append(
            {
                "at": _now(),
                "message": (
                    f"邮箱已创建：address={email} mode={receiver_mode or 'maindomain'} "
                    f"base={getattr(receiver, 'base_url', '') or 'https://keldie.cyou'}"
                ),
            }
        )

    sess = {
        "id": sid,
        "status": "queued",
        "created_at": _now(),
        "updated_at": _now(),
        "email": email,
        "password": password,
        "message": f"queued; email={email}",
        "sso": None,
        "oauth": None,
        "auth_json": None,
        "error": None,
        "mail_provider": receiver_provider,
        "mailbox_mode": receiver_mode,
        "mail_logs": mail_logs,
        "yescaptcha_key": yescaptcha_key,
        "proxy": proxy or None,
        "adapter_build": ADAPTER_BUILD,
        "batch_id": batch_id,
        "batch_index": batch_index,
        "batch_total": batch_total,
        # Keep receiver process-local only (not mirrored to Redis).
        "_receiver": receiver,
    }
    with _lock:
        _sessions[sid] = sess
        if batch_id and batch_id in _batches:
            _batches[batch_id]["session_ids"].append(sid)
            _batches[batch_id]["updated_at"] = _now()
            _mirror_reg_batch(batch_id, dict(_batches[batch_id]))
    _mirror_reg_sess(sid, sess)
    return {"ok": True, **_compact_session(sess)}


def _start_one_registration(
    *,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
    batch_id: str | None = None,
    batch_index: int | None = None,
    batch_total: int | None = None,
    start_delay: float = 0.0,
) -> dict[str, Any]:
    """Create one session and spawn its worker thread (single-job path)."""
    prepared = _prepare_registration_session(
        yescaptcha_key=yescaptcha_key,
        proxy=proxy,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        mail_provider=mail_provider,
        mailbox_mode=mailbox_mode,
        batch_id=batch_id,
        batch_index=batch_index,
        batch_total=batch_total,
        start_delay=start_delay,
    )
    if not prepared.get("ok"):
        return prepared
    sid = str(prepared.get("id") or "")
    with _lock:
        sess = _sessions.get(sid) or {}
        receiver = sess.get("_receiver")
    if not sid or receiver is None:
        return {"ok": False, "error": "registration session prepare failed"}
    with _lock:
        if sid in _sessions:
            _sessions[sid]["status"] = "started"
            _sessions[sid]["message"] = f"started; email={_sessions[sid].get('email') or ''}"
            _sessions[sid]["updated_at"] = _now()
            _mirror_reg_sess(sid, _sessions[sid])
    # Single-job starts are not covered by the batch finalizer — log "running"
    # immediately so 任务日志 shows the registration task right away.
    if not batch_id:
        with _lock:
            started_sess = dict(_sessions.get(sid) or {})
        if started_sess:
            payload = _session_task_log_payload(started_sess)
            _record_register_task(
                task_id=payload["task_id"],
                summary=payload["summary"] or f"协议注册启动 {started_sess.get('email') or sid}",
                status="running",
                ok=None,
                progress_done=0,
                progress_total=1,
                finished=False,
                detail={**payload["detail"], "phase": "started"},
            )
    threading.Thread(
        target=_run_registration,
        args=(sid, yescaptcha_key, proxy or "", receiver),
        daemon=True,
        name=f"gba-reg-{sid[-8:]}",
    ).start()
    with _lock:
        sess = _sessions.get(sid)
        if sess is None:
            return prepared
        return {"ok": True, **_compact_session(sess)}


def start_registration(
    *,
    captcha_provider: str | None = None,
    local_solver_url: str | None = None,
    yescaptcha_key: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
    proxy_strategy: str | None = None,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
    count: int | None = None,
    concurrency: int | None = None,
    stagger_ms: int | None = None,
    probe_delay_sec: float | int | None = None,
) -> dict[str, Any]:
    """Start one or many registration sessions (multi-thread).

    ``count`` is the number of successful accounts to produce. Failed attempts
    are recorded but do not consume that target. ``concurrency`` is the real
    in-flight limit; failed slots are replenished until the target is reached
    or the operator stops the batch.

    ``proxy`` may be a single URL or a multi-line proxy pool. Each registration
    job picks one entry via ``proxy_strategy`` (round_robin / random / sticky).
    """
    try:
        ensure_xconsole()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    _clean_old_sessions()

    # Allow admin form / env to override settle window for post-import probe.
    if probe_delay_sec is not None:
        try:
            globals()["REGISTER_PROBE_DELAY_SEC"] = max(
                0.0, min(600.0, float(probe_delay_sec))
            )
            os.environ["GROK2API_REG_PROBE_DELAY_SEC"] = str(
                int(globals()["REGISTER_PROBE_DELAY_SEC"])
            )
        except (TypeError, ValueError):
            pass

    provider = (
        captcha_provider
        or CAPTCHA_PROVIDER
        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
        or os.environ.get("CAPTCHA_PROVIDER")
        or "local"
    ).strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    try:
        globals()["CAPTCHA_PROVIDER"] = provider
    except Exception:
        pass

    if provider == "local":
        # Always inline in main container; ignore any external/custom URL.
        solver_url = _local_solver_base_url(local_solver_url)
        try:
            globals()["LOCAL_SOLVER_URL"] = solver_url
        except Exception:
            pass
        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url
        os.environ["LOCAL_SOLVER_URL"] = solver_url
        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url
        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url
        key = "local"
        # Gate: never spawn registration workers before the inline solver answers.
        # Lazy browser mode is fine (pool_ready may be false); HTTP /health is enough.
        solver_wait = wait_for_local_solver(solver_url)
        if not solver_wait.get("ready"):
            return {
                "ok": False,
                "error": solver_wait.get("error")
                or f"本地过盾未就绪: {solver_url}",
                "local_solver": solver_wait,
            }
    else:
        # Cloud YesCaptcha must not inherit local solver endpoint/key.
        try:
            globals()["LOCAL_SOLVER_URL"] = ""
        except Exception:
            pass
        for k in (
            "GROK2API_LOCAL_SOLVER_URL",
            "LOCAL_SOLVER_URL",
            "GROK2API_YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_API_BASE",
        ):
            os.environ.pop(k, None)
        key = (
            yescaptcha_key
            or YESCAPTCHA_KEY
            or os.environ.get("GROK2API_YESCAPTCHA_KEY")
            or os.environ.get("YESCAPTCHA_API_KEY")
            or ""
        ).strip()
        if key == "local":
            key = ""
        if not key:
            return {
                "ok": False,
                "error": "YESCAPTCHA_KEY is required (set GROK2API_YESCAPTCHA_KEY, save in 协议注册配置, or pass yescaptcha_key)",
            }

    if key and key != YESCAPTCHA_KEY:
        # keep module attr in sync for subsequent workers
        try:
            globals()["YESCAPTCHA_KEY"] = key
        except Exception:
            pass

    try:
        n = int(count if count is not None else 1)
    except (TypeError, ValueError):
        n = 1
    n = max(1, n)

    try:
        workers = int(
            concurrency
            if concurrency is not None
            else DEFAULT_CONCURRENCY
        )
    except (TypeError, ValueError):
        workers = DEFAULT_CONCURRENCY
    workers = max(1, min(workers, MAX_CONCURRENCY, n))

    try:
        stagger = int(stagger_ms if stagger_ms is not None else 400)
    except (TypeError, ValueError):
        stagger = 400
    stagger = max(0, min(stagger, 10_000))

    # Build proxy pool once; each job picks one URL (rotation / random / sticky).
    proxy_pool = _proxy_pool(
        proxy,
        username=proxy_username,
        password=proxy_password,
    )
    try:
        from register_lite_config import XAI_PROXY_STRATEGY as _default_strat
    except Exception:
        _default_strat = "round_robin"
    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()
    proxy_val = _pick_proxy_from_pool(proxy_pool, strategy=proxy_strat, index=0)
    try:
        from moemail import normalize_mail_provider as _norm_mail

        mail_prov = _norm_mail(mail_provider, base_url=moemail_base_url)
    except Exception:
        mail_prov = (mail_provider or "moemail").strip().lower() or "moemail"

    batch_id = f"batch_{uuid.uuid4().hex[:12]}"
    # Snapshot keeps the full multi-line text so resume / UI can re-parse the pool.
    proxy_snapshot = (proxy or "\n".join(proxy_pool) or proxy_val or "").strip()
    reg_cfg = _snapshot_reg_config(
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy_snapshot,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        concurrency=workers,
        stagger_ms=stagger,
        mail_provider=mail_prov,
        mailbox_mode=mailbox_mode,
    )
    reg_cfg["proxy_strategy"] = proxy_strat
    reg_cfg["proxy_pool_count"] = len(proxy_pool)
    batch = {
        "id": batch_id,
        "status": "running",
        "created_at": _now(),
        "updated_at": _now(),
        "count": n,
        "target_success": n,
        "concurrency": workers,
        "stagger_ms": stagger,
        "session_ids": [],
        "adapter_build": ADAPTER_BUILD,
        "message": f"batch started target_success={n} concurrency={workers}",
        "error": None,
        "finished": 0,
        "ok_count": 0,
        "fail_count": 0,
        "spawned": 0,
        "reg_config": reg_cfg,
        "owner_pid": os.getpid(),
        "runner_alive": True,
        "cancel_requested": False,
    }
    with _lock:
        _batches[batch_id] = batch
    _mirror_reg_batch(batch_id, batch)
    # Log batch start so 任务日志 has a running row even before the first
    # session finishes (previously only the terminal row was written).
    _record_register_task(
        task_id=batch_id,
        summary=f"协议注册批次启动 target_success={n} concurrency={workers}",
        status="running",
        ok=None,
        progress_done=0,
        progress_total=n,
        finished=False,
        detail={
            "batch_id": batch_id,
            "count": n,
            "target_success": n,
            "concurrency": workers,
            "stagger_ms": stagger,
            "phase": "started",
            "adapter_build": ADAPTER_BUILD,
        },
    )

    started = _spawn_batch_runner(
        batch_id,
        remaining=n,
        concurrency=workers,
        stagger_ms=stagger,
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy_snapshot,
        proxy_strategy=proxy_strat,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        mail_provider=mail_prov,
        mailbox_mode=mailbox_mode,
    )
    if not started.get("ok"):
        return started

    # Brief wait so the first wave (up to `workers`) is usually visible to UI.
    time.sleep(min(0.45, 0.08 * workers + 0.08))
    with _lock:
        b = dict(_batches.get(batch_id) or batch)
        sids = list(b.get("session_ids") or [])
        sessions = [_compact_session(_sessions[s]) for s in sids if s in _sessions]

    return {
        "ok": True,
        "batch": True,
        "batch_id": batch_id,
        "count": n,
        "target_success": n,
        "concurrency": workers,
        "stagger_ms": stagger,
        "proxy_pool_count": len(proxy_pool),
        "session_ids": sids,
        "sessions": sessions,
        "adapter_build": ADAPTER_BUILD,
        "message": (
            f"batch started: target_success={n}, threads={workers} "
            f"(in-flight cap), proxy_pool={len(proxy_pool)}, queued/started={len(sids)}"
        ),
        # Back-compat: first session fields for old UI single-session path.
        **(sessions[0] if sessions else {"id": None, "status": "starting"}),
    }


def _spawn_batch_runner(
    batch_id: str,
    *,
    remaining: int,
    concurrency: int,
    stagger_ms: int,
    captcha_provider: str,
    yescaptcha_key: str,
    proxy: str,
    proxy_strategy: str | None = None,
    moemail_api_key: str | None,
    moemail_base_url: str | None,
    prefix: str | None,
    domain: str | None,
    expiry_ms: int | None,
    mail_provider: str | None = None,
    mailbox_mode: str | None = None,
) -> dict[str, Any]:
    """Start the ThreadPool spawner for a batch (also used by resume/reclaim)."""
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    if remaining <= 0:
        with _lock:
            b = _batches.get(bid) or dict(batch)
            b["runner_alive"] = False
            b["status"] = "done"
            b["updated_at"] = _now()
            b["message"] = "nothing to spawn"
            _batches[bid] = b
            _mirror_reg_batch(bid, dict(b))
        return {
            "ok": True,
            "batch_id": bid,
            "already_complete": True,
            "remaining": 0,
            "batch": get_registration_batch(bid),
        }

    acquired, lock_token = _try_acquire_batch_runner(bid)
    if not acquired:
        return {
            "ok": False,
            "error": "batch runner already active on another worker",
            "batch_id": bid,
            "already_running": True,
        }

    provider = (captcha_provider or "local").strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    key = (yescaptcha_key or "").strip()
    if provider == "local":
        key = "local"
        solver_url = _local_solver_base_url(None)
        try:
            globals()["CAPTCHA_PROVIDER"] = "local"
            globals()["LOCAL_SOLVER_URL"] = solver_url
        except Exception:
            pass
        os.environ["GROK2API_CAPTCHA_PROVIDER"] = "local"
        os.environ["CAPTCHA_PROVIDER"] = "local"
        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url
        os.environ["LOCAL_SOLVER_URL"] = solver_url
        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url
        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url
        solver_wait = wait_for_local_solver(solver_url)
        if not solver_wait.get("ready"):
            _release_batch_runner(bid, lock_token)
            return {
                "ok": False,
                "error": solver_wait.get("error")
                or f"本地过盾未就绪: {solver_url}",
                "batch_id": bid,
                "local_solver": solver_wait,
            }
    else:
        if not key:
            _release_batch_runner(bid, lock_token)
            return {
                "ok": False,
                "error": "YESCAPTCHA_KEY missing",
                "batch_id": bid,
            }
        try:
            globals()["CAPTCHA_PROVIDER"] = "yescaptcha"
            globals()["YESCAPTCHA_KEY"] = key
            globals()["LOCAL_SOLVER_URL"] = ""
        except Exception:
            pass
        for k in (
            "GROK2API_LOCAL_SOLVER_URL",
            "LOCAL_SOLVER_URL",
            "GROK2API_YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_API_BASE",
        ):
            os.environ.pop(k, None)

    # `proxy` may be multi-line pool text; expand once for this runner.
    proxy_pool = _proxy_pool(proxy)
    try:
        from register_lite_config import XAI_PROXY_STRATEGY as _default_strat
    except Exception:
        _default_strat = "round_robin"
    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()
    proxy_snapshot = (proxy or "\n".join(proxy_pool) or "").strip()
    workers = max(1, min(int(concurrency or DEFAULT_CONCURRENCY), MAX_CONCURRENCY, remaining))
    stagger = max(0, min(int(stagger_ms or 400), 10_000))

    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["status"] = "running"
        b["cancel_requested"] = False
        b["concurrency"] = workers
        b["stagger_ms"] = stagger
        b["runner_alive"] = True
        b["owner_pid"] = os.getpid()
        b["adapter_build"] = ADAPTER_BUILD
        b["reg_config"] = _snapshot_reg_config(
            captcha_provider=provider,
            yescaptcha_key=key,
            proxy=proxy_snapshot,
            moemail_api_key=moemail_api_key,
            moemail_base_url=moemail_base_url,
            prefix=prefix,
            domain=domain,
            expiry_ms=expiry_ms,
            concurrency=workers,
            stagger_ms=stagger,
            mail_provider=mail_provider,
            mailbox_mode=mailbox_mode,
        )
        b["reg_config"]["proxy_strategy"] = proxy_strat
        b["reg_config"]["proxy_pool_count"] = len(proxy_pool)
        b["updated_at"] = _now()
        # Preserve historical counters when reclaiming after process restart;
        # only reset if this is a brand-new spawn with no prior progress.
        prior_finished = int(b.get("finished") or 0)
        prior_ok = int(b.get("ok_count") or 0)
        prior_fail = int(b.get("fail_count") or 0)
        target_success = int(b.get("count") or (prior_ok + max(0, int(remaining))))
        b["target_success"] = target_success
        b["remaining_success"] = max(0, target_success - prior_ok)
        b["message"] = (
            f"starting remaining_success={max(0, target_success - prior_ok)} threads={workers}"
            + (f" prior_attempts={prior_finished}" if prior_finished else "")
            + (f" proxies={len(proxy_pool)}" if proxy_pool else "")
        )
        if prior_finished <= 0 and not (b.get("session_ids") or []):
            b["finished"] = 0
            b["ok_count"] = 0
            b["fail_count"] = 0
        else:
            b["finished"] = prior_finished
            b["ok_count"] = prior_ok
            b["fail_count"] = prior_fail
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))

    def _run_batch() -> None:
        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        errors: list[str] = []
        with _lock:
            _seed = dict(_batches.get(bid) or batch or {})
        finished = int(_seed.get("finished") or 0)
        ok_n = int(_seed.get("ok_count") or 0)
        fail_n = int(_seed.get("fail_count") or 0)
        target_total = int(_seed.get("count") or (ok_n + max(0, int(remaining))))
        stop_renew = False
        # Feed the pool gradually: only keep ~workers(+prefetch) jobs prepared
        # at once. Submitting all remaining jobs up-front used to create hundreds
        # of mailboxes immediately and made stop/cancel racey under multi-thread.
        next_i = len(_seed.get("session_ids") or []) + 1
        in_flight: dict[Any, int] = {}
        prefetch = max(0, min(int(REG_PREFETCH_SLOTS), max(0, workers)))
        max_inflight = max(1, workers + prefetch)

        def _batch_cancel_requested() -> bool:
            with _lock:
                local = _batches.get(bid) or {}
            if local.get("cancel_requested") or str(local.get("status") or "").lower() in (
                "stopping",
                "cancelled",
                "stopped",
            ):
                return True
            if not _reg_redis():
                return False
            try:
                from store import sessions_redis

                remote = sessions_redis.reg_batch_get(bid)
                if not isinstance(remote, dict):
                    return False
                if remote.get("cancel_requested") or str(remote.get("status") or "").lower() in (
                    "stopping",
                    "cancelled",
                    "stopped",
                ):
                    with _lock:
                        cur = _batches.get(bid) or dict(remote)
                        cur["cancel_requested"] = True
                        if str(cur.get("status") or "").lower() not in (
                            "cancelled",
                            "stopped",
                            "done",
                            "partial",
                            "error",
                        ):
                            cur["status"] = remote.get("status") or "stopping"
                            if remote.get("message"):
                                cur["message"] = remote.get("message")
                        cur["updated_at"] = _now()
                        _batches[bid] = cur
                    return True
            except Exception:
                pass
            return False

        def _renew_loop() -> None:
            while not stop_renew:
                time.sleep(max(5.0, REG_BATCH_RUNNER_LOCK_TTL / 3))
                if stop_renew:
                    break
                if _batch_cancel_requested():
                    # Keep heartbeat while draining, but mark status as stopping.
                    with _lock:
                        bb = _batches.get(bid)
                        if bb is not None:
                            bb["cancel_requested"] = True
                            if str(bb.get("status") or "").lower() not in (
                                "cancelled",
                                "stopped",
                                "done",
                                "partial",
                                "error",
                            ):
                                bb["status"] = "stopping"
                            bb["updated_at"] = _now()
                            bb["runner_alive"] = True
                            _mirror_reg_batch(bid, dict(bb))
                _renew_batch_runner(bid, lock_token)
                with _lock:
                    bb = _batches.get(bid)
                    if bb is not None:
                        bb["updated_at"] = _now()
                        bb["runner_alive"] = True
                        bb["owner_pid"] = os.getpid()
                        _mirror_reg_batch(bid, dict(bb))

        renew_t = threading.Thread(
            target=_renew_loop,
            daemon=True,
            name=f"gba-batch-lock-{bid[-8:]}",
        )
        renew_t.start()

        def _job(i: int) -> dict[str, Any]:
            # Honour batch-level stop before creating more mailboxes.
            if _batch_cancel_requested():
                return {
                    "ok": False,
                    "id": None,
                    "status": "cancelled",
                    "error": "cancelled before start",
                }
            # One proxy per registration job (pool rotation / random / sticky).
            job_proxy = _pick_proxy_from_pool(
                proxy_pool, strategy=proxy_strat, index=max(0, int(i) - 1)
            )
            # Small per-slot stagger only (not cumulative across the whole batch).
            delay = (stagger / 1000.0) * ((i - 1) % max(1, workers))
            prepared = _prepare_registration_session(
                yescaptcha_key=key,
                proxy=job_proxy,
                moemail_api_key=moemail_api_key,
                moemail_base_url=moemail_base_url,
                prefix=prefix,
                domain=domain,
                expiry_ms=expiry_ms,
                mail_provider=mail_provider,
                mailbox_mode=mailbox_mode,
                batch_id=bid,
                batch_index=i,
                batch_total=int((_load_reg_batch(bid) or {}).get("count") or remaining),
                start_delay=delay,
            )
            if not prepared.get("ok"):
                return prepared
            sid = str(prepared.get("id") or "")
            with _lock:
                # Re-check cancel after prepare (user may stop mid-queue).
                b1 = _batches.get(bid) or {}
                sess = _sessions.get(sid) or {}
                if (
                    b1.get("cancel_requested")
                    or str(b1.get("status") or "").lower() in ("stopping", "cancelled", "stopped")
                    or sess.get("cancel_requested")
                ):
                    if sid in _sessions:
                        _sessions[sid]["status"] = "cancelled"
                        _sessions[sid]["message"] = "cancelled before worker start"
                        _sessions[sid]["error"] = "cancelled"
                        _sessions[sid]["cancel_requested"] = True
                        _sessions[sid]["updated_at"] = _now()
                        _sessions[sid].pop("_receiver", None)
                        _mirror_reg_sess(sid, _sessions[sid])
                    return {
                        "ok": False,
                        "id": sid,
                        "status": "cancelled",
                        "error": "cancelled",
                        "email": sess.get("email"),
                    }
                receiver = sess.get("_receiver")
                if sid in _sessions:
                    _sessions[sid]["status"] = "started"
                    _sessions[sid]["message"] = (
                        f"started; email={_sessions[sid].get('email') or ''}"
                    )
                    _sessions[sid]["updated_at"] = _now()
                    _mirror_reg_sess(sid, _sessions[sid])
            if not sid or receiver is None:
                return {"ok": False, "error": "registration session prepare failed", "id": sid}
            # Cross-batch admission control: many resumed batches otherwise all
            # run concurrency=8 and overwhelm local captcha + device-flow.
            admitted = False
            try:
                def _job_cancel() -> None:
                    with _lock:
                        sess2 = _sessions.get(sid) or {}
                        b2 = _batches.get(bid) or {}
                        if (
                            sess2.get("cancel_requested")
                            or b2.get("cancel_requested")
                        ):
                            raise _RegCancelled("cancelled while waiting for admission")

                _wait_reg_admission(check_cancel=_job_cancel)
                admitted = True
                _run_registration(sid, key, job_proxy or "", receiver)
            except _RegCancelled as e:
                with _lock:
                    if sid in _sessions:
                        _sessions[sid]["status"] = "cancelled"
                        _sessions[sid]["error"] = str(e)
                        _sessions[sid]["message"] = str(e)
                        _sessions[sid]["updated_at"] = _now()
                        _mirror_reg_sess(sid, _sessions[sid])
                return {
                    "ok": False,
                    "id": sid,
                    "status": "cancelled",
                    "error": str(e),
                }
            finally:
                if admitted:
                    _release_reg_admission()
                with _lock:
                    if sid in _sessions:
                        _sessions[sid].pop("_receiver", None)
            with _lock:
                final = _sessions.get(sid) or {}
            st = str(final.get("status") or "")
            # Only probe-passed terminal statuses count as batch success.
            # probe_failed / failed / error never increment ok_count.
            ok = st in ("imported", "success", "completed")
            return {
                "ok": ok,
                "id": sid,
                "status": st,
                "error": final.get("error"),
                "email": final.get("email"),
            }

        def _note_result(idx: int, r: dict[str, Any] | None = None, exc: Exception | None = None) -> None:
            nonlocal finished, ok_n, fail_n
            finished += 1
            if exc is not None:
                fail_n += 1
                errors.append(f"#{idx}: {exc}")
            elif not isinstance(r, dict):
                fail_n += 1
                errors.append(f"#{idx}: empty result")
            elif r.get("ok"):
                ok_n += 1
            elif str(r.get("status") or "").lower() in {"cancelled", "stopped"}:
                # Cancellation ends an attempt but is not a registration failure.
                pass
            else:
                fail_n += 1
                errors.append(
                    f"#{idx}: {r.get('error') or r.get('status') or 'failed'}"
                )
            with _lock:
                b = _batches.get(bid)
                if b is not None:
                    b["updated_at"] = _now()
                    # Don't clobber explicit stop marker.
                    if not b.get("cancel_requested"):
                        b["status"] = "running"
                    b["finished"] = finished
                    b["ok_count"] = ok_n
                    b["fail_count"] = fail_n
                    b["spawned"] = len(b.get("session_ids") or [])
                    b["spawn_errors"] = errors[-20:]
                    b["runner_alive"] = True
                    b["inflight"] = len(in_flight)
                    b["target_success"] = target_total
                    b["remaining_success"] = max(0, target_total - ok_n)
                    b["message"] = (
                        f"target {ok_n}/{target_total} successes; "
                        f"attempts={finished} fail={fail_n}, threads={workers}, "
                        f"inflight={len(in_flight)}"
                    )
                    _mirror_reg_batch(bid, dict(b))

        try:
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix=f"gba-batch-{bid[-6:]}"
            ) as pool:
                while True:
                    # Every in-flight attempt is a potential success. Never keep
                    # more candidates than the remaining success quota, which
                    # prevents concurrent completions from overshooting count.
                    while (
                        len(in_flight) < max_inflight
                        and ok_n + len(in_flight) < target_total
                        and not _batch_cancel_requested()
                    ):
                        fut = pool.submit(_job, next_i)
                        in_flight[fut] = next_i
                        next_i += 1
                        with _lock:
                            bb = _batches.get(bid)
                            if bb is not None:
                                bb["inflight"] = len(in_flight)
                                bb["updated_at"] = _now()
                                if not bb.get("cancel_requested"):
                                    bb["status"] = "running"
                                bb["target_success"] = target_total
                                bb["remaining_success"] = max(0, target_total - ok_n)
                                bb["message"] = (
                                    f"target {ok_n}/{target_total} successes; "
                                    f"attempts={finished} fail={fail_n}, threads={workers}, "
                                    f"inflight={len(in_flight)}"
                                )
                                _mirror_reg_batch(bid, dict(bb))

                    if not in_flight:
                        break

                    done, _pending = wait(
                        set(in_flight.keys()),
                        return_when=FIRST_COMPLETED,
                        timeout=0.5,
                    )
                    if not done:
                        # Timeout tick: re-check cancel and refresh progress.
                        if _batch_cancel_requested():
                            # Stop feeding new jobs; still drain in-flight workers.
                            pass
                        continue
                    for fut in done:
                        idx = in_flight.pop(fut, 0)
                        try:
                            r = fut.result()
                            _note_result(idx, r=r)
                        except Exception as e:  # noqa: BLE001
                            _note_result(idx, exc=e)

                    # If cancelled and no more work in flight, exit promptly.
                    if _batch_cancel_requested() and not in_flight:
                        break
                    # If cancelled, do not submit more jobs even if capacity frees.
                    if _batch_cancel_requested():
                        continue
        finally:
            stop_renew = True
            # Best-effort cancel of any leftover futures (usually empty now).
            for fut in list(in_flight.keys()):
                try:
                    fut.cancel()
                except Exception:
                    pass
            with _lock:
                b = _batches.get(bid)
                if b is not None:
                    b["updated_at"] = _now()
                    b["finished"] = finished
                    b["ok_count"] = ok_n
                    b["fail_count"] = fail_n
                    b["spawned"] = len(b.get("session_ids") or [])
                    b["spawn_errors"] = errors[-20:]
                    b["runner_alive"] = False
                    b["inflight"] = 0
                    target_total = int(b.get("count") or finished or 0)
                    b["target_success"] = target_total
                    b["remaining_success"] = max(0, target_total - ok_n)
                    cancelled = bool(b.get("cancel_requested")) or str(b.get("status") or "").lower() in (
                        "stopping",
                        "cancelled",
                        "stopped",
                    )
                    if ok_n >= target_total:
                        b["status"] = "done"
                        b["error"] = None
                        b["message"] = (
                            f"target reached {ok_n}/{target_total} successes; "
                            f"attempts={finished} fail={fail_n}, threads={workers}"
                        )
                    elif cancelled:
                        b["status"] = "cancelled"
                        b["message"] = (
                            f"stopped at {ok_n}/{target_total} successes; "
                            f"attempts={finished} fail={fail_n}, threads={workers}"
                        )
                    else:
                        b["status"] = "error"
                        b["error"] = "; ".join(errors[:5]) or "batch runner stopped before target"
                        b["message"] = (
                            f"runner stopped at {ok_n}/{target_total} successes; "
                            f"attempts={finished} fail={fail_n}, threads={workers}"
                            + (f"; errors={len(errors)}" if errors else "")
                        )
                    _mirror_reg_batch(bid, dict(b))
                    st = str(b.get("status") or "done")

                    # Auto-import already happened per-account on probe pass.
                    # Keep a lightweight summary for batch logs only.
                    batch_sync = None
                    try:
                        uploaded = 0
                        for sid0 in list(b.get("session_ids") or []):
                            sess0 = _sessions.get(sid0) or _load_reg_sess(str(sid0)) or {}
                            au = sess0.get("auto_upload") if isinstance(sess0.get("auto_upload"), dict) else None
                            if au and au.get("ok"):
                                uploaded += int(au.get("uploaded") or au.get("total") or 1)
                        if uploaded:
                            batch_sync = {"ok": True, "uploaded": uploaded, "total": uploaded, "mode": "immediate"}
                            b["auto_upload"] = batch_sync
                            b["message"] = str(b.get("message") or "") + f"；远端同步 {uploaded}/{uploaded}"
                            _mirror_reg_batch(bid, dict(b))
                    except Exception as se:  # noqa: BLE001
                        batch_sync = {"ok": False, "error": str(se)[:240]}

                    _record_register_task(
                        task_id=str(bid),
                        summary=str(b.get("message") or f"协议注册批次 {bid}"),
                        status=st,
                        ok=st == "done" and ok_n >= target_total,
                        progress_done=min(int(ok_n or 0), int(target_total or ok_n or 0)),
                        progress_total=int(target_total or ok_n or 0),
                        finished=True,
                        detail={
                            "batch_id": bid,
                            "ok_count": ok_n,
                            "fail_count": fail_n,
                            "attempts": finished,
                            "target_success": target_total,
                            "threads": workers,
                            "status": st,
                            "errors": (errors or [])[:10],
                            "phase": "finished",
                            "adapter_build": ADAPTER_BUILD,
                            "auto_upload": batch_sync,
                        },
                    )
            _release_batch_runner(bid, lock_token)

    threading.Thread(
        target=_run_batch,
        daemon=True,
        name=f"gba-batch-{bid[-8:]}",
    ).start()

    return {
        "ok": True,
        "batch_id": bid,
        "remaining": remaining,
        "concurrency": workers,
        "message": f"started batch {bid}: remaining={remaining} threads={workers}",
    }


def _registration_failure_detail(exc: Exception, client: Any) -> tuple[str, dict[str, Any] | None]:
    message = str(exc)
    lowered = message.lower()
    is_captcha_failure = any(
        marker in lowered
        for marker in (
            "turnstile",
            "captcha",
            "camoufox",
            "过盾",
        )
    )
    if is_captcha_failure:
        return message, None

    request_diag = dict(getattr(client, "last_request", {}) or {}) if client is not None else {}
    phase = str(request_diag.get("phase") or "").strip()
    request_url = str(request_diag.get("url") or "").strip()
    elapsed = request_diag.get("elapsed_sec")
    if phase and request_url and phase not in message:
        suffix = f" [last_request={phase} {request_url}"
        if isinstance(elapsed, (int, float)):
            suffix += f" elapsed={float(elapsed):.1f}s"
        suffix += "]"
        return message + suffix, request_diag
    return message, request_diag or None


def _complete_sso_only_registration(
    *,
    sess: dict[str, Any],
    email: str,
    password: str,
    sso: str,
    accounts: Any,
    update: Any,
    auth_error: Exception,
) -> dict[str, Any]:
    """Keep a registered account when only OAuth/Auth extraction failed."""
    result = accounts.import_local_credentials(
        [{"email": email, "password": password, "sso": sso}],
        source="registration_auth_partial",
    )
    preserved = int(result.get("created") or 0) + int(result.get("updated") or 0)
    if not result.get("ok") or preserved < 1:
        raise RuntimeError(
            "Auth extraction failed and SSO credentials could not be preserved: "
            f"{result.get('error') or 'account was skipped'}"
        ) from auth_error

    account_id = f"local::{email}"
    warning = str(auth_error or "Auth extraction failed")[:800]
    imported_accounts = [{"id": account_id, "email": email}]
    sess["auth_json"] = None
    sess["imported_account_ids"] = [account_id]
    sess["imported_accounts"] = imported_accounts
    sess["oauth"] = {"path": "sso_only", "email": email, "error": warning}
    sess["partial_auth"] = True
    sess["auth_extraction_error"] = warning
    update(
        "completed",
        "账号已注册并保留；Auth 提取失败，SSO/账号密码仍可导出。",
        error=None,
        warning=warning,
        partial_auth=True,
        auth_extraction_error=warning,
        imported_account_ids=[account_id],
        imported_accounts=imported_accounts,
        probe={"count": 0, "ok": 0, "fail": 0, "results": []},
    )
    return result


def _run_registration(
    sid: str,
    yescaptcha_key: str,
    proxy: str,
    receiver: Any,
) -> None:
    with _lock:
        sess = _sessions.get(sid)
    if not sess:
        # Another worker may hold the durable copy; still try to load.
        sess = _load_reg_sess(sid)
    if not sess:
        return
    # Re-bind process-local map so later progress stays readable on this worker.
    with _lock:
        _sessions[sid] = sess

    def _refresh_cancel_from_redis() -> None:
        """Pull cancel_requested from Redis so multi-worker stop works.

        Also honour batch-level stop so stopping a batch reaches in-flight
        sessions even if the session mirror lags.
        """
        if not _reg_redis():
            return
        try:
            from store import sessions_redis

            remote = sessions_redis.reg_sess_get(sid)
            batch_cancel = False
            remote_batch = None
            bid = ""
            with _lock:
                local_sess = _sessions.get(sid) or sess or {}
                bid = str(local_sess.get("batch_id") or "")
            if not bid and isinstance(remote, dict):
                bid = str(remote.get("batch_id") or "")
            if bid:
                try:
                    remote_batch = sessions_redis.reg_batch_get(bid)
                except Exception:
                    remote_batch = None
                if isinstance(remote_batch, dict) and (
                    remote_batch.get("cancel_requested")
                    or _is_cancel_status(remote_batch.get("status"))
                ):
                    batch_cancel = True
                    with _lock:
                        bb = _batches.get(bid) or dict(remote_batch)
                        bb["cancel_requested"] = True
                        if str(bb.get("status") or "").lower() not in (
                            "cancelled",
                            "stopped",
                            "done",
                            "partial",
                            "error",
                        ):
                            bb["status"] = remote_batch.get("status") or "stopping"
                        bb["updated_at"] = _now()
                        _batches[bid] = bb

            sess_cancel = isinstance(remote, dict) and (
                remote.get("cancel_requested")
                or _is_cancel_status(remote.get("status"))
            )
            if not sess_cancel and not batch_cancel:
                return
            with _lock:
                cur = _sessions.get(sid) or sess
                cur["cancel_requested"] = True
                if str(cur.get("status") or "").lower() not in _TERMINAL_STATUSES:
                    if sess_cancel and str(remote.get("status") or "").lower() in (
                        "stopping",
                        "cancelled",
                        "stopped",
                    ):
                        cur["status"] = remote.get("status") or "stopping"
                        if remote.get("message"):
                            cur["message"] = remote.get("message")
                    elif batch_cancel:
                        cur["status"] = "stopping"
                        cur["message"] = "stop requested via batch"
                _sessions[sid] = cur
        except Exception:
            pass

    def update(status: str, message: str, **kwargs: Any) -> None:
        _refresh_cancel_from_redis()
        with _lock:
            cur = _sessions.get(sid) or sess
            # Batch-level cancel also aborts this worker.
            bid = str(cur.get("batch_id") or "")
            batch_hit = False
            if bid:
                bb = _batches.get(bid) or {}
                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):
                    batch_hit = True
                    cur["cancel_requested"] = True
            # Do not overwrite a terminal cancel with intermediate progress.
            if (_session_cancel_requested(cur) or batch_hit) and status not in (
                "cancelled",
                "stopped",
                "error",
                "imported",
            ):
                raise _RegCancelled(cur.get("message") or "cancelled by user")
            cur["status"] = status
            cur["message"] = message
            cur["updated_at"] = _now()
            cur.update(kwargs)
            _sessions[sid] = cur
            _mirror_reg_sess(sid, cur)

    def _check_cancel() -> None:
        _refresh_cancel_from_redis()
        with _lock:
            cur = _sessions.get(sid) or sess
            bid = str(cur.get("batch_id") or "")
            if bid:
                bb = _batches.get(bid) or {}
                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):
                    cur["cancel_requested"] = True
                    _sessions[sid] = cur
        if _session_cancel_requested(cur):
            raise _RegCancelled(cur.get("message") or "cancelled by user")

    email = str(sess.get("email") or "").strip().lower()
    password = sess.get("password") or ""
    if not password:
        update("error", "missing password for registration session", error="missing password")
        return
    sess["email"] = email
    client = None

    try:
        _check_cancel()
        ensure_xconsole()
        from xconsole_client import (
            XConsoleAuthClient,
            YesCaptchaSolver,
            xai_oauth_login_protocol,
        )
        from xconsole_client import config as C
        from xconsole_client.oauth_protocol import extract_cookies_from_auth_client
        from xconsole_client.xai_oauth import (
            CLIPROXYAPI_GROK_HEADERS,
            build_cliproxyapi_auth_record,
        )
        import register_lite_store as accounts

        update("registering", "visiting signup page")
        _check_cancel()
        client = XConsoleAuthClient(
            debug=True,
            proxy=proxy or "",
            signup_url="https://accounts.x.ai/sign-up?redirect=grok-com",
        )
        client.visit_home()
        _check_cancel()
        client.load_signup_page()

        sitekey = (
            getattr(client, "turnstile_sitekey", None)
            or getattr(C, "TURNSTILE_SITEKEY", None)
            or ""
        ).strip()
        website_url = (getattr(client, "signup_url", None) or C.SIGNUP_URL or "").strip()
        if not sitekey:
            raise RuntimeError(
                "Turnstile sitekey missing. Signup page scrape failed and "
                "config TURNSTILE_SITEKEY is empty."
            )

        provider = (
            CAPTCHA_PROVIDER
            or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
            or os.environ.get("CAPTCHA_PROVIDER")
            or "local"
        ).strip().lower()
        if provider not in {"local", "yescaptcha"}:
            provider = "local"

        if provider == "local":
            # Always use in-container inline solver; ignore external/custom URL.
            endpoint = _local_solver_base_url(None)
            solver_key = "local"
            auto_fallback = False
            # Re-check right before first solve so a mid-batch solver restart
            # doesn't burn mailboxes while HTTP is still down.
            wait = wait_for_local_solver(
                endpoint,
                timeout_sec=min(60.0, max(5.0, LOCAL_SOLVER_WAIT_SEC)),
                progress=lambda m: update("waiting_solver", m),
            )
            if not wait.get("ready"):
                raise RuntimeError(
                    wait.get("error")
                    or f"本地过盾未就绪，无法开始打码: {endpoint}"
                )
        else:
            # Cloud YesCaptcha only; never inherit local solver endpoint.
            endpoint = (
                os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")
                or os.environ.get("YESCAPTCHA_ENDPOINT")
                or os.environ.get("YESCAPTCHA_API_BASE")
                or ""
            ).strip() or None
            # Guard against accidental local leftover endpoint.
            if endpoint and (
                "127.0.0.1" in endpoint
                or "localhost" in endpoint
                or endpoint.rstrip("/").endswith(":5072")
            ):
                endpoint = None
            solver_key = (
                yescaptcha_key
                or YESCAPTCHA_KEY
                or os.environ.get("GROK2API_YESCAPTCHA_KEY")
                or os.environ.get("YESCAPTCHA_API_KEY")
                or ""
            ).strip()
            if not solver_key or solver_key == "local":
                raise RuntimeError("YesCaptcha 模式需要有效的 YESCAPTCHA_KEY")
            auto_fallback = True

        def _turnstile_progress(msg: str) -> None:
            # Raise cancel out of solver polling so stop doesn't wait full captcha timeout.
            _check_cancel()
            update("solving_turnstile", f"Turnstile: {msg}")

        solver = YesCaptchaSolver(
            solver_key,
            endpoint=endpoint,
            # Keep captcha wait bounded; cancel still interrupts via on_progress.
            timeout=float(os.environ.get("GROK2API_YESCAPTCHA_TIMEOUT", "120") or 120),
            poll_interval=float(os.environ.get("GROK2API_YESCAPTCHA_POLL", "2") or 2),
            debug=True,
            on_progress=_turnstile_progress,
            # Local: no cloud fallback. YesCaptcha: allow cn/global peer fallback.
            auto_fallback_endpoint=auto_fallback,
        )
        print(
            f"[grok-build-auth] turnstile provider={provider} website_url={website_url} "
            f"sitekey={sitekey} endpoint={getattr(solver, '_endpoint', '?')}"
        )

        # Critical ordering:
        # 1) solve Turnstile first (slow, ~20-40s)
        # 2) send email code
        # 3) wait for mailbox code
        # 4) immediately verify + create_account
        # Old order verified the code then waited for captcha; create_account then
        # failed with WKE=email:invalid-validation-code because the code expired /
        # was single-use after the slow captcha step.
        solver_label = "本地过盾" if provider == "local" else "YesCaptcha"
        update("solving_turnstile", f"solving Turnstile via {solver_label} (before email code)")
        _check_cancel()

        def _solve_turnstile(url: str, *, premium: bool = True) -> Any:
            # Local inline solver is single-process and browser-backed; concurrent
            # createTask storms from many registration workers cause timeouts /
            # mixed results. Serialize local solves while keeping YesCaptcha parallel.
            # Original strategy (pre-1.2.3): local Camoufox is Proxyless only —
            # captcha uses server egress, protocol HTTP still uses job proxy.
            use_premium = bool(premium) and provider != "local"
            kwargs = {
                "website_url": url,
                "website_key": sitekey,
                "premium": use_premium,
                "fallback_non_premium": True,
                "proxy": None,
            }
            if provider == "local":
                # Original serial strategy from git history.
                with _CaptchaSlot():
                    _check_cancel()
                    try:
                        return solver.solve_turnstile(**kwargs)
                    except Exception as e:
                        # Camoufox queue meltdown / timeout → brief global pause
                        msg = str(e).lower()
                        if any(
                            k in msg
                            for k in (
                                "timeout",
                                "timed out",
                                "queue",
                                "busy",
                                "no browser",
                                "target closed",
                                "crashed",
                            )
                        ):
                            _note_reg_pressure(f"local captcha: {e}")
                        raise
            return solver.solve_turnstile(**kwargs)

        try:
            # Local: Proxyless only. Remote YesCaptcha: premium M1 first.
            turnstile = _solve_turnstile(website_url, premium=(provider != "local"))
        except _RegCancelled:
            raise
        except Exception as captcha_err:
            _check_cancel()
            alt_url = "https://accounts.x.ai/sign-up?redirect=cloud-console"
            if website_url.rstrip("/") == alt_url.rstrip("/"):
                alt_url = "https://accounts.x.ai/sign-up?redirect=grok-com"
            update(
                "solving_turnstile",
                f"primary Turnstile failed ({captcha_err}); retry {alt_url}",
            )
            try:
                turnstile = _solve_turnstile(alt_url, premium=False)
            except Exception as retry_err:
                if provider == "local":
                    raise RuntimeError(
                        "本地过盾失败：Camoufox 没有拿到 Turnstile token；"
                        f"首轮错误：{captcha_err}; 重试错误：{retry_err}"
                    ) from retry_err
                raise
        if not turnstile:
            raise RuntimeError("YesCaptcha returned empty Turnstile token")
        _check_cancel()

        # Password can be validated any time before create; do it while warm.
        client.validate_password(email, password)

        update("registering", "sending email validation code")
        _check_cancel()
        send_res = client.create_email_validation_code(email)
        if hasattr(send_res, "ok") and send_res.ok is False:
            print(
                f"[grok-build-auth] CreateEmailValidationCode ok=False "
                f"http={getattr(send_res, 'http_status', None)} "
                f"grpc={getattr(send_res, 'grpc_status', None)}"
            )

        update("waiting_email", "waiting for xAI verification code")
        # Poll mailbox with cancel-aware receiver so stop lands in ~0.25–1s.
        _check_cancel()

        def _mail_should_cancel() -> bool:
            # _check_cancel raises _RegCancelled when stop is requested.
            _check_cancel()
            return False

        def _mail_progress(message: str) -> None:
            with _lock:
                current = _sessions.get(sid) or sess
                logs = list(current.get("mail_logs") or [])
            logs.append({"at": _now(), "message": str(message or "")[:500]})
            update("waiting_email", str(message or ""), mail_logs=logs[-20:])

        try:
            code = receiver.wait_for_code(
                timeout=120.0,
                should_cancel=_mail_should_cancel,
                poll_interval=1.0,
                on_progress=_mail_progress,
            )
        except TypeError:
            # Older receiver signature fallback.
            code = None
            mail_deadline = time.time() + 120.0
            while time.time() < mail_deadline:
                _check_cancel()
                try:
                    code = receiver.wait_for_code(
                        timeout=min(4.0, max(1.0, mail_deadline - time.time()))
                    )
                except Exception:
                    code = None
                if code:
                    break
        if not code:
            raise RuntimeError("email verification code timeout")
        code = str(code or "").strip().upper().replace(" ", "").replace("-", "")
        if len(code) != 6:
            raise RuntimeError(
                f"invalid email verification code shape: {code!r} "
                f"(expect 6 alnum chars)"
            )
        update("registering", f"code received: {code}; verifying + creating immediately")

        # Prefer empty castle token (YesCaptcha cannot mint Castle fingerprints).
        # Retry create_account once with a fresh Turnstile + fresh email code when
        # the first flight is a structured hard error (expired code / turnstile).
        create_attempts = 2
        res = None
        sc: list[str] = []
        rsc_body = ""
        rsc_preview = ""
        http_status = 0
        signup_err: str | None = None
        for ca in range(1, create_attempts + 1):
            if ca > 1:
                # Full refresh path for invalid code / captcha failures.
                update(
                    "solving_turnstile",
                    f"create_account hard error ({signup_err}); refreshing Turnstile+email code",
                )
                try:
                    turnstile = _solve_turnstile(
                        website_url, premium=(provider != "local")
                    )
                except Exception as captcha_err:  # noqa: BLE001
                    print(f"[grok-build-auth] turnstile refresh failed: {captcha_err}")
                    break
                # New email code required after invalid-validation-code.
                try:
                    client.create_email_validation_code(email)
                    update("waiting_email", "waiting for fresh xAI verification code")
                    code = receiver.wait_for_code(
                        timeout=120,
                        should_cancel=_mail_should_cancel,
                        poll_interval=1.0,
                        on_progress=_mail_progress,
                    )
                    code = (
                        str(code or "")
                        .strip()
                        .upper()
                        .replace(" ", "")
                        .replace("-", "")
                    )
                    if len(code) != 6:
                        raise RuntimeError(f"fresh email code invalid: {code!r}")
                    update("registering", f"fresh code received: {code}")
                except Exception as mail_err:  # noqa: BLE001
                    print(f"[grok-build-auth] email code refresh failed: {mail_err}")
                    break

            # verify immediately before create_account (same second when possible)
            try:
                vres = client.verify_email_validation_code(email, code)
                print(
                    f"[grok-build-auth] VerifyEmailValidationCode "
                    f"ok={getattr(vres, 'ok', None)} "
                    f"http={getattr(vres, 'http_status', None)} "
                    f"grpc={getattr(vres, 'grpc_status', None)}"
                )
            except Exception as v_err:  # noqa: BLE001
                print(f"[grok-build-auth] verify_email error: {v_err}")

            update(
                "creating_account",
                f"creating xAI account (attempt {ca}/{create_attempts})",
            )
            res = client.create_account(
                email=email,
                given_name="User",
                family_name="Grok",
                password=password,
                email_validation_code=code,
                turnstile_token=turnstile,
                castle_request_token="",
                conversion_id=str(uuid.uuid4()),
            )
            sc = list(getattr(res, "set_cookies", None) or [])
            rsc_body = getattr(res, "rsc_body", "") or ""
            rsc_preview = rsc_body[:800]
            http_status = int(getattr(res, "http_status", 0) or 0)
            try:
                signup_err = client.extract_signup_error(rsc_body)
            except Exception:
                signup_err = None
            print(f"[grok-build-auth] create_account HTTP={http_status}")
            print(f"[grok-build-auth] create_account set-cookies count={len(sc)}")
            print(f"[grok-build-auth] create_account ok={bool(getattr(res, 'ok', False))}")
            print(f"[grok-build-auth] create_account error={signup_err!r}")
            print(f"[grok-build-auth] create_account rsc_body preview: {rsc_preview}")
            print(f"[grok-build-auth] adapter_build={ADAPTER_BUILD}")
            sess["create_account_http"] = http_status
            sess["create_account_ok_flag"] = bool(getattr(res, "ok", False))
            sess["create_account_set_cookies"] = len(sc)
            sess["create_account_error"] = signup_err

            # Optional offline diagnosis dump (off by default; ~70KB each).
            # Enable with GROK2API_DUMP_CREATE_ACCOUNT_RSC=1 when debugging signup.
            if os.environ.get("GROK2API_DUMP_CREATE_ACCOUNT_RSC", "").strip().lower() in {
                "1", "true", "yes", "on"
            }:
                try:
                    debug_path = (
                        # Prefer the lite data dir (Docker volume /data) when present.
                        Path(os.getenv("GROK_REGISTER_LITE_DATA_DIR") or (ROOT / "generated" / "register_lite"))
                        / "register_sso"
                        / f"{sid}.create_account.rsc.txt"
                    )
                    debug_path.parent.mkdir(parents=True, exist_ok=True)
                    debug_path.write_text(rsc_body[:200_000], encoding="utf-8")
                except Exception:
                    pass

            if http_status != 200:
                # Non-200 is terminal for this attempt; try once more only on 5xx.
                if http_status >= 500 and ca < create_attempts:
                    continue
                raise RuntimeError(
                    "create_account transport failed. "
                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                    f"error={signup_err!r}; set_cookies={len(sc)}; "
                    f"body_preview={rsc_preview!r}"
                )

            # Structured hard error: retry with fresh captcha when recoverable.
            if signup_err:
                recoverable = any(
                    x in str(signup_err).lower()
                    for x in (
                        "turnstile",
                        "rate_limited",
                        "rate limit",
                        "captcha",
                        "account_signup_error",
                    )
                )
                if recoverable and ca < create_attempts:
                    continue
                raise RuntimeError(
                    "create_account rejected by xAI. "
                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                    f"error={signup_err!r}; set_cookies={len(sc)}; "
                    f"body_preview={rsc_preview!r}"
                )

            # HTTP 200 without structured error — proceed even if res.ok is False
            # due to historical false negatives on RSC-only flights.
            break

        update(
            "fetching_sso",
            f"create_account HTTP {http_status} accepted; extracting SSO [{ADAPTER_BUILD}]",
        )

        sso = None
        try:
            sso = client.fetch_sso_token(
                email=email, password=password, save=True, retries=4
            )
        except Exception as sso_fetch_err:  # noqa: BLE001
            print(f"[grok-build-auth] fetch_sso_token error: {sso_fetch_err}")

        if not sso:
            try:
                from xconsole_client.sso import (
                    SSOExtractor,
                    parse_all_set_cookie_urls,
                    parse_sso_from_set_cookies,
                    parse_sso_jwt_url,
                    parse_sso_token_from_text,
                )

                sso = parse_sso_from_set_cookies(sc) or parse_sso_token_from_text(
                    rsc_body
                )
                if not sso and rsc_body:
                    print(
                        f"[grok-build-auth] set-cookie candidates="
                        f"{parse_all_set_cookie_urls(rsc_body)[:3]}"
                    )
                    print(
                        f"[grok-build-auth] primary set-cookie url="
                        f"{parse_sso_jwt_url(rsc_body)}"
                    )
                    extractor = SSOExtractor(
                        transport_request=client._request,
                        base_headers=client._base_headers,
                        cookie_jar=client._t.cookies,
                        debug=True,
                    )
                    sso = extractor.extract(
                        rsc_body, email=email, password=password, save=False
                    )
            except Exception as recover_err:  # noqa: BLE001
                print(f"[grok-build-auth] SSO recover failed: {recover_err}")

        # Current xAI create_account often returns only RSC chunks + CF cookies,
        # with no set-cookie JWT chain. Fall back to password CreateSession and
        # treat the returned session JWT as the sso cookie for sso_to_auth_json.
        if not sso:
            update(
                "fetching_sso",
                f"RSC has no sso chain; CreateSession password fallback [{ADAPTER_BUILD}]",
            )
            try:
                # Fresh turnstile for sign-in page improves CreateSession success.
                # Allow account propagation delay before first login attempt.
                time.sleep(2.0)
                signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
                try:
                    signin_turnstile = _solve_turnstile(
                        signin_url, premium=(provider != "local")
                    )
                except Exception:
                    signin_turnstile = turnstile
                sso = client.obtain_session_via_password(
                    email=email,
                    password=password,
                    turnstile_token=signin_turnstile,
                    referer=signin_url,
                    retries=4,
                )
                # One more captcha + login if first CreateSession returned empty.
                if not sso:
                    try:
                        signin_turnstile = _solve_turnstile(signin_url, premium=False)
                        time.sleep(1.5)
                        sso = client.obtain_session_via_password(
                            email=email,
                            password=password,
                            turnstile_token=signin_turnstile,
                            referer=signin_url,
                            retries=2,
                        )
                    except Exception as cs2_err:  # noqa: BLE001
                        print(
                            f"[grok-build-auth] CreateSession second pass failed: {cs2_err}"
                        )
                print(
                    f"[grok-build-auth] CreateSession fallback sso="
                    f"{(sso[:60] if sso else None)}"
                )
            except Exception as cs_err:  # noqa: BLE001
                print(f"[grok-build-auth] CreateSession fallback failed: {cs_err}")

        print(f"[grok-build-auth] fetch_sso_token result: {sso[:60] if sso else None}")
        sess["sso"] = sso
        session_cookies = extract_cookies_from_auth_client(client)
        print(
            f"[grok-build-auth] session cookies after signup: "
            f"{sorted((session_cookies or {}).keys())}"
        )
        if sso:
            session_cookies = dict(session_cookies or {})
            session_cookies["sso"] = sso
            session_cookies["sso-rw"] = sso

        if not sso:
            raise RuntimeError(
                "SSO_COOKIE_MISSING after create_account. "
                f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                f"create_ok={bool(getattr(res, 'ok', False))}; "
                f"signup_error={signup_err!r}; set_cookies={len(sc)}; "
                f"cookie_keys={sorted((session_cookies or {}).keys())}; "
                f"body_preview={rsc_preview!r}. "
                "Account may have been created, but neither RSC set-cookie chain "
                "nor CreateSession password fallback produced an sso cookie. "
                "Common causes: turnstile_failed, rate_limited, or account not yet "
                "visible to CreateSession."
            )

        # Required path: SSO/session JWT -> sso_to_auth_json device flow -> auth.json
        update(
            "importing",
            f"SSO obtained; converting via sso_to_auth_json [{ADAPTER_BUILD}]",
        )
        import sso_to_auth_json as sso_import

        try:
            token = sso_import.sso_to_token(sso)
            if not token or not token.get("access_token"):
                _note_reg_pressure("device-flow conversion failed", pause_sec=10)
                raise RuntimeError(
                    "SSO obtained but sso_to_auth_json conversion failed "
                    "(device verify/approve/token poll; often xAI device-flow "
                    "rate_limited/slow_down under concurrent registration). "
                    f"adapter_build={ADAPTER_BUILD}; sso_prefix={sso[:24]!r}"
                )
            _key, entry = sso_import.token_to_auth_entry(token, email=email)
            import_result = accounts.import_auth_payload(
                {
                    "key": entry["key"],
                    "auth_mode": entry.get("auth_mode", "oidc"),
                    "email": entry.get("email") or email,
                    "refresh_token": entry.get("refresh_token", ""),
                    "id_token": token.get("id_token", ""),
                    "expires_at": entry.get("expires_at"),
                    "oidc_issuer": entry.get("oidc_issuer", "https://auth.x.ai"),
                    "oidc_client_id": entry.get("oidc_client_id", ""),
                    "registration_password": password,
                    "sso": sso,
                    "batch_id": sess.get("batch_id") or "",
                    "session_id": sid,
                },
                merge=True,
            )
            if not import_result.get("ok"):
                raise RuntimeError(
                    f"SSO account import failed: {import_result.get('error')}; "
                    f"adapter_build={ADAPTER_BUILD}"
                )
        except _RegCancelled:
            raise
        except Exception as auth_exc:  # noqa: BLE001
            _check_cancel()
            _complete_sso_only_registration(
                sess=sess,
                email=email,
                password=password,
                sso=sso,
                accounts=accounts,
                update=update,
                auth_error=auth_exc,
            )
            return
        # Registration import is persisted in the local SQLite account store.
        imported_rows = [
            x for x in (import_result.get("imported") or []) if isinstance(x, dict)
        ]
        imported_ids = [str(x.get("id")) for x in imported_rows if x.get("id")]
        imported_accounts = [
            {"id": x.get("id"), "email": x.get("email") or email}
            for x in imported_rows
            if x.get("id") or x.get("email")
        ]
        sess["auth_json"] = import_result
        sess["imported_account_ids"] = imported_ids
        sess["imported_accounts"] = imported_accounts
        sess["oauth"] = {
            "path": "sso_to_auth_json",
            "access_token": (token.get("access_token") or "")[:20] + "...",
            "refresh_token": bool(token.get("refresh_token")),
            "email": email,
        }
        # Auto probe newly imported accounts so they are validated in the pool.
        probe_summaries: list[dict[str, Any]] = []
        lite_mode = os.environ.get("GROK_REGISTER_LITE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if imported_ids and not lite_mode:
            delay = max(0.0, float(REGISTER_PROBE_DELAY_SEC or 0.0))
            if delay > 0:
                update(
                    "probing",
                    f"imported {len(imported_ids)} account(s); wait {int(delay)}s "
                    f"before probe [{ADAPTER_BUILD}]",
                    imported_account_ids=imported_ids,
                    imported_accounts=imported_accounts,
                    probe_delay_sec=delay,
                )
                time.sleep(delay)
            update(
                "probing",
                f"imported {len(imported_ids)} account(s); probing pool health "
                f"(delay={int(delay)}s) [{ADAPTER_BUILD}]",
                imported_account_ids=imported_ids,
                imported_accounts=imported_accounts,
                probe_delay_sec=delay,
            )
            try:
                import model_health

                for aid in imported_ids:
                    try:
                        pr = model_health.probe_single_account(
                            aid, None, auto_disable=True, source="register"
                        )
                        detail = pr.get("result") if isinstance(pr, dict) else None
                        if not isinstance(detail, dict):
                            detail = pr if isinstance(pr, dict) else {}
                        err_text = (
                            detail.get("error")
                            or detail.get("message")
                            or (pr.get("error") if isinstance(pr, dict) else None)
                            or ""
                        )
                        latency = (
                            detail.get("latency_ms")
                            or detail.get("elapsed_ms")
                            or detail.get("duration_ms")
                        )
                        probe_summaries.append(
                            {
                                "account_id": aid,
                                "ok": bool(pr.get("ok") if isinstance(pr, dict) else False),
                                "model": detail.get("model")
                                or (pr.get("model") if isinstance(pr, dict) else None),
                                "error": (str(err_text)[:180] if err_text else None),
                                "latency_ms": latency,
                            }
                        )
                    except Exception as pe:  # noqa: BLE001
                        probe_summaries.append(
                            {
                                "account_id": aid,
                                "ok": False,
                                "error": str(pe)[:180],
                            }
                        )
            except Exception as pe:  # noqa: BLE001
                probe_summaries.append(
                    {
                        "account_id": None,
                        "ok": False,
                        "error": f"probe module error: {pe}"[:180],
                    }
                )
        elif imported_ids:
            delay = max(0.0, float(REGISTER_PROBE_DELAY_SEC or 0.0))
            if delay > 0:
                update(
                    "probing",
                    f"已导入 {len(imported_ids)} 个账号；等待 {int(delay)} 秒后测活 "
                    f"[{ADAPTER_BUILD}]",
                    imported_account_ids=imported_ids,
                    imported_accounts=imported_accounts,
                    probe_delay_sec=delay,
                )
                time.sleep(delay)
            update(
                "probing",
                f"已导入 {len(imported_ids)} 个账号；正在测活 [{ADAPTER_BUILD}]",
                imported_account_ids=imported_ids,
                imported_accounts=imported_accounts,
                probe_delay_sec=delay,
            )
            for account in imported_accounts or [{"id": imported_ids[0], "email": email}]:
                ident = str(account.get("email") or account.get("id") or "").strip()
                if not ident:
                    continue
                try:
                    pr = accounts.probe_account(ident, model="grok-4.5")
                    probe_summaries.append(
                        {
                            "account_id": account.get("id") or ident,
                            "email": account.get("email") or ident,
                            "ok": bool(pr.get("ok")),
                            "model": pr.get("model") or "grok-4.5",
                            "error": (str(pr.get("error"))[:180] if pr.get("error") else None),
                            "latency_ms": pr.get("latency_ms"),
                        }
                    )
                except Exception as pe:  # noqa: BLE001
                    probe_summaries.append(
                        {
                            "account_id": account.get("id") or ident,
                            "email": account.get("email") or ident,
                            "ok": False,
                            "error": str(pe)[:180],
                        }
                    )
        sess["probe"] = {
            "count": len(probe_summaries),
            "ok": sum(1 for p in probe_summaries if p.get("ok")),
            "fail": sum(1 for p in probe_summaries if not p.get("ok")),
            "results": probe_summaries,
        }
        ok_n = int(sess["probe"]["ok"])
        fail_n = int(sess["probe"]["fail"])
        probe_error = next(
            (str(item.get("error") or "") for item in probe_summaries if not item.get("ok")),
            "",
        )
        # Gate: only probe-passed accounts stay in SQLite and count as success.
        # Registration may write credentials first so probe can run; failures are discarded.
        if not probe_summaries:
            # No probe ran → do not keep half-baked credentials.
            fail_n = max(fail_n, 1)
            ok_n = 0
            probe_error = probe_error or "未测活，凭证未保留"
        keep_emails: list[str] = []
        drop_emails: list[str] = []
        for item in probe_summaries:
            em = str(item.get("email") or "").strip().lower()
            if not em and email:
                em = str(email).strip().lower()
            if not em:
                continue
            if item.get("ok"):
                keep_emails.append(em)
            else:
                drop_emails.append(em)
        if not probe_summaries and email:
            drop_emails.append(str(email).strip().lower())
        # Also drop anything we imported that is not in keep list.
        for acc in imported_accounts or []:
            em = str(acc.get("email") or "").strip().lower()
            if em and em not in keep_emails and em not in drop_emails:
                drop_emails.append(em)
        if drop_emails:
            try:
                discard_fn = getattr(accounts, "discard_accounts", None) or accounts.delete_accounts
                discarded = discard_fn(drop_emails)
                print(
                    f"[grok-build-auth] probe-fail discard emails={drop_emails} "
                    f"result={discarded}"
                )
            except Exception as de:  # noqa: BLE001
                print(f"[grok-build-auth] probe-fail discard error: {de}")
        if keep_emails and fail_n == 0:
            status = "imported"
            message = f"测活通过，已写入数据库（{ok_n}）。"
            imported_accounts = [
                a
                for a in (imported_accounts or [])
                if str(a.get("email") or "").strip().lower() in set(keep_emails)
            ] or [{"id": imported_ids[0] if imported_ids else "", "email": keep_emails[0]}]
            imported_ids = [
                str(a.get("id") or "")
                for a in imported_accounts
                if a.get("id")
            ] or list(imported_ids)

            # Auto-upload immediately after probe pass — no grouping / batch wait.
            auto_upload = None
            try:
                auto_upload = _immediate_auto_upload_emails(keep_emails)
            except Exception as ae:  # noqa: BLE001
                auto_upload = {"ok": False, "error": str(ae)[:240]}
            if isinstance(auto_upload, dict):
                sess["auto_upload"] = auto_upload
                g = auto_upload.get("grok2api")
                c = auto_upload.get("cpa")
                bits = []
                if isinstance(g, dict):
                    if g.get("ok"):
                        bits.append("Grok2API 自动导入成功")
                    else:
                        bits.append("Grok2API 自动导入失败：" + str(g.get("error") or "unknown")[:120])
                if isinstance(c, dict):
                    if c.get("ok"):
                        bits.append("CPA 自动导入成功")
                    else:
                        bits.append("CPA 自动导入失败：" + str(c.get("error") or "unknown")[:120])
                if auto_upload.get("uploaded") is not None:
                    bits.append(
                        f"远端同步 {int(auto_upload.get('uploaded') or 0)}/{int(auto_upload.get('total') or 0)}"
                    )
                if auto_upload.get("error") and not bits:
                    bits.append("自动导入失败：" + str(auto_upload.get("error"))[:120])
                if bits:
                    message += " " + "；".join(bits)
        else:
            # Count as hard failure so batch ok/fail reflects probe gate only.
            status = "failed"
            message = (
                f"测活未通过，已丢弃本地凭证（失败 {max(fail_n, 1)}）。"
            )
            if probe_error:
                message += f" 原因：{str(probe_error)[:160]}"
            imported_ids = []
            imported_accounts = []
            ok_n = 0
            fail_n = max(fail_n, 1)
            sess["probe"]["ok"] = 0
            sess["probe"]["fail"] = fail_n
        sess["imported_account_ids"] = imported_ids
        sess["imported_accounts"] = imported_accounts
        update(
            status,
            message,
            error=probe_error or None if status != "imported" else None,
            imported_account_ids=imported_ids,
            imported_accounts=imported_accounts,
            probe=sess.get("probe"),
            auto_upload=sess.get("auto_upload"),
        )
        return
    except _RegCancelled as exc:
        with _lock:
            cur = _sessions.get(sid) or sess
            cur["status"] = "cancelled"
            cur["message"] = str(exc) or "cancelled by user"
            cur["error"] = "cancelled"
            cur["cancel_requested"] = True
            cur["updated_at"] = _now()
            _sessions[sid] = cur
            _mirror_reg_sess(sid, cur)
        return
    except Exception as exc:  # noqa: BLE001
        try:
            # Preserve the last protocol request in the task record. This makes
            # curl/libcurl failures actionable even when stdout is unavailable.
            detail, request_diag = _registration_failure_detail(exc, client)
            update("error", f"failed: {detail}", error=detail, last_request=request_diag)
        except _RegCancelled:
            with _lock:
                cur = _sessions.get(sid) or sess
                cur["status"] = "cancelled"
                cur["message"] = "cancelled by user"
                cur["error"] = "cancelled"
                cur["cancel_requested"] = True
                cur["updated_at"] = _now()
                _sessions[sid] = cur
                _mirror_reg_sess(sid, cur)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        with _lock:
            final_sess = dict(_sessions.get(sid) or sess or {})
            if sid in _sessions:
                _sessions[sid].pop("_receiver", None)
                _sessions[sid].pop("_client", None)
        # Single sessions write their own terminal task log. Batch sessions are
        # summarized once by the batch finalizer (avoids N noise rows).
        if final_sess and not final_sess.get("batch_id"):
            payload = _session_task_log_payload(final_sess)
            if payload.get("finished"):
                _record_register_task(
                    task_id=payload["task_id"] or sid,
                    summary=payload["summary"],
                    status=payload["status"],
                    ok=payload["ok"],
                    progress_done=payload["progress_done"],
                    progress_total=payload["progress_total"],
                    finished=True,
                    detail={**payload["detail"], "phase": "finished"},
                )



def _nonterminal_session_statuses() -> frozenset[str]:
    return frozenset(
        {
            "pending",
            "queued",
            "starting",
            "started",
            "running",
            "probing",
            "solving_turnstile",
            "waiting_email",
            "fetching_sso",
            "converting",
            "importing",
            "stopping",
        }
    )


def reclaim_orphaned_registration_sessions(
    *,
    stale_sec: float | None = None,
    batch_id: str | None = None,
) -> dict[str, Any]:
    """Mark abandoned non-terminal sessions as error so a batch can resume.

    After process restart / image upgrade, in-flight workers die but Redis still
    shows ``solving_turnstile`` etc. Those sessions never finish, and the
    batch runner is gone — registration appears "hung mid-way".
    """
    try:
        ttl = float(
            stale_sec
            if stale_sec is not None
            else (os.environ.get("GROK2API_REG_STALE_SEC", "180") or 180)
        )
    except (TypeError, ValueError):
        ttl = 180.0
    ttl = max(30.0, min(ttl, 3600.0))
    now = _now()
    nonterm = _nonterminal_session_statuses()
    want_batch = (batch_id or "").strip() or None

    reclaimed: list[dict[str, Any]] = []
    # Prefer durable Redis list when available.
    sessions: list[dict[str, Any]] = []
    if _reg_redis():
        try:
            from store import sessions_redis

            listed = sessions_redis.reg_sess_list() or []
            if isinstance(listed, list):
                sessions = [s for s in listed if isinstance(s, dict)]
        except Exception:
            sessions = []
    if not sessions:
        with _lock:
            sessions = [dict(v) for v in _sessions.values() if isinstance(v, dict)]

    for sess in sessions:
        sid = str(sess.get("id") or "").strip()
        if not sid:
            continue
        bid = str(sess.get("batch_id") or "").strip()
        if want_batch and bid != want_batch:
            continue
        st = str(sess.get("status") or "").strip().lower()
        if st in _TERMINAL_STATUSES or st not in nonterm:
            continue
        # Always reclaim if no local/remote runner can own it; use stale age as
        # a safety so we don't kill a still-running worker in the same process.
        age = now - float(sess.get("updated_at") or sess.get("created_at") or 0)
        # If this process holds an active runner for the batch, only reclaim
        # sessions older than ttl (true stalls). If no runner, reclaim all
        # non-terminal after a short grace (30s) so resume can proceed.
        has_runner = False
        if bid:
            with _lock:
                has_runner = bool(_active_batch_runners.get(bid))
            if not has_runner and _reg_redis():
                try:
                    from store.redis_client import get_str as redis_get

                    has_runner = bool(redis_get(_batch_runner_lock_key(bid)))
                except Exception:
                    has_runner = False
        min_age = ttl if has_runner else min(30.0, ttl)
        if age < min_age:
            continue
        msg = (
            f"reclaimed orphan session after {age:.0f}s "
            f"(status was {st}; runner_alive={has_runner})"
        )
        with _lock:
            cur = _sessions.get(sid) or dict(sess)
            prev = str(cur.get("status") or "").strip().lower()
            already_terminal = prev in _TERMINAL_STATUSES
            cur["status"] = "error"
            cur["error"] = msg
            cur["message"] = msg
            cur["cancel_requested"] = False
            cur["updated_at"] = now
            _sessions[sid] = cur
            _mirror_reg_sess(sid, dict(cur))
            # Count orphan as failed completion so batch remaining does not overshoot.
            if bid and not already_terminal:
                b = _batches.get(bid) or _load_reg_batch(bid) or {"id": bid}
                b = dict(b)
                b["fail_count"] = int(b.get("fail_count") or 0) + 1
                b["finished"] = int(b.get("finished") or 0) + 1
                b["updated_at"] = now
                if not b.get("message"):
                    b["message"] = "reclaimed orphan sessions"
                _batches[bid] = b
                _mirror_reg_batch(bid, dict(b))
        reclaimed.append(
            {
                "id": sid,
                "batch_id": bid,
                "prev_status": st,
                "age_sec": int(age),
                "email": sess.get("email"),
            }
        )
    return {
        "ok": True,
        "reclaimed": len(reclaimed),
        "stale_sec": ttl,
        "items": reclaimed[:100],
    }


def resume_registration_batch(
    batch_id: str,
    *,
    force: bool = False,
    reclaim_stale_sec: float | None = None,
) -> dict[str, Any]:
    """Reclaim orphan sessions and resume until the success target is reached.

    Used after process restart when Redis still shows status=running but no
    worker is actually spawning jobs.
    """
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    st = str(batch.get("status") or "").strip().lower()
    if st in {"done", "cancelled", "stopped"} and not force:
        return {
            "ok": False,
            "error": f"batch already terminal ({st}); pass force=true to resume",
            "batch_id": bid,
            "status": st,
        }
    if batch.get("cancel_requested") and not force:
        return {
            "ok": False,
            "error": "batch cancel_requested; clear stop or pass force=true",
            "batch_id": bid,
        }

    # Drop dead runner lock if our process does not own it (TTL may still hold).
    if force and _reg_redis():
        try:
            from store.redis_client import get_str as redis_get

            lock_k = _batch_runner_lock_key(bid)
            token = redis_get(lock_k)
            with _lock:
                local_alive = bool(_active_batch_runners.get(bid))
            if token and not local_alive:
                try:
                    from store.redis_client import compare_and_delete

                    compare_and_delete(lock_k, str(token))
                except Exception:
                    try:
                        # last resort: overwrite with short TTL empty marker then let expire
                        from store.redis_client import set_ex

                        set_ex(lock_k, "reclaimed", 1)
                    except Exception:
                        pass
        except Exception:
            pass

    reclaimed = reclaim_orphaned_registration_sessions(
        stale_sec=reclaim_stale_sec, batch_id=bid
    )

    batch = _load_reg_batch(bid) or batch
    count = int(batch.get("count") or 0)
    finished = int(batch.get("finished") or 0)
    stored_ok = int(batch.get("ok_count") or 0)
    # Prefer durable sessions when mirrored counters lag behind a completed job.
    sids = list(batch.get("session_ids") or [])
    terminal = 0
    observed_ok = 0
    for sid in sids:
        sess = _load_reg_sess(str(sid)) or {}
        if not sess and _reg_redis():
            try:
                from store import sessions_redis

                sess = sessions_redis.reg_sess_get(str(sid)) or {}
            except Exception:
                sess = {}
        st_s = str(sess.get("status") or "").lower()
        if st_s in _TERMINAL_STATUSES:
            terminal += 1
        if st_s in {"imported", "success", "completed"}:
            observed_ok += 1
    effective_ok = max(stored_ok, observed_ok)
    finished = max(finished, terminal)
    remaining = max(0, count - effective_ok)
    if remaining <= 0:
        with _lock:
            b = _batches.get(bid) or dict(batch)
            b["status"] = "done"
            b["runner_alive"] = False
            b["ok_count"] = effective_ok
            b["finished"] = finished
            b["target_success"] = count
            b["remaining_success"] = 0
            b["updated_at"] = _now()
            b["message"] = (
                f"resume: target already reached "
                f"(success={effective_ok}/{count} attempts={finished})"
            )
            _batches[bid] = b
            _mirror_reg_batch(bid, dict(b))
        return {
            "ok": True,
            "batch_id": bid,
            "remaining": 0,
            "reclaimed": reclaimed.get("reclaimed") or 0,
            "message": "batch already complete",
            "status": (_load_reg_batch(bid) or {}).get("status"),
        }

    cfg = batch.get("reg_config") if isinstance(batch.get("reg_config"), dict) else {}
    provider = str(cfg.get("captcha_provider") or CAPTCHA_PROVIDER or "local").strip().lower()
    key = str(cfg.get("yescaptcha_key") or "").strip()
    proxy = str(cfg.get("proxy") or "").strip()
    workers = int(cfg.get("concurrency") or batch.get("concurrency") or DEFAULT_CONCURRENCY)
    # Local captcha is the bottleneck; when resuming after restart, prefer a
    # safer concurrency so multiple auto-resumed batches don't thrash Camoufox.
    if provider == "local":
        try:
            local_cap = int(os.environ.get("GROK2API_REG_LOCAL_CONCURRENCY", "3") or 3)
        except (TypeError, ValueError):
            local_cap = 3
        workers = max(1, min(workers, max(1, local_cap)))
    stagger = int(cfg.get("stagger_ms") or batch.get("stagger_ms") or 400)
    # Spread job starts a bit more under pressure.
    try:
        min_stagger = int(os.environ.get("GROK2API_REG_MIN_STAGGER_MS", "600") or 600)
    except (TypeError, ValueError):
        min_stagger = 600
    if provider == "local":
        stagger = max(stagger, min_stagger)
    mail_provider = str(cfg.get("mail_provider") or "moemail").strip().lower()
    proxy_strategy = str(cfg.get("proxy_strategy") or "round_robin").strip().lower()

    # Clear cancel so spawn is allowed.
    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = False
        b["ok_count"] = effective_ok
        b["finished"] = finished
        b["target_success"] = count
        b["remaining_success"] = remaining
        if str(b.get("status") or "").lower() in {"stopping", "cancelled", "stopped", "error"}:
            b["status"] = "running"
        b["updated_at"] = _now()
        b["message"] = (
            f"resume requested remaining_success={remaining} "
            f"(reclaimed={reclaimed.get('reclaimed') or 0})"
        )
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))

    spawned = _spawn_batch_runner(
        bid,
        remaining=remaining,
        concurrency=workers,
        stagger_ms=stagger,
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy,
        proxy_strategy=proxy_strategy,
        moemail_api_key=cfg.get("moemail_api_key"),
        moemail_base_url=cfg.get("moemail_base_url"),
        prefix=cfg.get("prefix"),
        domain=cfg.get("domain"),
        expiry_ms=cfg.get("expiry_ms"),
        mail_provider=mail_provider,
        mailbox_mode=cfg.get("mailbox_mode"),
    )
    out = {
        "ok": bool(spawned.get("ok")),
        "batch_id": bid,
        "remaining": remaining,
        "reclaimed": reclaimed.get("reclaimed") or 0,
        "reclaim": reclaimed,
        "spawn": spawned,
        "message": spawned.get("message") or spawned.get("error"),
    }
    if not out["ok"]:
        out["error"] = spawned.get("error") or "spawn failed"
    return out


def reclaim_orphaned_registration_batches(
    *,
    stale_sec: float | None = None,
    auto_resume: bool = True,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """On startup: reclaim orphan sessions and optionally resume open batches."""
    try:
        ttl = float(
            stale_sec
            if stale_sec is not None
            else (os.environ.get("GROK2API_REG_STALE_SEC", "120") or 120)
        )
    except (TypeError, ValueError):
        ttl = 120.0
    if max_batches is None:
        try:
            max_batches = int(os.environ.get("GROK2API_REG_AUTO_RESUME_MAX", "1") or 1)
        except (TypeError, ValueError):
            max_batches = 1
    max_batches = max(0, min(10, int(max_batches)))

    # First pass: mark dead in-flight sessions.
    sess_result = reclaim_orphaned_registration_sessions(stale_sec=ttl)

    batches: list[dict[str, Any]] = []
    if _reg_redis():
        try:
            from store import sessions_redis

            listed = sessions_redis.reg_batch_list() or []
            if isinstance(listed, list):
                batches = [b for b in listed if isinstance(b, dict)]
        except Exception:
            batches = []
    if not batches:
        with _lock:
            batches = [dict(v) for v in _batches.values() if isinstance(v, dict)]

    resumed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    # Newest first.
    batches = sorted(
        batches, key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0), reverse=True
    )
    for b in batches:
        if len(resumed) >= max(0, int(max_batches)):
            break
        bid = str(b.get("id") or "").strip()
        if not bid:
            continue
        st = str(b.get("status") or "").strip().lower()
        if st not in {"running", "starting", "stopping", "partial"} and not (
            st == "error" and int(b.get("ok_count") or 0) < int(b.get("count") or 0)
        ):
            continue
        if b.get("cancel_requested") and st in {"stopping", "cancelled", "stopped"}:
            skipped.append({"batch_id": bid, "reason": "cancel_requested", "status": st})
            continue
        # Skip only if THIS process has a live runner. Redis locks from a dead
        # process (image restart) must not block auto-resume forever — force
        # clear them when no local runner owns the batch.
        has_local = False
        with _lock:
            has_local = bool(_active_batch_runners.get(bid))
        if has_local:
            skipped.append({"batch_id": bid, "reason": "local_runner_alive", "status": st})
            continue
        if _reg_redis():
            try:
                from store.redis_client import get_str as redis_get

                token = redis_get(_batch_runner_lock_key(bid))
                if token:
                    # Stale lock from previous process — clear so resume can claim.
                    try:
                        from store.redis_client import compare_and_delete

                        compare_and_delete(_batch_runner_lock_key(bid), str(token))
                    except Exception:
                        try:
                            from store.redis_client import set_ex

                            set_ex(_batch_runner_lock_key(bid), "reclaimed", 1)
                        except Exception:
                            pass
            except Exception:
                pass
        count = int(b.get("count") or 0)
        ok_count = int(b.get("ok_count") or 0)
        if count > 0 and ok_count >= count:
            skipped.append({"batch_id": bid, "reason": "target_reached", "status": st})
            continue
        if not auto_resume:
            skipped.append({"batch_id": bid, "reason": "auto_resume_disabled", "status": st})
            continue
        r = resume_registration_batch(bid, force=True, reclaim_stale_sec=ttl)
        resumed.append(r)

    return {
        "ok": True,
        "sessions_reclaimed": sess_result.get("reclaimed") or 0,
        "session_reclaim": sess_result,
        "batches_resumed": sum(1 for r in resumed if r.get("ok")),
        "resumed": resumed,
        "skipped": skipped[:20],
    }


def stop_registration_session(session_id: str) -> dict[str, Any]:
    """Request cooperative cancel for one registration session."""
    sid = str(session_id or "").strip()
    if not sid:
        return {"ok": False, "error": "missing session id"}
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    st = str(sess.get("status") or "").lower()
    if st in _TERMINAL_STATUSES:
        return {
            "ok": True,
            "id": sid,
            "status": st,
            "already_terminal": True,
            "message": sess.get("message") or st,
        }
    with _lock:
        cur = _sessions.get(sid) or dict(sess)
        cur["cancel_requested"] = True
        cur["status"] = "stopping"
        cur["message"] = "stop requested; waiting for worker to exit"
        cur["updated_at"] = _now()
        _sessions[sid] = cur
        _mirror_reg_sess(sid, cur)
        out = _compact_session(cur)
    return {"ok": True, "id": sid, **out}


def stop_registration_batch(batch_id: str) -> dict[str, Any]:
    """Request cooperative cancel for every non-terminal session in a batch."""
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    # Mark batch cancelled FIRST so spawner/workers observe stop even before
    # individual session mirrors catch up (multi-worker / Redis path).
    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = True
        if str(b.get("status") or "").lower() not in (
            "done",
            "partial",
            "error",
            "cancelled",
            "stopped",
        ):
            b["status"] = "stopping"
        b["message"] = "stop requested; signalling sessions"
        b["updated_at"] = _now()
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))
        sids = list(b.get("session_ids") or [])

    stopped: list[str] = []
    already: list[str] = []
    missing: list[str] = []
    for sid in sids:
        r = stop_registration_session(str(sid))
        if not r.get("ok"):
            missing.append(str(sid))
            continue
        if r.get("already_terminal"):
            already.append(str(sid))
        else:
            stopped.append(str(sid))

    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = True
        if str(b.get("status") or "").lower() not in (
            "done",
            "partial",
            "error",
            "cancelled",
            "stopped",
        ):
            b["status"] = "stopping"
        b["message"] = (
            f"stop requested: stopping={len(stopped)} "
            f"already_done={len(already)} missing={len(missing)}"
        )
        b["updated_at"] = _now()
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))
        out = dict(b)
    return {
        "ok": True,
        "batch_id": bid,
        "stopped": stopped,
        "already_terminal": already,
        "missing": missing,
        "message": out.get("message") or "stop requested",
        "batch": out,
    }


def stop_all_active_registrations() -> dict[str, Any]:
    """Stop every non-terminal registration session currently visible."""
    listed = list_registration_sessions()
    sessions = list(listed.get("sessions") or [])
    stopped = []
    already = []
    for s in sessions:
        sid = str(s.get("id") or "")
        if not sid:
            continue
        r = stop_registration_session(sid)
        if r.get("already_terminal"):
            already.append(sid)
        elif r.get("ok"):
            stopped.append(sid)
    # Also mark running batches as stopping.
    for b in list(listed.get("batches") or []):
        bid = str(b.get("id") or b.get("batch_id") or "")
        if not bid:
            continue
        st = str(b.get("status") or b.get("batch_status") or "").lower()
        if st in ("done", "partial", "error", "cancelled", "stopped"):
            continue
        try:
            stop_registration_batch(bid)
        except Exception:
            pass
    return {
        "ok": True,
        "stopped": stopped,
        "already_terminal": already,
        "stopped_count": len(stopped),
        "already_count": len(already),
    }


def list_registration_sessions() -> dict[str, Any]:
    _clean_old_sessions()
    # Merge Redis-visible sessions/batches so other workers can observe progress.
    if _reg_redis():
        try:
            from store import sessions_redis

            for remote in sessions_redis.reg_sess_list():
                sid = str(remote.get("id") or "")
                if not sid:
                    continue
                with _lock:
                    if sid not in _sessions:
                        _sessions[sid] = remote
                    else:
                        # Prefer newer updated_at, but keep local process-only fields.
                        local = _sessions[sid]
                        if float(remote.get("updated_at") or 0) >= float(
                            local.get("updated_at") or 0
                        ):
                            merged = {**local, **remote}
                            for k, v in local.items():
                                if isinstance(k, str) and k.startswith("_") and k not in remote:
                                    merged[k] = v
                            _sessions[sid] = merged
            for remote_b in sessions_redis.reg_batch_list():
                bid = str(remote_b.get("id") or remote_b.get("batch_id") or "")
                if not bid:
                    continue
                with _lock:
                    if bid not in _batches:
                        _batches[bid] = remote_b
                    else:
                        local_b = _batches[bid]
                        if float(remote_b.get("updated_at") or 0) >= float(
                            local_b.get("updated_at") or 0
                        ):
                            # Union session_ids so late workers don't drop early ones.
                            ids = list(local_b.get("session_ids") or [])
                            for x in remote_b.get("session_ids") or []:
                                if x not in ids:
                                    ids.append(x)
                            merged_b = {**local_b, **remote_b, "session_ids": ids}
                            _batches[bid] = merged_b
        except Exception:
            pass
    with _lock:
        sessions = [_compact_session(s) for s in _sessions.values()]
        sessions.sort(
            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),
            reverse=True,
        )
        batches = []
        for b in _batches.values():
            sids = list(b.get("session_ids") or [])
            stats = _batch_stats(sids, batch=b)
            # If all observed sessions cancelled, surface batch as cancelled.
            if sids and stats.get("running") == 0 and stats.get("cancelled", 0) > 0:
                if (
                    stats.get("imported", 0) == 0
                    and stats.get("error", 0) == 0
                    and stats.get("missing", 0) == 0
                ):
                    stats["batch_status"] = "cancelled"
            item = {**b, **stats}
            # Align top-level status with computed batch_status for UI restore filters.
            bst = str(stats.get("batch_status") or "").lower()
            cur = str(b.get("status") or "").lower()
            if bst and (
                cur in ("", "running", "starting")
                or (bst in ("done", "partial", "error", "cancelled", "stopped") and stats.get("running", 0) == 0)
            ):
                if cur != "stopping" or stats.get("running", 0) == 0:
                    item["status"] = bst if bst != "running" or cur != "stopping" else cur
            batches.append(item)
        batches.sort(
            key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0),
            reverse=True,
        )
    return {
        "sessions": sessions,
        "batches": batches,
        "active": sum(
            1
            for s in sessions
            if str(s.get("status") or "").lower() not in _TERMINAL_STATUSES
        ),
    }


def get_registration_session(
    sid: str, *, include_auth_json: bool = False
) -> dict[str, Any] | None:
    sess = _load_reg_sess(sid)
    if not sess:
        return None
    out = dict(sess)
    out.pop("_client", None)
    out.pop("_oauth_client", None)
    out.pop("password", None)
    out.pop("yescaptcha_key", None)
    if not include_auth_json:
        out.pop("auth_json", None)
    return out


def _batch_stats(
    session_ids: list[str],
    *,
    batch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute success-target progress while retaining attempt counters."""
    imported = error = running = cancelled = missing = 0
    for sid in session_ids:
        sess = _load_reg_sess(sid)
        if not sess:
            missing += 1
            continue
        st = str(sess.get("status") or "").lower()
        if st in ("imported", "success", "completed"):
            imported += 1
        elif st in ("cancelled", "stopped"):
            cancelled += 1
        elif st in ("error", "failed", "probe_failed", "expired", "protocol_error", "protocol_blocked"):
            error += 1
        else:
            running += 1

    cfg = batch if isinstance(batch, dict) else {}

    def _int_field(name: str, default: int = 0) -> int:
        try:
            return int(cfg.get(name) or default)
        except (TypeError, ValueError):
            return default

    target = _int_field("count", len(session_ids))
    if target <= 0:
        target = max(1, len(session_ids))
    imported = max(imported, _int_field("ok_count"), _int_field("imported"))
    error = max(error, _int_field("fail_count"))
    cancelled = max(cancelled, _int_field("cancelled"))
    terminal_attempts = imported + error + cancelled
    finished = max(terminal_attempts, _int_field("finished"), _int_field("done"))
    attempts = max(len(session_ids), _int_field("spawned"), finished)
    stored = str(cfg.get("batch_status") or cfg.get("status") or "").lower()
    runner_alive = bool(cfg.get("runner_alive"))
    stop_requested = bool(cfg.get("cancel_requested")) or stored in {
        "stopping", "cancelled", "stopped"
    }

    if imported >= target and running == 0:
        status = "done"
    elif runner_alive and not stop_requested:
        # A failed wave can briefly leave zero live sessions before refill.
        status = "running"
    elif running:
        status = "running"
    elif stop_requested:
        status = "cancelled" if stored != "stopping" or cancelled else "stopped"
    elif stored in {"done", "partial", "error", "cancelled", "stopped"}:
        status = stored
    elif imported:
        status = "partial"
    elif error or missing:
        status = "error"
    else:
        status = "running"

    return {
        "total": target,
        "target_success": target,
        "imported": imported,
        "error": error,
        "cancelled": cancelled,
        "running": running,
        "missing": missing,
        "done": finished,
        "attempts": attempts,
        "remaining_success": max(0, target - imported),
        "batch_status": status,
    }


def get_registration_batch(batch_id: str) -> dict[str, Any] | None:
    b = _load_reg_batch(batch_id)
    if not b:
        return None
    sids = list(b.get("session_ids") or [])
    stats = _batch_stats(sids, batch=b)
    # Keep response bounded for large batches: newest sessions first for UI.
    MAX_BATCH_SESSIONS = 120
    sessions = []
    for s in sids[-MAX_BATCH_SESSIONS:]:
        sess = _load_reg_sess(s)
        if sess:
            sessions.append(_compact_session(sess))
    # Prefer recency if timestamps available.
    try:
        sessions.sort(
            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),
            reverse=True,
        )
    except Exception:
        pass
    out = {**b, **stats, "sessions": sessions}
    # Surface effective status for older UIs that only read `status`.
    if stats.get("batch_status"):
        # Don't clobber an explicit cooperative "stopping" marker while workers live.
        if str(b.get("status") or "").lower() != "stopping" or stats.get("running", 0) == 0:
            if stats.get("running", 0) == 0 or str(b.get("status") or "").lower() in (
                "",
                "running",
                "starting",
            ):
                out["status"] = stats["batch_status"]
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    print("grok-build-auth adapter for grok-register-lite")
    result = start_registration()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        return 1

    batch_id = str(result.get("batch_id") or "")
    sid = str(result.get("id") or "")
    deadline = time.time() + 600
    while time.time() < deadline:
        if batch_id:
            batch = get_registration_batch(batch_id)
            if not batch:
                print("batch disappeared", file=sys.stderr)
                return 1
            status = str(batch.get("status") or batch.get("batch_status") or "")
            print(f"[{time.strftime('%H:%M:%S')}] {status}: {batch.get('message')}")
            if status in {"done", "error", "cancelled", "stopped"}:
                print(json.dumps(batch, ensure_ascii=False, indent=2))
                return 0 if status == "done" else 1
            time.sleep(5)
            continue
        sess = get_registration_session(sid, include_auth_json=True)
        if not sess:
            print("session disappeared", file=sys.stderr)
            return 1
        status = sess.get("status")
        print(f"[{time.strftime('%H:%M:%S')}] {status}: {sess.get('message')}")
        if status in ("imported", "error"):
            print(json.dumps(sess, ensure_ascii=False, indent=2))
            return 0 if status == "imported" else 1
        time.sleep(5)

    print("timeout", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
