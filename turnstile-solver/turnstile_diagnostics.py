from __future__ import annotations

import json
from typing import Any


def _clip(value: Any, limit: int = 320) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _event_text(items: Any, limit: int = 420) -> str:
    if not isinstance(items, list) or not items:
        return ""
    return _clip(json.dumps(items[:5], ensure_ascii=False, separators=(",", ":")), limit)


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def turnstile_error_hint(code: Any) -> str:
    text = str(code or "").strip()
    exact = {
        "110100": "invalid_sitekey",
        "110110": "invalid_sitekey",
        "110200": "unknown_domain_for_sitekey",
        "110420": "invalid_action",
        "110430": "invalid_cdata",
        "110500": "unsupported_browser",
        "110510": "inconsistent_user_agent",
        "110600": "challenge_timed_out",
        "110620": "challenge_timed_out",
        "200010": "stale_or_cached_challenge",
        "200100": "client_clock_problem",
        "400020": "stale_or_cached_challenge",
        "400030": "client_clock_problem",
        "token_expired": "token_expired",
        "widget_timeout": "widget_timeout",
        "unsupported_browser": "unsupported_browser",
    }
    if text in exact:
        return exact[text]
    prefixes = {
        "100": "turnstile_initialization_error",
        "102": "invalid_turnstile_parameters",
        "103": "invalid_turnstile_parameters",
        "104": "invalid_turnstile_parameters",
        "105": "turnstile_api_compatibility_error",
        "106": "invalid_challenge",
        "120": "turnstile_internal_error",
        "300": "client_execution_error",
        "600": "challenge_execution_failure",
    }
    for prefix, hint in prefixes.items():
        if text.startswith(prefix):
            return hint
    return "unknown_widget_error"


def classify_turnstile_failure(error: str, diagnostics: dict[str, Any] | None) -> str:
    diag = diagnostics or {}
    stage = str(diag.get("stage") or "").strip()
    widget = diag.get("widget") if isinstance(diag.get("widget"), dict) else {}
    widget_errors = widget.get("error_codes") if isinstance(widget, dict) else []

    if "browser_disconnected" in error:
        return "browser_disconnected"
    if "proxy_context_failed" in error:
        return "proxy_context_failed"
    if stage in {"browser_pool_acquire", "context_creation", "page_creation"}:
        return stage + "_failed"
    if stage == "page_navigation":
        return "target_page_navigation_failed"
    if _as_int(diag.get("main_status")) >= 400:
        return "target_page_http_error"
    if widget_errors:
        return "turnstile_widget_error"

    failures = diag.get("request_failures") if isinstance(diag.get("request_failures"), list) else []
    if any("challenges.cloudflare.com" in str(item) for item in failures):
        return "turnstile_network_failed"

    script_status = str(widget.get("script_status") or "") if isinstance(widget, dict) else ""
    render_status = str(widget.get("render_status") or "") if isinstance(widget, dict) else ""
    if script_status in {"load_failed", "missing"} or diag.get("turnstile_available") is False:
        return "turnstile_script_unavailable"
    if render_status == "render_error":
        return "turnstile_render_failed"
    token_inputs = _as_int(diag.get("token_input_count"))
    iframe_count = _as_int(diag.get("iframe_count"))
    if stage == "token_wait" and token_inputs == 0 and iframe_count == 0 and render_status != "rendered":
        return "turnstile_widget_missing"
    if stage == "token_wait":
        return "turnstile_token_timeout"
    return _clip(error, 120) or "unknown_turnstile_failure"


def format_turnstile_failure(
    error: str,
    elapsed_time: float | int | None,
    diagnostics: dict[str, Any] | None,
) -> str:
    diag = diagnostics or {}
    reason = str(diag.get("likely_reason") or "").strip() or classify_turnstile_failure(error, diag)
    parts = [f"Camoufox failed: reason={_clip(reason, 140)}"]

    stage = str(diag.get("stage") or "").strip()
    if stage:
        parts.append(f"stage={_clip(stage, 80)}")
    if isinstance(elapsed_time, (int, float)):
        parts.append(f"elapsed={float(elapsed_time):.1f}s")
    if diag.get("browser"):
        parts.append(f"browser={_clip(diag.get('browser'), 60)}")
    if diag.get("proxy") is not None:
        parts.append("proxy=" + ("yes" if diag.get("proxy") else "no"))
    if diag.get("sitekey_prefix"):
        parts.append(f"sitekey={_clip(diag.get('sitekey_prefix'), 24)}...")

    page_url = str(diag.get("page_url") or "").strip()
    if page_url:
        parts.append(f"page={_clip(page_url, 220)}")
    if diag.get("main_status") is not None:
        parts.append(f"main_http={diag.get('main_status')}")
    if diag.get("cf_ray"):
        parts.append(f"cf_ray={_clip(diag.get('cf_ray'), 120)}")
    if diag.get("cf_mitigated"):
        parts.append(f"cf_mitigated={_clip(diag.get('cf_mitigated'), 80)}")
    if diag.get("ready_state"):
        parts.append(f"ready={_clip(diag.get('ready_state'), 40)}")
    if diag.get("turnstile_available") is not None:
        parts.append("turnstile_api=" + ("yes" if diag.get("turnstile_available") else "no"))
    if diag.get("iframe_count") is not None:
        parts.append(f"iframes={diag.get('iframe_count')}")
    if diag.get("token_input_count") is not None:
        parts.append(f"token_inputs={diag.get('token_input_count')}")
    viewport = diag.get("viewport") if isinstance(diag.get("viewport"), dict) else {}
    if viewport:
        parts.append(f"viewport={viewport.get('width')}x{viewport.get('height')}")

    widget = diag.get("widget") if isinstance(diag.get("widget"), dict) else {}
    if widget:
        if widget.get("script_status"):
            parts.append(f"script={_clip(widget.get('script_status'), 60)}")
        if widget.get("render_status"):
            parts.append(f"render={_clip(widget.get('render_status'), 60)}")
        errors = _event_text(widget.get("error_codes"), 280)
        if errors:
            parts.append(f"widget_errors={errors}")
            hints = [
                f"{code}:{turnstile_error_hint(code)}"
                for code in list(widget.get("error_codes") or [])[:5]
            ]
            parts.append(f"widget_hints={_event_text(hints, 320)}")
        render_error = _clip(widget.get("render_error"), 220)
        if render_error:
            parts.append(f"render_error={render_error}")

    for key, label in (
        ("request_failures", "request_failures"),
        ("http_errors", "http_errors"),
        ("console_errors", "console_errors"),
    ):
        event_text = _event_text(diag.get(key))
        if event_text:
            parts.append(f"{label}={event_text}")

    artifact = _clip(diag.get("screenshot"), 220)
    if artifact:
        parts.append(f"screenshot={artifact}")
    raw_error = _clip(error, 360)
    if raw_error and raw_error not in reason:
        parts.append(f"error={raw_error}")
    context_error = _clip(diag.get("context_fallback_error"), 260)
    if context_error:
        parts.append(f"context_fallback_error={context_error}")

    return _clip("; ".join(parts), 1900)
