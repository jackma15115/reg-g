from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "turnstile-solver"))
sys.path.insert(0, str(ROOT / "grok-build-auth"))

import grok_build_adapter
from turnstile_diagnostics import (
    classify_turnstile_failure,
    format_turnstile_failure,
    turnstile_error_hint,
)
from xconsole_client.solver import _solver_error_detail


class TurnstileDiagnosticTests(unittest.TestCase):
    def test_widget_error_is_classified_and_rendered(self) -> None:
        diagnostics = {
            "stage": "token_wait",
            "page_url": "https://accounts.x.ai/sign-up?redirect=grok-com",
            "main_status": 200,
            "ready_state": "complete",
            "turnstile_available": True,
            "iframe_count": 1,
            "token_input_count": 1,
            "widget": {
                "script_status": "loaded",
                "render_status": "rendered",
                "error_codes": ["110200"],
            },
        }

        reason = classify_turnstile_failure("timeout_waiting_for_token", diagnostics)
        rendered = format_turnstile_failure("timeout_waiting_for_token", 24.25, diagnostics)

        self.assertEqual(reason, "turnstile_widget_error")
        self.assertIn("reason=turnstile_widget_error", rendered)
        self.assertIn("stage=token_wait", rendered)
        self.assertIn("main_http=200", rendered)
        self.assertIn("widget_errors=[\"110200\"]", rendered)
        self.assertIn("unknown_domain_for_sitekey", rendered)
        self.assertEqual(turnstile_error_hint("110510"), "inconsistent_user_agent")

    def test_cloudflare_request_failure_takes_priority_over_missing_script(self) -> None:
        diagnostics = {
            "stage": "token_wait",
            "turnstile_available": False,
            "iframe_count": 0,
            "request_failures": [
                {
                    "url": "https://challenges.cloudflare.com/turnstile/v0/api.js",
                    "failure": "net::ERR_CONNECTION_RESET",
                }
            ],
            "widget": {"script_status": "load_failed", "error_codes": []},
        }

        self.assertEqual(
            classify_turnstile_failure("timeout_waiting_for_token", diagnostics),
            "turnstile_network_failed",
        )

    def test_solver_client_preserves_structured_diagnostics(self) -> None:
        detail = _solver_error_detail(
            {
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Workers could not solve the Captcha",
                "diagnostics": {
                    "stage": "page_navigation",
                    "likely_reason": "target_page_navigation_failed",
                },
            }
        )

        self.assertIn("ERROR_CAPTCHA_UNSOLVABLE", detail)
        self.assertIn("target_page_navigation_failed", detail)

    def test_captcha_failure_does_not_attach_protocol_last_request(self) -> None:
        client = type(
            "Client",
            (),
            {
                "last_request": {
                    "phase": "GET /_next/static/chunks/example.js",
                    "url": "https://accounts.x.ai/_next/static/chunks/example.js",
                    "elapsed_sec": 0.1,
                }
            },
        )()

        detail, request_diag = grok_build_adapter._registration_failure_detail(
            RuntimeError("Camoufox failed: reason=turnstile_script_unavailable"),
            client,
        )

        self.assertNotIn("last_request", detail)
        self.assertIsNone(request_diag)

    def test_transport_failure_keeps_protocol_last_request(self) -> None:
        client = type(
            "Client",
            (),
            {
                "last_request": {
                    "phase": "POST CreateUser",
                    "url": "https://accounts.x.ai/rpc/CreateUser",
                    "elapsed_sec": 30.0,
                }
            },
        )()

        detail, request_diag = grok_build_adapter._registration_failure_detail(
            RuntimeError("curl operation timed out"),
            client,
        )

        self.assertIn("last_request=POST CreateUser", detail)
        self.assertEqual(request_diag["elapsed_sec"], 30.0)


if __name__ == "__main__":
    unittest.main()
