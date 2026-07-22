from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "turnstile-solver"))

from xai_signup_navigation import enter_xai_email_signup, is_xai_signup_url


class _FakeLocator:
    def __init__(self, page: "_FakePage") -> None:
        self.page = page

    @property
    def first(self) -> "_FakeLocator":
        return self

    async def count(self) -> int:
        self.page.locator_count_calls += 1
        if (
            self.page.choice_after_locator_counts
            and self.page.locator_count_calls >= self.page.choice_after_locator_counts
        ):
            self.page.email_choice_visible = True
        return 1 if self.page.email_choice_visible else 0

    async def click(self, timeout: int = 0) -> None:
        self.page.click_timeout = timeout
        self.page.email_choice_visible = False
        self.page.email_form_visible = True


class _FakePage:
    def __init__(
        self,
        url: str,
        *,
        email_choice_visible: bool = False,
        email_form_visible: bool = False,
        choice_after_locator_counts: int = 0,
    ) -> None:
        self.url = url
        self.email_choice_visible = email_choice_visible
        self.email_form_visible = email_form_visible
        self.choice_after_locator_counts = choice_after_locator_counts
        self.locator_count_calls = 0
        self.click_timeout = 0

    def locator(self, _selector: str) -> _FakeLocator:
        return _FakeLocator(self)


async def _evaluate(page: _FakePage, script: str):
    if "return {clicked: false}" in script:
        if not page.email_choice_visible:
            return {"clicked": False}
        page.email_choice_visible = False
        page.email_form_visible = True
        return {"clicked": True, "tag": "BUTTON", "text": "Sign up with email"}
    return {
        "email_form_visible": page.email_form_visible,
        "email_input_count": 1 if page.email_form_visible else 0,
        "email_choice_visible": page.email_choice_visible,
        "email_choice_count": 1 if page.email_choice_visible else 0,
        "headings": ["Create your account"],
    }


class XaiSignupNavigationTests(unittest.TestCase):
    def test_xai_signup_url_detection(self) -> None:
        self.assertTrue(is_xai_signup_url("https://accounts.x.ai/sign-up?redirect=cloud-console"))
        self.assertTrue(is_xai_signup_url("https://accounts.x.ai/sign-up/"))
        self.assertFalse(is_xai_signup_url("https://accounts.x.ai/sign-in"))
        self.assertFalse(is_xai_signup_url("https://example.test/sign-up"))

    def test_email_choice_is_clicked_before_solver_continues(self) -> None:
        page = _FakePage(
            "https://accounts.x.ai/sign-up?redirect=grok-com",
            email_choice_visible=True,
        )

        result = asyncio.run(enter_xai_email_signup(page, _evaluate, timeout_sec=1))

        self.assertTrue(result["ok"])
        self.assertTrue(result["required"])
        self.assertEqual(result["status"], "email_form_ready")
        self.assertEqual(result["click_strategy"], "locator")
        self.assertEqual(result["stability_samples"], 2)
        self.assertTrue(result["after"]["email_form_visible"])
        self.assertEqual(page.click_timeout, 3000)

    def test_existing_email_form_does_not_click_again(self) -> None:
        page = _FakePage(
            "https://accounts.x.ai/sign-up?redirect=grok-com",
            email_form_visible=True,
        )

        result = asyncio.run(enter_xai_email_signup(page, _evaluate, timeout_sec=0))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "already_on_email_form")
        self.assertEqual(page.click_timeout, 0)

    def test_waits_for_client_rendered_email_choice(self) -> None:
        page = _FakePage(
            "https://accounts.x.ai/sign-up?redirect=grok-com",
            choice_after_locator_counts=4,
        )

        result = asyncio.run(enter_xai_email_signup(page, _evaluate, timeout_sec=1))

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "email_form_ready")
        self.assertGreaterEqual(page.locator_count_calls, 4)

    def test_missing_email_entry_fails_instead_of_injecting_on_parent_page(self) -> None:
        page = _FakePage("https://accounts.x.ai/sign-up?redirect=grok-com")

        result = asyncio.run(enter_xai_email_signup(page, _evaluate, timeout_sec=0))

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "email_entry_not_found")

    def test_non_xai_target_keeps_generic_solver_behavior(self) -> None:
        page = _FakePage("https://example.test/challenge")

        result = asyncio.run(enter_xai_email_signup(page, _evaluate, timeout_sec=0))

        self.assertTrue(result["ok"])
        self.assertFalse(result["required"])
        self.assertEqual(result["status"], "not_required")


if __name__ == "__main__":
    unittest.main()
