from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse


EvaluatePage = Callable[[Any, str], Awaitable[Any]]


def is_xai_signup_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url or ""))
    except Exception:
        return False
    return (parsed.hostname or "").lower() == "accounts.x.ai" and parsed.path.rstrip("/") == "/sign-up"


async def _email_signup_state(page: Any, evaluate_page: EvaluatePage) -> dict[str, Any]:
    state = await evaluate_page(
        page,
        """() => {
            const visible = (el) => Boolean(
                el && (el.getClientRects().length || el.offsetWidth || el.offsetHeight)
            );
            const emailInputs = Array.from(document.querySelectorAll([
                'input[type="email"]',
                'input[name="email"]',
                'input[autocomplete="email"]',
                'input[id*="email" i]'
            ].join(',')));
            const choices = Array.from(document.querySelectorAll('button,a,[role="button"]'))
                .filter((el) => {
                    const text = String(el.innerText || el.textContent || '').trim().toLowerCase();
                    return visible(el) && (
                        text.includes('sign up with email') ||
                        text.includes('continue with email') ||
                        text.includes('register with email') ||
                        text.includes('use email') ||
                        text.includes('使用邮箱') ||
                        text.includes('使用郵箱')
                    );
                });
            return {
                email_form_visible: emailInputs.some(visible),
                email_input_count: emailInputs.length,
                email_choice_visible: choices.length > 0,
                email_choice_count: choices.length,
                headings: Array.from(document.querySelectorAll('h1,h2'))
                    .filter(visible)
                    .map((el) => String(el.innerText || el.textContent || '').trim())
                    .filter(Boolean)
                    .slice(0, 4)
            };
        }""",
    )
    result = dict(state) if isinstance(state, dict) else {}
    try:
        result["url"] = str(page.url or "")
    except Exception:
        result["url"] = ""
    return result


async def enter_xai_email_signup(
    page: Any,
    evaluate_page: EvaluatePage,
    *,
    timeout_sec: float = 15.0,
) -> dict[str, Any]:
    """Enter x.ai's email sign-up child view before injecting Turnstile."""
    page_url = str(getattr(page, "url", "") or "")
    if not is_xai_signup_url(page_url):
        return {"ok": True, "required": False, "status": "not_required", "url": page_url}

    try:
        before = await _email_signup_state(page, evaluate_page)
    except Exception as exc:
        return {
            "ok": False,
            "required": True,
            "status": "initial_state_failed",
            "error": f"{type(exc).__name__}: {exc}"[:300],
            "url": page_url,
        }
    loop = asyncio.get_running_loop()
    entry_deadline = loop.time() + max(0.0, float(timeout_sec))
    click_strategy = ""
    click_errors: list[str] = []
    selectors = (
        'button:has-text("Sign up with email"),a:has-text("Sign up with email"),[role="button"]:has-text("Sign up with email")',
        'button:has-text("Continue with email"),a:has-text("Continue with email"),[role="button"]:has-text("Continue with email")',
        'button:has-text("email"),a:has-text("email"),[role="button"]:has-text("email")',
    )
    while not click_strategy:
        if before.get("email_form_visible"):
            return {
                "ok": True,
                "required": True,
                "status": "already_on_email_form",
                "before": before,
                "after": before,
            }

        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() <= 0:
                    continue
                await locator.click(timeout=3000)
                click_strategy = "locator"
                break
            except Exception as exc:
                click_errors.append(f"locator: {type(exc).__name__}: {exc}"[:240])

        if not click_strategy:
            try:
                clicked = await evaluate_page(
                    page,
                    """() => {
                        const visible = (el) => Boolean(
                            el && (el.getClientRects().length || el.offsetWidth || el.offsetHeight)
                        );
                        const candidates = Array.from(document.querySelectorAll('button,a,[role="button"]'));
                        const target = candidates.find((el) => {
                            const text = String(el.innerText || el.textContent || '').trim().toLowerCase();
                            const mentionsEmail = text.includes('email') || text.includes('邮箱') || text.includes('郵箱');
                            const isSignup = text.includes('sign up') || text.includes('continue') ||
                                text.includes('register') || text.includes('use ') || text.includes('使用');
                            return visible(el) && mentionsEmail && isSignup;
                        });
                        if (!target) return {clicked: false};
                        const text = String(target.innerText || target.textContent || '').trim().slice(0, 120);
                        target.click();
                        return {clicked: true, tag: target.tagName, text};
                    }""",
                )
                if isinstance(clicked, dict) and clicked.get("clicked"):
                    click_strategy = "main_world"
            except Exception as exc:
                click_errors.append(f"main_world: {type(exc).__name__}: {exc}"[:240])

        if click_strategy or loop.time() >= entry_deadline:
            break
        await asyncio.sleep(0.25)
        try:
            before = await _email_signup_state(page, evaluate_page)
        except Exception as exc:
            click_errors.append(f"entry_state: {type(exc).__name__}: {exc}"[:240])

    if not click_strategy:
        return {
            "ok": False,
            "required": True,
            "status": "email_entry_not_found",
            "before": before,
            "click_errors": click_errors[-4:],
        }

    deadline = loop.time() + max(0.0, float(timeout_sec))
    after: dict[str, Any] = {}
    ready_samples = 0
    while True:
        try:
            after = await _email_signup_state(page, evaluate_page)
            if after.get("email_form_visible"):
                ready_samples += 1
                if ready_samples >= 2:
                    return {
                        "ok": True,
                        "required": True,
                        "status": "email_form_ready",
                        "click_strategy": click_strategy,
                        "stability_samples": ready_samples,
                        "before": before,
                        "after": after,
                        "click_errors": click_errors[-4:],
                    }
            else:
                ready_samples = 0
        except Exception as exc:
            click_errors.append(f"post_click_state: {type(exc).__name__}: {exc}"[:240])
            ready_samples = 0
        if loop.time() >= deadline:
            break
        await asyncio.sleep(0.25)

    return {
        "ok": False,
        "required": True,
        "status": "email_form_not_ready",
        "click_strategy": click_strategy,
        "stability_samples": ready_samples,
        "before": before,
        "after": after,
        "click_errors": click_errors[-4:],
    }
