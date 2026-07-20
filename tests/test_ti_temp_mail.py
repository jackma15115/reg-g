from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import MagicMock, patch

import moemail
import register_lite_store


def _response(status: int, data: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.content = b"{}"
    response.text = "{}"
    response.json.return_value = data
    return response


class TiTempMailTests(unittest.TestCase):
    def test_provider_and_mode_normalization(self) -> None:
        self.assertEqual(moemail.normalize_mail_provider("ti-temp-mail"), "ti-temp-mail")
        self.assertEqual(
            moemail.normalize_mail_provider(None, base_url="https://keldie.cyou/mailbox"),
            "ti-temp-mail",
        )
        self.assertEqual(moemail.normalize_ti_temp_mail_mode("main-domain"), "maindomain")
        self.assertEqual(moemail.normalize_ti_temp_mail_mode("sub"), "subdomain")

    def test_create_supports_both_mailbox_modes(self) -> None:
        for mode in ("maindomain", "subdomain"):
            with self.subTest(mode=mode):
                client = MagicMock()
                client.__enter__.return_value = client
                client.__exit__.return_value = False
                client.post.return_value = _response(
                    201,
                    {
                        "token": f"mailbox-token-{mode}",
                        "mailbox": f"random@{mode}.example",
                    },
                )
                with patch("moemail.httpx.Client", return_value=client):
                    box = moemail.ti_temp_mail_create_mailbox(
                        domain="mail.example",
                        api_key="create-token",
                        base_url="https://keldie.cyou/mailbox",
                        mailbox_mode=mode,
                    )

                self.assertEqual(box["provider"], "ti-temp-mail")
                self.assertEqual(box["mailbox_mode"], mode)
                self.assertEqual(box["token"], f"mailbox-token-{mode}")
                client.post.assert_called_once_with(
                    "https://keldie.cyou/mailbox",
                    json={"type": mode, "domain": "mail.example"},
                    headers={
                        "Authorization": "create-token",
                        "Content-Type": "application/json",
                    },
                )

    def test_fetch_uses_mailbox_token_and_expands_details(self) -> None:
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.get.side_effect = [
            _response(
                200,
                {
                    "mailbox": "random@example.com",
                    "messages": [
                        {
                            "_id": "message-1",
                            "receivedAt": 1746356501,
                            "from": "noreply@x.ai",
                            "subject": "Verify your email",
                            "bodyPreview": "Your code is 123456",
                            "attachmentsCount": 0,
                        }
                    ],
                },
            ),
            _response(
                200,
                {
                    "_id": "message-1",
                    "subject": "Verify your email",
                    "bodyPreview": "Your code is 123456",
                    "bodyHtml": "<p>Your code is 123456</p>",
                    "attachmentsCount": 0,
                    "attachments": [],
                },
            ),
        ]

        with patch("moemail.httpx.Client", return_value=client):
            messages = moemail.ti_temp_mail_fetch_messages(
                "random@example.com",
                base_url="https://keldie.cyou",
                address="random@example.com",
                token="mailbox-token",
            )

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["html"], "<p>Your code is 123456</p>")
        self.assertEqual(messages[0]["extracted"]["codes"], ["123456"])
        expected_headers = {"Authorization": "mailbox-token"}
        self.assertEqual(client.get.call_args_list[0].args, ("https://keldie.cyou/messages",))
        self.assertEqual(client.get.call_args_list[0].kwargs["headers"], expected_headers)
        self.assertEqual(
            client.get.call_args_list[1].args,
            ("https://keldie.cyou/messages/message-1",),
        )
        self.assertEqual(client.get.call_args_list[1].kwargs["headers"], expected_headers)

    def test_fetch_reports_detail_endpoint_failure(self) -> None:
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.get.side_effect = [
            _response(
                200,
                {
                    "messages": [
                        {
                            "_id": "message-1",
                            "subject": "Verify your email",
                            "bodyPreview": "",
                        }
                    ]
                },
            ),
            _response(502, {"error": "upstream unavailable"}),
        ]

        with patch("moemail.httpx.Client", return_value=client):
            messages = moemail.ti_temp_mail_fetch_messages(
                "random@example.com",
                token="mailbox-token",
            )

        self.assertEqual(len(messages), 1)
        self.assertIn("HTTP 502", messages[0]["_detail_error"])

    def test_registration_config_keeps_provider_specific_slots(self) -> None:
        cfg = register_lite_store.normalize_registration_config(
            {
                "mail_provider": "ti-temp-mail",
                "base_url": "https://keldie.cyou",
                "api_key": "create-token",
                "domain": "mail.example",
                "mailbox_mode": "subdomain",
            }
        )
        self.assertEqual(cfg["mail_provider"], "ti-temp-mail")
        self.assertEqual(cfg["ti_temp_mail_base_url"], "https://keldie.cyou")
        self.assertEqual(cfg["ti_temp_mail_api_key"], "create-token")
        self.assertEqual(cfg["ti_temp_mail_domain"], "mail.example")
        self.assertEqual(cfg["ti_temp_mail_mode"], "subdomain")
        self.assertEqual(cfg["mailbox_mode"], "subdomain")

    def test_adapter_does_not_reuse_moemail_credentials(self) -> None:
        import grok_build_adapter
        import register_lite_config

        mailbox = {
            "id": "random@sub.ticloud.tech",
            "email": "random@sub.ticloud.tech",
            "token": "mailbox-token",
        }
        with (
            patch.object(register_lite_config, "MOEMAIL_API_KEY", "moemail-secret"),
            patch.object(register_lite_config, "MOEMAIL_BASE_URL", "https://moemail.invalid"),
            patch("moemail.create_mailbox", return_value=mailbox) as create,
        ):
            address, receiver = grok_build_adapter._make_email_receiver(
                mail_provider="ti-temp-mail",
                mailbox_mode="subdomain",
            )

        self.assertEqual(address, "random@sub.ticloud.tech")
        self.assertEqual(receiver.base_url, "https://keldie.cyou")
        self.assertIsNone(create.call_args.kwargs["api_key"])
        self.assertIsNone(create.call_args.kwargs["base_url"])
        self.assertEqual(create.call_args.kwargs["mailbox_mode"], "subdomain")

    def test_adapter_emits_ti_mail_poll_progress_without_tokens(self) -> None:
        import grok_build_adapter

        mailbox = {
            "id": "random@sub.ticloud.tech",
            "email": "random@sub.ticloud.tech",
            "token": "mailbox-token-secret",
            "mailbox_mode": "subdomain",
        }
        progress: list[str] = []
        stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            patch("moemail.create_mailbox", return_value=mailbox),
            patch(
                "moemail.fetch_messages",
                side_effect=[
                    RuntimeError("HTTP 502: temporary upstream error"),
                    [],
                    [
                        {
                            "id": "message-1",
                            "subject": "Your x.ai code ABC-123",
                            "content": "Your x.ai code ABC-123",
                        }
                    ],
                ],
            ),
            patch("grok_build_adapter.time.sleep", return_value=None),
        ):
            _, receiver = grok_build_adapter._make_email_receiver(
                mail_provider="ti-temp-mail",
                mailbox_mode="subdomain",
            )
            code = receiver.wait_for_code(
                timeout=5,
                poll_interval=0.4,
                on_progress=progress.append,
            )

        output = stdout.getvalue()
        self.assertEqual(code, "ABC123")
        self.assertTrue(any("轮询 #1 异常" in item for item in progress))
        self.assertTrue(any("接口已恢复" in item for item in progress))
        self.assertTrue(any("找到验证码" in item for item in progress))
        self.assertIn("[ti-temp-mail]", output)
        self.assertNotIn("mailbox-token-secret", output)


if __name__ == "__main__":
    unittest.main()
