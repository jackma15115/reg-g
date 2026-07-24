from __future__ import annotations

import asyncio
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

import register_lite_app
import register_lite_store


class CredentialsCsvExportTests(unittest.TestCase):
    def test_csv_response_contains_all_credentials_and_escapes_values(self) -> None:
        rows = [
            {"email": "alpha@example.test", "password": "plain"},
            {"email": "special@example.test", "password": 'comma, quote" and\nnewline'},
            {"email": "empty@example.test", "password": None},
        ]

        with patch.object(register_lite_app.lite_store, "export_account_credentials_rows", return_value=rows):
            response = asyncio.run(register_lite_app.export_credentials_csv())

        self.assertTrue(response.body.startswith(b"\xef\xbb\xbf"))
        parsed = list(csv.reader(io.StringIO(response.body.decode("utf-8-sig"), newline="")))
        self.assertEqual(
            parsed,
            [
                ["email", "passwd"],
                ["alpha@example.test", "plain"],
                ["special@example.test", 'comma, quote" and\nnewline'],
                ["empty@example.test", ""],
            ],
        )
        self.assertEqual(response.headers["content-type"], "text/csv; charset=utf-8")
        self.assertRegex(
            response.headers["content-disposition"],
            r'^attachment; filename="register-lite-accounts-\d{8}-\d{6}\.csv"$',
        )

    def test_csv_export_rejects_an_empty_account_store(self) -> None:
        with patch.object(register_lite_app.lite_store, "export_account_credentials_rows", return_value=[]):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(register_lite_app.export_credentials_csv())

        self.assertEqual(caught.exception.status_code, 404)
        self.assertEqual(caught.exception.detail, "没有可导出的账号")

    def test_store_query_has_no_status_or_page_filter(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.execute.return_value.fetchall.return_value = [
            {"email": "all@example.test", "password": "secret"}
        ]

        with (
            patch.object(register_lite_store, "init_db"),
            patch.object(register_lite_store, "_connect", return_value=connection),
        ):
            rows = register_lite_store.export_account_credentials_rows()

        self.assertEqual(rows, [{"email": "all@example.test", "password": "secret"}])
        sql = connection.execute.call_args.args[0]
        self.assertIn("SELECT email, password FROM accounts", sql)
        self.assertNotIn("WHERE", sql.upper())
        self.assertNotIn("LIMIT", sql.upper())

    def test_sso_only_account_remains_visible_and_exportable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            output_dir = data_dir / "outputs"
            connections = []
            original_connect = register_lite_store._connect

            def tracked_connect():
                connection = original_connect()
                connections.append(connection)
                return connection

            with patch.multiple(
                register_lite_store,
                DATA_DIR=data_dir,
                DB_PATH=data_dir / "register_lite.sqlite3",
                OUTPUT_DIR=output_dir,
                AUTH_MAP_DIR=output_dir / "grok2api_auth",
                CPA_DIR=output_dir / "cpa_auth",
                BACKUP_DIR=data_dir / "backups",
            ), patch.object(register_lite_store, "_connect", side_effect=tracked_connect):
                try:
                    saved = register_lite_store.import_local_credentials(
                        [
                            {
                                "email": "partial@example.test",
                                "password": "secret-password",
                                "sso": "sso-token",
                            }
                        ],
                        source="registration_auth_partial",
                    )
                    listed = register_lite_store.list_accounts(page=1, page_size=10)
                    sso_rows = register_lite_store.export_sso_rows(status=["sso_pending"])
                finally:
                    for connection in connections:
                        connection.close()

        self.assertTrue(saved["ok"])
        self.assertEqual(saved["created"], 1)
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["accounts"][0]["email"], "partial@example.test")
        self.assertEqual(listed["accounts"][0]["status"], "sso_pending")
        self.assertEqual(sso_rows[0]["email"], "partial@example.test")
        self.assertEqual(sso_rows[0]["password"], "secret-password")
        self.assertEqual(sso_rows[0]["sso"], "sso-token")


if __name__ == "__main__":
    unittest.main()
