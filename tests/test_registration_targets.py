from __future__ import annotations

import unittest
import uuid
import time
from unittest.mock import patch

import grok_build_adapter


class RegistrationTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session_ids: list[str] = []
        self.batch_ids: list[str] = []

    def tearDown(self) -> None:
        with grok_build_adapter._lock:
            for session_id in self.session_ids:
                grok_build_adapter._sessions.pop(session_id, None)
            for batch_id in self.batch_ids:
                grok_build_adapter._batches.pop(batch_id, None)
                grok_build_adapter._active_batch_runners.pop(batch_id, None)

    def _session(self, status: str) -> str:
        session_id = f"test_{uuid.uuid4().hex}"
        self.session_ids.append(session_id)
        with grok_build_adapter._lock:
            grok_build_adapter._sessions[session_id] = {
                "id": session_id,
                "status": status,
            }
        return session_id

    def test_failures_do_not_consume_success_target(self) -> None:
        session_ids = [
            self._session("imported"),
            self._session("error"),
            self._session("imported"),
            self._session("probe_failed"),
            self._session("imported"),
        ]

        stats = grok_build_adapter._batch_stats(
            session_ids,
            batch={
                "count": 3,
                "ok_count": 3,
                "fail_count": 2,
                "finished": 5,
                "spawned": 5,
                "runner_alive": False,
                "status": "done",
            },
        )

        self.assertEqual(stats["target_success"], 3)
        self.assertEqual(stats["imported"], 3)
        self.assertEqual(stats["error"], 2)
        self.assertEqual(stats["attempts"], 5)
        self.assertEqual(stats["remaining_success"], 0)
        self.assertEqual(stats["batch_status"], "done")

    def test_failed_wave_stays_running_until_target_is_met(self) -> None:
        session_ids = [
            self._session("imported"),
            self._session("error"),
            self._session("error"),
        ]

        stats = grok_build_adapter._batch_stats(
            session_ids,
            batch={
                "count": 3,
                "ok_count": 1,
                "fail_count": 2,
                "finished": 3,
                "spawned": 3,
                "runner_alive": True,
                "status": "running",
            },
        )

        self.assertEqual(stats["remaining_success"], 2)
        self.assertEqual(stats["batch_status"], "running")

    def test_runner_replenishes_failed_attempts_without_overshooting(self) -> None:
        batch_id = f"batch_test_{uuid.uuid4().hex}"
        self.batch_ids.append(batch_id)
        outcomes = iter([False, True, False, True])

        with grok_build_adapter._lock:
            grok_build_adapter._batches[batch_id] = {
                "id": batch_id,
                "status": "running",
                "count": 2,
                "target_success": 2,
                "session_ids": [],
                "finished": 0,
                "ok_count": 0,
                "fail_count": 0,
                "runner_alive": False,
                "cancel_requested": False,
            }

        def prepare(**_kwargs):
            session_id = f"test_{uuid.uuid4().hex}"
            self.session_ids.append(session_id)
            with grok_build_adapter._lock:
                grok_build_adapter._sessions[session_id] = {
                    "id": session_id,
                    "status": "queued",
                    "email": f"{session_id}@example.test",
                    "_receiver": object(),
                }
                grok_build_adapter._batches[batch_id]["session_ids"].append(session_id)
            return {"ok": True, "id": session_id}

        def run_registration(session_id, *_args):
            ok = next(outcomes)
            with grok_build_adapter._lock:
                session = grok_build_adapter._sessions[session_id]
                session["status"] = "imported" if ok else "error"
                session["error"] = None if ok else "simulated failure"

        with (
            patch.object(grok_build_adapter, "wait_for_local_solver", return_value={"ready": True}),
            patch.object(grok_build_adapter, "_prepare_registration_session", side_effect=prepare),
            patch.object(grok_build_adapter, "_run_registration", side_effect=run_registration),
        ):
            started = grok_build_adapter._spawn_batch_runner(
                batch_id,
                remaining=2,
                concurrency=2,
                stagger_ms=0,
                captcha_provider="local",
                yescaptcha_key="local",
                proxy="",
                moemail_api_key=None,
                moemail_base_url=None,
                prefix=None,
                domain=None,
                expiry_ms=None,
            )
            self.assertTrue(started["ok"])
            deadline = time.time() + 3
            while time.time() < deadline:
                with grok_build_adapter._lock:
                    if not grok_build_adapter._batches[batch_id].get("runner_alive"):
                        break
                time.sleep(0.01)

        with grok_build_adapter._lock:
            batch = dict(grok_build_adapter._batches[batch_id])
        self.assertFalse(batch["runner_alive"])
        self.assertEqual(batch["status"], "done")
        self.assertEqual(batch["ok_count"], 2)
        self.assertEqual(batch["fail_count"], 2)
        self.assertEqual(batch["finished"], 4)
        self.assertEqual(batch["spawned"], 4)


if __name__ == "__main__":
    unittest.main()
