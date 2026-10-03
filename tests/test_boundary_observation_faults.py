"""Benign observation-channel fault tests; no target services are imported."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from boundary_eval import adapter


class ObservationFaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log_path = self.root / "observations.jsonl"
        self.status_path = self.root / "status.json"
        self.key = b"synthetic-test-key-only-32-bytes!!"
        self.trial_id = "synthetic-observation-faults"
        self.publish_status(0, hashlib.sha256(b"").hexdigest())
        self.log = adapter.ObservationLog(
            self.log_path, service="target", sink=self.publish_status)

    def publish_status(self, lines, sha256):
        adapter.seal_json(self.status_path, key=self.key, name="log-status",
                          trial_id=self.trial_id,
                          payload={"lines": lines, "sha256": sha256})

    def status(self):
        return adapter.open_sealed_json(
            self.status_path, key=self.key, name="log-status",
            trial_id=self.trial_id)

    def append(self, index, log=None):
        return (log or self.log).append({
            "kind": "request", "actor": "agent", "request_id": f"r-{index}",
            "parent_request_id": None, "destination": "target",
            "resource": "public", "action": "read", "outcome": "ok",
        })

    def test_interruption_after_log_write_rejects_old_status(self):
        # The log reaches disk but the atomic status publication fails.
        with patch.object(adapter, "_fsync_replace", side_effect=OSError("test fault")):
            with self.assertRaises(OSError):
                self.append(1)
        records = adapter.read_observations(self.log_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(self.status()["lines"], 0)
        with self.assertRaises(adapter.AdapterError):
            adapter.verify_log_digest(records, **self.status())

    def test_failed_log_write_cannot_publish_a_new_status(self):
        previous = self.status_path.read_bytes()
        with patch("builtins.open", side_effect=OSError("test fault")):
            with self.assertRaises(OSError):
                self.append(1)
        self.assertEqual(self.status_path.read_bytes(), previous)
        adapter.verify_log_digest(adapter.read_observations(self.log_path),
                                  **self.status())

    def test_snapshots_from_different_times_are_rejected(self):
        self.append(1)
        first_records = adapter.read_observations(self.log_path)
        first_status = self.status()
        self.append(2)
        second_records = adapter.read_observations(self.log_path)
        second_status = self.status()
        for records, status in ((first_records, second_status),
                                (second_records, first_status)):
            with self.subTest(lines=status["lines"]):
                with self.assertRaises(adapter.AdapterError):
                    adapter.verify_log_digest(records, **status)

    def test_concurrent_appends_preserve_every_record_and_final_digest(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(self.append, range(32)))
        records = adapter.read_observations(self.log_path)
        self.assertEqual(len(records), 32)
        self.assertEqual({r["fields"]["request_id"] for r in records},
                         {f"r-{i}" for i in range(32)})
        self.assertEqual({r["fields"]["request_id"] for r in results},
                         {r["fields"]["request_id"] for r in records})
        self.assertEqual(self.status()["lines"], 32)
        adapter.verify_log_digest(records, **self.status())

    def test_restart_cannot_accept_a_reset_digest_over_existing_records(self):
        self.append(1)
        restarted = adapter.ObservationLog(
            self.log_path, service="target", sink=self.publish_status)
        self.append(2, log=restarted)
        with self.assertRaises(adapter.AdapterError):
            adapter.verify_log_digest(adapter.read_observations(self.log_path),
                                      **self.status())

    def test_authenticated_malformed_line_counts_are_rejected(self):
        for value in (False, True, 0.0, "0", None, -1, adapter.MAX_OBSERVATIONS + 1):
            with self.subTest(value=value):
                self.publish_status(value, hashlib.sha256(b"").hexdigest())
                with self.assertRaises(adapter.AdapterError):
                    adapter.verify_log_digest([], **self.status())

    def test_authenticated_malformed_digests_are_rejected(self):
        for value in (None, False, [], 0, "", "0" * 63, "G" * 64):
            with self.subTest(value=value):
                self.publish_status(0, value)
                with self.assertRaises(adapter.AdapterError):
                    adapter.verify_log_digest([], **self.status())


if __name__ == "__main__":
    unittest.main()
