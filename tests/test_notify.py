"""Offline, synthetic tests: no Telegram requests or real SERVER probe."""
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import homelab_notify as n


class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.db = n._connect(self.state)
        self.addCleanup(self.db.close)

    def test_permissions_and_symlink_are_enforced(self):
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        (self.root / "bad").symlink_to(self.state)
        with self.assertRaises(ValueError):
            n._connect(self.root / "bad")
        token = self.root / "token"
        token.write_text("synthetic")
        token.chmod(0o644)
        with self.assertRaises(ValueError):
            n._secret(token)

    def test_queue_dedup_and_no_duplicate_messages(self):
        self.assertTrue(n.enqueue(self.db, "example_1", "SERVER", "WARNING", "Disk nearly full", 100))
        self.assertFalse(n.enqueue(self.db, "example_1", "SERVER", "WARNING", "Disk nearly full", 101))
        rows = self.db.execute("SELECT * FROM outbound").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("[WARNING] SERVER", rows[0]["message"])

    def test_first_healthy_probe_silent_and_failure_threshold(self):
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", True, now=1), "unchanged")
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", False, now=2), "unchanged")
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", False, now=3), "unchanged")
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbound").fetchone()[0], 0)
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", False, now=4), "alerted")
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", False, now=5), "unchanged")
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", True, now=6), "recovered")
        self.assertEqual(n.observe_probe(self.db, "server_ssh", "AI-Server", "SERVER", True, now=7), "unchanged")
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbound").fetchone()[0], 2)

    def test_transient_failure_reset(self):
        for ok in (True, False, False, True, False, False, True):
            n.observe_probe(self.db, "peer", "SERVER", "AI-Server", ok)
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbound").fetchone()[0], 0)

    def test_probe_event_transaction_reverted_if_outbox_full(self):
        with patch.object(n, "MAX_PENDING", 0):
            for _ in range(2):
                n.observe_probe(self.db, "peer", "SERVER", "AI-Server", False)
            with self.assertRaises(RuntimeError):
                n.observe_probe(self.db, "peer", "SERVER", "AI-Server", False)
        row = self.db.execute("SELECT state,consecutive_failures FROM probes WHERE probe_id='peer'").fetchone()
        self.assertEqual((row["state"], row["consecutive_failures"]), ("unknown", 2))

    def test_claim_lease_and_telegram_retry(self):
        n.enqueue(self.db, "example_2", "SERVER", "WARNING", "Probe failed", 100)
        claimed = n._claim(self.db, 100)
        self.assertEqual(claimed["attempts"], 0)
        self.assertIsNone(n._claim(self.db, 100))
        self.assertIsNotNone(n._claim(self.db, 146))
        config = self.root / "config"
        config.mkdir(mode=0o700)
        (config / "telegram-bot-token").write_text("1234:" + "A" * 25)
        (config / "telegram-chat-id").write_text("-1001234567890")
        for entry in config.iterdir():
            entry.chmod(0o600)
        with patch.object(n, "_send", return_value=(False, 60, "http_429")):
            with patch.object(n.time, "time", return_value=200.0):
                attempted, sent = n.flush(self.db, config)
        self.assertEqual((attempted, sent), (1, 0))
        r = self.db.execute("SELECT attempts,next_attempt,lease_until,last_error FROM outbound").fetchone()
        self.assertEqual((r["attempts"], r["next_attempt"], r["lease_until"], r["last_error"]), (1, 260.0, 0, "http_429"))
        with patch.object(n, "_send", return_value=(True, 0, "")):
            with patch.object(n.time, "time", return_value=261.0):
                self.assertEqual(n.flush(self.db, config), (1, 1))

    def test_pending_limit_and_invalid_inputs(self):
        with patch.object(n, "MAX_PENDING", 1):
            n.enqueue(self.db, "a", "SERVER", "INFO", "one")
            with self.assertRaises(RuntimeError):
                n.enqueue(self.db, "b", "SERVER", "INFO", "two")
        with self.assertRaises(ValueError):
            n.enqueue(self.db, "invalid/name", "SERVER", "INFO", "message")
        with self.assertRaises(ValueError):
            n.enqueue(self.db, "good", "SERVER", "INFO", "x" * 3001)
        with self.assertRaises(ValueError):
            n.ssh_banner_ok("invalid-host", 22)

    def test_transport_never_leaks_token_through_returned_error(self):
        from urllib.error import HTTPError
        from io import BytesIO
        token = "1234:" + "X" * 25
        error = HTTPError(f"https://api.telegram.org/bot{token}/sendMessage", 429, "busy", {}, BytesIO(b'{"parameters":{"retry_after":25}}'))
        with patch.object(n.urllib.request, "urlopen", side_effect=error):
            result = n._send(token, -1001234567890, "test")
        self.assertEqual(result, (False, 25, "http_429"))
        self.assertNotIn(token, repr(result))


if __name__ == "__main__":
    unittest.main()
