"""Synthetic local alerts: no host probes, production data, credentials or Telegram."""
import json
import os
from pathlib import Path
import tempfile
import ssl
import unittest
from unittest.mock import patch, MagicMock

import homelab_notify as n
import local_alerts as runtime
import local_policy as p
import local_sources as s


class Decisions(unittest.TestCase):
    def test_ups_only_danger_alarms_immediately(self):
        def observation(flags, runtime=1000, charge=50, low=10):
            return p.ups("ups.a", {"available": True, "ups.status": flags, "values": {
                "battery.runtime": runtime, "battery.charge": charge, "battery.charge.low": low}})
        self.assertEqual(observation(["OL"]).level, "ok")
        self.assertEqual(observation(["OB"]).level, "ok")
        self.assertEqual(observation(["OL"], runtime=100, charge=5).level, "ok")
        for flags, remaining, charge, low in ((["OB", "LB"], 1000, 50, 10), (["OB"], 300, 50, 10),
                                             (["OB"], 1000, 10, 10), (["OFF"], None, None, None),
                                             (["OVER"], None, None, None), (["FSD"], None, None, None),
                                             (["OB"], 1000, 5, None)):
            with self.subTest(flags=flags):
                o = observation(flags, remaining, charge, low)
                self.assertEqual((o.level, o.delay), ("critical", 0))
        self.assertEqual(observation(["OL", "RB"]).delay, 900)
        self.assertEqual(p.ups("ups.a", {"available": False}).code, "ups_unknown")

    def test_storage_mount_idle_and_read_only_are_distinct(self):
        limits = {"warning_bytes": 100, "critical_bytes": 20}
        self.assertEqual(p.storage("disk", {"idle": True}, limits)[0].level, "idle")
        self.assertEqual(p.storage("disk", {"mounted": False}, limits)[0].code, "mount_unavailable")
        self.assertEqual(p.storage("disk", {"mounted": True, "read_only": True}, limits)[0].level, "critical")
        for free, level in ((1000, "ok"), (50, "warning"), (10, "critical")):
            self.assertEqual(p.storage("disk", {"mounted": True, "available_bytes": free}, limits)[0].level, level)

    def test_backup_needs_trusted_success_not_process_presence(self):
        self.assertEqual(p.backup("backup", {"source_verified": True, "last_success": 1000}, 2000, 172800).level, "ok")
        self.assertEqual(p.backup("backup", {"source_verified": True, "last_success": 1000}, 200000, 172800).code, "backup_stale")
        for stamp in (None, "unverified", float("nan"), float("inf"), 9999999):
            self.assertEqual(p.backup("backup", {"source_verified": True, "last_success": stamp}, 2000, 172800).code, "backup_unverified")

    def test_https_auth_responses_are_not_application_failures(self):
        for status in (200, 302, 307, 401, 403):
            rows = p.frontend("web", {"addresses": ["127.0.0.1"], "tls_verified": True, "http_status": status}, "127.0.0.1")
            self.assertTrue(all(o.level == "ok" for o in rows))
        rows = p.frontend("web", {"addresses": ["8.8.8.8"], "tls_verified": True, "http_status": 502}, "127.0.0.1")
        self.assertTrue(all(o.level == "warning" for o in rows))

    def test_certificate_expiry_windows(self):
        self.assertEqual(p.certificate("cert", None, 1000).code, "certificate_unknown")
        self.assertEqual(p.certificate("cert", 1000 + 86400, 1000).level, "critical")
        self.assertEqual(p.certificate("cert", 1000 + 7*86400, 1000).level, "warning")
        self.assertEqual(p.certificate("cert", 1000 + 8*86400, 1000).level, "ok")

    def test_shared_frontend_outage_does_not_send_one_alert_per_name(self):
        good = {"addresses": ["127.0.0.1"], "tls_verified": True, "http_status": 200}
        both = p.frontend_group([("one.invalid", {}), ("two.invalid", {})], "127.0.0.1")
        self.assertEqual([o.key for o in both if o.level == "warning"], ["frontend.dns", "frontend.https"])
        partial = p.frontend_group([("one.invalid", {}), ("two.invalid", good)], "127.0.0.1")
        self.assertEqual([o.key for o in partial if o.level == "warning"], ["web.one.invalid.dns", "web.one.invalid.https"])
        self.assertTrue(all(o.level == "ok" for o in p.frontend_group([("one.invalid", good), ("two.invalid", good)], "127.0.0.1")))


class Sources(unittest.TestCase):
    def test_head_405_retries_get_without_following_redirect(self):
        plain = MagicMock()
        tls = MagicMock()
        tls.__enter__.return_value = tls
        tls.getpeercert.return_value = {"notAfter": "Jan 12 09:15:55 2027 GMT"}
        tls.recv.side_effect = [b"HTTP/1.1 405 Not Allowed\r\n", b"HTTP/1.1 307 Temporary Redirect\r\n"]
        context = MagicMock()
        context.wrap_socket.return_value = tls
        with patch.object(s, "command", return_value="127.0.0.1 STREAM host\n"), \
             patch.object(s.socket, "create_connection", return_value=plain) as connect, \
             patch.object(s.ssl, "create_default_context", return_value=context):
            result = s.frontend("fixture.invalid", "127.0.0.1")
        self.assertTrue(result["tls_verified"])
        self.assertEqual(result["http_status"], 307)
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(tls.sendall.call_args_list[0].args[0].startswith(b"HEAD /"))
        self.assertTrue(tls.sendall.call_args_list[1].args[0].startswith(b"GET /"))

    def test_expired_tls_is_a_known_certificate_failure(self):
        context = MagicMock()
        error = ssl.SSLCertVerificationError("expired")
        error.verify_code = 10
        context.wrap_socket.side_effect = error
        with patch.object(s, "command", return_value="127.0.0.1 STREAM host\n"), \
             patch.object(s.socket, "create_connection", return_value=MagicMock()), \
             patch.object(s.ssl, "create_default_context", return_value=context):
            result = s.frontend("fixture.invalid", "127.0.0.1")
        self.assertFalse(result["tls_verified"])
        self.assertEqual(p.certificate("cert", result["expires"], 1000).level, "critical")

    def test_readonly_systemd_credential_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credential"
            path.write_text("fixture-value")
            path.chmod(0o400)
            self.assertEqual(n._secret(path), "fixture-value")

    def test_autofs_plus_real_disk_and_sandbox_readonly(self):
        text = "20 1 0:19 / /srv/data rw - autofs systemd-1 rw\n21 20 8:2 / /srv/data rw - fuseblk /dev/sda2 rw,user_id=0\n22 21 8:2 / /srv/data ro - fuseblk /dev/sda2 rw,user_id=0\n"
        result = s.mountinfo(text, "/srv/data")
        self.assertTrue(result["mounted"])
        self.assertFalse(result["read_only"])
        self.assertEqual(result["source"], "/dev/sda2")
        self.assertTrue(s.mountinfo(text.splitlines()[0], "/srv/data")["idle"])
        self.assertFalse(s.mountinfo("", "/srv/data")["mounted"])
        self.assertEqual(s.mountinfo(text + "23 1 8:3 / /srv/data rw - ext4 /dev/sdb1 rw\n", "/srv/data")["error"], "ambiguous_mount")
        self.assertTrue(s.mountinfo("21 1 8:2 / /srv/data ro - ext4 /dev/sda2 ro\n", "/srv/data")["read_only"])

    def test_systemd_multiple_timer_entries_preserved(self):
        text = "Type=oneshot\nTimersMonotonic={ OnUnitActiveUSec=1d ; next_elapse=1d }\nTimersMonotonic={ OnBootUSec=20min ; next_elapse=20min }\n"
        with patch.object(s, "command", return_value=text):
            result = s.properties("backup.timer")
        self.assertEqual(len(result["TimersMonotonic"]), 2)
        self.assertIn("1d", result["TimersMonotonic"][0])

    def test_idle_automount_does_not_get_statvfs(self):
        with patch.object(s.Path, "read_text", return_value="20 1 0:19 / /srv/data rw - autofs systemd-1 rw\n"), patch.object(s.os, "statvfs") as statvfs:
            self.assertTrue(s.storage("/srv/data", "/dev/sda2")["idle"])
            statvfs.assert_not_called()

    def test_kernel_output_removes_private_log_text(self):
        rows = [{"MESSAGE": "I/O error dev sda PRIVATE_FILENAME", "__REALTIME_TIMESTAMP": "1000000000"},
                {"MESSAGE": "I/O error dev sdb PRIVATE_FILENAME", "__REALTIME_TIMESTAMP": "2000000000"}]
        with patch.object(s, "command", return_value="\n".join(json.dumps(r) for r in rows)):
            result = s.kernel_errors({"disk.data": ["sda"]})
        self.assertEqual(result["devices"], {"disk.data": 1000})
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_send_is_bounded_and_redirects_denied(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * 65537
        with patch.object(n, "_open", return_value=response):
            self.assertEqual(n._send("private", -1001, "test"), (False, 0, "response_limit"))
        self.assertIsNone(n._NoRedirect().redirect_request(None))
        response.read.return_value = b'{"ok":true}'
        with patch.object(n, "_open", return_value=response):
            self.assertEqual(n._send("private", -1001, "test"), (True, 0, ""))


class Incidents(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = n._connect(self.root / "state")
        self.bad = p.Observation("disk.data", "warning", "low", "места мало", "Есть риск записи.", "available=1 GiB", 300)
        self.good = p.Observation("disk.data", "ok", "good", "хранилище", "", "")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()
        os.umask(self.previous_umask)

    def observe(self, o, now):
        return p.observe(self.db, o, now, "TEST", "https://example.invalid/runbook")

    def count(self):
        return self.db.execute("SELECT count(*) FROM outbound").fetchone()[0]

    def test_healthy_and_transient_are_quiet(self):
        self.observe(self.good, 1000)
        self.observe(self.bad, 1060)
        self.observe(self.bad, 1120)
        self.observe(self.good, 1180)
        self.assertEqual(self.count(), 0)

    def test_persistent_failure_restart_and_cancel_unsent(self):
        for now in range(1000,1301,60):
            self.observe(self.bad, now)
        self.assertEqual(self.count(), 1)
        self.db.close()
        self.db = n._connect(self.root / "state")
        self.observe(self.bad, 1360)
        self.assertEqual(self.count(), 1)
        self.observe(self.good, 1420)
        self.assertEqual(self.count(), 0)
        self.observe(self.good, 1600)
        self.assertEqual(self.count(), 0)

    def test_recovery_only_after_delivery_and_stable_health(self):
        for now in range(1000,1301,60):
            self.observe(self.bad, now)
        self.db.execute("UPDATE outbound SET sent_at=1300")
        for now in (1360,1420,1480):
            self.observe(self.good, now)
        self.assertEqual(self.count(), 2)
        self.observe(self.good, 1540)
        self.assertEqual(self.count(), 2)
        self.db.execute("UPDATE outbound SET sent_at=1540 WHERE sent_at IS NULL")
        self.observe(self.good, 1600)
        self.observe(self.good, 1660)
        self.assertEqual(self.count(), 2)

    def test_recovery_cancelled_on_relapse(self):
        for now in range(1000,1301,60):
            self.observe(self.bad, now)
        self.db.execute("UPDATE outbound SET sent_at=1300")
        for now in (1360,1420,1480):
            self.observe(self.good, now)
        self.assertEqual(self.count(), 2)
        self.observe(self.bad, 1540)
        self.assertEqual(self.count(), 1)

    def test_critical_upgrade_cancels_pending_warning_and_has_priority(self):
        for now in range(1000,1301,60):
            self.observe(self.bad, now)
        critical = p.Observation("disk.data", "critical", "io", "ошибка диска", "Опасность данным.", "kernel", 0)
        self.assertEqual(self.observe(critical, 1360), "incident_queued")
        self.assertEqual(self.count(), 1)
        n.enqueue(self.db, "other_warning", "TEST", "WARNING", "other", 1)
        claimed = n._claim(self.db, 1420)
        self.assertIn("СРОЧНО", claimed["message"])

    def test_observation_gap_restarts_confirmation(self):
        self.observe(self.bad,1000)
        self.observe(self.bad,2000)
        self.assertEqual(self.count(),0)

    def test_deescalation_and_return_to_critical_do_not_spam(self):
        critical = p.Observation("disk.data", "critical", "danger", "danger", "", "", 0)
        self.observe(critical, 1000)
        self.db.execute("UPDATE outbound SET sent_at=1000")
        self.observe(self.bad, 1060)
        self.observe(critical, 1120)
        self.observe(self.bad, 1180)
        self.observe(critical, 1240)
        self.assertEqual(self.count(), 1)

    def test_reminder_is_daily_and_cancelled_if_unsent_on_recovery(self):
        critical = p.Observation("disk.data", "critical", "danger", "danger", "", "", 0)
        self.observe(critical, 1000)
        self.db.execute("UPDATE outbound SET sent_at=1000")
        self.observe(critical, 1000 + 86399)
        self.assertEqual(self.count(), 1)
        self.observe(critical, 1000 + 86400)
        self.assertEqual(self.count(), 2)
        self.observe(self.good, 1000 + 86460)
        self.assertEqual(self.count(), 1)

    def test_backup_receipt_survives_a_new_running_invocation_and_restart(self):
        config = {"ups_name": "fixture", "storage": [], "frontends": [], "kernel_devices": {},
                  "backup": {"initial_last_success": 1000, "max_age_seconds": 172800},
                  "connect_address": "127.0.0.1", "expected_dns": "127.0.0.1"}
        with patch.object(s, "nut", return_value={"available": True, "ups.status": ["OL"]}), \
             patch.object(s, "kernel_errors", return_value={"available": True, "devices": {}}), \
             patch.object(s, "backup", return_value={"source_verified": True, "last_success": 2000}):
            runtime.collect(config, self.db, 2060)
        self.db.close()
        self.db = n._connect(self.root / "state")
        with patch.object(s, "nut", return_value={"available": True, "ups.status": ["OL"]}), \
             patch.object(s, "kernel_errors", return_value={"available": True, "devices": {}}), \
             patch.object(s, "backup", return_value={"source_verified": True, "last_success": None, "active_state": "active"}):
            rows = runtime.collect(config, self.db, 2120)
        self.assertEqual(next(o for o in rows if o.key == "backup.cloud").code, "backup_fresh")
        self.assertEqual(self.db.execute("SELECT timestamp FROM local_receipts WHERE key='backup'").fetchone()[0], 2000)

    def test_kernel_fault_is_not_recovered_by_silence(self):
        fault = p.Observation("disk.data", "critical", "io", "ошибка диска", "Опасность данным.", "kernel", 0, False)
        self.observe(fault,1000)
        idle = p.Observation("disk.data", "idle", "quiet", "", "", "", recoverable=False)
        self.observe(idle,1060)
        self.assertEqual(self.count(),1)
        self.db.execute("UPDATE outbound SET sent_at=1100")
        self.observe(idle,1120)
        self.assertEqual(self.count(),1)


if __name__ == "__main__":
    unittest.main()
