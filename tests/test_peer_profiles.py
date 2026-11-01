"""Peer deployment contracts, missing-source honesty and encrypted enrollment fixtures."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import homelab_notify as outbox
import local_alerts as runtime
import local_policy as policy
import local_sources as sources

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy = load("peer_deployer", "deploy/install_local.py")
export = load("peer_export", "deploy/export_local_credentials.py")


class PeerProfiles(unittest.TestCase):
    def test_missing_ups_and_backup_are_idle_without_source_calls(self):
        previous = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory:
                with outbox._connect(Path(directory) / "state") as db, patch.object(sources, "nut") as nut, \
                     patch.object(sources, "backup") as backup, patch.object(sources, "kernel_errors", return_value={"available": True, "devices": {}}):
                    rows = runtime.collect({"ups_name": None, "backup": None, "storage": [], "frontends": [], "kernel_devices": {},
                                            "expected_dns": "127.0.0.1", "connect_address": "127.0.0.1"}, db, 1000)
                nut.assert_not_called()
                backup.assert_not_called()
                self.assertIn(("idle", "ups_not_configured"), [(o.level, o.code) for o in rows])
                self.assertIn(("idle", "backup_not_configured"), [(o.level, o.code) for o in rows])
        finally:
            os.umask(previous)

    def test_remote_mount_only_never_attempts_network_filesystem_stat(self):
        text = "42 1 0:61 / /srv/remote rw - cifs //fixture/share rw\n"
        with patch.object(sources.Path, "read_text", return_value=text), patch.object(sources.os, "statvfs") as stat:
            data = sources.storage("/srv/remote", "//fixture/share", check_capacity=False)
            rows = policy.storage("remote", data, {"mount_only": True})
            self.assertEqual(rows[0].code, "mount_present")
            stat.assert_not_called()
        data["read_only"] = True
        self.assertEqual(policy.storage("remote", data, {"mount_only": True})[0].level, "critical")

    def test_known_warning_does_not_allow_critical_or_other_source_faults(self):
        import time
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            data = {"collector_ok": True, "observed_at": time.time(), "machine_heartbeat_enabled": False,
                    "credentials_validated": True, "pending_events": 0,
                    "observations": [{"key": "ups.primary", "level": "warning", "code": "ups_unknown"}]}
            def save():
                path.write_text(json.dumps(data))
                path.chmod(0o644)
            save()
            with self.assertRaisesRegex(RuntimeError, "baseline_findings"):
                deploy.validate_status(path, os.geteuid())
            allowed = {"ups.primary": ["ups_unknown"]}
            deploy.validate_status(path, os.geteuid(), allowed)
            for key, level, code in (("ups.primary", "critical", "ups_unknown"), ("storage.system", "warning", "space_low")):
                data["observations"] = [{"key": key, "level": level, "code": code}]
                save()
                with self.assertRaisesRegex(RuntimeError, "baseline_findings"):
                    deploy.validate_status(path, os.geteuid(), allowed)

    def test_dispatcher_extension_keeps_legacy_and_maintenance_text(self):
        for profile, caps in (("ai_workspace", 'CAPABILITIES=("agent.capabilities", "workspace.info", "service.restart.fixture")'),
                              ("spark_workspace", 'CAPABILITIES={"operations": ["agent.capabilities", "workspace.info", "workspace.request"],}')):
            text = ('import os\nENV={"PATH":"/usr/bin:/bin"}\n' + caps + '\ndef main(request):\n'
                    '    if request in ("workspace.info", "workspace.request"):\n        return "workspace"\n'
                    '    if request == "service.restart.fixture":\n        return "existing-maintenance"\n'
                    '    return "legacy-denial"\n').encode()
            updated = deploy.extend_dispatcher(text, profile)
            namespace = {}
            exec(compile(updated, "fixture_dispatcher", "exec"), namespace)
            self.assertEqual(namespace["main"]("service.restart.fixture"), "existing-maintenance")
            self.assertEqual(namespace["main"]("diagnostics.important_alerts extra"), "legacy-denial")
            self.assertEqual(namespace["main"]("workspace.request"), "workspace")
            with patch.object(os, "execve", side_effect=InterruptedError) as execute:
                with self.assertRaises(InterruptedError):
                    namespace["main"]("diagnostics.important_alerts")
                self.assertEqual(execute.call_args.args[1], ["/usr/bin/python3", "-I", "/usr/local/libexec/sg-important-alerts-status.py"])
            with self.assertRaisesRegex(RuntimeError, "diagnostic_already_present"):
                deploy.extend_dispatcher(updated, profile)

    def test_export_never_handles_private_recipient_key(self):
        data = {"public_key_base64": base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nfixture").decode(), "public_key_sha256": "0"*64}
        with patch.object(export, "encrypt") as encrypt:
            with self.assertRaisesRegex(RuntimeError, "public_key_mismatch"):
                export.make_envelopes({"fixture": data}, "123:" + "X"*25, "-100123")
            encrypt.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, "Disposable root-owned recipient integration fixture")
    def test_real_oaep_envelope_decrypts_only_for_the_reviewed_host_and_key(self):
        previous = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                recipient = root / "recipient"
                recipient.mkdir(mode=0o700)
                key = recipient / "recipient.pem"
                subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key)], capture_output=True, check=True)
                key.chmod(0o600)
                public = subprocess.check_output(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout"])
                fingerprint = hashlib.sha256(public).hexdigest()
                token, chat = "123:" + "X"*25, "-100123"
                envelopes = export.make_envelopes({"fixture": {"public_key_base64": base64.b64encode(public).decode(), "public_key_sha256": fingerprint}}, token, chat)
                self.assertNotIn(token, json.dumps(envelopes))
                payload = {"hostname": "fixture", "recipient_public_key_sha256": fingerprint, "credential_envelope": envelopes["fixture"]}
                real_path = Path
                def mapped(value):
                    return recipient if str(value) == "/var/lib/homelab-alerts-onboarding" else real_path(value)
                with patch.object(deploy, "Path", side_effect=mapped), patch.object(deploy, "telegram_read", side_effect=[
                    {"id": 123}, {"type": "channel"}, {"status": "administrator", "can_post_messages": True}]) as api:
                    self.assertEqual(deploy.credentials_from_envelope(payload), (token.encode(), chat.encode()))
                    self.assertEqual([c.args[1] for c in api.call_args_list], ["getMe", "getChat", "getChatMember"])
                payload["hostname"] = "different"
                with self.assertRaisesRegex(RuntimeError, "envelope_target_mismatch"):
                    deploy.credentials_from_envelope(payload)
        finally:
            os.umask(previous)


if __name__ == "__main__":
    unittest.main()
