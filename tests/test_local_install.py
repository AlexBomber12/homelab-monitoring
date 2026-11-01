"""Owner deployment safety with disposable files and mocked system/API calls only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_local", ROOT / "deploy/install_local.py")
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class InstallTests(unittest.TestCase):
    def test_credentials_only_from_existing_separate_infra_destination(self):
        token = "123:" + "X" * 25
        env = ["TELEGRAM_BOT_TOKEN=" + token, "TELEGRAM_CHAT_ID=private-sms", "HEARTBEAT_TELEGRAM_CHAT_ID=-10012345"]
        with patch.object(deploy, "command", return_value=json.dumps(env).encode()), patch.object(deploy, "telegram_read", side_effect=[
            {"id": 123}, {"type": "channel"}, {"status": "administrator", "can_post_messages": True}]) as api:
            result = deploy.credentials_from_existing_infra_sender("sms-gateway-v2")
        self.assertEqual(result, (token.encode(), b"-10012345"))
        self.assertEqual([c.args[1] for c in api.call_args_list], ["getMe", "getChat", "getChatMember"])
        with self.assertRaisesRegex(RuntimeError, "unexpected_credential_source"):
            deploy.credentials_from_existing_infra_sender("other-container")

    def test_never_falls_back_to_private_sms_chat(self):
        env = ["TELEGRAM_BOT_TOKEN=123:" + "X" * 25, "TELEGRAM_CHAT_ID=-100999"]
        with patch.object(deploy, "command", return_value=json.dumps(env).encode()), patch.object(deploy, "telegram_read") as api:
            with self.assertRaisesRegex(RuntimeError, "separate_infra_destination"):
                deploy.credentials_from_existing_infra_sender("sms-gateway-v2")
            api.assert_not_called()

    def test_telegram_installer_cannot_send_test_or_mutating_requests(self):
        for method in ("sendMessage", "setWebhook", "deleteMessage"):
            with self.assertRaisesRegex(RuntimeError, "read_api_method"):
                deploy.telegram_read("fixture", method, {})

    def test_target_set_guard_precedes_file_changes(self):
        with patch.object(deploy.os, "geteuid", return_value=0), patch.object(deploy.socket, "gethostname", return_value="fixture"), patch.object(deploy, "private_write") as write:
            with self.assertRaisesRegex(RuntimeError, "managed_target_set"):
                deploy.install({"hostname": "fixture", "files": {"/etc/ssh/sshd_config": "malicious"}})
            write.assert_not_called()

    def test_real_filesystem_rollback_keeps_state_and_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "backup"
            backup.mkdir()
            config = root / "config"
            config.mkdir(mode=0o700)
            state = root / "state"
            state.write_bytes(b"LATEST OUTBOX DATA")
            role = root / "dispatcher.py"
            role.write_bytes(b"new-role")
            owned = root / "installed.py"
            owned.write_bytes(b"owned-code")
            untouched = root / "unrelated.py"
            untouched.write_bytes(b"preserve")
            (backup / "dispatcher.before").write_bytes(b"old-role")
            metadata = {"role_before": hashlib.sha256(b"old-role").hexdigest(), "role_after": hashlib.sha256(b"new-role").hexdigest(),
                        "installed_files": {str(owned): hashlib.sha256(b"owned-code").hexdigest()}}
            (backup / "transaction.json").write_text(json.dumps(metadata))
            with patch.object(deploy, "ROLE", role), patch.object(deploy, "CONFIG", config), \
                 patch.object(deploy, "command") as command, patch.object(deploy.subprocess, "run") as subprocess_run, \
                 patch.object(deploy.os, "fchown"):
                deploy.rollback(backup)
            self.assertEqual(role.read_bytes(), b"old-role")
            self.assertFalse(owned.exists())
            self.assertEqual(untouched.read_bytes(), b"preserve")
            self.assertEqual(state.read_bytes(), b"LATEST OUTBOX DATA")
            self.assertEqual(json.loads((config / "rollback-receipt.json").read_bytes())["status"], "rolled_back")
            self.assertTrue(all("homelab-local-alerts" in " ".join(c.args[0]) for c in subprocess_run.call_args_list))

    def test_unit_hardening_and_no_peer_activation(self):
        unit = (ROOT / "deploy/systemd/homelab-local-alerts.service").read_text()
        self.assertIn("User=homelab-alerts", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("LoadCredential=telegram-bot-token:", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertNotIn("TELEGRAM_BOT_TOKEN=", unit)
        self.assertNotIn("probe-ssh", unit)
        self.assertNotIn("homelab-peer-ssh", (ROOT / "deploy/install_local.py").read_text())


if __name__ == "__main__":
    unittest.main()
