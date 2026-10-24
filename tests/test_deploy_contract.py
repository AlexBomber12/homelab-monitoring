"""Read-only tests for the deployment entrypoint; no real hosts or secrets."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from validate_peer_ip import validate_peer_ip  # noqa: E402


class DeploymentContract(unittest.TestCase):
    def test_rfc1918_literals(self):
        for x in ("192.168.50.2", "192.168.50.4", "10.0.0.3", "172.31.255.254"):
            self.assertEqual(validate_peer_ip(x), x)

    def test_invalid_addresses(self):
        for x in ("8.8.8.8", "127.0.0.1", "::1", "localhost", "0.0.0.0",
                  "172.32.0.1", "192.168.50.256", "169.254.0.1"):
            with self.subTest(address=x), self.assertRaises(ValueError):
                validate_peer_ip(x)

    def test_shell_syntax_and_missing_args(self):
        script = ROOT / "deploy/deploy.sh"
        subprocess.run(["bash", "-n", str(script)], check=True)
        r = subprocess.run(["bash", str(script)], check=False, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Usage", r.stderr)

    def test_units_and_secrets_contract(self):
        code = (ROOT / "deploy/ansible/site.yml").read_text()
        for name in ("homelab-peer-ssh.service", "homelab-peer-ssh.timer",
                     "homelab-telegram-flush.service", "homelab-telegram-flush.timer"):
            self.assertIn(name, code)
            self.assertTrue((ROOT / "deploy/systemd" / name).is_file())
        self.assertIn("telegram-bot-token", code)
        self.assertIn("telegram-chat-id", code)
        self.assertIn("monitoring_activate | default(false) | bool", code)
        self.assertIn("ansible.builtin.assert", code)
        self.assertIn("mode: '0600'", code)


if __name__ == "__main__":
    unittest.main()
