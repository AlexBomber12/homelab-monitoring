"""Real Linux ACL fixtures; no host credentials or Telegram requests."""
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import homelab_notify as n
import local_alerts as runtime
import local_policy as policy


def acl(uid, *, group=0, other=0, named=4, mask=4, extra=None):
    entries = [(1, 4, 0xffffffff), (2, named, uid)]
    if extra is not None:
        entries.append((2, 4, extra))
    entries += [(4, group, 0xffffffff), (16, mask, 0xffffffff), (32, other, 0xffffffff)]
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


class CredentialTests(unittest.TestCase):
    def test_actual_acl_mask_is_not_group_read_permission(self):
        with tempfile.TemporaryFile() as stream:
            os.setxattr(stream.fileno(), "system.posix_acl_access", acl(os.geteuid()))
            self.assertEqual(stat.S_IMODE(os.fstat(stream.fileno()).st_mode), 0o440)
            self.assertTrue(n._systemd_read_acl(stream.fileno(), os.geteuid()))
            for data in (acl(os.geteuid(), group=4), acl(os.geteuid(), other=4),
                         acl(os.geteuid(), named=6, mask=6), acl(os.geteuid()+1),
                         acl(os.geteuid(), extra=os.geteuid()+1), b"bad", acl(os.geteuid()) + b"extra"):
                with self.subTest(data=data), patch.object(n.os, "getxattr", return_value=data):
                    self.assertFalse(n._systemd_read_acl(stream.fileno(), os.geteuid()))

    def test_single_fd_reader_supports_root_acl_but_not_group_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_text("fixture-only")
            os.setxattr(path, "system.posix_acl_access", acl(os.geteuid()))
            real = os.stat(path)
            metadata = SimpleNamespace(st_uid=0, st_mode=real.st_mode, st_nlink=1, st_size=real.st_size)
            with patch.object(n.os, "fstat", return_value=metadata):
                self.assertEqual(n._secret(path), "fixture-only")
                with patch.object(n.os, "getxattr", return_value=acl(os.geteuid(), group=4)):
                    with self.assertRaisesRegex(n.CredentialError, "credential_not_private"):
                        n._secret(path)

    def test_secret_swap_after_open_does_not_replace_checked_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_text("checked-data")
            path.chmod(0o600)
            other = path.with_name("other")
            other.write_text("untrusted-replacement")
            real_fstat = n.os.fstat
            def swap(fd):
                before = real_fstat(fd)
                os.replace(other, path)
                return before
            with patch.object(n.os, "fstat", side_effect=swap):
                self.assertEqual(n._secret(path), "checked-data")

    def test_probe_validates_credentials_and_never_flushes_even_with_pending_event(self):
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                status = root / "status"
                status.mkdir()
                creds = root / "credentials"
                creds.mkdir(mode=0o700)
                for name, value in (("telegram-bot-token", "123:" + "X"*25), ("telegram-chat-id", "-100123")):
                    path = creds / name
                    path.write_text(value)
                    path.chmod(0o400)
                fault = policy.Observation("fixture", "critical", "fault", "fixture", "", "", 0)
                with patch.object(runtime, "collect", return_value=[fault]), patch.object(n, "flush") as flush:
                    data = runtime.run({"origin": "TEST", "runbook": "https://example.invalid"}, root / "state", status, creds, no_send=True)
                    self.assertEqual(data["pending_events"], 1)
                    self.assertTrue(data["credentials_validated"])
                    self.assertFalse(data["sending_enabled"])
                    flush.assert_not_called()
                token = creds / "telegram-bot-token"
                token.chmod(0o644)
                with patch.object(runtime, "collect") as collect, patch.object(n, "flush") as flush:
                    with self.assertRaises(n.CredentialError):
                        runtime.run({}, root / "state", status, creds, no_send=True)
                    collect.assert_not_called()
                    flush.assert_not_called()
        finally:
            os.umask(previous_umask)

    @unittest.skipUnless(os.geteuid() == 0, "Supplemental root-to-service-UID integration fixture")
    def test_real_root_owned_acl_read_by_different_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            module = root / "homelab_notify.py"
            shutil.copyfile(Path(n.__file__), module)
            module.chmod(0o644)
            path = root / "fixture"
            path.write_text("fixture-only")
            os.setxattr(path, "system.posix_acl_access", acl(65534))
            code = "import sys;sys.path.insert(0,sys.argv[1]);from pathlib import Path;import homelab_notify as n;assert n._secret(Path(sys.argv[2]))=='fixture-only'"
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root), str(path)],
                                    user=65534, group=65534, extra_groups=[], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
