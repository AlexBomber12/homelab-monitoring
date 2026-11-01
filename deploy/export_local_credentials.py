"""Owner-only encrypted enrollment export; no plaintext credential leaves the owner process."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import uuid

ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def secret(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not (stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size <= 4096):
            raise RuntimeError("source_credential_metadata")
        value = stream.read(4097)
    if len(value) > 4096:
        raise RuntimeError("source_credential_size")
    return value.decode().strip()


def encrypt(public, plaintext):
    # A temporary file contains the public key only. Plaintext is passed through stdin.
    with tempfile.TemporaryDirectory(prefix="homelab-envelope-") as directory:
        path = Path(directory) / "recipient-public.pem"
        path.write_bytes(public)
        result = subprocess.run(["/usr/bin/openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(path),
                                 "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                                 "-pkeyopt", "rsa_mgf1_md:sha256"], input=plaintext, capture_output=True, env=ENV, timeout=10)
    if result.returncode or len(result.stdout) != 384:
        raise RuntimeError("recipient_encryption_failed")
    return result.stdout


def make_envelopes(recipients, token, chat):
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token) or not re.fullmatch(r"-100[0-9]+", chat):
        raise RuntimeError("source_credential_format")
    result = {}
    for hostname, item in recipients.items():
        if not re.fullmatch(r"[a-z0-9-]{1,64}", hostname):
            raise RuntimeError("recipient_hostname")
        public = base64.b64decode(item["public_key_base64"], validate=True)
        if not public.startswith(b"-----BEGIN PUBLIC KEY-----") or b"PRIVATE" in public or hashlib.sha256(public).hexdigest() != item["public_key_sha256"]:
            raise RuntimeError("recipient_public_key_mismatch")
        plaintext = json.dumps({"v": 1, "host": hostname, "token": token, "chat": chat}, separators=(",", ":")).encode()
        if len(plaintext) > 318:
            raise RuntimeError("credential_envelope_size")
        encrypted = encrypt(public, plaintext)
        result[hostname] = {"host": hostname, "recipient_public_key_sha256": item["public_key_sha256"],
                            "ciphertext_base64": base64.b64encode(encrypted).decode(), "method": "RSA-OAEP-SHA256"}
    return result


def main():
    payload = globals()["EXPORT_PAYLOAD"]
    if os.geteuid() != 0 or socket.gethostname().lower() != payload["source_hostname"]:
        raise RuntimeError("source_owner_sudo_required")
    os.umask(0o077)
    directory = Path(payload["source_config"])
    if str(directory) not in ("/etc/homelab-monitoring", "/etc/homelab-local-alerts"):
        raise RuntimeError("source_config_not_allowed")
    meta = os.lstat(directory)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o700:
        raise RuntimeError("source_directory_metadata")
    fd = os.open("/run/lock/homelab-alerts-envelope.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        if os.fstat(lock.fileno()).st_uid != 0:
            raise RuntimeError("export_lock_owner")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        token = secret(directory / "telegram-bot-token")
        chat = secret(directory / "telegram-chat-id")
        envelopes = make_envelopes(payload["recipients"], token, chat)
        if secret(directory / "telegram-bot-token") != token or secret(directory / "telegram-chat-id") != chat:
            raise RuntimeError("source_credentials_changed_concurrently")
        report = {"host": payload["source_hostname"], "kind": "peer_alerts_encrypted_envelopes",
                  "verified_source_sha256": globals()["EXPORT_VERIFIED_SHA256"], "envelopes": envelopes,
                  "source_credentials_unchanged": True, "plaintext_credentials_exported": False,
                  "services_changed": False, "messages_sent": False}
        data = (json.dumps(report, indent=2) + "\n").encode()
        path = "/srv/sg-workspaces/default/peer-alerts-envelopes-" + uuid.uuid4().hex + ".json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"status": "encrypted_envelopes_ready", "report": path, "sha256": hashlib.sha256(data).hexdigest(),
                          "plaintext_credentials_exported": False, "services_changed": False, "messages_sent": False}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "stopped", "error_type": type(exc).__name__, "details_withheld": True}), flush=True)
        raise SystemExit(1)
