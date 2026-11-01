"""Reviewed owner transaction for local alerts; private payload is supplied separately.

The payload is accepted only through a hash-verified owner launch, never via SSH
agent operations. No package manager, service restart, peer monitor, or production
application deployment is performed.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

USER = "homelab-alerts"
STATE = Path("/var/lib/homelab-local-alerts")
STATUS = Path("/var/lib/homelab-local-alerts-status")
CONFIG = Path("/etc/homelab-local-alerts")
CODE = Path("/opt/homelab-local-alerts")
ROLE = Path("/usr/local/libexec/sg-agent-dispatch.py")
UNIT = "homelab-local-alerts.service"
TIMER = "homelab-local-alerts.timer"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "TZ": "UTC"}
EXPECTED_FILES = {str(CODE / n) for n in ("homelab_notify.py", "local_policy.py", "local_sources.py", "local_alerts.py", "run_local.py")} | {
    "/etc/systemd/system/" + UNIT, "/etc/systemd/system/" + TIMER,
    "/usr/local/libexec/sg-important-alerts-status.py"}
RESUMING = False


def emit(stage, **fields):
    try:
        print(json.dumps({"stage": stage, **fields}), flush=True)
    except OSError:
        pass


def check(value, code):
    if not value:
        raise RuntimeError(code)


def command(args, timeout=25, data=None):
    p = subprocess.run(args, env=ENV, input=data, capture_output=True, timeout=timeout)
    tag = Path(args[0]).name
    if len(args) > 1 and args[1] in ("start", "enable", "show", "verify"):
        tag += "_" + args[1]
    check(p.returncode == 0 and len(p.stdout) <= 1048576, tag + "_failed_output_withheld")
    return p.stdout


def private_write(path, data, mode=0o600, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), mode)
        os.fchown(f.fileno(), uid, gid)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def unit_state(name):
    text = command(["/usr/bin/systemctl", "show", name, "--property=MainPID,InvocationID,ActiveState"]).decode()
    return sorted(text.splitlines())


def baseline(payload):
    units = {n: unit_state(n) for n in payload["protected_units"]}
    paths = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in payload["protected_files"]}
    ids = command(["/usr/bin/docker", "ps", "--no-trunc", "--format", "{{.ID}}"]).decode().splitlines()
    containers = command(["/usr/bin/docker", "inspect", "--format", "{{.Id}} {{.Name}} {{.Image}} {{.State.StartedAt}} {{.RestartCount}}", *sorted(ids)]).decode().splitlines() if ids else []
    return {"units": units, "files": paths, "containers": sorted(containers)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def telegram_read(token, method, parameters):
    check(method in ("getMe", "getChat", "getChatMember"), "read_api_method")
    url = "https://api.telegram.org/bot" + token + "/" + method
    request = urllib.request.Request(url, data=urllib.parse.urlencode(parameters).encode(), method="POST")
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=12) as r:
        data = r.read(65537)
    check(len(data) <= 65536, "api_response_limit")
    result = json.loads(data)
    check(result.get("ok") is True, "telegram_read_rejected")
    return result["result"]


def credentials_from_existing_infra_sender(container):
    check(container == "sms-gateway-v2", "unexpected_credential_source")
    # Secret values remain in owner-process memory and protected local files only.
    info = json.loads(command(["/usr/bin/docker", "inspect", "--format", "{{json .Config.Env}}", container]))
    env = dict(v.split("=", 1) for v in info if "=" in v)
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chat = env.get("HEARTBEAT_TELEGRAM_CHAT_ID", "")
    check(bool(re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token)), "infra_sender_token_unavailable")
    check(bool(re.fullmatch(r"-100[0-9]+", chat)), "separate_infra_destination_required")
    identity = telegram_read(token, "getMe", {})
    room = telegram_read(token, "getChat", {"chat_id": chat})
    member = telegram_read(token, "getChatMember", {"chat_id": chat, "user_id": identity["id"]})
    allowed = member.get("status") in ("creator", "administrator") and (room.get("type") != "channel" or member.get("can_post_messages", member.get("status") == "creator"))
    check(allowed, "infra_sender_post_permission_not_confirmed")
    return token.encode(), chat.encode()


def ensure_directory(path, mode, uid=0, gid=0):
    if path.exists() or path.is_symlink():
        s = os.lstat(path)
        check(RESUMING and stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid and stat.S_IMODE(s.st_mode) == mode,
              "existing_installation_requires_review")
        return
    path.mkdir(mode=mode)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def validate_status(path, uid, allowed_findings=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        check(stat.S_ISREG(s.st_mode) and s.st_uid == uid and not s.st_mode & 0o022 and s.st_size <= 65536, "status_metadata")
        data = json.loads(f.read(65537))
    check(data["collector_ok"] is True and time.time() - 180 <= data["observed_at"] <= time.time() + 60, "collector_not_fresh")
    check(data["machine_heartbeat_enabled"] is False, "unexpected_machine_heartbeat")
    check(data.get("credentials_validated") is True, "credentials_not_validated")
    allowed_findings = allowed_findings or {}
    acceptable = all(o["level"] in ("ok", "idle") or (o["level"] == "warning" and o["code"] in allowed_findings.get(o["key"], [])) for o in data["observations"])
    if not (data["pending_events"] == 0 and acceptable):
        emit("baseline_findings", observations=[{k: o[k] for k in ("key", "level", "code")} for o in data["observations"]])
        raise RuntimeError("baseline_findings_require_review")
    return data


def extend_dispatcher(original, profile):
    fixed = (b'    if request == "diagnostics.important_alerts":\n'
             b'        os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", "/usr/local/libexec/sg-important-alerts-status.py"], ENV)\n')
    check(b"diagnostics.important_alerts" not in original, "diagnostic_already_present")
    if profile == "host_mapping":
        check(original.count(b"HOST_DIAGNOSTICS = {") == 1, "dispatcher_anchor_changed")
        updated = original.replace(b"HOST_DIAGNOSTICS = {", b"HOST_DIAGNOSTICS = {\n    'diagnostics.important_alerts': '/usr/local/libexec/sg-important-alerts-status.py',", 1)
    elif profile in ("ai_workspace", "spark_workspace"):
        anchor = b'    if request in ("workspace.info", "workspace.request"):'
        check(original.count(anchor) == 1, "dispatcher_anchor_changed")
        updated = original.replace(anchor, fixed + anchor, 1)
        if profile == "ai_workspace":
            caps = b'"agent.capabilities", "workspace.info",'
            replacement = b'"agent.capabilities", "diagnostics.important_alerts", "workspace.info",'
        else:
            caps = b'"workspace.request"],'
            replacement = b'"workspace.request", "diagnostics.important_alerts"],'
        check(updated.count(caps) == 1, "capabilities_anchor_changed")
        updated = updated.replace(caps, replacement, 1)
    else:
        raise RuntimeError("unsupported_dispatcher_profile")
    compile(updated, str(ROLE), "exec")
    return updated


def credentials_from_envelope(payload):
    """Decrypt the reviewed ciphertext only inside the selected owner's process."""
    envelope = payload["credential_envelope"]
    check(envelope["host"] == payload["hostname"], "envelope_target_mismatch")
    directory = Path("/var/lib/homelab-alerts-onboarding")
    meta = os.lstat(directory)
    check(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700, "recipient_directory_metadata")
    key = directory / "recipient.pem"
    fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        check(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size <= 16384, "recipient_key_metadata")
        private = stream.read(16385)
    public = command(["/usr/bin/openssl", "pkey", "-pubout"], data=private)
    check(hashlib.sha256(public).hexdigest() == payload["recipient_public_key_sha256"] == envelope["recipient_public_key_sha256"], "recipient_key_changed")
    encrypted = base64.b64decode(envelope["ciphertext_base64"], validate=True)
    check(len(encrypted) == 384, "envelope_ciphertext_size")
    plain = command(["/usr/bin/openssl", "pkeyutl", "-decrypt", "-inkey", str(key), "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"], data=encrypted)
    data = json.loads(plain)
    check(set(data) == {"v", "host", "token", "chat"} and data["v"] == 1 and data["host"] == payload["hostname"], "envelope_plaintext_schema")
    token, chat = data["token"], data["chat"]
    check(isinstance(token, str) and bool(re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token)), "envelope_token_format")
    check(isinstance(chat, str) and bool(re.fullmatch(r"-100[0-9]+", chat)), "envelope_chat_format")
    identity = telegram_read(token, "getMe", {})
    room = telegram_read(token, "getChat", {"chat_id": chat})
    member = telegram_read(token, "getChatMember", {"chat_id": chat, "user_id": identity["id"]})
    check(member.get("status") in ("creator", "administrator") and (room.get("type") != "channel" or member.get("can_post_messages", member.get("status") == "creator")), "envelope_sender_permission")
    return token.encode(), chat.encode()


def safe_service_failure():
    """Keep only constant collector error codes, never raw journal messages."""
    try:
        data = command(["/usr/bin/journalctl", "-u", UNIT, "-n", "30", "--no-pager", "-o", "json"])
        records = []
        for line in data.splitlines():
            try:
                message = json.loads(json.loads(line)["MESSAGE"])
                if not isinstance(message, dict) or message.get("collector_ok") is not False:
                    continue
                allowed = {"error_type": {"ValueError", "CredentialError", "KeyError", "RuntimeError", "OSError", "PermissionError", "OperationalError"},
                           "error_code": {"details_withheld", "credential_symlink", "credential_not_private", "credential_size_limit", "credential_token_format", "credential_chat_format"}}
                row = {k: message[k] for k in allowed if isinstance(message.get(k), str) and message[k] in allowed[k]}
                if row:
                    records.append(row)
            except (ValueError, TypeError, KeyError):
                continue
        return records[-3:]
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        return []


def rollback(backup):
    metadata = json.loads((backup / "transaction.json").read_bytes())
    subprocess.run(["/usr/bin/systemctl", "disable", "--now", TIMER], capture_output=True, timeout=20)
    subprocess.run(["/usr/bin/systemctl", "stop", UNIT], capture_output=True, timeout=190)
    # Preserve state, credentials and all application data. Only owned files are revoked/restored.
    current = ROLE.read_bytes()
    check(hashlib.sha256(current).hexdigest() in (metadata["role_before"], metadata["role_after"]), "role_changed_concurrently")
    saved = (backup / "dispatcher.before").read_bytes()
    check(hashlib.sha256(saved).hexdigest() == metadata["role_before"], "dispatcher_backup_mismatch")
    if hashlib.sha256(current).hexdigest() != metadata["role_before"]:
        temp = ROLE.with_name(".sg-alerts-rollback-" + uuid.uuid4().hex)
        private_write(temp, saved, 0o644)
        os.replace(temp, ROLE)
    for path, expected in metadata["installed_files"].items():
        p = Path(path)
        if p.exists():
            check(not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest() == expected, "installed_file_changed_concurrently")
            p.unlink()
    marker = CONFIG / "rollback-receipt.json"
    if CONFIG.is_dir() and not CONFIG.is_symlink():
        data = json.dumps({"status": "rolled_back", "role_before": metadata["role_before"]}).encode()
        if marker.exists():
            check(not marker.is_symlink() and marker.stat().st_uid == 0, "rollback_marker_ownership")
            marker.unlink()
        private_write(marker, data)
    command(["/usr/bin/systemctl", "daemon-reload"])


def install(payload):
    emit("preflight_local_only")
    check(os.geteuid() == 0 and socket.gethostname().lower() == payload["hostname"], "owner_host_identity")
    check(set(payload["files"]) == EXPECTED_FILES, "managed_target_set_mismatch")
    if RESUMING:
        marker = CONFIG / "rollback-receipt.json"
        check(not marker.is_symlink() and marker.stat().st_uid == 0 and stat.S_IMODE(marker.stat().st_mode) == 0o600, "resume_marker_metadata")
        receipt = json.loads(marker.read_bytes())
        check(receipt == {"status": "rolled_back", "role_before": payload["dispatcher_before_sha256"]}, "resume_marker_mismatch")
        check("ActiveState=active" not in unit_state(UNIT) and "ActiveState=active" not in unit_state(TIMER), "resume_unit_active")
    else:
        check(not CONFIG.exists() and not CODE.exists() and not STATE.exists() and not STATUS.exists(), "existing_installation_requires_review")
    for path in payload["files"]:
        check(not Path(path).exists() and not Path(path).is_symlink(), "existing_managed_file_requires_review")
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        account = None
    check(account is None or RESUMING, "existing_service_account_requires_review")
    before = baseline(payload)
    original_role = ROLE.read_bytes()
    check(hashlib.sha256(original_role).hexdigest() == payload["dispatcher_before_sha256"], "dispatcher_baseline_changed")
    updated_role = extend_dispatcher(original_role, payload.get("dispatcher_profile", "host_mapping"))
    emit("verify_existing_channel_without_test_message")
    token, chat = credentials_from_envelope(payload) if "credential_envelope" in payload else credentials_from_existing_infra_sender(payload["credential_source_container"])
    backup = Path(tempfile.mkdtemp(prefix="homelab-local-alerts.", dir="/var/backups"))
    os.chmod(backup, 0o700)
    private_write(backup / "dispatcher.before", original_role)
    private_write(backup / "installer.py", globals()["INSTALLER_VERIFIED_BYTES"], 0o700)
    metadata = {"role_before": hashlib.sha256(original_role).hexdigest(), "role_after": hashlib.sha256(updated_role).hexdigest(),
                "installed_files": {p: hashlib.sha256(base64.b64decode(v, validate=True)).hexdigest() for p, v in payload["files"].items()}}
    private_write(backup / "transaction.json", json.dumps(metadata).encode())
    emit("prepare_service_identity_and_protected_files", backup_dir=str(backup))
    try:
        try:
            pwd.getpwnam(USER)
        except KeyError:
            command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", USER])
        account = pwd.getpwnam(USER)
        check(account.pw_uid > 0 and account.pw_gid > 0 and account.pw_shell == "/usr/sbin/nologin" and account.pw_dir == "/nonexistent"
              and os.getgrouplist(USER, account.pw_gid) == [account.pw_gid], "service_account_mismatch")
        ensure_directory(CODE, 0o755)
        ensure_directory(CONFIG, 0o700)
        for directory, mode in ((STATE, 0o700), (STATUS, 0o755), (Path(str(STATE) + "-probe"), 0o700), (Path(str(STATUS) + "-probe"), 0o755)):
            ensure_directory(directory, mode, account.pw_uid, account.pw_gid)
        for name, data in (("telegram-bot-token", token), ("telegram-chat-id", chat), ("checks.json", json.dumps(payload["config"]).encode())):
            path = CONFIG / name
            if RESUMING and path.exists():
                s = os.lstat(path)
                check(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600 and path.read_bytes() == data,
                      "existing_private_config_requires_review")
            else:
                private_write(path, data)
        for path, encoded in payload["files"].items():
            p = Path(path)
            data = base64.b64decode(encoded, validate=True)
            private_write(p, data, 0o644)
            metadata["installed_files"][path] = hashlib.sha256(data).hexdigest()
        # Persist the exact rollback ownership manifest before activation.
        (backup / "transaction.json").write_text(json.dumps(metadata))
        command(["/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/" + UNIT, "/etc/systemd/system/" + TIMER])
        emit("same_identity_probe_with_credentials_sending_disabled")
        probe_name = "homelab-local-alerts-probe-" + uuid.uuid4().hex
        probe_unit = payload["probe_unit"].replace("__CHECKS__", str(CONFIG / "checks.json"))
        runtime_unit = Path("/run/systemd/system") / (probe_name + ".service")
        private_write(runtime_unit, probe_unit.encode(), 0o644)
        try:
            command(["/usr/bin/systemctl", "daemon-reload"])
            command(["/usr/bin/systemctl", "start", probe_name + ".service"], timeout=185)
            validate_status(Path(str(STATUS) + "-probe") / "status.json", account.pw_uid, payload.get("allowed_baseline_findings"))
        finally:
            runtime_unit.unlink(missing_ok=True)
            command(["/usr/bin/systemctl", "daemon-reload"])
        check(baseline(payload) == before, "protected_baseline_changed")
        emit("activate_local_alerts_only")
        temp = ROLE.with_name(".sg-alerts-" + uuid.uuid4().hex)
        check(ROLE.read_bytes() == original_role, "dispatcher_changed_concurrently")
        private_write(temp, updated_role, 0o644)
        os.replace(temp, ROLE)
        command(["/usr/bin/systemctl", "enable", "--now", TIMER])
        command(["/usr/bin/systemctl", "start", UNIT], timeout=185)
        status = validate_status(STATUS / "status.json", account.pw_uid, payload.get("allowed_baseline_findings"))
        after = baseline(payload)
        expected = {**before, "files": {k: v for k, v in before["files"].items() if k != str(ROLE)}}
        after["files"].pop(str(ROLE), None)
        check(after == expected, "unrelated_baseline_changed")
    except BaseException as exc:
        failure = {"host": payload["hostname"], "status": "installation_failed_rolled_back",
                   "source_revision": payload["source_revision"], "verified_source_sha256": globals()["INSTALLER_VERIFIED_SHA256"],
                   "error_type": type(exc).__name__, "safe_service_errors": safe_service_failure(),
                   "backup_dir": str(backup), "machine_heartbeat_enabled": False}
        emit("automatic_deactivation_and_dispatcher_rollback")
        rollback(backup)
        failure["protected_baseline_unchanged"] = baseline(payload) == before
        filename = "/srv/sg-workspaces/default/important-alerts-failure-" + uuid.uuid4().hex + ".json"
        data = (json.dumps(failure, indent=2) + "\n").encode()
        private_write(filename, data, 0o644)
        emit("failure_report_saved", report=filename, sha256=hashlib.sha256(data).hexdigest(), safe_service_errors=failure["safe_service_errors"])
        raise
    report = {"host": payload["hostname"], "status": "local_alerts_installed", "source_revision": payload["source_revision"],
              "verified_source_sha256": globals()["INSTALLER_VERIFIED_SHA256"], "backup_dir": str(backup),
              "rollback": "/usr/bin/python3 -I -B " + str(backup / "installer.py") + " --rollback",
              "machine_heartbeat_enabled": False, "test_message_sent": False,
              "credentials_validated_via_read_only_api": True, "existing_sender_unchanged": True,
              "protected_files_and_service_identities_unchanged": True, "fresh_status": status,
              "diagnostic_operation": "diagnostics.important_alerts", "privileged_agent_grants_added": False,
              "acknowledged_baseline_findings": payload.get("allowed_baseline_findings", {})}
    filename = "/srv/sg-workspaces/default/important-alerts-apply-" + uuid.uuid4().hex + ".json"
    private_write(filename, (json.dumps(report, indent=2) + "\n").encode(), 0o644)
    emit("installed", report=filename, sha256=hashlib.sha256(Path(filename).read_bytes()).hexdigest())


def main():
    global RESUMING
    check(os.geteuid() == 0, "owner_sudo_required")
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    fd = os.open("/run/lock/homelab-local-alerts.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as stream:
        check(os.fstat(stream.fileno()).st_uid == 0, "lock_ownership")
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1:] == ["--rollback"]:
            backup = Path(__file__).resolve().parent
            check(backup.parent == Path("/var/backups") and backup.name.startswith("homelab-local-alerts."), "rollback_location")
            rollback(backup)
            emit("deactivated_state_and_credentials_retained")
        else:
            check(sys.argv[1:] in ([], ["--resume"]), "unexpected_arguments")
            RESUMING = sys.argv[1:] == ["--resume"]
            install(globals()["DEPLOY_PAYLOAD"])


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        emit("stopped", error_type=type(exc).__name__, error_code=str(exc) if type(exc) is RuntimeError else "details_withheld")
        raise SystemExit(1)
