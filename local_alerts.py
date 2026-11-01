#!/usr/bin/env python3
"""Local UPS/storage/backup/DNS/TLS alerts. No machine heartbeat or maintenance actions."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

import homelab_notify as outbox
import local_policy as policy
import local_sources as sources


def collect(config: dict, db: sqlite3.Connection, now: float) -> list[policy.Observation]:
    rows = [policy.ups("ups.primary", sources.nut(config["ups_name"]))] if config.get("ups_name") else [
        policy.Observation("ups.primary", "idle", "ups_not_configured", "источник UPS не настроен", "", "")]
    for item in config["storage"]:
        data = sources.storage(item["target"], item["source"], check_capacity=not item.get("mount_only", False))
        if data.get("idle"):
            unit = item["mount_unit"]
            state = sources.properties(unit)
            if state.get("ActiveState") == "failed":
                data = {"mounted": False}
        rows.extend(policy.storage(item["key"], data, item))
    db.execute("CREATE TABLE IF NOT EXISTS local_receipts (key TEXT PRIMARY KEY, timestamp REAL NOT NULL)")
    if config.get("backup"):
        backup_data = sources.backup(config["backup"])
        row = db.execute("SELECT timestamp FROM local_receipts WHERE key='backup'").fetchone()
        last = row[0] if row else config["backup"]["initial_last_success"]
        new = backup_data.get("last_success")
        if new is not None and new <= now + 60:
            last = max(last, new)
        if backup_data.get("source_verified"):
            db.execute("INSERT OR REPLACE INTO local_receipts VALUES ('backup',?)", (last,))
        backup_data["last_success"] = last
        rows.append(policy.backup("backup.cloud", backup_data, now, config["backup"]["max_age_seconds"]))
    else:
        rows.append(policy.Observation("backup.cloud", "idle", "backup_not_configured", "источник резервного копирования не настроен", "", ""))
    expires = []
    # A failed frontend must not serially delay UPS delivery behind every timeout.
    with ThreadPoolExecutor(max_workers=3) as pool:
        frontends = list(pool.map(lambda name: sources.frontend(name, config["connect_address"]), config["frontends"]))
    rows.extend(policy.frontend_group(list(zip(config["frontends"], frontends)), config["expected_dns"]))
    for name, data in zip(config["frontends"], frontends):
        if data.get("expires") is not None:
            expires.append(data["expires"])
    rows.append(policy.certificate("https.certificate", min(expires) if expires else None, now))
    errors = sources.kernel_errors(config["kernel_devices"])
    if not errors["available"]:
        rows.append(policy.Observation("storage.kernel", "warning", "kernel_source_unavailable", "не удаётся прочитать аппаратную диагностику хранения",
                                       "Нельзя подтвердить отсутствие новых ошибок ввода-вывода.", "kernel: source unavailable", 900))
    else:
        rows.append(policy.Observation("storage.kernel", "ok", "kernel_source_ok", "диагностика хранения", "", ""))
    for key in config["kernel_devices"]:
        when = errors["devices"].get(key)
        if when is not None:
            rows.append(policy.Observation(key + ".io", "critical", "storage_io_error", "система сообщила об ошибке хранения",
                                           "Возможна потеря данных. Не перезагружайте и не меняйте диски до проверки.",
                                           f"kernel_error_utc={int(when)}", 0, recoverable=False))
        else:
            rows.append(policy.Observation(key + ".io", "idle", "no_new_io_record", "диагностика хранения", "", "", recoverable=False))
    return rows


def write_status(directory: Path, data: dict) -> None:
    # Directory is created and owned by the dedicated service account at installation.
    encoded = (json.dumps(data, ensure_ascii=True) + "\n").encode()
    if len(encoded) > 65536:
        raise ValueError("status limit")
    fd, name = tempfile.mkstemp(prefix=".status-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / "status.json")
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(config: dict, state_dir: Path, status_dir: Path, credentials: Path | None, *, no_send: bool = False) -> dict:
    # Both the deployment probe and the real service validate the same credentials.
    # The probe cannot flush even if its isolated outbox contains a fault event.
    if credentials is not None:
        outbox._credentials(credentials)
    outbox._private_dir(state_dir)
    with (state_dir / "local.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with outbox._connect(state_dir) as db:
            now = time.time()
            observations = collect(config, db, now)
            for observation in observations:
                policy.observe(db, observation, now, config["origin"], config["runbook"])
            attempted, sent = outbox.flush(db, credentials, limit=5) if credentials and not no_send else (0, 0)
            data = {"schema": 1, "observed_at": now, "collector_ok": True,
                    "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "observations": [{"key": o.key, "level": o.level, "code": o.code} for o in observations],
                    "pending_events": db.execute("SELECT count(*) FROM outbound WHERE sent_at IS NULL").fetchone()[0],
                    "attempted": attempted, "sent": sent, "machine_heartbeat_enabled": False,
                    "credentials_validated": credentials is not None, "sending_enabled": credentials is not None and not no_send}
            write_status(status_dir, data)
            return data


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--status-dir", type=Path, required=True)
    parser.add_argument("--credentials", type=Path)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()
    try:
        if args.config.stat().st_size > 65536:
            raise ValueError("configuration limit")
        config = json.loads(args.config.read_bytes())
        data = run(config, args.state_dir, args.status_dir, args.credentials, no_send=args.no_send)
        print(json.dumps({k: data[k] for k in ("collector_ok", "attempted", "sent", "pending_events")}))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error) as exc:
        code = str(exc) if isinstance(exc, outbox.CredentialError) else "details_withheld"
        print(json.dumps({"collector_ok": False, "error_type": type(exc).__name__, "error_code": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
