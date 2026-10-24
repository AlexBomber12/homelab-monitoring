#!/usr/bin/env python3
"""Small dependency-free Telegram outbox and independent SSH reachability probe.

Uses a root-protected SQLite outbox with at-least-once delivery. No incoming API,
arbitrary command execution, privileged SSH, or modification of monitored hosts.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid

MAX_PENDING = 1000
MAX_TEXT = 3000
LEASE_SECONDS = 45
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SEVERITIES = ("INFO", "WARNING", "CRITICAL", "RECOVERED")


def _label(value: str) -> str:
    if not LABEL_RE.fullmatch(value):
        raise ValueError("invalid event label")
    return value


def _private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("symlink directory forbidden")
    path.mkdir(mode=0o700, exist_ok=True)
    st = path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError("state directory must belong to executor and be mode 0700")


def _secret(path: Path) -> str:
    if path.is_symlink():
        raise ValueError("symlink secret forbidden")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError("secret must belong to executor and be mode 0600")
    if st.st_size > 4096:
        raise ValueError("oversized configuration")
    return path.read_text(encoding="utf-8").strip()


def _credentials(config_dir: Path) -> tuple[str, int]:
    token = _secret(config_dir / "telegram-bot-token")
    chat = _secret(config_dir / "telegram-chat-id")
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{20,}", token):
        raise ValueError("invalid bot credentials")
    if not re.fullmatch(r"-100[0-9]+", chat):
        raise ValueError("invalid private channel identifier")
    return token, int(chat)


def _connect(state_dir: Path) -> sqlite3.Connection:
    _private_dir(state_dir)
    path = state_dir / "outbox.sqlite3"
    if path.is_symlink():
        raise ValueError("symlink database forbidden")
    if path.exists():
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("database must be owned by executor and mode 0600")
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS outbound (
            id INTEGER PRIMARY KEY,
            event_key TEXT NOT NULL UNIQUE,
            message TEXT NOT NULL,
            created_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt REAL NOT NULL DEFAULT 0,
            lease_until REAL NOT NULL DEFAULT 0,
            sent_at REAL,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS probes (
            probe_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            consecutive_failures INTEGER NOT NULL
        );
        """)
        return db
    except BaseException:
        db.close()
        raise


@contextmanager
def _tx(db: sqlite3.Connection):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")


def _enqueue_tx(db: sqlite3.Connection, event_key: str, message: str, now: float) -> bool:
    _label(event_key)
    if not message or len(message) > MAX_TEXT:
        raise ValueError("invalid message size")
    if db.execute("SELECT 1 FROM outbound WHERE event_key=?", (event_key,)).fetchone():
        return False
    pending = db.execute("SELECT count(*) FROM outbound WHERE sent_at IS NULL").fetchone()[0]
    if pending >= MAX_PENDING:
        raise RuntimeError("outbox full: manual attention required")
    db.execute(
        "INSERT INTO outbound(event_key,message,created_at) VALUES (?,?,?)",
        (event_key, message, now),
    )
    return True


def enqueue(db: sqlite3.Connection, event_key: str, origin: str, severity: str, message: str, now: float | None = None) -> bool:
    _label(origin)
    if severity not in SEVERITIES:
        raise ValueError("invalid severity")
    body = f"[{severity}] {origin}\n{message}"
    with _tx(db):
        return _enqueue_tx(db, event_key, body, time.time() if now is None else now)


def observe_probe(
    db: sqlite3.Connection, probe_id: str, origin: str, target_label: str,
    ok: bool, failures_to_alert: int = 3, now: float | None = None,
) -> str:
    """Record a peer SSH banner result. Alert only on confirmed state transitions."""
    for label in (probe_id, origin, target_label):
        _label(label)
    if not 2 <= failures_to_alert <= 30:
        raise ValueError("invalid failure threshold")
    timestamp = time.time() if now is None else now
    with _tx(db):
        row = db.execute(
            "SELECT state,consecutive_failures FROM probes WHERE probe_id=?",
            (probe_id,),
        ).fetchone()
        previous = row["state"] if row else "unknown"
        failures = row["consecutive_failures"] if row else 0
        state = previous
        action = "unchanged"
        if ok:
            failures = 0
            state = "up"
            if previous == "down":
                event = f"probe_{probe_id}_{uuid.uuid4().hex}"
                _enqueue_tx(db, event, f"[RECOVERED] {origin}\n{target_label}: SSH endpoint reachable again", timestamp)
                action = "recovered"
        else:
            failures = min(failures + 1, failures_to_alert)
            if previous != "down" and failures >= failures_to_alert:
                state = "down"
                event = f"probe_{probe_id}_{uuid.uuid4().hex}"
                _enqueue_tx(
                    db, event,
                    f"[CRITICAL] {origin}\n{target_label}: SSH endpoint unavailable after {failures_to_alert} consecutive probes",
                    timestamp,
                )
                action = "alerted"
        db.execute(
            "INSERT INTO probes(probe_id,state,consecutive_failures) VALUES(?,?,?) "
            "ON CONFLICT(probe_id) DO UPDATE SET state=excluded.state,consecutive_failures=excluded.consecutive_failures",
            (probe_id, state, failures),
        )
    return action


def ssh_banner_ok(ipv4: str, port: int = 22) -> bool:
    ipaddress.IPv4Address(ipv4)
    if not 1 <= port <= 65535:
        raise ValueError("invalid TCP port")
    try:
        with socket.create_connection((ipv4, port), timeout=3) as conn:
            conn.settimeout(3)
            return conn.recv(128).startswith(b"SSH-")
    except (OSError, TimeoutError):
        return False


def _claim(db: sqlite3.Connection, now: float) -> sqlite3.Row | None:
    with _tx(db):
        row = db.execute(
            "SELECT id,message,attempts FROM outbound "
            "WHERE sent_at IS NULL AND next_attempt<=? AND lease_until<=? "
            "ORDER BY id LIMIT 1",
            (now, now),
        ).fetchone()
        if row is not None:
            db.execute("UPDATE outbound SET lease_until=? WHERE id=?", (now + LEASE_SECONDS, row["id"]))
        return row


def _send(token: str, chat_id: int, message: str) -> tuple[bool, int, str]:
    """Never include a credential-bearing Telegram URL or response body in diagnostics."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    req = urllib.request.Request(
        url,
        data=json.dumps({"chat_id": chat_id, "text": message}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            payload = json.load(response)
        return (bool(payload.get("ok")), 0, "api_rejected" if not payload.get("ok") else "")
    except urllib.error.HTTPError as exc:
        delay = 0
        if exc.code == 429:
            try:
                retry = json.loads(exc.read(2048).decode("utf-8"))
                delay = int(retry.get("parameters", {}).get("retry_after", 0))
            except (ValueError, TypeError, UnicodeError):
                pass
            try:
                delay = max(delay, int(exc.headers.get("Retry-After", "0")))
            except (ValueError, TypeError):
                pass
        return False, max(0, min(delay, 86400)), f"http_{exc.code}"
    except (OSError, ValueError, TimeoutError):
        return False, 0, "transport_or_response_error"


def flush(db: sqlite3.Connection, config_dir: Path, limit: int = 20) -> tuple[int, int]:
    if not 1 <= limit <= 100:
        raise ValueError("invalid flush limit")
    token, chat_id = _credentials(config_dir)
    attempted = sent = 0
    for _ in range(limit):
        now = time.time()
        row = _claim(db, now)
        if row is None:
            break
        attempted += 1
        success, retry_after, error = _send(token, chat_id, row["message"])
        with _tx(db):
            if success:
                db.execute(
                    "UPDATE outbound SET sent_at=?,lease_until=0,last_error=NULL WHERE id=?",
                    (time.time(), row["id"]),
                )
                sent += 1
            else:
                attempts = row["attempts"] + 1
                delay = max(min(3600, 30 * (2 ** min(attempts - 1, 7))), retry_after)
                db.execute(
                    "UPDATE outbound SET attempts=?,next_attempt=?,lease_until=0,last_error=? WHERE id=?",
                    (attempts, time.time() + delay, error, row["id"]),
                )
    with _tx(db):
        db.execute("DELETE FROM outbound WHERE sent_at IS NOT NULL AND sent_at<?", (time.time() - 30 * 86400,))
    return attempted, sent


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-dir", type=Path, default=Path("/var/lib/homelab-monitoring"))
    p.add_argument("--config-dir", type=Path, default=Path("/etc/homelab-monitoring"))
    sub = p.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enqueue")
    e.add_argument("--event-key", required=True)
    e.add_argument("--origin", required=True)
    e.add_argument("--severity", required=True, choices=SEVERITIES)
    e.add_argument("--text", required=True)
    f = sub.add_parser("flush")
    f.add_argument("--limit", type=int, default=20)
    q = sub.add_parser("probe-ssh")
    q.add_argument("--probe-id", required=True)
    q.add_argument("--origin", required=True)
    q.add_argument("--label", required=True)
    q.add_argument("--ipv4", required=True)
    q.add_argument("--port", type=int, default=22)
    q.add_argument("--failures-to-alert", type=int, default=3)
    a = p.parse_args(argv)
    try:
        with _connect(a.state_dir) as db:
            if a.command == "enqueue":
                result = enqueue(db, a.event_key, a.origin, a.severity, a.text)
                print("ENQUEUED" if result else "DUPLICATE: SKIPPED")
            elif a.command == "probe-ssh":
                reachable = ssh_banner_ok(a.ipv4, a.port)
                result = observe_probe(db, a.probe_id, a.origin, a.label, reachable, a.failures_to_alert)
                print(f"PROBE {a.label}: {'REACHABLE' if reachable else 'UNREACHABLE'}; {result}")
            else:
                attempted, sent = flush(db, a.config_dir, a.limit)
                print(f"TELEGRAM FLUSH: attempted={attempted} sent={sent}")
                if attempted != sent:
                    return 1
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        # Deliberately never print exception details: HTTP URLs can contain bot tokens.
        print(f"NOTIFIER ERROR: {type(exc).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
