"""Fixed unprivileged status reader: no credentials, state database or command arguments."""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time


def read_status():
    uid = pwd.getpwnam("homelab-alerts").pw_uid
    path = Path("/var/lib/homelab-local-alerts-status/status.json")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid != uid or s.st_nlink != 1 or s.st_mode & 0o022 or s.st_size > 65536:
            raise ValueError("untrusted status")
        data = json.loads(stream.read(65537))
    observed = data["observed_at"]
    if type(observed) not in (float, int) or not 0 <= observed <= time.time() + 60:
        raise ValueError("invalid timestamp")
    result = {"schema": 1, "observed_at": observed, "fresh": time.time() - observed <= 180,
              "collector_ok": data.get("collector_ok") is True, "machine_heartbeat_enabled": False,
              "observations": []}
    for key in ("pending_events", "attempted", "sent"):
        value = data[key]
        if type(value) is not int or not 0 <= value <= 1000:
            raise ValueError("invalid counter")
        result[key] = value
    rows = data["observations"]
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError("invalid observation count")
    for row in rows:
        if not all(isinstance(row.get(k), str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", row[k]) for k in ("key", "code")):
            raise ValueError("invalid observation label")
        if row.get("level") not in ("ok", "idle", "warning", "critical"):
            raise ValueError("invalid observation level")
        result["observations"].append({k: row[k] for k in ("key", "level", "code")})
    return result


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(126)
    try:
        print(json.dumps(read_status(), ensure_ascii=True))
    except (OSError, KeyError, ValueError, TypeError) as exc:
        print(json.dumps({"collector_ok": False, "fresh": False, "error_type": type(exc).__name__}))
        raise SystemExit(1)
