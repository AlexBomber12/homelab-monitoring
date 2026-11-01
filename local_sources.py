"""Bounded read-only Linux sources. Private inventory is supplied by the operator."""
from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}


def command(args: list[str], timeout: int = 5, limit: int = 1048576) -> str:
    p = subprocess.run(args, env=ENV, capture_output=True, timeout=timeout)
    if p.returncode or len(p.stdout) > limit or len(p.stderr) > limit:
        raise OSError("source unavailable; raw output withheld")
    return p.stdout.decode("utf-8", errors="strict")


def mountinfo(text: str, target: str) -> dict:
    """Distinguish autofs from its backing filesystem and read-only service bind mounts."""
    rows = []
    automount = False
    for line in text.splitlines():
        fields = line.split()
        split = fields.index("-")
        point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        if point != target:
            continue
        fstype, source, options = fields[split + 1:split + 4]
        if fstype == "autofs":
            automount = True
        else:
            rows.append({"mounted": True, "source": source, "fstype": fstype,
                         "device": fields[2], "root": fields[3], "read_only": "ro" in options.split(",")})
    if not rows:
        return {"mounted": False, "idle": automount}
    identities = {(r["source"], r["device"], r["root"], r["fstype"]) for r in rows}
    if len(identities) != 1:
        return {"mounted": False, "error": "ambiguous_mount"}
    return rows[-1]


def storage(target: str, expected_source: str, *, check_capacity: bool = True) -> dict:
    result = mountinfo(Path("/proc/self/mountinfo").read_text(), target)
    if not result.get("mounted"):
        # Avoid touching an idle automount, which would spin up the disk.
        return result
    if result["source"] != expected_source:
        return {"mounted": False, "error": "unexpected_device"}
    if not check_capacity:
        return result
    try:
        s = os.statvfs(target)
        result.update(available_bytes=s.f_bavail * s.f_frsize, total_bytes=s.f_blocks * s.f_frsize,
                      total_inodes=s.f_files if result["fstype"] in ("ext4", "xfs", "btrfs") else 0,
                      free_inodes=s.f_favail if result["fstype"] in ("ext4", "xfs", "btrfs") else 0)
    except OSError:
        return {"mounted": False, "error": "capacity_unavailable"}
    return result


def nut(name: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise ValueError("invalid UPS identifier")
    try:
        text = command(["/usr/bin/upsc", name + "@localhost"], limit=65536)
        fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
        known = {"OL", "OB", "LB", "RB", "CHRG", "DISCHRG", "BYPASS", "CAL", "OFF", "OVER", "TRIM", "BOOST", "FSD", "ALARM"}
        flags = fields.get("ups.status", "").split()
        values = {}
        for key, maximum in (("battery.charge", 100), ("battery.charge.low", 100), ("battery.runtime", 86400)):
            try:
                v = float(fields[key])
                values[key] = v if math.isfinite(v) and 0 <= v <= maximum else None
            except (KeyError, ValueError):
                values[key] = None
        return {"available": True, "ups.status": sorted(set(flags) & known), "values": values,
                "unknown_status_present": bool(set(flags) - known), "alarm_present": bool(fields.get("ups.alarm"))}
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return {"available": False}


def properties(unit: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}\.(?:service|timer|mount|automount)", unit):
        raise ValueError("invalid fixed unit")
    names = ("Type,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,"
             "ExecMainStartTimestamp,ExecMainExitTimestamp,TimersMonotonic,TimersCalendar,FragmentPath")
    text = command(["/usr/bin/systemctl", "show", unit, "--property=" + names])
    result = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("TimersMonotonic", "TimersCalendar"):
            result.setdefault(key, []).append(value)
        else:
            result[key] = value
    return result


def backup(config: dict) -> dict:
    try:
        source = Path(config["unit_path"])
        if source.is_symlink() or source.stat().st_size > 65536 or hashlib.sha256(source.read_bytes()).hexdigest() != config["unit_sha256"]:
            return {"source_verified": False}
        state = properties(config["unit"])
        success = None
        if (state.get("Type") == "oneshot" and state.get("ActiveState") == "inactive"
                and state.get("Result") == "success" and state.get("ExecMainCode") == "1"
                and state.get("ExecMainStatus") == "0"):
            start = datetime.strptime(state["ExecMainStartTimestamp"], "%a %Y-%m-%d %H:%M:%S %Z").replace(tzinfo=UTC)
            end = datetime.strptime(state["ExecMainExitTimestamp"], "%a %Y-%m-%d %H:%M:%S %Z").replace(tzinfo=UTC)
            if end >= start:
                success = end.timestamp()
        return {"source_verified": True, "last_success": success, "active_state": state.get("ActiveState")}
    except (OSError, KeyError, ValueError, subprocess.TimeoutExpired):
        return {"source_verified": False}


def frontend(name: str, address: str) -> dict:
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", name):
        raise ValueError("invalid frontend name")
    result = {}
    try:
        text = command(["/usr/bin/getent", "ahostsv4", name], timeout=3, limit=16384)
        result["addresses"] = sorted({r.split()[0] for r in text.splitlines()})
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        result["addresses"] = []
    try:
        context = ssl.create_default_context()
        for method in ("HEAD", "GET"):
            with socket.create_connection((address, 443), timeout=3) as plain:
                with context.wrap_socket(plain, server_hostname=name) as tls:
                    result["tls_verified"] = True
                    result["expires"] = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
                    tls.sendall(f"{method} / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode("ascii"))
                    buffer = b""
                    while b"\r\n" not in buffer and len(buffer) < 4096:
                        chunk = tls.recv(min(512, 4096 - len(buffer)))
                        if not chunk:
                            break
                        buffer += chunk
                    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", buffer.split(b"\r\n", 1)[0])
                    result["http_status"] = int(match[1]) if match else None
            if result["http_status"] != 405:
                break
    except ssl.SSLCertVerificationError as exc:
        result["tls_verified"] = False
        if exc.verify_code == 10:  # OpenSSL X509_V_ERR_CERT_HAS_EXPIRED
            result["expires"] = 0
    except (OSError, KeyError, ValueError):
        result["tls_verified"] = False
    return result


def kernel_errors(devices: dict) -> dict:
    """Return only categories/times for selected devices; never return raw kernel text."""
    try:
        text = command(["/usr/bin/journalctl", "-k", "--since=-15min", "-p", "err", "-n", "1000", "--no-pager", "-o", "json"], limit=4194304)
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "devices": {}}
    result = {}
    for line in text.splitlines():
        try:
            row = json.loads(line)
            message = row.get("MESSAGE", "")
            if not isinstance(message, str) or not re.search(r"I/O error|Buffer I/O error|EXT4-fs error|XFS.*corrupt|ntfs3?.*corrupt|remount.*read.only", message, re.I):
                continue
            timestamp = int(row["__REALTIME_TIMESTAMP"]) / 1000000
            for key, names in devices.items():
                if any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", message) for n in names):
                    result[key] = max(timestamp, result.get(key, 0))
        except (ValueError, KeyError, TypeError):
            continue
    return {"available": True, "devices": result}
