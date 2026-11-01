"""Pure local alert decisions and durable incident transitions; no host/network I/O."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import math
import sqlite3
import uuid

import homelab_notify as outbox


@dataclass(frozen=True)
class Observation:
    key: str
    level: str  # ok, idle, warning, critical
    code: str
    title: str
    consequence: str
    evidence: str
    delay: int = 300
    recoverable: bool = True


def ups(key: str, data: dict) -> Observation:
    base = (key, "warning", "ups_unknown", "нет свежих данных UPS",
            "Нельзя подтвердить исправность резервного питания.", "UPS: telemetry unavailable", 300)
    if not data.get("available"):
        return Observation(*base)
    flags = set(data.get("ups.status", []))
    v = data.get("values", {})
    runtime = v.get("battery.runtime")
    charge = v.get("battery.charge")
    critical = bool(flags & {"FSD", "OVER", "OFF"}) or ("OB" in flags and (
        "LB" in flags or (runtime is not None and runtime <= 300)
        or (charge is not None and charge <= (v.get("battery.charge.low") if v.get("battery.charge.low") is not None else 10))))
    if critical:
        return Observation(key, "critical", "ups_power_danger", "UPS сообщает об угрозе питанию",
                           "Возможно скорое отключение оборудования и потеря незаписанных данных.",
                           "UPS: " + " ".join(sorted(flags)) + (f"; remaining={int(runtime)}s" if runtime is not None else ""), 0)
    if "RB" in flags or data.get("alarm_present"):
        return Observation(key, "warning", "ups_service", "UPS требует проверки батареи или аварийного состояния",
                           "Резервное питание может не обеспечить ожидаемую защиту.", "UPS: persistent maintenance flag", 900)
    if data.get("unknown_status_present") or not flags & {"OL", "OB"} or ("OB" in flags and runtime is None and charge is None):
        return Observation(*base)
    return Observation(key, "ok", "ups_ok", "UPS", "", "")


def storage(key: str, data: dict, limits: dict) -> list[Observation]:
    if data.get("idle"):
        return [Observation(key, "idle", "automount_idle", "диск ожидает обращения", "", "")]
    if not data.get("mounted") or data.get("error"):
        return [Observation(key, "warning", "mount_unavailable", "том хранения недоступен",
                            "Приложения могут потерять доступ к данным. Не записывайте файлы в пустую точку монтирования.",
                            "mount: missing, failed or unverifiable", 300)]
    if data.get("read_only"):
        return [Observation(key, "critical", "filesystem_read_only", "файловая система перешла в режим только чтения",
                            "Сохранение данных нарушено; возможна неисправность хранения.", "filesystem: read-only", 0)]
    free = data["available_bytes"]
    inode_low = data.get("total_inodes", 0) and data.get("free_inodes", 0) < max(1000, data["total_inodes"] * 0.01)
    inode_critical = data.get("total_inodes", 0) and data.get("free_inodes", 0) <= 1000
    if free < limits["critical_bytes"] or inode_critical:
        level, code, delay = "critical", "space_critical", 0
    elif free < limits["warning_bytes"] or inode_low:
        level, code, delay = "warning", "space_low", 300
    else:
        return [Observation(key, "ok", "space_ok", "хранилище", "", "")]
    return [Observation(key, level, code, "заканчивается место или запас файловых записей",
                        "Запись данных и резервное копирование могут прекратиться. Не удаляйте данные наугад.",
                        f"available={free // 2**30} GiB", delay)]


def backup(key: str, data: dict, now: float, max_age: int) -> Observation:
    success = data.get("last_success")
    if not data.get("source_verified") or type(success) not in (int, float) or not math.isfinite(success) or success > now + 60:
        return Observation(key, "warning", "backup_unverified", "не удаётся подтвердить успешную облачную копию",
                           "Свежесть настроенной копии неизвестна; сохранность остальных данных этим заданием не проверяется.",
                           "backup: no trusted completion receipt", 900)
    if now - success > max_age:
        return Observation(key, "warning", "backup_stale", "облачная копия давно не обновлялась",
                           "Нет подтверждённого успешного завершения задания за допустимый интервал.",
                           f"last_success={datetime.fromtimestamp(success, UTC).isoformat(timespec='minutes')}; age_hours={int((now-success)//3600)}", 300)
    return Observation(key, "ok", "backup_fresh", "облачная копия", "", "")


def frontend(key: str, data: dict, expected_ip: str) -> list[Observation]:
    rows = []
    good_dns = data.get("addresses") == [expected_ip]
    rows.append(Observation(key + ".dns", "ok" if good_dns else "warning", "dns_ok" if good_dns else "dns_wrong",
                            "локальное имя разрешается неправильно", "Доступ к домашним сервисам может быть нарушен.",
                            "DNS: expected private address" if not good_dns else "", 300))
    good_http = data.get("tls_verified") and data.get("http_status") in (200, 204, 301, 302, 303, 307, 308, 401, 403)
    rows.append(Observation(key + ".https", "ok" if good_http else "warning", "https_ok" if good_http else "https_failed",
                            "HTTPS-вход сервиса не проходит проверку", "Сервис может быть недоступен или соединение не подтверждено сертификатом.",
                            "HTTPS: TLS/HTTP check failed" if not good_http else "", 300))
    return rows


def certificate(key: str, expires: float | None, now: float) -> Observation:
    if expires is None:
        return Observation(key, "warning", "certificate_unknown", "не удаётся проверить срок сертификата",
                           "Нельзя подтвердить, что HTTPS останется доступным.", "certificate: unavailable", 900)
    remaining = expires - now
    if remaining <= 86400:
        return Observation(key, "critical", "certificate_critical", "HTTPS-сертификат истёк или истекает в течение суток",
                           "Браузеры могут перестать открывать домашние сервисы безопасно.",
                           f"expires_utc={int(expires)}", 0)
    if remaining <= 7 * 86400:
        return Observation(key, "warning", "certificate_expiring", "HTTPS-сертификат скоро истекает",
                           "Автоматическое продление нужно проверить до истечения сертификата.",
                           f"expires_utc={int(expires)}", 900)
    return Observation(key, "ok", "certificate_ok", "HTTPS-сертификат", "", "")


def frontend_group(items: list[tuple[str, dict]], expected_ip: str) -> list[Observation]:
    rows = [o for name, data in items for o in frontend("web." + name, data, expected_ip)]
    for suffix, key, title in ((".dns", "frontend.dns", "локальный DNS не проходит проверку для всех сервисов"),
                               (".https", "frontend.https", "все проверяемые HTTPS-входы недоступны")):
        selected = [o for o in rows if o.key.endswith(suffix)]
        shared = len(selected) > 1 and all(o.level == "warning" for o in selected)
        if shared:
            rows = [Observation(o.key, "idle", "covered_by_shared_incident", "", "", "") if o in selected else o for o in rows]
        rows.append(Observation(key, "warning" if shared else "ok", "shared_frontend_failure" if shared else "shared_frontend_ok",
                                title, "Доступ к домашним сервисам может быть нарушен.",
                                f"affected_frontends={len(selected)}" if shared else "", 300))
    return rows


def message(origin: str, observation: Observation, now: float, runbook: str) -> str:
    priority = "СРОЧНО" if observation.level == "critical" else "Требует внимания"
    return (f"{priority} — {origin}: {observation.title}.\n{observation.consequence}\n"
            "Проверка не меняет настройки оборудования и не перезапускает службы.\n"
            "Передайте сообщение в ChatGPT для проверки и безопасного плана действий.\n"
            f"Диагностика: {observation.key} / {observation.code}; {datetime.fromtimestamp(now, UTC).isoformat(timespec='seconds')}; {observation.evidence}\n"
            f"Инструкция: {runbook}")


def observe(db: sqlite3.Connection, o: Observation, now: float, origin: str, runbook: str) -> str:
    """Serialize observation, stale-event cancellation and enqueue in one SQLite transaction."""
    outbox._label(o.key)
    if o.level not in ("ok", "idle", "warning", "critical"):
        raise ValueError("invalid observation")
    db.execute("CREATE TABLE IF NOT EXISTS local_incidents (key TEXT PRIMARY KEY, state TEXT NOT NULL)")
    with outbox._tx(db):
        row = db.execute("SELECT state FROM local_incidents WHERE key=?", (o.key,)).fetchone()
        s = json.loads(row[0]) if row else {}
        previous = s.get("event")
        receipt = db.execute("SELECT sent_at FROM outbound WHERE event_key=?", (previous,)).fetchone() if previous else None
        delivered = receipt is not None and receipt[0] is not None
        if delivered:
            s["notified"] = receipt[0]
        if now < s.get("seen", now) or now - s.get("seen", now) > 180:
            s.pop("since", None)
            s.pop("healthy", None)
        s["seen"] = now
        action = "quiet"
        if o.level in ("ok", "idle"):
            if previous and not delivered and s.get("recoverable", True):
                db.execute("DELETE FROM outbound WHERE event_key=? AND sent_at IS NULL", (previous,))
                s.pop("event", None)
            s.pop("since", None)
            if o.level == "ok" and s.get("notified") is not None and s.get("recoverable", True):
                s.setdefault("healthy", now)
                if now - s["healthy"] >= 120:
                    # Recovery is eligible only after a delivered incident, never a green heartbeat.
                    recovery = s.get("recovery")
                    if not recovery:
                        recovery = "recovered_" + uuid.uuid4().hex
                        outbox._enqueue_tx(db, recovery, f"{origin}: ранее сообщённая проблема {o.key} устранена.\n"
                                           "Действие по предыдущему уведомлению больше не требуется.\n"
                                           f"Инструкция: {runbook}", now)
                        s["recovery"] = recovery
                        action = "recovery_queued"
                    recovered = db.execute("SELECT sent_at FROM outbound WHERE event_key=?", (recovery,)).fetchone()
                    if recovered and recovered[0] is not None:
                        s = {"seen": now}
            else:
                s.pop("healthy", None)
            if s.get("notified") is None and s.get("recoverable", True):
                s = {"seen": now}
        else:
            # Never deliver a queued recovery after the problem has returned.
            if s.get("recovery"):
                db.execute("DELETE FROM outbound WHERE event_key=? AND sent_at IS NULL", (s.pop("recovery"),))
            s.pop("healthy", None)
            s.setdefault("since", now)
            worsened = o.level == "critical" and s.get("peak_level") == "warning"
            ready = now - s["since"] >= o.delay
            pending = previous and receipt is not None and not delivered
            if worsened and pending:
                db.execute("DELETE FROM outbound WHERE event_key=? AND sent_at IS NULL", (previous,))
                pending = False
            due = s.get("notified") is None or now - s["notified"] >= 86400 or worsened
            if ready and not pending and due:
                event = ("critical_" if o.level == "critical" else "warning_") + uuid.uuid4().hex
                outbox._enqueue_tx(db, event, message(origin, o, now, runbook), now)
                s["event"] = event
                if s.get("peak_level") != "critical":
                    s["peak_level"] = o.level
                action = "incident_queued"
            s["level"] = o.level
            s["recoverable"] = o.recoverable
        s["code"] = o.code
        db.execute("INSERT OR REPLACE INTO local_incidents VALUES (?,?)", (o.key, json.dumps(s)))
    return action
