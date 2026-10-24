# Homelab Monitoring — Telegram notification foundation

**Status:** initial review candidate, not yet deployed. See [issue #3](https://github.com/AlexBomber12/homelab-monitoring/issues/3).

This is a deliberately small, dependency-free Linux notification primitive. It does not install packages, read arbitrary server files, restart services, execute remote commands, or grant ChatGPT extra permissions.

## Existing infrastructure contract

- The user has created the **private** `Homelab Infrastructure` Telegram channel and a dedicated Telegram bot. The two existing hosts have already successfully delivered independent manual test messages.
- Separate bot token and numeric private-channel ID files already exist, owned by root, mode 0600, under `/etc/homelab-monitoring` on each host.
- Incoming SMS content/phone numbers remain in the current SMS Gateway workflow, **not** this channel.
- MegaRAID email notifications remain untouched. A separate [MegaRAID issue](https://github.com/AlexBomber12/megaraid-dashboard/issues/120) covers independent Telegram delivery state alongside existing SMTP.
- SERVER hosts the central OpenAI Tunnel and Inspector; AI-Server must report SERVER connectivity failures independently. Inspector stays strictly read-only.

## Components

One Python 3.12 file, SQLite from stdlib, two tiny systemd timers per host. No server, web endpoint, background daemon, Docker image, Prometheus stack, or third-party Python packages.

- `enqueue`: add an idempotent event to a durable bounded local queue by caller-supplied event key (max 1000 unsent).
- `flush`: send queued plain-text events to Telegram HTTPS Bot API, at most 20 each minute, with retry/backoff and handling of Telegram 429 retry-after.
- `probe-ssh`: connect to a specified fixed IPv4:port and verify it responds with an SSH protocol banner; generate one CRITICAL event after 3 consecutive failures and one RECOVERED when reachable again. Healthy initial state and repeat failures are quiet.
- State is stored under `/var/lib/homelab-monitoring/` with owner-only 0700 directory and SQLite file mode 0600.
- Credentials are read only by root at flush time, never included in command arguments or logs.

**Limitations:** SSH banner reachability is not an application-level health test and does not prove RAID, disk, backup or MCP health. Delivery is **at least once**, not exactly once: a crash between successful Bot API response and SQLite acknowledgement can duplicate a Telegram message. A bot outage can temporarily delay queued messages; queue overflow fails closed. The initial implementation does not yet send independent self-failure notifications if both hosts or Telegram itself are unavailable.

## Offline validation

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile homelab_notify.py
```

Tests use only temporary SQLite databases and mocked Telegram calls. They must not read actual credentials or reach production servers.

## Proposed controlled deployment (NOT performed by this PR)

1. Review source, tests and systemd units. Confirm that the real existing protected token/chat-id files are present on both hosts without printing their content.
2. Install reviewed `homelab_notify.py` at `/opt/homelab-monitoring/homelab_notify.py` (root 0644). Create `/var/lib/homelab-monitoring` as root-owned 0700.
3. Create a root-only `/etc/homelab-monitoring/peer.env`, mode 0600:
    - On AI-Server: `MONITOR_LOCAL_LABEL=AI-Server`, `MONITOR_PEER_LABEL=SERVER`, `MONITOR_PEER_IPV4=192.168.50.2`.
    - On SERVER: `MONITOR_LOCAL_LABEL=SERVER`, `MONITOR_PEER_LABEL=AI-Server`, `MONITOR_PEER_IPV4=192.168.50.4`.
   Validate unit environment and its supported systemd variable substitution on an isolated test machine. Keep host-specific data out of the public repository where feasible.
4. Install reviewed sample units from `deploy/systemd/`, `systemd-analyze verify`, `systemctl daemon-reload`; first run a **manual** probe and queue flush in a controlled test.
5. Temporarily simulate a peer SSH probe failure **using a disposable test target** rather than blocking live SSH or rebooting SERVER. Confirm three-failure alert, single recovery, deduplication and retry. Never change production firewall rules to simulate a fault.
6. Enable `homelab-telegram-flush.timer` and `homelab-peer-ssh.timer` one host at a time after explicit operator approval; check service hardening and independent Telegram delivery.
7. Add service-specific event producers only after each check's state machine and failure semantics are tested; do not make backup, RAID, SMS or UPS notification depend on a central SERVER-only process.

Example queued synthetic event (does **not** send until flush runs):

```sh
sudo python3 /opt/homelab-monitoring/homelab_notify.py enqueue \
  --origin AI-Server --severity INFO --event-key initial_probe_test \
  --text 'Infrastructure notifier ready'
sudo python3 /opt/homelab-monitoring/homelab_notify.py flush
```

**Secrets:** never copy token, protected config, private chat ID or real hardware alert contents into public PR comments, CI logs or plain-text Obsidian.

## Safety and maintenance

- Generic email/Telegram notification policy and future maintenance/reboot integration are documented in private Obsidian `20-homelab/infrastructure-inspector-maintenance-policy.md`.
- This repository does not manage `apt`, Docker Engine, updates, reboot, SSH privileges, RAID configuration or backup state. They will remain separate reviewed changes.
- Do not change SMS Gateway delivery, MegaRAID SMTP or production Inspector/Tunnel to deploy this foundation.
