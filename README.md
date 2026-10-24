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

## Reproducible deployment (review candidate only)

The application, systemd templates, deployment logic and tests are all versioned in this repository. See [Ansible deployment and recovery](deploy/ansible/README.md) for one code path for SERVER and AI-Server.

The command `bash deploy/deploy.sh plan ROLE PEER_IPV4 REVIEWED_SHA` is read-only (Ansible check mode), `apply` installs reviewed files and verifies them but **does not enable timers**, `activate` enables automated checks only after separate approval, and `deactivate` stops both timers without deleting credentials or queued events.

Ansible is only needed on the deployment controller; the notifier runtime remains Python stdlib and systemd. Bot token and numeric private-channel ID are still protected root-owned files outside Git, never passed to Ansible. The same Git revision is deployed on each host with its declared role and peer IP. A clean reinstall requires separately restored encrypted credentials; this repository does not yet provide an encrypted off-host backup.

Rollback of an upgraded notifier means deactivating, checking out the previous reviewed Git commit, applying and verifying that version, then activating after smoke tests. This is not yet an automatic transactional rollback. No production timers have been enabled by this PR.

## Safety and maintenance

- Generic email/Telegram notification policy and future maintenance/reboot integration are documented in private Obsidian `20-homelab/infrastructure-inspector-maintenance-policy.md`.
- This repository does not manage `apt`, Docker Engine, updates, reboot, SSH privileges, RAID configuration or backup state. They will remain separate reviewed changes.
- Do not change SMS Gateway delivery, MegaRAID SMTP or production Inspector/Tunnel to deploy this foundation.
