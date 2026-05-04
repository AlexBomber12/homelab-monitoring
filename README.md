# Homelab Monitoring

Homelab Monitoring runs the shared Prometheus and Grafana stack for homelab products.
The first supported producer is MegaRAID Dashboard, which exposes Prometheus metrics at
`192.168.50.2:8091/metrics`. Future products such as sms-relay can join the same stack
without coupling their release cycle to observability infrastructure.

## Goals

- Provide one Prometheus + Grafana deployment for homelab services.
- Keep monitoring configuration separate from product application repositories.
- Use pinned upstream container images for reproducible deployments.
- Bind service ports to loopback by default until Caddy or a VPN exposes them intentionally.
- Store all monitoring data under `/srv/homelab-monitoring/`.

This repository currently bootstraps the stack and ships Prometheus scrape configuration
for MegaRAID Dashboard. Grafana provisioning, Caddy, TLS, and dashboards arrive in later
PRs.

## Architecture

```text
+----------------------+
| MegaRAID Dashboard   |
| 192.168.50.2:8091    |
| /metrics exporter    |
+----------+-----------+
           |
           v
+----------------------+
| Prometheus           |
| 127.0.0.1:9090       |
| TSDB under /srv      |
+----------+-----------+
           |
           v
+----------------------+        +----------------------+
| Grafana              | <----> | Operator browser     |
| 127.0.0.1:3000       |        | SSH tunnel for now   |
+----------+-----------+        +----------------------+
           ^
           |
+----------------------+
| Caddy reverse proxy  |
| optional, PR-050     |
+----------------------+
```

Prometheus scrapes product exporters. Grafana reads Prometheus and renders dashboards for
the operator. Caddy is intentionally not enabled yet; until that PR lands, access Grafana
and Prometheus over SSH tunnels or directly on the host.

## Prerequisites

- Ubuntu 24.04 host or equivalent Linux system.
- Docker Engine installed.
- Docker Compose plugin installed.
- At least 4 GB RAM available for monitoring plus the product services.
- Ports `3000` and `9090` available on loopback.
- Permission to create `/srv/homelab-monitoring/` and its child directories.
- MegaRAID Dashboard metrics exporter reachable from the Prometheus container network.

Check Docker:

```bash
docker --version
docker compose version
```

Check local port usage:

```bash
ss -ltnp | grep -E ':(3000|9090)\b' || true
```

## Install

Clone the repository on the monitoring host:

```bash
git clone https://github.com/AlexBomber12/homelab-monitoring.git
cd homelab-monitoring
```

Create the environment file:

```bash
cp .env.example .env
```

Edit `.env` and set a strong Grafana administrator password:

```text
GRAFANA_ADMIN_PASSWORD=replace-with-a-long-random-value
```

Create the host directory layout:

```bash
sudo mkdir -p /srv/homelab-monitoring/prometheus/etc
sudo mkdir -p /srv/homelab-monitoring/prometheus/data
sudo mkdir -p /srv/homelab-monitoring/grafana/data
sudo mkdir -p /srv/homelab-monitoring/grafana/provisioning
```

Set ownership for the container users:

```bash
sudo chown -R 65534:65534 /srv/homelab-monitoring/prometheus
sudo chown -R 472:472 /srv/homelab-monitoring/grafana
```

Install the Prometheus scrape configuration:

```bash
sudo cp prometheus/etc/prometheus.yml /srv/homelab-monitoring/prometheus/etc/prometheus.yml
sudo chown 65534:65534 /srv/homelab-monitoring/prometheus/etc/prometheus.yml
```

Validate the Compose model:

```bash
GRAFANA_ADMIN_PASSWORD=replace-me docker compose -f docker-compose.yml config
```

Start the stack:

```bash
docker compose up -d
```

## Verify

Confirm both containers are running:

```bash
docker compose ps
```

Check Prometheus health:

```bash
curl http://localhost:9090/-/healthy
```

Check Grafana health:

```bash
curl http://localhost:3000/api/health
```

Open Grafana through an SSH tunnel from your workstation:

```bash
ssh -L 3000:127.0.0.1:3000 192.168.50.2
```

Then browse to <http://localhost:3000/> and log in as `admin` with the password from `.env`.

## Smoke

Use this short smoke check after installation or upgrades:

```bash
docker compose pull
docker compose up -d
docker compose ps
curl --fail http://localhost:9090/-/healthy
curl --fail http://localhost:3000/api/health
```

If any command fails, inspect logs:

```bash
docker compose logs prometheus
docker compose logs grafana
```

## Operations

Persistent data lives on the host:

```text
/srv/homelab-monitoring/
|-- prometheus/
|   |-- etc/
|   |   `-- prometheus.yml
|   `-- data/
`-- grafana/
    |-- data/
    `-- provisioning/
```

Prometheus writes time-series data to `/srv/homelab-monitoring/prometheus/data`. Grafana
writes its SQLite database, plugins, and runtime state to
`/srv/homelab-monitoring/grafana/data`. Provisioned Grafana datasources and dashboards will
live under `/srv/homelab-monitoring/grafana/provisioning` after PR-049.

Upgrade containers:

```bash
docker compose pull
docker compose up -d
docker image prune
```

Back up Grafana state:

```bash
sudo tar -C /srv/homelab-monitoring -czf grafana-backup.tgz grafana
```

Back up Prometheus configuration:

```bash
sudo tar -C /srv/homelab-monitoring -czf prometheus-config-backup.tgz prometheus/etc
```

Prometheus data can be large. Back it up only if you need historical metrics after a host
rebuild; dashboards and scrape configuration are usually the higher-value backup targets.

If Grafana logs permission errors, confirm the bind mount owner:

```bash
sudo chown -R 472:472 /srv/homelab-monitoring/grafana
```

If Prometheus logs permission errors, confirm its bind mount owner:

```bash
sudo chown -R 65534:65534 /srv/homelab-monitoring/prometheus
```

## Adding A New Scrape Target

Use one job per product exporter with a stable target name, explicit host:port pair, and
labels that dashboards can rely on across product releases.

1. Edit `prometheus/etc/prometheus.yml` and add a new `scrape_configs` entry:

```yaml
- job_name: megaraid-dashboard
  static_configs:
    - targets:
        - "192.168.50.2:8091"
      labels:
        host: nas
        product: megaraid-dashboard
```

2. Validate the file:

```bash
yamllint prometheus/etc/prometheus.yml
```

3. Copy the updated config to the host bind mount:

```bash
sudo cp prometheus/etc/prometheus.yml /srv/homelab-monitoring/prometheus/etc/prometheus.yml
sudo chown 65534:65534 /srv/homelab-monitoring/prometheus/etc/prometheus.yml
```

4. Reload Prometheus without restarting when it is already running:

```bash
docker compose exec prometheus kill -HUP 1
```

If reload fails or Prometheus is not running yet, restart the service:

```bash
docker compose restart prometheus
```

5. Confirm the target appears in Prometheus before building Grafana panels:

```bash
curl http://localhost:9090/api/v1/targets
```

Keep exporters in their product repositories. Bind exporters to private addresses or
protect them with firewall rules, and keep this repository limited to scrape
configuration.

## Development

Run local validation before opening PRs:

```bash
GRAFANA_ADMIN_PASSWORD=replace-me docker compose -f docker-compose.yml config
yamllint -d "{extends: default, rules: {line-length: {max: 160}}}" docker-compose.yml
if compgen -G "scripts/*.sh" > /dev/null; then shellcheck scripts/*.sh; fi
```

The CI workflow mirrors these checks for Compose and future shell scripts.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
