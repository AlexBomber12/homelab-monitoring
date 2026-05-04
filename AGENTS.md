# Mission

Run the homelab observability stack: Prometheus + Grafana, eventually fronted by Caddy.
Consumes metrics from products in adjacent repos.

# Workflow Rules

- All changes go through PRs targeting `main`.
- No direct commits to `main`.
- PR titles and commit messages follow Conventional Commits: `feat`, `fix`, `chore`, `refactor`, `docs`, `test`, `ci`, `perf`.
- For ad-hoc human-driven branches: use Conventional Commit prefixes plus a short kebab-case description (e.g. `feat/add-controller-status`).
- For pipeline-orchestrator daemon-driven PRs: use the daemon-managed branch naming rules appended during onboarding.
- CI must be green before merge.
- Approving reviews are not required because this is a solo repo.

# Code Style

- Use `shellcheck` for Bash scripts.
- Use `yamllint` for YAML files.
- Keep shell scripts explicit and portable unless a task requires Bash-specific behavior.
- Prefer readable configuration over clever templating.
- Pin externally consumed container image tags; do not use unpinned `:latest`.

# Testing

- Run `docker compose -f docker-compose.yml config` before opening PRs that touch Compose.
- Run `yamllint docker-compose.yml` before opening PRs that touch Compose.
- Run `shellcheck scripts/*.sh` when shell scripts exist.
- Tests and lint must not require contacting production services.

# Architecture Rules

- Use upstream container images unless a task explicitly introduces a custom service.
- Pin image tags for reproducibility.
- Keep Prometheus, Grafana, Caddy, and future stack-level services in this repository.
- Keep product exporters and application code in their own product repositories.
- Store persistent host data under `/srv/homelab-monitoring/`.
- Do not add product-specific application logic to this stack.

# Security Model

- Do not put secrets in code; load them from `.env` or the deployment environment.
- Services bind to loopback by default.
- Reverse proxy or VPN handles external access.
- Caddy terminates TLS when PR-050 adds public access.
- Grafana sign-up stays disabled.
- Default credentials must not be usable in production.
- Host data directories should be readable and writable only by the container UIDs that need them.

# Hardware Target

- Production host `192.168.50.2` running Ubuntu 24.04.
- Docker Engine with Docker Compose plugin.
- At least 4 GB RAM available for the monitoring stack and product services.

# Out Of Scope (For Now)

- Prometheus scrape config and retention tuning.
- Grafana datasource provisioning.
- Caddy reverse proxy and TLS.
- Dashboards.
- Custom container images.

# Communication

If a change touches the security model, network exposure, credential handling, or persistent
data paths, the PR description must explicitly call this out under a Risk heading.

# Note about pipeline-orchestrator daemon-managed sections

The sections below this note are appended automatically by the pipeline-orchestrator daemon
when this repository is onboarded. They describe how the daemon dispatches and reviews work.
They do not override project-specific rules above.

Project-specific equivalents for orchestrator-level concepts:

- This project has no Python test suite yet.
- This project has no external testbed repository.
- CI workflow: `.github/workflows/ci.yml` running shellcheck for future scripts and yamllint
  for `docker-compose.yml`.
- This project has no `task_status.py` module; it is not part of pipeline-orchestrator.
