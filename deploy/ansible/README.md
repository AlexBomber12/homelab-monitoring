# Infrastructure as Code: Homelab Telegram

This is the deployment source of truth for the same notifier on SERVER and
AI-Server. The application itself needs Python 3 and systemd only.
Ansible Core is a deployment-time controller dependency, not a runtime daemon.

**Status: draft, not approved for unattended production activation.**
Source/units live in Git, host-specific peer IPv4 lives in protected peer.env,
Telegram bot token and channel ID remain in root-owned 0600 files outside Git.
The outbox SQLite state is preserved and is never copied by this deployment.

## Safe first rollout

On the *target* Linux host, get an operator-reviewed, clean Git checkout at a
specific commit. Install Ansible Core in the admin environment first (no
unattended package changes to SERVER are part of this playbook). Run these
commands as the normal sudo-capable administrator, not through restricted
Inspector SSH and not as root over SSH:

    bash deploy/deploy.sh plan ai-server VERIFIED_SERVER_IPV4 FULL_SHA
    bash deploy/deploy.sh apply ai-server VERIFIED_SERVER_IPV4 FULL_SHA
    bash deploy/deploy.sh verify ai-server VERIFIED_SERVER_IPV4 FULL_SHA

On SERVER use role "server" and AI-Server's verified private IPv4 instead.
The runner fails if role does not match local hostname, if peer is not a
literal RFC1918 IPv4, if the Git revision differs, or if the checkout is dirty.

The plan command uses Ansible check-mode. Apply creates and maintains only:
- /opt/homelab-monitoring/homelab_notify.py
- /etc/systemd/system/homelab-peer-ssh.service and .timer
- /etc/systemd/system/homelab-telegram-flush.service and .timer
- /etc/homelab-monitoring/peer.env (non-secret, private mode 0600)
- /var/lib/homelab-monitoring (existing outbox data retained)

Apply runs verification and does **not** enable timers. Once smoke/denial
tests are approved, use:

    bash deploy/deploy.sh activate ai-server VERIFIED_SERVER_IPV4 FULL_SHA

This action is separated so the user explicitly controls the first real
activation. To pause both timers, preserving credentials and outbox:

    bash deploy/deploy.sh deactivate ai-server VERIFIED_SERVER_IPV4 FULL_SHA

No secrets need be passed to these commands. Ansible prompts locally for
sudo privileges.

## Verification and rollback

A rerun is idempotent: identical file content is not reinstalled, and systemd
is reloaded only when a unit changes. The playbook checks ownership/permissions
of existing token and channel-ID files without reading their contents. It
verifies the installed Python file hash against the reviewed checkout.

For a failed activation, use the **deactivate** action. To restore the previous
known-good application version: deactivate, check out the previous verified
commit, run its apply and verify, and activate only after smoke tests. This is
a documented rollback **procedure**, not an atomic automated upgrade/rollback.
Production auto-updates must not rely on it until a release manifest,
encrypted off-host backup, and fault-injected release promotion are complete.

After clean Ubuntu reinstall, restore the token/channel ID and other private
configuration from an independently verified encrypted off-host backup.
Neither this PR nor the earlier same-host Inspector snapshot creates that
secret backup. If the backup does not exist, recovery requires reissuing the
Telegram bot token and re-authorizing the channel.

Do not change SMS Gateway message forwarding, MegaRAID SMTP, Docker,
Inspector/Tunnel, SSH audit restrictions or OS package update policies
as part of this rollout. The peer SSH banner is *reachability only*, not
full service health. All notifications are at-least-once.
