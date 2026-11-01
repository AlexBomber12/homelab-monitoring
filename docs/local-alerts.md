# Local important alerts

This profile checks local UPS telemetry, selected storage filesystems, an existing
backup job and named HTTPS frontends. It does not monitor machine reachability,
install a remote agent, restart applications or change backup/UPS/ACME settings.
Healthy checks are silent. Private host inventory and credentials stay outside Git.

## Incident rules

| Source | Alert condition | Confirmation |
|---|---|---|
| UPS power | On battery with LB, <=5 minutes runtime or low charge; FSD/OVER/OFF | Immediate |
| UPS maintenance | RB or a persistent alarm | 15 minutes |
| UPS telemetry | Fresh data unavailable | 5 minutes |
| Storage | Real filesystem read-only or a new selected-device kernel I/O error | Immediate |
| Storage capacity | Below configured critical reserve or <=1000 available inodes | Immediate |
| Storage capacity | Below configured warning reserve or <1% available inodes | 5 minutes |
| Mount | Missing, wrong device or inaccessible | 5 minutes |
| Backup | No trustworthy successful completion | 15 minutes |
| Backup | Last confirmed completion exceeds the configured age | 5 minutes |
| DNS or HTTPS | Wrong private address, failed verified TLS or unexpected HTTP result | 5 minutes |
| Certificate | <=7 days remaining | 15 minutes |
| Certificate | Expired or <=24 hours remaining | Immediate |

Runtime thresholds and device identity belong in the private operator configuration.
UPS data unavailable is a telemetry problem, not proof of hardware failure. Normal
on-battery transitions do not alert unless the available protection becomes dangerous.

An idle systemd automount is not a missing disk. The collector does not access its
contents to wake it. Active autofs plus backing-filesystem entries are distinguished.
Filesystem superblock read-only flags are used so the service's own read-only bind
mounts do not generate false alarms. Per-mount-only restrictions outside this
namespace cannot be inferred from that check; kernel errors provide another signal.

HTTPS HEAD=405 is retried using GET / without following redirects or reading page
contents. Expected redirects and 401/403 are valid frontend responses. Authentication
responses verify the TLS/frontend path, not the protected backend application's health.
Certificate monitoring uses the certificate actually served over verified TLS.
When all checked names fail the same DNS or HTTPS check, one shared incident replaces
the individual warnings for that category. Individual service failures remain distinct.

Backup success requires a matching operator-reviewed unit definition, oneshot type,
normal exit and exit status zero. A running process is not a successful backup.
Confirmed completions persist independently of transient systemd invocation state.
This does not prove backup content integrity, version history or restoration ability.

## Delivery and recovery

One incident is tracked per resource. Repeated checks are quiet; an unresolved problem
may remind once a day, and escalation from warning to critical is immediate. Critical
queue items have priority. SQLite state, delivery leases and backoff survive restart.
Pending warnings are removed when they become stale before delivery. Recovery requires
a previously delivered incident and two minutes of valid healthy observations. A queued
recovery is cancelled on relapse. A kernel I/O error is not declared repaired simply
because the journal becomes quiet.

The existing bounded outbox retries Telegram errors without exposing credential-bearing
URLs or response bodies. Delivery is at least once; ambiguous network outcomes may
duplicate a message. Telegram failure does not stop the monitored applications.
Credentials are read from per-unit systemd credentials, not command arguments or Git.

## Diagnosis

The owner checks the local observer with:

```sh
systemctl status homelab-local-alerts.timer homelab-local-alerts.service
```

The restricted agent can read `diagnostics.important_alerts` after installation. It
returns freshness, counters and safe observation codes, not credentials or full logs.
A stale report does not prove the observer is healthy. `pending_events` can indicate
delivery backlog; no messages during healthy operation is expected.

Forward the notification and this runbook to the next troubleshooting chat. First
check facts and timestamps. Do not delete files, change disks, reboot, force a backup
or renew certificates as an automatic response to an alert. Kernel diagnostics must
keep private filenames out of Telegram and reports.

## Installation and rollback

The versioned owner installer accepts a separately prepared, hash-verified private
payload. It creates a dedicated non-login service account and no SSH/sudo/maintenance
grants. A same-identity systemd probe validates the actual Telegram credentials with
sending disabled before activation. It does not make a Telegram delivery attempt.
Both owner-only credential files and systemd's root-owned, named-user read-only ACL
are supported. A readable Unix group, other users, write access, symlinks, oversized
files or multiple hard links are rejected. File metadata and contents use one descriptor.
It must report a healthy or intentionally idle baseline. Existing application identities
and protected policies are compared before and after. No OS packages are installed.

Only the local timer is enabled. Existing peer reachability and standalone flush timers
are not deployed by this profile. The installed status-reader operation is read-only.

On failure the installer deactivates the local timer, restores the previous dispatcher
and removes exact-hash owned executable/unit files. Credential and outbox state remain
protected for diagnosis. A root-owned failure report exposes only constant collector
error codes, not raw journal messages or credentials, for restricted workspace retrieval.
The installation report gives the exact owner rollback command.
That command deactivates notifications while preserving monitored data and queued history.
An interrupted/failed preparation may be resumed with a reviewed `--resume` launch only
after the rollback receipt and all existing ownership/configuration checks pass.

No real UPS power failure, disk error, private SMS or production backup is used as a
test fixture. Synthetic tests cover fault decisions, deduplication, unsent cancellation,
conditional recovery, mounted/idle distinctions and rollback. The final target-side
systemd probe verifies current permissions and source access before activation.

## Reference semantics

* [NUT upsc](https://networkupstools.org/docs/man/upsc) and
  [critical UPS states](https://networkupstools.org/docs/user-manual.chunked/ar01s06.html).
* [Linux mountinfo per-mount and superblock options](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html).
* [systemd credentials and filesystem restrictions](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html),
  and [systemd 255 credential ACL creation](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c#L176).
