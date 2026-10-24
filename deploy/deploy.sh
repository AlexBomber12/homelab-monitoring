#!/usr/bin/env bash
# One code path on both hosts. Default apply never enables timers.
set -Eeuo pipefail
if [ "$#" -ne 4 ]; then
  echo "Usage: bash deploy/deploy.sh plan|apply|verify|activate|deactivate ROLE PEER_IPV4 REVIEWED_COMMIT_SHA" >&2
  exit 2
fi
action="$1"
role="$2"
peer_ip="$3"
expected_rev="$4"
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
case "$action" in plan|apply|verify|activate|deactivate) ;; *) echo "Unknown action" >&2; exit 2 ;; esac
case "$role" in server|ai-server) ;; *) echo "Unknown host role" >&2; exit 2 ;; esac
if ! [[ "$expected_rev" =~ ^[a-f0-9]{40}$ ]]; then
  echo "Use a full reviewed Git commit SHA" >&2
  exit 2
fi
for program in git python3 ansible-playbook; do
  command -v "$program" >/dev/null || { echo "Missing prerequisite: $program" >&2; exit 2; }
done
test "$(git -C "$repo" rev-parse HEAD)" = "$expected_rev" || {
  echo "Unreviewed source revision; refusing deployment" >&2
  exit 2
}
test -z "$(git -C "$repo" status --porcelain)" || {
  echo "Source checkout is dirty; refusing deployment" >&2
  exit 2
}
python3 "$repo/deploy/validate_peer_ip.py" "$peer_ip"
local_hostname="$(hostname | tr '[:upper:]' '[:lower:]')"
if [ "$role" = ai-server ]; then expected_hostname="ai-server"; else expected_hostname="server"; fi
if [ "$local_hostname" != "$expected_hostname" ]; then
  echo "Selected host role does not match local hostname" >&2
  exit 2
fi
case "$action" in
  plan)
    ansible-playbook -i localhost, --connection local --ask-become-pass \
      -e "monitoring_role=$role" -e "monitoring_peer_ipv4=$peer_ip" \
      --check --diff "$repo/deploy/ansible/site.yml"
    ;;
  apply)
    ansible-playbook -i localhost, --connection local --ask-become-pass \
      -e "monitoring_role=$role" -e "monitoring_peer_ipv4=$peer_ip" \
      "$repo/deploy/ansible/site.yml" --tags preflight,install,verify
    ;;
  verify)
    ansible-playbook -i localhost, --connection local --ask-become-pass \
      -e "monitoring_role=$role" -e "monitoring_peer_ipv4=$peer_ip" \
      "$repo/deploy/ansible/site.yml" --tags preflight,verify
    ;;
  activate)
    ansible-playbook -i localhost, --connection local --ask-become-pass \
      -e "monitoring_role=$role" -e "monitoring_peer_ipv4=$peer_ip" \
      -e monitoring_activate=true "$repo/deploy/ansible/site.yml" \
      --tags preflight,verify,activate
    ;;
  deactivate)
    ansible-playbook -i localhost, --connection local --ask-become-pass \
      "$repo/deploy/ansible/deactivate.yml"
    ;;
esac
