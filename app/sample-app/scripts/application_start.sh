#!/bin/bash
# ApplicationStart -- bring the new revision up.
set -euo pipefail

SERVICE=hipaa-demo-app

systemctl enable "$SERVICE"
systemctl start "$SERVICE"

# Fail fast here rather than leaving ValidateService to time out: a unit that
# refuses to start is a clearer failure signal in the deployment log.
for _ in $(seq 1 15); do
  if systemctl is-active --quiet "$SERVICE"; then
    echo "$SERVICE is running"
    exit 0
  fi
  sleep 1
done

echo "ERROR: $SERVICE failed to start" >&2
systemctl status "$SERVICE" --no-pager || true
journalctl -u "$SERVICE" -n 50 --no-pager || true
exit 1
