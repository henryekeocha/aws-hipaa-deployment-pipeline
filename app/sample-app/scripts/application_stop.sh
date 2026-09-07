#!/bin/bash
# ApplicationStop -- runs on the outgoing revision before its files are touched.
#
# Must succeed on a host that has never run this application (the first
# deployment, and every instance in a freshly provisioned green fleet), so
# "not installed" is a success, not a failure.
set -euo pipefail

SERVICE=hipaa-demo-app

if systemctl list-unit-files | grep -q "^$SERVICE.service"; then
  echo "stopping $SERVICE"
  # Graceful: systemd sends SIGTERM, server.js reports unhealthy, drains, exits.
  systemctl stop "$SERVICE" || true

  for _ in $(seq 1 30); do
    if ! systemctl is-active --quiet "$SERVICE"; then
      echo "$SERVICE stopped"
      exit 0
    fi
    sleep 1
  done

  echo "ERROR: $SERVICE did not stop within 30s" >&2
  exit 1
fi

echo "$SERVICE not installed; nothing to stop"
