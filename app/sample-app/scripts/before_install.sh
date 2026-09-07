#!/bin/bash
# BeforeInstall -- prepare the host for the incoming revision.
#
# Deliberately removes the previous revision's files rather than merging over
# them. A partially-overwritten directory is how a deployment ends up running a
# mix of two releases, which is unreviewable and therefore unauditable.
set -euo pipefail

APP_DIR=/opt/hipaa-demo-app
SERVICE_USER=appuser

echo "verifying runtime"
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is not installed on this instance" >&2
  exit 1
fi
node --version

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "creating service account $SERVICE_USER"
  useradd --system --home-dir "$APP_DIR" --shell /sbin/nologin "$SERVICE_USER"
fi

# Preserve logs across releases; they are the audit record for this host and
# may not yet have been shipped to CloudWatch.
if [ -d "$APP_DIR" ]; then
  echo "clearing previous revision (keeping logs/)"
  find "$APP_DIR" -mindepth 1 -maxdepth 1 ! -name logs -exec rm -rf {} +
fi

mkdir -p "$APP_DIR/logs"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 0750 "$APP_DIR"

echo "before_install complete"
