#!/bin/bash
# AfterInstall -- wire up configuration and the service unit.
#
# THE SECRETS STORY
# Configuration is pulled from Parameter Store at deploy time using the
# instance's own IAM role. Nothing sensitive is in the bundle, in the AMI, in
# user-data or in this repository. The instance role can read one Parameter
# Store path and can decrypt SecureStrings only through Systems Manager, so
# even a full copy of this bundle is worthless to an attacker without that role.
set -euo pipefail

APP_DIR=/opt/hipaa-demo-app
CONFIG_DIR=/etc/hipaa-demo-app
SERVICE_USER=appuser
SERVICE=hipaa-demo-app

# IMDSv2: a token is required before the metadata service will answer, which is
# why a blind SSRF against the application cannot read these values.
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
REGION=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/placement/region)
INSTANCE_ID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)

# PARAMETER_PATH is written by the Terraform-rendered user-data script.
# shellcheck disable=SC1091
[ -f "$CONFIG_DIR/app.env" ] && . "$CONFIG_DIR/app.env"
PARAMETER_PATH="${PARAMETER_PATH:-/hipaa-demo/prod/app}"
APP_PORT="${APP_PORT:-8080}"

echo "loading configuration from $PARAMETER_PATH"
mkdir -p "$CONFIG_DIR"
TMP_ENV=$(mktemp)
# umask before writing: the file must never briefly exist as world-readable.
chmod 0600 "$TMP_ENV"

{
  echo "APP_PORT=$APP_PORT"
  echo "AWS_REGION=$REGION"
  echo "PARAMETER_PATH=$PARAMETER_PATH"
  echo "RELEASE_ID=${DEPLOYMENT_ID:-manual}-${INSTANCE_ID}"
} >> "$TMP_ENV"

# --with-decryption is what exercises the KMS grant. Values are never echoed to
# stdout, because deployment logs are shipped to CloudWatch and a secret in a
# log is a secret in one more place than it should be.
if aws ssm get-parameters-by-path \
  --path "$PARAMETER_PATH" \
  --with-decryption \
  --region "$REGION" \
  --query 'Parameters[].[Name,Value]' \
  --output text > /tmp/params.tsv 2>/dev/null; then
  while IFS=$'\t' read -r name value; do
    [ -z "$name" ] && continue
    key=$(basename "$name" | tr '[:lower:]-' '[:upper:]_')
    printf '%s=%s\n' "$key" "$value" >> "$TMP_ENV"
  done < /tmp/params.tsv
  echo "loaded $(wc -l < /tmp/params.tsv) parameters"
  shred -u /tmp/params.tsv 2>/dev/null || rm -f /tmp/params.tsv
else
  echo "WARNING: no parameters found under $PARAMETER_PATH; starting with defaults" >&2
fi

install -o root -g "$SERVICE_USER" -m 0640 "$TMP_ENV" "$CONFIG_DIR/app.env"
rm -f "$TMP_ENV"

echo "installing systemd unit"
install -o root -g root -m 0644 "$APP_DIR/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/logs"

echo "after_install complete"
