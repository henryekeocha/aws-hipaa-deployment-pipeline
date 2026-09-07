#!/bin/bash
# ValidateService -- the gate between "deployed" and "receiving traffic".
#
# In a blue/green deployment this runs on the GREEN fleet while all production
# traffic is still served by the blue fleet. A non-zero exit fails the
# deployment, auto_rollback_configuration fires, and the green fleet is torn
# down without a single user request ever having reached it.
#
# This is the cheapest place in the whole pipeline to catch a bad release, so
# it checks behaviour, not just liveness.
set -euo pipefail

CONFIG_DIR=/etc/hipaa-demo-app
# shellcheck disable=SC1091
[ -f "$CONFIG_DIR/app.env" ] && . "$CONFIG_DIR/app.env"
PORT="${APP_PORT:-8080}"
HEALTH_URL="http://127.0.0.1:$PORT/health"
ROOT_URL="http://127.0.0.1:$PORT/"
ATTEMPTS=30

echo "waiting for $HEALTH_URL"
for i in $(seq 1 $ATTEMPTS); do
  if code=$(curl -sS -o /tmp/health.json -w '%{http_code}' --max-time 5 "$HEALTH_URL" 2>/dev/null) \
    && [ "$code" = "200" ]; then
    echo "health check passed on attempt $i: $(cat /tmp/health.json)"

    # A 200 from /health only proves the process is up. Confirm the service is
    # actually serving its contract before letting traffic move.
    root_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$ROOT_URL")
    if [ "$root_code" != "200" ]; then
      echo "ERROR: health endpoint is up but / returned $root_code" >&2
      exit 1
    fi

    if ! grep -q '"status":"ok"' /tmp/health.json; then
      echo "ERROR: health endpoint returned 200 but reported a non-ok status" >&2
      exit 1
    fi

    rm -f /tmp/health.json
    echo "validate_service complete: this revision is safe to receive traffic"
    exit 0
  fi
  sleep 2
done

echo "ERROR: service did not become healthy after $((ATTEMPTS * 2))s" >&2
journalctl -u hipaa-demo-app -n 50 --no-pager || true
exit 1
