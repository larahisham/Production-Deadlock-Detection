#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_SRC="$ROOT_DIR/tools/daemon/deadlock-detector.service"
ENV_SRC="$ROOT_DIR/tools/daemon/deadlock-detector.env"
SERVICE_DST="/etc/systemd/system/deadlock-detector.service"
ENV_DST="/etc/default/deadlock-detector"
APP_ROOT="${APP_ROOT:-$ROOT_DIR}"

if [[ $EUID -ne 0 ]]; then
    echo "run as root: sudo $0"
    exit 1
fi

mkdir -p /var/log/deadlock-detector

sed "s|/opt/production-deadlock-detection|$APP_ROOT|g" "$SERVICE_SRC" > "$SERVICE_DST"
install -m 0644 "$ENV_SRC" "$ENV_DST"

systemctl daemon-reload
systemctl enable deadlock-detector
systemctl restart deadlock-detector

systemctl --no-pager --full status deadlock-detector || true
echo "installed: $SERVICE_DST"
echo "config: $ENV_DST"
