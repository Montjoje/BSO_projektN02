#!/usr/bin/env sh
set -eu

cd /app

CONFIG_PATH="${BSO_CONFIG:-/app/configs/config.yaml}"
if [ ! -f "$CONFIG_PATH" ] && [ -f /app/configs/config.example.yaml ]; then
  cp /app/configs/config.example.yaml "$CONFIG_PATH"
fi

exec /app/scanner -config "$CONFIG_PATH" ${BSO_EXTRA_ARGS:-}
