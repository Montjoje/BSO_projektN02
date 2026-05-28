#!/bin/sh
set -eu

CONFIG_PATH="${CONFIG_PATH:-/app/configs/config.yaml}"
exec /app/scanner -config "$CONFIG_PATH"
