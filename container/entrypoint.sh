#!/bin/sh
set -eu

CONFIG_PATH="${CONFIG_PATH:-/app/configs/config.example.yaml}"
exec /app/scanner -config "$CONFIG_PATH"
