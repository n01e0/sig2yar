#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_DIR="${ROOT_DIR}/clamav-db"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

mkdir -p "${DB_DIR}/unpacked"

docker compose -f "${ROOT_DIR}/compose.yaml" run --rm --user root \
  -e HOST_UID="${HOST_UID}" -e HOST_GID="${HOST_GID}" \
  clamav 'set -e; \
    mkdir -p /var/lib/clamav /var/lib/clamav/unpacked; \
    chown -R 100:101 /var/lib/clamav; \
    chmod -R ug+rwX /var/lib/clamav; \
    freshclam --verbose --datadir=/var/lib/clamav; \
    chown -R "${HOST_UID}:${HOST_GID}" /var/lib/clamav'
