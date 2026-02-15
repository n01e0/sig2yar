#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

mkdir -p "${ROOT_DIR}/clamav-db/unpacked"

docker compose -f "${ROOT_DIR}/compose.yaml" run --rm --user root \
  -e HOST_UID="${HOST_UID}" -e HOST_GID="${HOST_GID}" \
  clamav 'set -e; \
    mkdir -p /var/lib/clamav/unpacked; \
    rm -rf /var/lib/clamav/unpacked/*; \
    cd /var/lib/clamav/unpacked; \
    for db in /var/lib/clamav/*.cvd /var/lib/clamav/*.cld; do \
      [ -f "$db" ] || continue; \
      sigtool --unpack "$db"; \
    done; \
    chown -R "${HOST_UID}:${HOST_GID}" /var/lib/clamav/unpacked'
