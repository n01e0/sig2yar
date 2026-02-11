#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/clamav-db/unpacked"

docker compose -f "${ROOT_DIR}/compose.yaml" run --rm clamav 'set -e; \
mkdir -p /var/lib/clamav/unpacked; \
cd /var/lib/clamav/unpacked; \
for db in /var/lib/clamav/*.cvd /var/lib/clamav/*.cld; do \
  [ -f "$db" ] || continue; \
  sigtool --unpack "$db"; \
done'
