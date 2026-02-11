#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/clamav-db"

docker compose -f "${ROOT_DIR}/compose.yaml" run --rm clamav "freshclam --verbose"
