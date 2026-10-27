#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -i --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --env AEGIS_MODE=unconfigured "${1:-aegis-portal:registration}" python - < tests/container_smoke.py
