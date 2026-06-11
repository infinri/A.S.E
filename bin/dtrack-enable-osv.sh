#!/usr/bin/env bash
# Enable the OSV vulnerability source on a Dependency-Track 5.0 instance.
#
# Why this exists: DT 5.0.0 mirrors only NVD+EPSS by default. NVD matches by CPE,
# so composer/npm components silently produce ZERO findings until OSV (or GitHub
# Advisories) is enabled. 5.0.0 ships no API or UI for vuln-data-source config
# (see docs/planning/ws4-findings.md), so this edits EXTENSION_RUNTIME_CONFIG
# directly and restarts the apiserver. Revisit when a 5.0.x patch adds a
# supported surface.
#
# The OSV mirror then runs at its next cron (03:00 UTC daily). For an immediate
# mirror, recreate the apiserver container once with:
#   -e DT_TASK_OSV_VULN_DATA_SOURCE_MIRROR_CRON='* * * * *'
# wait for "Starting mirror [vulnDataSourceName=osv]" in its logs, then recreate
# without the override.
#
# Usage: bin/dtrack-enable-osv.sh [ecosystems-csv] [postgres-container] [apiserver-container]
set -euo pipefail

ECOSYSTEMS="${1:-Packagist,npm}"
PG="${2:-dtrack-postgres}"
API="${3:-dtrack-apiserver}"

ECO_JSON=$(printf '%s' "$ECOSYSTEMS" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?", ":""), $i}}')
CONFIG="{\"dataUrl\": \"https://storage.googleapis.com/osv-vulnerabilities\", \"enabled\": true, \"ecosystems\": [${ECO_JSON}], \"aliasSyncEnabled\": true, \"incrementalMirroringEnabled\": true}"

docker exec "$PG" psql -U dtrack -d dtrack -v ON_ERROR_STOP=1 -c \
  "UPDATE \"EXTENSION_RUNTIME_CONFIG\" SET \"CONFIG\" = '${CONFIG}', \"UPDATED_AT\" = now() WHERE \"EXTENSION_POINT\" = 'vuln-data-source' AND \"EXTENSION\" = 'osv';"

echo "OSV source enabled for ecosystems: ${ECOSYSTEMS}"
docker exec "$PG" psql -U dtrack -d dtrack -t -c \
  "SELECT \"CONFIG\" FROM \"EXTENSION_RUNTIME_CONFIG\" WHERE \"EXTENSION_POINT\" = 'vuln-data-source' AND \"EXTENSION\" = 'osv';"

docker restart "$API" >/dev/null
echo "apiserver restarted; OSV mirror runs at the next 03:00 UTC cron (see header for immediate-mirror option)"
