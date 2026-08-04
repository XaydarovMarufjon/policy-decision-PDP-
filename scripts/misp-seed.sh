#!/usr/bin/env bash
# Seed a malicious IP indicator into the local MISP so the PDP's risk provider
# reports threat_intel_match=true for that source IP.
#
#   ./scripts/misp-seed.sh <ip> [threat_level_id] [event_info]
#   ./scripts/misp-seed.sh 203.0.113.66 1 "Known C2 infrastructure"
#
# threat_level_id: 1=High (default) 2=Medium 3=Low 4=Undefined
set -euo pipefail

IP="${1:?usage: misp-seed.sh <ip> [threat_level_id] [event_info]}"
LEVEL="${2:-1}"
INFO="${3:-PDP demo malicious indicator}"

MISP_URL="${MISP_URL:-http://localhost:8083}"
MISP_API_KEY="${MISP_API_KEY:-0123456789abcdef0123456789abcdef01234567}"

# Create an event with the IP as an ip-src attribute (to_ids so it is actionable).
RESP=$(curl -sk -X POST "${MISP_URL}/events/add" \
  -H "Authorization: ${MISP_API_KEY}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d "{
    \"Event\": {
      \"info\": \"${INFO}\",
      \"distribution\": \"0\",
      \"threat_level_id\": \"${LEVEL}\",
      \"analysis\": \"2\",
      \"Attribute\": [
        { \"type\": \"ip-src\", \"category\": \"Network activity\", \"value\": \"${IP}\", \"to_ids\": true }
      ]
    }
  }")

EVENT_ID=$(echo "$RESP" | sed -n 's/.*"id":"\([0-9]*\)".*/\1/p' | head -1)
if [ -z "$EVENT_ID" ]; then
  echo "Failed to create MISP event. Response:" >&2
  echo "$RESP" | head -c 600 >&2
  echo >&2
  exit 1
fi

# Publish so the indicator is fully active.
curl -sk -X POST "${MISP_URL}/events/publish/${EVENT_ID}" \
  -H "Authorization: ${MISP_API_KEY}" -H "Accept: application/json" -o /dev/null

echo "seeded MISP event ${EVENT_ID}: ${IP} (threat_level=${LEVEL}) — ${INFO}"
echo "verify: curl -sk -H 'Authorization: ${MISP_API_KEY}' -H 'Accept: application/json' \\"
echo "  -d '{\"returnFormat\":\"json\",\"value\":\"${IP}\"}' ${MISP_URL}/attributes/restSearch"
