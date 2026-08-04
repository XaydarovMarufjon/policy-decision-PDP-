#!/usr/bin/env bash
# Fetch a real user access token from the local Keycloak "soc" realm using the
# Resource Owner Password grant (pdp-test public client, direct access grants).
#
#   ./scripts/kc-token.sh <username> [password]
#
# Defaults: password "Passw0rd!". Seeded users: ali.valiyev (analyst/SOC),
# malika.saidova (auditor/GRC), vali.karimov (guest/HR).
set -euo pipefail

USER="${1:?usage: kc-token.sh <username> [password]}"
PASS="${2:-Passw0rd!}"
KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${KC_REALM:-soc}"
CLIENT="${KC_CLIENT:-pdp-test}"

TOKEN=$(curl -s -X POST \
  "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT}" \
  -d "username=${USER}" \
  -d "password=${PASS}" \
  -d "grant_type=password" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [ -z "${TOKEN}" ]; then
  echo "Failed to obtain token for ${USER} from ${KC_URL}/realms/${REALM}" >&2
  exit 1
fi

echo "${TOKEN}"
