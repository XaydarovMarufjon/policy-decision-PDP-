#!/usr/bin/env bash
# Create (or update) a user in the local Keycloak "soc" realm via the Admin API,
# with everything the PDP needs for a meaningful decision: a realm role plus the
# department and mfa attributes, and a usable password.
#
#   ./scripts/kc-create-user.sh <username> <role> <department> <mfa> [password]
#   ./scripts/kc-create-user.sh nodira.tosheva analyst SOC true
#
# role: admin | analyst | auditor | guest      mfa: true | false
#
# Sets firstName/lastName/email in the SAME create call so the declarative user
# profile is complete (avoids "Account is not fully set up"), and includes the
# password credential inline (avoids a follow-up PUT wiping fields).
set -euo pipefail

USER="${1:?usage: kc-create-user.sh <username> <role> <department> <mfa> [password]}"
ROLE="${2:?role required: admin|analyst|auditor|guest}"
DEPT="${3:?department required, e.g. SOC}"
MFA="${4:?mfa required: true|false}"
PASS="${5:-Passw0rd!}"

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${KC_REALM:-soc}"
FIRST="${USER%%.*}"
LAST="${USER#*.}"

admin() {
  curl -s -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
    -d "grant_type=password" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

TOKEN=$(admin)
[ -n "$TOKEN" ] || { echo "Failed to get admin token from ${KC_URL}" >&2; exit 1; }

# Create the user (idempotent: 409 -> already exists, we continue to role assign).
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${KC_URL}/admin/realms/${REALM}/users" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  -d "{
    \"username\":\"${USER}\",\"enabled\":true,\"emailVerified\":true,
    \"firstName\":\"${FIRST}\",\"lastName\":\"${LAST}\",\"email\":\"${USER}@soc.local\",
    \"attributes\":{\"department\":[\"${DEPT}\"],\"mfa\":[\"${MFA}\"]},
    \"credentials\":[{\"type\":\"password\",\"value\":\"${PASS}\",\"temporary\":false}]
  }")

case "$CODE" in
  201) echo "created user ${USER}";;
  409) echo "user ${USER} already exists — updating role only";;
  *)   echo "create user failed (HTTP ${CODE})" >&2; exit 1;;
esac

# Look up the user id and assign the realm role.
USERID=$(curl -s "${KC_URL}/admin/realms/${REALM}/users?username=${USER}&exact=true" \
  -H "Authorization: Bearer ${TOKEN}" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
[ -n "$USERID" ] || { echo "could not resolve user id for ${USER}" >&2; exit 1; }

ROLE_JSON=$(curl -s "${KC_URL}/admin/realms/${REALM}/roles/${ROLE}" \
  -H "Authorization: Bearer ${TOKEN}")
echo "$ROLE_JSON" | grep -q "\"name\":\"${ROLE}\"" || { echo "role ${ROLE} not found" >&2; exit 1; }

RCODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "${KC_URL}/admin/realms/${REALM}/users/${USERID}/role-mappings/realm" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  -d "[${ROLE_JSON}]")
[ "$RCODE" = "204" ] || { echo "role assignment failed (HTTP ${RCODE})" >&2; exit 1; }

echo "assigned role=${ROLE} department=${DEPT} mfa=${MFA} to ${USER}"
echo "get a token with: ./scripts/kc-token.sh ${USER} ${PASS}"
