#!/usr/bin/env bash
set -euo pipefail
TOKEN_PATH=${SOCP_BACKDOOR_TOKEN_PATH:-/tmp/socp_backdoor_token}
AUDIT_LOG=${SOCP_BACKDOOR_AUDIT:-/tmp/socp_backdoor_audit.log}

echo "This will ENABLE lab backdoor simulation for SOCP on this machine (lab VM only)."
read -p "Type BACKDOOR-ENABLE to confirm: " CONF
if [ "$CONF" != "BACKDOOR-ENABLE" ]; then
  echo "Confirmation mismatch. Aborting."
  exit 1
fi

mkdir -p "$(dirname "$TOKEN_PATH")"
head -c 32 /dev/urandom | base64 | tr -d '=+/ ' > "$TOKEN_PATH"
chmod 600 "$TOKEN_PATH"
echo "$(date +%s) ENABLED by $USER" >> "$AUDIT_LOG"

echo "Token: $TOKEN_PATH"
echo "Now: export SOCP_ALLOW_BACKDOOR=1"
