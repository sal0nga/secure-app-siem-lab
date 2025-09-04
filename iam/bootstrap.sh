#!/usr/bin/env bash
set -euo pipefail

# --- Config (env-overridable) ---
REALM="${REALM:-secure-lab}"
CLIENT_ID="${CLIENT_ID:-flask-app}"
APP_BASE_URL="${APP_BASE_URL:-https://app.local}"

ADMIN_USERNAME="${ADMIN_USERNAME:-alice}"
USER_USERNAME="${USER_USERNAME:-bob}"

ADMIN_PASSWORD="${ADMIN_PASSWORD:-Password123!}"
USER_PASSWORD="${USER_PASSWORD:-Password123!}"

KEYCLOAK_USER="${KEYCLOAK_USER:-admin}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:?export KEYCLOAK_PASSWORD in your shell or .env}"

# docker compose service name
KC_SVC="${KC_SVC:-keycloak}"

kc() {
  docker compose exec -T "${KC_SVC}" /opt/keycloak/bin/kcadm.sh "$@"
}

echo ">> Logging into Keycloak admin CLI…"
kc config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "${KEYCLOAK_USER}" \
  --password "${KEYCLOAK_PASSWORD}"

# --- Realm ---
if kc get "realms/${REALM}" >/dev/null 2>&1; then
  echo ">> Realm ${REALM} exists."
else
  echo ">> Creating realm ${REALM}…"
  kc create realms -s realm="${REALM}" -s enabled=true
fi

# Enforce TOTP at first login (make CONFIGURE_TOTP a default required action)
echo ">> Enforcing TOTP as default required action…"
kc update "authentication/required-actions/CONFIGURE_TOTP" -r "${REALM}" \
  -s enabled=true -s defaultAction=true || true

# --- Roles ---
for role in admin user; do
  if kc get "roles/${role}" -r "${REALM}" >/dev/null 2>&1; then
    echo ">> Role ${role} exists."
  else
    echo ">> Creating role ${role}…"
    kc create roles -r "${REALM}" -s name="${role}" -s "description=${role} role"
  fi
done

# --- Client (confidential, Auth Code + PKCE S256) ---
echo ">> Ensuring client ${CLIENT_ID}…"
if kc get clients -r "${REALM}" -q "clientId=${CLIENT_ID}" | grep -q '"clientId" : "'${CLIENT_ID}'"'; then
  echo ">> Client exists."
else
  echo ">> Creating client ${CLIENT_ID}…"
  kc create clients -r "${REALM}" \
    -s clientId="${CLIENT_ID}" \
    -s protocol=openid-connect \
    -s publicClient=false \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false \
    -s implicitFlowEnabled=false \
    -s serviceAccountsEnabled=false \
    -s 'redirectUris=["'"${APP_BASE_URL}"'/*","'"${APP_BASE_URL}"':8443/*","http://localhost:5000/*"]' \
    -s 'webOrigins=["'"${APP_BASE_URL}"'","'"${APP_BASE_URL}"':8443","http://localhost:5000"]'
fi

# Find client UUID
CLIENT_UUID="$(kc get clients -r "${REALM}" -q "clientId=${CLIENT_ID}" | sed -n 's/.*"id" : "\([^"]*\)".*/\1/p' | head -n1)"
if [[ -z "${CLIENT_UUID}" ]]; then
  echo "!! Could not resolve client UUID for ${CLIENT_ID}" >&2
  exit 1
fi

# Require PKCE S256 (Keycloak supports setting via attributes)
echo ">> Enforcing PKCE S256…"
kc update "clients/${CLIENT_UUID}" -r "${REALM}" \
  -s publicClient=false \
  -s 'attributes."pkce.code.challenge.method"=S256' || true

# Get client secret (for confidential client)
CLIENT_SECRET="$(kc get "clients/${CLIENT_UUID}/client-secret" -r "${REALM}" | sed -n 's/.*"value" : "\([^"]*\)".*/\1/p')"
echo ">> Client secret: ${CLIENT_SECRET}"

# --- Users + role mapping ---
ensure_user() {
  local username="$1" pw="$2" primary_role="$3"
  if kc get users -r "${REALM}" -q "username=${username}" | grep -q '"username" : "'${username}'"'; then
    echo ">> User ${username} exists."
  else
    echo ">> Creating user ${username}…"
    kc create users -r "${REALM}" \
      -s username="${username}" -s enabled=true -s emailVerified=true
  fi
  echo ">> Setting password for ${username} (permanent)…"
  kc set-password -r "${REALM}" --username "${username}" --new-password "${pw}" --temporary=false

  echo ">> Assigning roles to ${username}…"
  kc add-roles -r "${REALM}" --uusername "${username}" --rolename "${primary_role}" || true
  # everyone also gets 'user'
  if [[ "${primary_role}" != "user" ]]; then
    kc add-roles -r "${REALM}" --uusername "${username}" --rolename user || true
  fi
}

ensure_user "${ADMIN_USERNAME}" "${ADMIN_PASSWORD}" admin
ensure_user "${USER_USERNAME}" "${USER_PASSWORD}" user

# --- Export realm to version control ---
echo ">> Exporting realm to iam/realm-export.json…"
mkdir -p iam
kc get "realms/${REALM}" > iam/realm-export.json

# --- Convenience: print .env stanza for the secret ---
echo
echo ">> Add/update these in .env:"
echo "OIDC_CLIENT_ID=${CLIENT_ID}"
echo "OIDC_CLIENT_SECRET=${CLIENT_SECRET}"
echo "OIDC_ISSUER=http://localhost:8080/realms/${REALM}"
echo "OIDC_DISCOVERY_INTERNAL=http://keycloak:8080/realms/${REALM}/.well-known/openid-configuration"
echo "APP_BASE_URL=${APP_BASE_URL}"
echo
echo "Done."