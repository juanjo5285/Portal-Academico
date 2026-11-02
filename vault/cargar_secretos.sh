#!/usr/bin/env bash
# Carga los secretos del portal en Vault y crea una política de SOLO LECTURA
# y un token de corta duración exclusivo para la aplicación (mínimo privilegio).
set -euo pipefail
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
export VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN:?}
vault kv put secret/portal \
  FLASK_SECRET_KEY="$(openssl rand -base64 48)" \
  DATA_KEY_ACTIVE=v1 DATA_KEY_v1="$(openssl rand -base64 32)" \
  ADMIN_INITIAL_PASSWORD="$(openssl rand -base64 18)"
vault policy write portal-app - <<'HCL'
path "secret/data/portal" { capabilities = ["read"] }
HCL
echo "Token de la aplicación (TTL 24h, solo lectura de secret/portal):"
vault token create -policy=portal-app -ttl=24h -field=token
