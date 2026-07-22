#!/bin/sh
set -eu

mkdir -p /opt/keycloak/data/import
rm -f /opt/keycloak/data/import/*.json
cp /bootstrap/secure-bank-realm.json /opt/keycloak/data/import/secure-bank-realm.json

export KC_DB_PASSWORD="$(cat "${KC_DB_PASSWORD_FILE}")"
exec /opt/keycloak/bin/kc.sh start --import-realm --spi-password-hashing--provider-default=argon2
