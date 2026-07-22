#!/bin/sh
set -eu
export KC_DB_PASSWORD="$(cat "${KC_DB_PASSWORD_FILE}")"
exec /opt/keycloak/bin/kc.sh start --import-realm

