#!/bin/sh
set -eu

app_password="$(cat /run/secrets/app_db_password)"
keycloak_password="$(cat /run/secrets/keycloak_db_password)"
export PGPASSWORD="$(cat /run/secrets/db_admin_password)"

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE banking_app LOGIN PASSWORD '${app_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE banking TO banking_app;
GRANT USAGE, CREATE ON SCHEMA public TO banking_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO banking_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO banking_app;
CREATE ROLE keycloak LOGIN PASSWORD '${keycloak_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE keycloak OWNER keycloak;
SQL
