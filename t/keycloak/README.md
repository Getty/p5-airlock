# Keycloak live test

`t/90-live-keycloak.t` runs only when `TEST_AIRLOCK_KEYCLOAK_URL` is set. It
needs a Keycloak with the realm `airlock-test` from `realm.json` in this
directory: a public client `airlock-test-cli` with the device authorization
grant and direct access grants enabled, a user `plain` with a password, and a
user `otp` with a password and a TOTP credential whose secret is the RFC 6238
test secret `12345678901234567890`.

## Start a throwaway Keycloak

```bash
docker run --rm --name airlock-keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/t/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak:latest start-dev --import-realm
```

Keycloak needs about 1 GB of memory. Do not start it on a machine that is
already short of it.

## Run

```bash
TEST_AIRLOCK_KEYCLOAK_URL=http://localhost:8080 prove -lv t/90-live-keycloak.t
```

## Findings

Recorded by whoever ran the test last. The `diag` lines of the test print
what to copy here.

| Keycloak version | Login | acr | amr | auth_time |
|---|---|---|---|---|
