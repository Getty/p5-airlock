# Keycloak live test

`t/90-live-keycloak.t` runs only when `TEST_AIRLOCK_KEYCLOAK_URL` is set. It
needs a Keycloak with the realm `airlock-test` from `realm.json` in this
directory: a public client `airlock-test-cli` with the device authorization
grant and direct access grants enabled, a user `plain` with a password, and a
user `otp` with a password and a TOTP credential whose secret is the RFC 6238
test secret `12345678901234567890`.

## Start a throwaway Keycloak

On Kubernetes (`k8s.yaml` in this directory; no persistence, NodePort service):

```bash
kubectl create namespace airlock-test
kubectl -n airlock-test create configmap airlock-realm --from-file=realm.json=t/keycloak/realm.json
kubectl -n airlock-test apply -f t/keycloak/k8s.yaml
kubectl -n airlock-test rollout status deploy/keycloak
kubectl -n airlock-test get svc keycloak        # the NodePort is the port of the URL
kubectl delete namespace airlock-test           # when done
```

The Keycloak image needs a CPU with x86-64-v2. On a VM with a generic CPU model
the pod dies with `Fatal glibc error: CPU does not support x86-64-v2`; give the
VM the host's CPU model or schedule the pod on another node.

With Docker:

```bash
docker run --rm --name airlock-keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/t/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak:26.8.0 start-dev --import-realm
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
| 26.8.0 | `plain`, direct grant, password | `1` | absent | absent |
| 26.8.0 | `otp`, direct grant, password + TOTP | `1` | absent | absent |

Recorded 2026-10-02 against the realm in `realm.json`, identical in ID token and
access token.

What this run established:

- `realm.json` imports as written, including the OTP credential.
- `Airlock::Client` runs against Keycloak's device authorization endpoint:
  discovery, start, and polling answered with `authorization_pending`. The
  device response carries `verification_uri_complete`.
- The direct grant takes the `totp` parameter, and Keycloak enforces it: the
  user `otp` without it gets `invalid_grant`.
- **A default realm does not say in the token whether a second factor was
  used.** Both logins carry `acr=1` and no `amr`. `Airlock::Factor::Upstream`
  therefore cannot recognise a Keycloak second factor until the realm is
  configured to report one: an `amr` protocol mapper with reference values on
  the authenticators, or step-up authentication with an ACR-to-LoA mapping.
  The last assertion of the live test is marked TODO for that reason.
- A direct grant carries no `auth_time`. Freshness (`max_age`) can only be
  tested with a browser login.
