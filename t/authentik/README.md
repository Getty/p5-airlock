# authentik live test

`t/91-live-authentik.t` runs only when `TEST_AIRLOCK_AUTHENTIK_URL` and
`TEST_AIRLOCK_AUTHENTIK_TOKEN` are set and `setup.pl` in this directory has run
against that instance.

## Start a throwaway authentik

The compose file lives with `WWW::Authentik`, not here: it pins the image, binds
its ports to `127.0.0.1` and keeps its secrets in a `.env` beside itself, and
duplicating it would mean two files to keep in step for one instance.

```bash
cd ~/dev/p5-www-authentik/t/authentik
cp env.example .env          # then fill in the four secrets
docker compose up -d
curl -s http://127.0.0.1:9000/-/health/ready/    # 200 once ready, about two minutes
```

`AUTHENTIK_BOOTSTRAP_TOKEN` from that `.env` is the API token below.

## Build the fixtures

```bash
perl -I ~/dev/p5-www-authentik/lib t/authentik/setup.pl http://127.0.0.1:9000 "$AUTHENTIK_BOOTSTRAP_TOKEN"
```

It makes an application `airlock-test` with a public OAuth2 provider that can do
the device flow, two users (`airlock-plain` and `airlock-otp`, password
`<username>-password`), and an empty flow that the brand needs as its
`flow_device_code` before anyone can approve a device code at `/device`. Every
step is an `ensure_*`, so it can be run again at any time. `--remove` as a third
argument takes it all away again, including the service account authentik makes
for a client credentials grant.

Unlike Keycloak, authentik needs **nothing** configured to report a second
factor, so the script does not touch any mapper or flow step. Enrolling the TOTP
device is the test's own job: it goes through the setup flow the way a person
would, and deletes the device again at the end.

## Run

```bash
TEST_AIRLOCK_AUTHENTIK_URL=http://127.0.0.1:9000 \
TEST_AIRLOCK_AUTHENTIK_TOKEN="$AUTHENTIK_BOOTSTRAP_TOKEN" \
  prove -lv t/91-live-authentik.t
```

The test needs the `p5-www-authentik` checkout next door, for two things it does
not carry itself: `WWW::Authentik` to make and remove the fixtures, and
`t/lib/AuthentikExecutor.pm` to log in and enrol TOTP through authentik's flow
executor. Point `AIRLOCK_WWW_AUTHENTIK` at that checkout if it is not
`~/dev/p5-www-authentik`; without it the test skips.

**Airlock does not depend on either at runtime.** Neither is in `cpanfile`, and
nothing under `lib/` mentions them. The executor is deliberately not copied in
here: the shape of a flow challenge belongs to authentik and changes with its
versions, a copy would drift unnoticed, and a distribution that ships no
provider code should not carry two hundred lines of one.

## Findings

authentik 2026.8.3, recorded 2026-10-04, through the whole chain.

| Login | acr | amr | auth_time |
|---|---|---|---|
| device flow, browser login, password | `goauthentik.io/providers/oauth2/default` | `pwd` | time of login |
| device flow, browser login, password + TOTP | the same | `pwd`, `mfa` | time of login |
| a second token from the same session | the same | unchanged | **the first login**, not the new token |

What the runs established:

- **authentik reports the second factor out of the box.** No mapper, no scope,
  no flow setting: a password login carries `amr=pwd`, a login with TOTP
  `amr=pwd,mfa`, and `Airlock::Factor::Upstream` tells them apart with its
  defaults. This is the difference to Keycloak, which says nothing until
  `t/keycloak/setup.pl` has run.
- **`acr` is one constant string** whatever happened, so `mfa_acr` stays empty
  in `Airlock::Upstream::Authentik`. Sending `acr_values` changes nothing.
- **`auth_time` is when the session began**, and it survives a refresh and
  further authorization requests. `max_age` on the factor therefore measures the
  age of the authentication, which is what a caller wants: a token minted now
  from a ten-minute-old session is refused by `max_age => 300`.
- **`max_age=0` does not force a new login.** authentik hands back a code at
  once with the old `auth_time`, so `Airlock::Factor::Upstream->reauth_params`
  has no effect here. A host application that wants a fresh authentication has
  to end the authentik session first, through the application's `end-session`
  endpoint.
- `Airlock::Client` completes a device flow against authentik: discovery, start,
  `authorization_pending` while waiting, and the token after the approval. The
  device response carries `verification_uri_complete`.
- A device code is approved by opening `/device?code=…` with a session, which
  redirects into the authorization flow; one run of that flow through the
  executor ends at `ak-provider-oauth2-device-code-finish` and the poll
  succeeds.
- **authentik refuses a TOTP code twice.** The executor waits for the next
  thirty-second window and submits again, so a run can take a minute.
- The brand needs a `flow_device_code`; without it `/device` has nothing to
  show.
