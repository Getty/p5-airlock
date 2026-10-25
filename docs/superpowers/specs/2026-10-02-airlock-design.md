# Airlock – Design

Date: 2026-10-02 (revision 3: details clarified during planning, see section 11)
Status: approved on 2026-10-02; implementation plan in `docs/superpowers/plans/2026-10-02-airlock-phase-1.md`
Distribution: `Airlock` (repo `p5-airlock`), CPAN-ready, `[@Author::GETTY]`

## 1. What Airlock is

**Airlock is the airlock: a waiting request is confirmed by an already trusted
session, if needed only after a second factor.**

The first and most important use case is the server side of the OAuth 2.0 Device
Authorization Grant (RFC 8628): a device or CLI shows a short code, a
logged-in human types or scans it somewhere else, sees who wants what, confirms, and
the device gets a token.

Airlock is a **core to embed**, not a finished application. The host app brings:

- who is currently logged in (its own session, or an IdP like Keycloak behind it),
- the confirmation page in its own look, with its own templates,
- where data lives (a handful of subs against the database it already has).

Airlock brings: codes, state machine, poll rules, one-time redemption,
step-up rules, second factors, QR codes, the two machine endpoints as PSGI, and
functions for everything the host app wants to render itself.

The first user is Mothership (`mothership-web`, several prefork workers, store
connected via DBIO).

### What Airlock is not

- **Not an identity provider.** No accounts, no passwords, no login form, no
  OIDC discovery for third parties. Who confirms is up to the host app.
- **No user interface.** No HTML, no templates, no CSS. Airlock gives the
  confirmation page its data and takes its decision; how it looks
  belongs to the system Airlock is embedded in.
- **Not a general OAuth server.** No authorization code flow, no client secret
  handling, no refresh tokens in v1.
- **Not a replacement for an IdP's MFA.** If Keycloak has already checked the second factor,
  Airlock takes over the result and does not ask again.
- **Not a database driver.** No DBI, no ORM. The store is a handful of coderefs.

## 2. Terms

| Term | Meaning |
|---|---|
| **Request** | The waiting request: `device_code`, `user_code`, client, scopes, state, expiry |
| **Client** | Who is asking (CLI, device, app), identified by `client_id` |
| **Subject** | Who confirms: the logged-in person, supplied by the host app |
| **Factor** | A second factor that secures a confirmation (TOTP, WebAuthn, …) |
| **Policy** | Decides per request which factors are needed |
| **Grant** | The confirmed, redeemable request: subject, scopes, `amr`, `auth_time` |
| **Issuer** | Turns a grant into the token response |

States of a request: `pending → approved | denied | expired`, and `approved → redeemed`
(exactly once).

## 3. Layers

```
Host app (Mothership, …)
   │
   │  Machine side (JSON)                    Human side (host app renders it itself)
   │  ───────────────────────                ─────────────────────────────────────────
   ├─ $airlock->to_app          PSGI         $airlock->inspect / requirements
   ├─ $airlock->handle($req)    HTTP::Request → HTTP::Response
   │                                         $airlock->approve / deny
   │                                         Airlock::QR
   │
   └─ Airlock                   Core: functions, no web framework
        ├─ store    => { ... }  four subs of the host app (memory built in)
        ├─ factors  => [ ... ]  TOTP, Callback, Upstream, WebAuthn later
        ├─ policy               Step-up rules
        ├─ issuer   => sub      Token issuing (opaque built in)
        ├─ Airlock::Code        Code generation and normalization
        └─ Airlock::QR          SVG, Terminal, Data-URI

Airlock::Client                 Other side: RFC 8628 client for CLIs
```

There is exactly one neutral place where a request is answered:
`$airlock->respond($method, $path, \%params)` returns `[$status, \%headers, \%json]`.
`to_app` and `handle` are two thin wrappers around it. Anyone with a different framework builds
the third wrapper in ten lines or calls the core methods directly.

## 4. Core API

```perl
my $airlock = Airlock->new(
  store   => { insert => sub {...}, find => sub {...}, update => sub {...}, purge => sub {...} },
  clients => { 'mothership-cli' => { name => 'Mothership CLI', scopes => [qw(read admin)] } },
  policy  => { step_up => { admin => ['totp'] }, max_auth_age => 300 },
  factors => [ Airlock::Factor::Callback->new(name => 'totp', amr => 'otp', verify => sub {...}) ],
  issuer  => sub ($grant) { ... },          # omit = built-in opaque token
  verification_uri => 'https://my.example.org/airlock',
);

my $req    = $airlock->open(client_id => $id, scope => 'read admin', origin => { ip => ..., ua => ... });
my $view   = $airlock->inspect($user_code);                # for the confirmation page, or undef
my $needs  = $airlock->requirements($view, $subject);      # e.g. ['totp'] or []
my $done   = $airlock->approve($user_code, subject => $subject, proofs => { totp => '123456' });
my $done   = $airlock->deny($user_code, subject => $subject);
my $result = $airlock->redeem(device_code => $dc, client_id => $id);
```

- `open` returns the fields from RFC 8628 §3.2 including `verification_uri_complete`.
- `inspect` returns everything a confirmation page has to show: client name, scopes,
  origin, age, remaining lifetime. Pure data, no markup.
- `redeem` returns exactly one of `granted`, `authorization_pending`, `slow_down`,
  `access_denied`, `expired_token`, `invalid_grant`. With `granted`, the issuer's token
  response is attached.
- `subject` is a structure of the host app: at least `id`, optionally `amr`, `acr`,
  `auth_time` (see section 7).
- Time comes through an injectable `now`, so tests check expiry and `slow_down`
  without `sleep`.
- `on_event` (callback) reports `opened`, `approved`, `denied`, `redeemed`,
  `factor_failed`, `code_miss`. The host app hangs its audit log and rate limits on it.

## 5. Embedding

### Machine endpoints

```perl
# PSGI, without a Plack dependency
builder { mount '/airlock' => $airlock->to_app; mount '/' => $app };

# everywhere else: HTTP::Request in, HTTP::Response out
my $res = $airlock->handle($http_request);
```

| Route | Purpose |
|---|---|
| `POST …/device` | Client fetches codes (RFC 8628 §3.1) |
| `POST …/token` | Client polls (RFC 8628 §3.4) |

There are no more routes. `to_app` reads the form-encoded body itself from the
PSGI env and needs no Plack. `handle` loads `HTTP::Message` only when called; it is
a `recommends` dependency.

### Human side

The host app builds two handlers in its own framework: one that fills the page with `inspect` and
`requirements`, and one that completes the form with `approve` or `deny`.
Login enforcement, CSRF and templates are its business. Airlock gives it the
QR code (section 6) and clear result objects with a failure reason.

`examples/` shows the complete integration: a Plack app with a minimal
confirmation page, the same in Mojolicious, and the store once with DBI and once with
DBIO. A Mojolicious plugin comes only if the example turns out to be too much typing
(phase 2).

## 6. Building blocks

### Store: four subs

```perl
store => {
  insert => sub ($row)                         { ... },   # store a new request
  find   => sub ($field, $value)               { ... },   # by user_code or device_hash
  update => sub ($id, $from_state, \%changes)  { ... },   # only if state == $from_state; returns true/false
  purge  => sub ($before_epoch)                { ... },   # optional: clear out expired rows
}
```

`$row` is a flat hash with fixed keys (documented as a table, with an
example SQL schema in `examples/`). `update` is the only place that has to be atomic:
the condition on the old state prevents two simultaneous polls from producing two
tokens. Without `store`, Airlock uses a built-in in-process storage, for
tests and single-process apps.

`Airlock::Test::Store` checks a store binding against the contract: whoever writes their four subs
runs the suite against them and knows whether they are right. The same suite checks
the built-in storage and the examples.

The `device_code` reaches the store only as SHA-256.

### Factor (`Airlock::Factor`, Moo::Role)

`name`, `amr` (e.g. `otp`), `available_for($subject)`, `verify($subject, $proof)`.

- `Airlock::Factor::Callback`: the host app checks for itself. This is the way for Mothership,
  where by design TOTP lives at Stalwart and Mothership stores nothing.
- `Airlock::Factor::TOTP`: RFC 6238 with `Digest::SHA`, window ±1, replay protection via
  the last accepted time step, `otpauth://` URI for setup. The secret and the
  last time step come through two subs of the host app.
- `Airlock::Factor::Upstream`: counts as fulfilled when the subject brings matching `amr`/`acr`
  from the IdP and `auth_time` is fresh enough.
- Later: `Airlock::Factor::WebAuthn` via `Authen::WebAuthn` as an optional dependency,
  and recovery codes.

### Policy

Maps request and subject to a list of required factors. Declarative for the
normal case (`step_up => { scope => [factors] }`, `max_auth_age => 300`), coderef for
everything else. If the subject lacks a required factor, nothing is confirmed; the result
says what is missing.

### Issuer

A sub `($grant) → token response`. Without one, Airlock issues an opaque random token,
stores it hashed in the store and offers `verify_token` to check it. That is enough as long as
only the host app itself accepts the token. Phase 2 brings a ready-made JWT issuer with
`amr`, `auth_time`, `scope`, `sub` and JWKS export.

### Code (`Airlock::Code`)

`user_code`: 8 characters from `BCDFGHJKLMNPQRSTVWXZ` (no vowels, nothing confusable),
displayed as `XXXX-XXXX`, input is normalized (case, separators, spaces).
`device_code`: 32 bytes of system randomness (`Crypt::URandom`).

### QR (`Airlock::QR`)

Two places need QR codes, both via the same small API:

1. `verification_uri_complete`: the laptop or the CLI shows the QR, the phone scans it
   and lands on the confirmation page with the code prefilled.
2. TOTP setup: the `otpauth://` URI for the authenticator app.

```perl
Airlock::QR->new(text => $uri)->svg;        # for the web, no image library needed
Airlock::QR->new(text => $uri)->terminal;   # Unicode half blocks for the CLI
Airlock::QR->new(text => $uri)->data_uri;   # straight into <img src>
Airlock::QR->new(text => $uri)->matrix;     # raw modules, for your own rendering
```

Encoding uses `GD::Barcode::QRcode` (pure Perl; the dist does not require
GD at runtime). The encoder sits behind a small seam, so that `Text::QRCode` (libqrencode)
can be used when it is installed. The plan starts with a proof that
the generated matrix can be read back with an independent decoder; if the
proof fails, the encoder is switched before anything builds on it.

### `Airlock::Client`

The other side, i.e. what this project started with: an RFC 8628 client with
`HTTP::Tiny`. Finds the endpoints via `.well-known/openid-configuration`
(`device_authorization_endpoint`) or gets them directly, shows the code and a terminal QR,
polls and honors `slow_down`. Talks to Airlock, Keycloak and GitHub alike.

## 7. Keycloak: minimal, but tested

Two touch points in v1, both checked against a real Keycloak:

**A. Keycloak is the login source of the confirmation page.** The host app logs in via OIDC
and hands Airlock the subject including `amr`, `acr` and `auth_time` from the ID token.
`Airlock::Factor::Upstream` uses them to recognize whether Keycloak has already checked a second factor.
If not, Airlock gives the host app the parameters (`acr_values`, `max_age=0`)
with which it sends the person to Keycloak once more. How Keycloak actually fills `acr` and `amr`
is not taken from the docs, but determined on the real token
and recorded as `Airlock::Upstream::Keycloak`.

**B. The client talks to Keycloak directly.** Keycloak supports the device grant itself.
`Airlock::Client` has to run through against its endpoints.

**The live test** (`t/90-live-keycloak.t`, only when `TEST_AIRLOCK_KEYCLOAK_URL` is
set) needs a Keycloak with a realm, a client with the device flow turned on
and a user with TOTP. For the test, a container with a realm import from a
JSON file in `t/keycloak/` is enough; no admin client is needed for it.

**Not in v1:** Zitadel and Authentik mappings (same seam, they come when needed),
Airlock as a facade in front of Keycloak's device endpoint (unnecessary), and Airlock tokens
verifiable by third parties including token exchange (phase 2/3; from there on Airlock is effectively a small
issuer, which touches the line "Not an identity provider" for Mothership).

**Outside this dist:** there is no Keycloak module on CPAN (as of 2026-10-02; the
search only finds generic OIDC and SAML modules that mention Keycloak). A
`WWW::Keycloak` following the pattern of `WWW::Zitadel` (OIDC plus admin API for realms,
clients, users) is a separate dist and the basis for an automated
Keycloak setup. Airlock does not depend on it.

## 8. Security

- `user_code` has about 2.5 · 10¹⁰ possibilities and lives 10 minutes. The core reports failed attempts
  as `code_miss` with subject and origin; the host app has to do the limiting, because only
  it knows sessions and IPs. The docs say so clearly, the example demonstrates it.
- `inspect` returns client name, scopes, origin (IP, user agent) and the age of the request,
  so the page can show them. Confirmation happens only through an `approve` call with a
  subject, never by merely opening `verification_uri_complete`.
- `device_code` only hashed in the store; comparisons in constant time.
- Redemption is atomic and one-time.
- Factors: replay protection for TOTP, limited attempts per request, after which the request is
  `denied`.
- Error responses strictly per RFC 8628 (HTTP 400 with `error`).
- No codes, tokens or factor secrets in logs or events.

## 9. Tests and phases

Tests: state machine with built-in storage and a fake clock; `Airlock::Test::Store`
against the built-in storage and against the DBI example on SQLite; TOTP against the
test vectors from RFC 6238; QR by reading back; `to_app` with raw PSGI envs and
`handle` with `HTTP::Request`; `Airlock::Client` against `to_app` on a local port;
Keycloak live behind the environment variable.

| Phase | Content |
|---|---|
| 1 | Core, code, policy, store subs with built-in storage, `Airlock::Test::Store`, Factor::Callback/TOTP/Upstream, issuer sub with opaque default, QR, `to_app`, `handle`, client, Keycloak mapping with live test, examples (Plack, Mojolicious, DBI, DBIO) |
| 2 | JWT issuer with JWKS, recovery codes, Mojolicious plugin if needed, further IdP mappings |
| 3 | Factor::WebAuthn, "confirm login on a second device" (session instead of token), token exchange |

Dependencies in phase 1: `Moo`, `Crypt::URandom`, `JSON::MaybeXS`, `GD::Barcode`,
`HTTP::Tiny`, `Digest::SHA`. `HTTP::Message` as `recommends`. No Plack, no DBI, no
Mojolicious at runtime; the examples and tests pull them in only as test or
development dependencies.

## 10. Decided

- One dist `Airlock`, with the client in it.
- PSGI and functions in phase 1, plus `HTTP::Request`/`HTTP::Response`. Mojolicious
  phase 2 at the earliest.
- No templates, no user interface in Airlock.
- Store as subs of the host app, examples for DBI and DBIO, no driver in the dist.
- Keycloak minimal (login source plus client), tested live.
- Opaque token as default, JWT in phase 2.

## 11. Clarified during planning (revision 3)

The implementation plan was written against a working prototype. In the process,
several points shifted relative to the text above; where they contradict it, they win.

- **`handle` is not a method of `Airlock`.** It lives in `Airlock::HTTPMessage->new(
  airlock => $airlock )->handle( $request, ip => ... )`. Reason: the house rule forbids
  deferred `require`, and `Airlock` itself should not depend on `HTTP::Message`.
  `to_app` and `respond` stay methods of `Airlock`.
- **The store row** has the fields `hash kind user_code client_id scope state created
  expires poll_interval last_poll subject amr acr auth_time approved origin_ip origin_ua
  factor_failures`. `find` searches by `hash` or `user_code`. The poll interval is called
  `poll_interval`, because `INTERVAL` is reserved in some SQL dialects.
- **Opaque tokens live in the same table** as the requests (`kind` is `request` or
  `token`). That keeps the store at four subs. There is also `revoke_token`.
- **The `user_code` stays on a confirmed request** until it is redeemed, denied
  or expired. Only that way does a double click on "Confirm" also report success the second time
  instead of "unknown code". For every other person the code stays unknown.
- **The built-in storage refuses use across a fork.** Under a
  prefork server, codes would otherwise be randomly unknown.
- **The encoder seam of `Airlock::QR` is a coderef attribute** (`encoder`). There is no
  automatic switch to `Text::QRCode`. The proof is done:
  `GD::Barcode::QRcode` 2.02 runs without GD, and an independent decoder (jsQR) reads the
  matrices back at all four error correction levels.
- **`code_miss` carries the subject, not the origin.** The host app knows IP and session
  itself at that point.

After the independent review and the first live run against Keycloak, these were added:

- **The store can add.** A value in the changes of `update` that is a reference
  to a number (`{ factor_failures => \1 }`) is added to the column. Only that way do
  parallel failed attempts count individually; `Airlock::Test::Store` checks it.
- **Factors have two phases:** `verify` checks, `commit` consumes. A TOTP code is
  consumed only once all factors of a confirmation have held, and `accept_step`
  can report a lost race by returning a false value.
- **An empty proof counts as missing,** not as a failed attempt.
- **`auth_time` is not invented.** If the subject brings none, the grant has none.
- **Keycloak finding (26.8.0):** in the default realm, password login and login with TOTP
  both carry `acr=1` and no `amr`. With the AMR protocol mapper on the client and reference values
  on the steps of the authentication flows (`t/keycloak/setup.pl`), Keycloak reports
  `amr=pwd` or `amr=pwd,otp` respectively, and `Airlock::Factor::Upstream` tells
  the logins apart. Points A and B from section 7 are thus confirmed live: the test
  runs a complete device flow with a browser login against Keycloak. Details in
  `t/keycloak/README.md`.

The policy is a separate class `Airlock::Policy`; a hash is converted at construction.
Results are `Airlock::Result` objects with `ok`, `status`, `data`,
`missing` and `oauth`.
