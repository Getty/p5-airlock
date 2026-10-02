---
name: airlock-core
description: Use when working on Airlock — the embeddable device-authorization core (RFC 8628 server side), its store/factor/issuer contracts, QR output, PSGI endpoints, or the device-flow client.
---

# Airlock core

Airlock approves a waiting request from an already trusted session, optionally after a
second factor. First use case: the server side of the OAuth 2.0 Device Authorization
Grant (RFC 8628). It is a core to embed, not an application.

**The design is `docs/superpowers/specs/2026-10-02-airlock-design.md`.** Read the section
you are working in before writing code. This skill is the short version; the spec wins.

## Vocabulary

| Term | Meaning |
|---|---|
| Request | the waiting request: `device_code`, `user_code`, client, scopes, state, expiry |
| Client | who asks (CLI, device), identified by `client_id` |
| Subject | who approves — supplied by the host app, at least `id`, optionally `amr`/`acr`/`auth_time` |
| Factor | a second factor securing an approval |
| Policy | decides per request which factors are required |
| Grant | the approved, redeemable request |
| Issuer | turns a grant into the token response |

States: `pending → approved | denied | expired`, `approved → redeemed` exactly once.

## Layout

- `Airlock` — the core: `open`, `inspect`, `requirements`, `approve`, `deny`, `redeem`,
  plus `respond($method, $path, \%params)` → `[$status, \%headers, \%json]`.
- `to_app` (PSGI) and `handle` (`HTTP::Request` → `HTTP::Response`) are thin skins over
  `respond`. Routes: `POST …/device`, `POST …/token`. Nothing else.
- Store: four coderefs from the host app — `insert`, `find`, `update`, `purge`. A built-in
  in-process store is the default. `Airlock::Test::Store` is the contract suite.
- `Airlock::Factor` (Moo::Role): `::Callback`, `::TOTP`, `::Upstream`.
- Issuer: one coderef; default is an opaque token with `verify_token`.
- `Airlock::Code`, `Airlock::QR` (`svg`, `terminal`, `data_uri`, `matrix`).
- `Airlock::Client` — RFC 8628 client over `HTTP::Tiny`.

## Invariants

- **No surface.** No HTML, templates or CSS. The approval page belongs to the host app.
- **No drivers, no frameworks at runtime.** No DBI, Plack or Mojolicious in `requires`.
  `HTTP::Message` is `recommends` and loaded only inside `handle`. `to_app` parses the
  form body from the PSGI env itself.
- **`update` is the only atomic operation.** It carries the expected old state; that
  condition is what prevents two tokens from two concurrent polls.
- **`device_code` reaches the store only as SHA-256.** Comparisons are constant-time.
- **Time is injected** through `now`; no `time()` calls scattered in the code, no `sleep`
  in tests.
- **Errors follow RFC 8628** — HTTP 400 with `error`.
- **Nothing secret in logs or `on_event` payloads** — no codes, tokens, factor secrets.
- **Approval needs an `approve` call with a subject.** Opening
  `verification_uri_complete` never approves anything.

## Phase 1 scope

Core, Code, Policy, store subs with built-in store, `Airlock::Test::Store`,
Factor::Callback/TOTP/Upstream, issuer sub with opaque default, QR, `to_app`, `handle`,
Client, Keycloak mapping with live test, examples (Plack, Mojolicious, DBI, DBIO).
JWT issuer, recovery codes, a Mojolicious plugin and WebAuthn are later phases — do not
build them early.

## Keycloak

`t/90-live-keycloak.t` runs only with `TEST_AIRLOCK_KEYCLOAK_URL`. How Keycloak fills
`acr` and `amr` is established from a real token, not from documentation or memory, and
recorded in `Airlock::Upstream::Keycloak`.
