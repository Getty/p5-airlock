# Airlock House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They
load as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish
nothing until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Embeddable core for approving a waiting request from an already trusted session — the
server side of the OAuth 2.0 Device Authorization Grant (RFC 8628) with optional step-up
factors, QR codes, PSGI endpoints and a device-flow client. Read first: the callers and the
spec section the code belongs to (`docs/superpowers/specs/`).

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug behavior-relevant code | `airlock-worker` (default) |
| Write/extend tests | `airlock-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `airlock-release-manager` |
| Write/maintain POD | `airlock-doc-writer` |
| Read-only research, audit, gap analysis | `airlock-worker` ("read-only, change nothing") |

Behavior-relevant = runtime behavior, the public API (`Airlock`, `Airlock::QR`,
`Airlock::Client`, the store/factor/issuer contracts, the PSGI and HTTP::Message entry
points), error handling, tests, performance. Pure prose docs and `Changes` notes are not.

## Hazards

- **Airlock ships no surface and no drivers.** No HTML, no templates, no DBI, no Plack and
  no Mojolicious at runtime. A convenience that needs one of them belongs in `examples/`.
- **Security invariants are not negotiable in review.** `device_code` only hashed in the
  store, redeem exactly once through the conditional `update`, constant-time comparisons,
  no codes, tokens or secrets in logs or events. A change that weakens one needs the
  maintainer, not a judgment call.
- **Live test hits a real Keycloak.** `t/90-live-keycloak.t` runs only with
  `TEST_AIRLOCK_KEYCLOAK_URL` set. Never enable it in a fanned-out or parallel context.
- **Board writes on this shared box** have OOM-rebooted it — the serialization rule is not
  theoretical here.
- **Test runner trap.** Plain `prove -l t/` is non-recursive; always use `prove -lr t` so
  subdir tests are never silently skipped.

## Perl specifics — reference, don't restate

Module loading, Moo patterns, dependency pinning, `[@Author::GETTY]` release metadata, POD
and house style live in skills `getty-perl-core`, `getty-perl-moo`, `perl-release-dist-ini`,
`getty-perl-release-author-getty` and `airlock-core` (force-loaded per lane via
`briefing.skills`).
