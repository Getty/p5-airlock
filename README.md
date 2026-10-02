# Airlock

Embeddable device authorization (RFC 8628) with step-up second factors.

Airlock approves a waiting request from an already trusted session: a device or CLI
shows a short code, a logged-in person enters or scans it elsewhere, sees who wants what,
approves — optionally after a second factor — and the device gets its token.

It is a core to embed, not an application. The host app supplies the logged-in subject,
the approval page and four storage subs; Airlock supplies codes, the state machine, poll
rules, one-time redemption, step-up policy, second factors, QR codes, the two machine
endpoints as PSGI, and a device-flow client.

**Status: skeleton.** Nothing is implemented yet. The design is in
[`docs/superpowers/specs/`](docs/superpowers/specs/2026-10-02-airlock-design.md).

## License

This library is free software; you can redistribute it and/or modify it under the same
terms as Perl itself.
