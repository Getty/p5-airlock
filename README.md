# Airlock

Embeddable device authorization (RFC 8628) with step-up second factors.

A device or CLI shows a short code. A logged-in person enters or scans it
somewhere else, sees who wants what, approves — if the policy says so, only
after a second factor — and the device gets its token.

Airlock is a core to embed, not an application. The host application supplies
who is logged in, the approval page and four storage subs. Airlock supplies
codes, the state machine, poll rules, one-time redemption, step-up policy,
second factors, QR codes, the two machine endpoints, and a device-flow client.

It has no HTML, no database driver and no web framework at runtime.

## Installation

```bash
cpanm Airlock
```

## Embedding

```perl
use Airlock;
use Airlock::Factor::Callback;

my $airlock = Airlock->new(
  clients          => { 'my-cli' => { name => 'My CLI', scopes => [qw( read admin )] } },
  verification_uri => 'https://my.example.org/approve',
  store            => { insert => sub {...}, find => sub {...}, update => sub {...}, purge => sub {...} },
  policy           => { step_up => { admin => ['totp'] } },
  factors          => [ Airlock::Factor::Callback->new( name => 'totp', amr => 'otp', verify => sub {...} ) ],
);
```

### Machine side

```perl
# PSGI, no Plack needed
builder { mount '/airlock' => $airlock->to_app; mount '/' => $app };

# HTTP::Request in, HTTP::Response out
my $response = Airlock::HTTPMessage->new( airlock => $airlock )->handle( $request, ip => $remote_address );

# anything else
my ( $status, $headers, $json ) = @{ $airlock->respond( 'POST', $path, \%form, { ip => $ip, ua => $ua } ) };
```

Two routes, matched on the last path segment: `POST .../device` and
`POST .../token`.

### Human side

The approval page is yours. Airlock gives it data and takes its decision:

```perl
my $view  = $airlock->inspect( $typed_code, subject => $subject ) or return not_found();
my $needs = $airlock->requirements( $view, $subject );     # ['totp']
my $done  = $airlock->approve( $typed_code, subject => $subject, proofs => { totp => $typed } );
my $done  = $airlock->deny( $typed_code, subject => $subject );
```

`$subject` is who is logged in: `{ id => ... }`, optionally with `amr`, `acr`
and `auth_time` from your identity provider. Login, CSRF protection and rate
limits are yours too; `on_event` reports every `code_miss` and
`factor_failed` to hang a limit on.

## Store

Four subs against whatever database you have:

| Sub | Does |
|---|---|
| `insert(\%row)` | stores a row; dies on a duplicate `hash` or `user_code` |
| `find($field, $value)` | row by `hash` or `user_code`, or nothing |
| `update($hash, $from_state, \%changes)` | applies the changes only if `state` is still `$from_state`; returns true if it did |
| `purge($before)` | removes rows with `expires < $before`; optional |

`update` is the only one that has to be atomic. `Airlock->row_fields` lists
the columns, `examples/schema.sql` is a table for them, and
`Airlock::Test::Store` checks your four subs against the contract:

```perl
use Airlock::Test::Store;
Airlock::Test::Store->new( store => $my_subs )->run;
```

Without a store Airlock keeps rows in the process, which is right for tests
and wrong under a preforking server; it croaks when used across a fork.

## Second factors

| Class | Use |
|---|---|
| `Airlock::Factor::Callback` | your application checks the proof |
| `Airlock::Factor::TOTP` | RFC 6238, secrets supplied by your application |
| `Airlock::Factor::Upstream` | the identity provider already checked one (`amr`, `acr`, `auth_time`) |

`Airlock::Upstream::Keycloak` turns Keycloak token claims into a subject.

## QR codes

```perl
my $qr = Airlock::QR->new( text => $verification_uri_complete );
$qr->svg;        # for the web
$qr->data_uri;   # for an <img>
$qr->terminal;   # for a CLI
```

## Client

```perl
my $token = Airlock::Client->new(
  issuer    => 'https://id.example.org/realms/main',
  client_id => 'my-cli',
)->login;
```

Works against Airlock, Keycloak and any other RFC 8628 server.

## Examples

`examples/` has the whole thing running: `app.psgi` (Plack) and `mojo.pl`
(Mojolicious) with a minimal approval page, `login.pl` as the device, and the
store on DBI and on DBIO.

## License

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
