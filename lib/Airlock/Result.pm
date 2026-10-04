package Airlock::Result;

# ABSTRACT: Outcome of an Airlock operation

use Moo;
use Types::Standard qw( ArrayRef Bool HashRef Str );
use namespace::autoclean;

our $VERSION = '0.002';

=synopsis

    my $result = $airlock->redeem( device_code => $device_code, client_id => $client_id );

    if ( $result->ok ) { my $token = $result->data->{access_token} }
    else               { warn $result->status }

    my ( $http_status, $json ) = @{ $result->oauth };

=description

Every L<Airlock> operation that can fail for an ordinary reason returns one of
these instead of throwing. Exceptions are kept for programming errors.

=cut

has ok => (
  is       => 'ro',
  isa      => Bool,
  required => 1
);

=attr ok

True when the operation did what was asked.

=cut

has status => (
  is       => 'ro',
  isa      => Str,
  required => 1
);

=attr status

What happened, as one word. On failure this is the OAuth error code where one
exists (C<authorization_pending>, C<slow_down>, C<access_denied>,
C<expired_token>, C<invalid_grant>, C<invalid_client>, C<invalid_scope>,
C<invalid_request>) or an Airlock reason (C<unknown_code>, C<factor_required>,
C<factor_unavailable>, C<factor_failed>, C<too_many_failures>,
C<reauth_required>).

=cut

has data => (
  is      => 'ro',
  isa     => HashRef,
  default => sub { {} }
);

=attr data

The payload of a success: the device authorization response after C<open>, the
token response after C<redeem>.

=cut

has missing => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [] }
);

=attr missing

Names of the factors an approval still needs or that did not hold.

=cut

sub oauth {
  my ( $self ) = @_;
  return $self->ok ? [ 200, { %{ $self->data } } ] : [ 400, { error => $self->status } ];
}

=method oauth

    my ( $http_status, $json ) = @{ $result->oauth };

The result as RFC 8628 wants it on the wire: 200 with the payload, or 400 with
C<error>.

=cut

1;
