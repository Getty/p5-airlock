package Airlock::Factor::Callback;

# ABSTRACT: Second factor checked by the host application

use Moo;
with 'Airlock::Factor';
use Types::Standard qw( CodeRef );
use namespace::autoclean;

our $VERSION = '0.002';

=synopsis

    my $factor = Airlock::Factor::Callback->new(
      name   => 'totp',
      amr    => 'otp',
      verify => sub {
        my ( $subject, $proof ) = @_;
        return $directory->check_totp( $subject->{id}, $proof );
      },
    );

=description

For a host application that already has a second factor somewhere else, for
example in its directory server. Airlock hands over subject and proof and
takes the answer.

=cut

has _verify => (
  is       => 'ro',
  isa      => CodeRef,
  init_arg => 'verify',
  required => 1
);

=attr verify

Required. Coderef called with the subject and the proof; returns true when the
proof holds.

=cut

has _available => (
  is        => 'ro',
  isa       => CodeRef,
  init_arg  => 'available',
  predicate => '_has_available'
);

=attr available

Optional. Coderef called with the subject; returns true when the subject can
use this factor. Without it the factor is available to everyone.

=cut

sub verify {
  my ( $self, $subject, $proof ) = @_;
  return $self->_verify->( $subject, $proof ) ? 1 : 0;
}

sub available_for {
  my ( $self, $subject ) = @_;
  return 1 unless $self->_has_available;
  return $self->_available->($subject) ? 1 : 0;
}

1;
