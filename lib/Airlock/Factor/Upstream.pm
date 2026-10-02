package Airlock::Factor::Upstream;

# ABSTRACT: Accept a second factor the identity provider has already checked

use Moo;
with 'Airlock::Factor';
use Types::Standard qw( ArrayRef CodeRef Int Str );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $upstream = Airlock::Factor::Upstream->new( max_age => 300 );

    # the host app passes what the ID token said
    $airlock->approve( $user_code, subject => {
      id        => $claims->{sub},
      amr       => $claims->{amr},
      acr       => $claims->{acr},
      auth_time => $claims->{auth_time},
    } );

=description

When the host application logs people in through an identity provider that
already does multi-factor authentication, asking again would be noise. This
factor holds when the subject carries the right C<amr> or C<acr> and, if
C<max_age> is set, authenticated recently enough.

It needs no proof from the person. When it does not hold, the host application
sends the person back to the identity provider with L</reauth_params>.

=cut

has '+name' => ( default => 'upstream' );
has '+amr'  => ( default => 'mfa' );

has accept_amr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [qw( mfa otp hwk )] }
);

=attr accept_amr

C<amr> values of which one is enough. Default C<mfa>, C<otp>, C<hwk>.

=cut

has accept_acr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [] }
);

=attr accept_acr

C<acr> values of which one is enough. Empty by default, because what an C<acr>
value means is defined by each identity provider.

=cut

has max_age => (
  is        => 'ro',
  isa       => Int,
  predicate => 'has_max_age'
);

=attr max_age

Optional. Seconds since C<auth_time> after which the authentication is too old.

=cut

has now => (
  is      => 'ro',
  isa     => CodeRef,
  default => sub { sub { time } }
);

=attr now

Coderef returning the current epoch. For tests.

=cut

sub needs_proof { 0 }

sub verify {
  my ( $self, $subject ) = @_;
  my %amr    = map { $_ => 1 } @{ $subject->{amr} || [] };
  my $strong = grep { $amr{$_} } @{ $self->accept_amr };
  $strong ||= grep { defined $subject->{acr} && $_ eq $subject->{acr} } @{ $self->accept_acr };
  return 0 unless $strong;
  return 1 unless $self->has_max_age;
  return 0 unless defined $subject->{auth_time};
  return $self->now->() - $subject->{auth_time} <= $self->max_age ? 1 : 0;
}

sub reauth_params {
  my ( $self ) = @_;
  return {
    max_age => 0,
    @{ $self->accept_acr } ? ( acr_values => join ' ', @{ $self->accept_acr } ) : ()
  };
}

=method reauth_params

    my $params = $upstream->reauth_params;   # { max_age => 0, acr_values => '...' }

Parameters to add to the OIDC authorization request that sends the person back
to the identity provider for a fresh, strong authentication.

=cut

1;
