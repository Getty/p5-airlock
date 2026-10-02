package Airlock::Upstream::Keycloak;

# ABSTRACT: Use a Keycloak login as the subject of an Airlock approval

use Moo;
use Airlock::Factor::Upstream;
use Carp qw( croak );
use Types::Standard qw( ArrayRef Str );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $keycloak = Airlock::Upstream::Keycloak->new;

    my $airlock = Airlock->new(
      policy  => { always => ['upstream'] },
      factors => [ $keycloak->factor( max_age => 300 ) ],
      ...
    );

    # in the approval action, with the claims of the person's ID token
    my $result = $airlock->approve( $code, subject => $keycloak->subject($claims) );

=description

When the host application logs people in through Keycloak, this class turns
the token claims into the subject L<Airlock> wants, and builds the
L<Airlock::Factor::Upstream> that recognises a Keycloak login with a second
factor.

A Keycloak realm in its default configuration does not report a second factor
in the token: with Keycloak 26.8.0 a password login and a login with TOTP both
carry C<acr=1> and no C<amr>. The factor built here holds only once the realm
is configured to report one, through an C<amr> protocol mapper or through
step-up authentication with its own C<acr> values, and L</mfa_amr> or
L</mfa_acr> name what it reports.

=cut

has mfa_amr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [qw( mfa otp hwk )] }
);

=attr mfa_amr

C<amr> values that mean a second factor was used.

=cut

has mfa_acr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [] }
);

=attr mfa_acr

C<acr> values that mean a second factor was used.

=cut

sub factor_class { 'Airlock::Factor::Upstream' }

sub subject {
  my ( $self, $claims ) = @_;
  croak __PACKAGE__.'->subject needs claims with a sub'
    unless ref $claims eq 'HASH' && defined $claims->{sub} && length $claims->{sub};
  my $amr = $claims->{amr};
  return {
    id        => $claims->{sub},
    amr       => ref $amr eq 'ARRAY' ? [@$amr] : defined $amr ? [ split ' ', $amr ] : [],
    acr       => $claims->{acr},
    auth_time => $claims->{auth_time}
  };
}

=method subject

    my $subject = $keycloak->subject($claims);

The Airlock subject for a set of token claims: C<id> from C<sub>, and C<amr>,
C<acr> and C<auth_time> as Keycloak sent them. Croaks without C<sub>.

=cut

sub factor {
  my ( $self, %arg ) = @_;
  return $self->factor_class->new( accept_amr => $self->mfa_amr, accept_acr => $self->mfa_acr, %arg );
}

=method factor

    my $factor = $keycloak->factor( max_age => 300 );

An L<Airlock::Factor::Upstream> that holds for a Keycloak login with a second
factor. Takes its options.

=cut

1;
