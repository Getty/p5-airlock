package Airlock::Upstream::Authentik;

# ABSTRACT: Use an authentik login as the subject of an Airlock approval

use Moo;
use Airlock::Factor::Upstream;
use Carp qw( croak );
use Types::Standard qw( ArrayRef Str );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $authentik = Airlock::Upstream::Authentik->new;

    my $airlock = Airlock->new(
      policy  => { always => ['upstream'] },
      factors => [ $authentik->factor( max_age => 300 ) ],
      ...
    );

    # in the approval action, with the claims of the person's ID token
    my $result = $airlock->approve( $code, subject => $authentik->subject($claims) );

=description

When the host application logs people in through authentik, this class turns
the token claims into the subject L<Airlock> wants, and builds the
L<Airlock::Factor::Upstream> that recognises an authentik login with a second
factor.

Unlike L<Airlock::Upstream::Keycloak>, there is nothing to configure in
authentik first. These are the claims of authentik 2026.8.3, observed through
the whole chain in F<t/91-live-authentik.t>, with the default flows and no
mapper added:

=over 4

=item *

A password login carries C<< amr => ['pwd'] >>, a login with TOTP
C<< amr => [ 'pwd', 'mfa' ] >>. The default L</mfa_amr> recognises C<mfa>, so
the factor tells the two apart out of the box.

=item *

C<acr> is C<goauthentik.io/providers/oauth2/default> for both, and is of no
use here. L</mfa_acr> is therefore empty, and C<acr_values> in an
authorization request does not change it either.

=item *

C<auth_time> is the moment the B<session> began, not the moment the token was
minted, and it survives both a refresh and further authorization requests.
That is what L<Airlock::Factor::Upstream/max_age> wants: it measures how old
the authentication is, not how fresh the token is. A token minted now from a
session that is ten minutes old is correctly refused by
C<< max_age => 300 >>.

=item *

C<amr> and C<auth_time> are the same in the ID token, the access token and the
introspection answer.

=back

=head2 Asking for a fresh authentication does not work

L<Airlock::Factor::Upstream/reauth_params> returns C<< max_age => 0 >>, which
is the OpenID Connect way of saying "authenticate this person again". B<authentik
2026.8.3 ignores it>: the authorization endpoint hands back a code at once,
carrying the C<auth_time> of the old session. Observed directly — a session
logged in ten seconds earlier answered a C<< max_age=0 >> request immediately
with the unchanged C<auth_time>.

So a host application on authentik cannot send a person back for a stronger or
fresher login by adding parameters. What does work is ending the authentik
session first, through the application's C<end-session> endpoint, and only then
starting the authorization request again. Airlock does not do that for you: it
has no OIDC client and does not know your application's endpoints.

=head2 Requiring the second factor in authentik

Nothing here forces anyone to use TOTP; it reports what happened. To make
authentik insist, set C<not_configured_action> on the Authenticator Validation
stage of the authentication flow from C<skip> to C<deny> (a person without a
configured authenticator is refused) or to C<configure> (they are sent through
the setup stage first, which also needs C<configuration_stages>).
F<t/authentik/setup.pl> does neither; it builds the test fixtures and leaves
the stage alone, because the live test wants both kinds of login.

=cut

has mfa_amr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [qw( mfa otp hwk )] }
);

=attr mfa_amr

C<amr> values that mean a second factor was used. authentik writes C<mfa>,
which the default covers.

=cut

has mfa_acr => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [] }
);

=attr mfa_acr

C<acr> values that mean a second factor was used. Empty, and worth leaving
empty: authentik sends one constant C<acr> whatever happened.

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

    my $subject = $authentik->subject($claims);

The Airlock subject for a set of token claims: C<id> from C<sub>, and C<amr>,
C<acr> and C<auth_time> as authentik sent them. Croaks without C<sub>.

C<sub> is the provider's C<sub_mode>, by default a hash of the user's id, so
it differs between two applications of one authentik. That is fine for Airlock,
which only compares it with itself, but it is not a user id to store.

=cut

sub factor {
  my ( $self, %arg ) = @_;
  return $self->factor_class->new( accept_amr => $self->mfa_amr, accept_acr => $self->mfa_acr, %arg );
}

=method factor

    my $factor = $authentik->factor( max_age => 300 );

An L<Airlock::Factor::Upstream> that holds for an authentik login with a
second factor. Takes its options.

=cut

1;
