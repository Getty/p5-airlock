package Airlock::Factor::Upstream;

# ABSTRACT: Accept a second factor the identity provider has already checked

use Moo;
with 'Airlock::Factor';
use Types::Standard qw( ArrayRef CodeRef Int Str );
use namespace::autoclean;

our $VERSION = '0.002';

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
Left out, the age of the authentication does not matter and only C<amr> and
C<acr> decide.

Set, it needs an C<auth_time> to measure: a subject without one never passes,
whatever its C<amr> says. That is deliberate — an unknown age is not a young
one — but it means that against an identity provider which omits C<auth_time>
the factor silently never holds. Check that yours sends it before setting this.

=cut

has now => (
  is      => 'ro',
  isa     => CodeRef,
  default => sub { sub { time } }
);

=attr now

Coderef returning the current epoch. For tests.

=cut

sub clock_skew { 60 }

=method clock_skew

    my $seconds = $upstream->clock_skew;   # 60

How far the identity provider's clock may run ahead of this one, in seconds.
Sixty, not configurable; override the method in a subclass to change it.

It bends one way only. An C<auth_time> up to C<clock_skew> seconds in the future
is taken as now, because a provider whose clock is fast would otherwise be
unusable. The L</max_age> edge gets no such tolerance: with the default skew and
C<< max_age => 300 >>, an authentication passes while its apparent age is
between C<-60> and C<300> seconds. A provider running fast therefore gets a
shorter effective window, never a longer one, which is the safe direction.

=cut

sub needs_proof { 0 }

=method needs_proof

False. The person does nothing here; the identity provider already asked.

=cut

sub verify {
  my ( $self, $subject ) = @_;
  my %amr    = map { $_ => 1 } @{ $subject->{amr} || [] };
  my $strong = grep { $amr{$_} } @{ $self->accept_amr };
  $strong ||= grep { defined $subject->{acr} && $_ eq $subject->{acr} } @{ $self->accept_acr };
  return 0 unless $strong;
  return 1 unless $self->has_max_age;
  return 0 unless defined $subject->{auth_time};
  my $age = $self->now->() - $subject->{auth_time};
  return $age >= -$self->clock_skew && $age <= $self->max_age ? 1 : 0;
}

=method verify

    my $ok = $upstream->verify( $subject );

True when the subject carries one of L</accept_amr> or one of L</accept_acr>
and, if L</max_age> is set, has an C<auth_time> within it. The proof argument
the role passes is ignored.

=cut

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

C<< max_age => 0 >> is what OpenID Connect Core gives for "authenticate again
whatever happened". Not every provider honours it: authentik 2026.8.3 tests the
value for truth and so discards exactly the zero, letting the existing session
through. L<Airlock::Upstream::Authentik/reauth_params> sends C<prompt=login>
instead. If your provider is not authentik, send one request with
C<< max_age => 0 >> against a live session before you trust this.

=cut

1;
