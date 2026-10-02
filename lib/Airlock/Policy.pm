package Airlock::Policy;

# ABSTRACT: Decide which factors an Airlock approval needs

use Moo;
use Types::Standard qw( ArrayRef CodeRef HashRef Int Str );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $policy = Airlock::Policy->new(
      always       => ['upstream'],
      step_up      => { admin => ['totp'] },
      max_auth_age => 300,
    );

=description

Maps a request and the approving subject to the names of the factors that have
to verify before the approval counts. Declarative for the usual case, a coderef
for everything else.

=cut

has always => (
  is      => 'ro',
  isa     => ArrayRef[Str],
  default => sub { [] }
);

=attr always

Factor names required for every approval.

=cut

has step_up => (
  is      => 'ro',
  isa     => HashRef[ArrayRef[Str]],
  default => sub { {} }
);

=attr step_up

Hash of scope to factor names. A request asking for that scope needs those
factors.

=cut

has max_auth_age => (
  is        => 'ro',
  isa       => Int,
  predicate => 'has_max_auth_age'
);

=attr max_auth_age

Optional. Seconds since the subject's C<auth_time> after which no approval is
accepted at all. A subject without C<auth_time> then counts as too old.

=cut

has decide => (
  is        => 'ro',
  isa       => CodeRef,
  predicate => 'has_decide'
);

=attr decide

Optional. Coderef called with the request view, the subject and the list the
declarative rules produced; returns the list to use.

=cut

sub required {
  my ( $self, $request, $subject ) = @_;
  my %seen;
  my @names = grep { !$seen{$_}++ } @{ $self->always },
    map { @{ $self->step_up->{$_} || [] } } @{ $request->{scopes} || [] };
  return $self->has_decide ? $self->decide->( $request, $subject, \@names ) : \@names;
}

=method required

    my $names = $policy->required( $view, $subject );

The factor names this approval needs, without duplicates, in a stable order.

=cut

sub fresh {
  my ( $self, $subject, $now ) = @_;
  return 1 unless $self->has_max_auth_age;
  return 0 unless defined $subject->{auth_time};
  return $now - $subject->{auth_time} <= $self->max_auth_age ? 1 : 0;
}

=method fresh

    $policy->fresh( $subject, time ) or return;

True when the subject's authentication is recent enough to approve anything.

=cut

1;
