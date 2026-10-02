package Airlock::Factor;

# ABSTRACT: Role for a second factor that secures an Airlock approval

use Types::Standard qw( Str );
use Moo::Role;

our $VERSION = '0.001';

=synopsis

    package My::Factor;
    use Moo;
    with 'Airlock::Factor';

    sub verify {
      my ( $self, $subject, $proof ) = @_;
      return $proof eq 'open sesame' ? 1 : 0;
    }

=description

A factor answers one question: does this proof, from this subject, hold?
L<Airlock::Policy> decides which factors an approval needs; L<Airlock> asks
each of them and only then lets the request through.

=cut

requires 'verify';

=method verify

    $factor->verify( $subject, $proof )

Required of the consumer. Returns true when the proof holds. Must not throw
for a wrong proof.

=cut

has name => (
  is       => 'ro',
  isa      => Str,
  required => 1
);

=attr name

Required. The name a policy refers to, and the key under which the proof
arrives in C<< approve( proofs => { ... } ) >>.

=cut

has amr => (
  is       => 'ro',
  isa      => Str,
  required => 1
);

=attr amr

Required. The Authentication Method Reference (RFC 8176) this factor adds to
the grant once it has verified, for example C<otp>.

=cut

sub commit { 1 }

=method commit

    $factor->commit( $subject, $proof )

Called once every factor of an approval has verified. A factor whose proof may
be used only once records that here, not in C<verify>, so that a proof is not
used up when another factor fails. Returns true; a false return fails the
approval.

=cut

sub needs_proof { 1 }

=method needs_proof

True when the person has to supply something. A factor that only looks at the
subject returns false and is checked without a proof.

=cut

sub available_for { 1 }

=method available_for

    $factor->available_for($subject)

True when the subject can use this factor at all, for example has enrolled.

=cut

1;
