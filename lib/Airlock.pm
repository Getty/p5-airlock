package Airlock;

# ABSTRACT: Embeddable device authorization (RFC 8628) with step-up second factors

use strict;
use warnings;

our $VERSION = '0.001';

1;

__END__

=head1 DESCRIPTION

Airlock is an embeddable core for approving a waiting request from an already
trusted session: the OAuth 2.0 Device Authorization Grant (RFC 8628) on the
server side, with an optional second factor before the approval counts.

This is a skeleton. The design lives in F<docs/superpowers/specs/>.

=cut
