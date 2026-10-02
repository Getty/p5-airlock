package Airlock::Code;

# ABSTRACT: Generate, normalize, hash and compare Airlock codes

use Moo;
use Crypt::URandom qw( urandom );
use Digest::SHA qw( sha256_hex );
use Types::Standard qw( Int Str );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $code = Airlock::Code->new;

    my $user_code = $code->user_code;              # 'BCDFGHJK'
    print $code->display($user_code);              # 'BCDF-GHJK'
    my $clean = $code->normalize('bcdf ghjk');     # 'BCDFGHJK', or nothing

    my $device_code = $code->secret;               # 64 hex characters
    my $stored      = $code->hash($device_code);   # SHA-256, hex

=description

Everything Airlock does with codes: the short code a person types, the long
secret a device holds, the hash that reaches the store, and a comparison that
takes the same time whether or not the strings match.

=cut

has alphabet => (
  is      => 'ro',
  isa     => Str,
  default => 'BCDFGHJKLMNPQRSTVWXZ'
);

=attr alphabet

Characters a user code is drawn from. The default has no vowels, so no words
appear, and nothing that is easily confused when typed.

=cut

has user_code_length => (
  is      => 'ro',
  isa     => Int,
  default => 8
);

=attr user_code_length

Length of a user code. Default 8.

=cut

has secret_bytes => (
  is      => 'ro',
  isa     => Int,
  default => 32
);

=attr secret_bytes

Random bytes in a secret. Default 32.

=cut

sub user_code {
  my ( $self ) = @_;
  my @chars = split //, $self->alphabet;
  my $limit = 256 - ( 256 % @chars );
  my $code  = '';
  while ( length $code < $self->user_code_length ) {
    for my $byte ( unpack 'C*', urandom(16) ) {
      next if $byte >= $limit;
      $code .= $chars[ $byte % @chars ];
      last if length $code == $self->user_code_length;
    }
  }
  return $code;
}

=method user_code

    my $user_code = $code->user_code;

A new random user code without separator, drawn without modulo bias.

=cut

sub secret { unpack 'H*', urandom( $_[0]->secret_bytes ) }

=method secret

    my $device_code = $code->secret;

A new random secret as hex. Used for device codes and opaque tokens.

=cut

sub hash {
  my ( $self, $value ) = @_;
  utf8::encode($value) if utf8::is_utf8($value);
  return sha256_hex($value);
}

=method hash

    my $stored = $code->hash($device_code);

SHA-256 of a value as hex. Secrets reach the store only in this form.

=cut

sub normalize {
  my ( $self, $input ) = @_;
  return unless defined $input;
  my $code = uc $input;
  $code =~ s/[\s\-_.]//g;
  my $alphabet = $self->alphabet;
  return unless length $code == $self->user_code_length;
  return unless $code =~ /\A[\Q$alphabet\E]+\z/;
  return $code;
}

=method normalize

    my $clean = $code->normalize($typed) or return;

Turns what a person typed into the stored form: upper case, separators and
whitespace removed. Returns nothing unless the result is a well-formed code.

=cut

sub display {
  my ( $self, $code ) = @_;
  return join '-', $code =~ /(.{1,4})/g;
}

=method display

    print $code->display('BCDFGHJK');   # BCDF-GHJK

A code in groups of four, joined by a dash.

=cut

sub equals {
  my ( $self, $left, $right ) = @_;
  return 0 unless defined $left && defined $right;
  return 0 unless length $left == length $right;
  my $diff = 0;
  $diff |= ord( substr $left, $_, 1 ) ^ ord( substr $right, $_, 1 ) for 0 .. length($left) - 1;
  return $diff == 0 ? 1 : 0;
}

=method equals

    $code->equals( $expected, $given ) or return;

Compares two strings in constant time. Returns 1 or 0.

=cut

1;
