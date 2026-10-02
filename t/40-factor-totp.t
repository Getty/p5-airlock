#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use Airlock::Factor::TOTP;

# RFC 6238 appendix B, SHA-1 rows: 8 digits, secret "12345678901234567890"
my $rfc_secret = '12345678901234567890';
my %vector     = (
  59          => '94287082',
  1111111109  => '07081804',
  1111111111  => '14050471',
  1234567890  => '89005924',
  2000000000  => '69279037',
  20000000000 => '65353130'
);

my $clock = 0;
my %step;

sub totp {
  my ( %arg ) = @_;
  return Airlock::Factor::TOTP->new(
    secret      => sub { $_[0]{id} eq 'nobody' ? undef : $rfc_secret },
    last_step   => sub { $step{ $_[0]{id} } },
    accept_step => sub { $step{ $_[0]{id} } = $_[1] },
    now         => sub { $clock },
    %arg
  );
}

subtest 'RFC 6238 test vectors' => sub {
  my $totp = totp( digits => 8 );
  is( $totp->code_at( $rfc_secret, int( $_ / 30 ) ), $vector{$_}, 'time '.$_ ) for sort { $a <=> $b } keys %vector;
};

subtest 'defaults' => sub {
  my $totp = totp();
  is( $totp->name, 'totp', 'name' );
  is( $totp->amr,  'otp',  'amr' );
  is( $totp->needs_proof, 1, 'needs a proof' );
  is( length $totp->code_at( $rfc_secret, 1 ), 6, 'six digits' );
};

subtest 'verify' => sub {
  my $totp  = totp();
  my $alice = { id => 'alice' };
  $clock = 1_700_000_000;
  my $now_step = int( $clock / 30 );
  my $good     = $totp->code_at( $rfc_secret, $now_step );

  is( $totp->verify( $alice, 'abcdef' ),  0, 'letters' );
  is( $totp->verify( $alice, '12345' ),   0, 'too short' );
  is( $totp->verify( $alice, '1234567' ), 0, 'too long' );
  is( $totp->verify( $alice, undef ),     0, 'undef' );
  is( $totp->verify( $alice, '' ),        0, 'empty' );
  my $wrong = sprintf '%06d', ( $good + 1 ) % 1_000_000;
  is( $totp->verify( $alice, $wrong ), 0, 'wrong code' );
  is( $step{alice}, undef, 'a wrong code records no step' );

  is( $totp->verify( $alice, substr( $good, 0, 3 ).' '.substr( $good, 3 ) ), 1, 'right code, typed with a space' );
  is( $step{alice}, $now_step, 'the accepted step is recorded' );
  is( $totp->verify( $alice, $good ), 0, 'the same code a second time is refused' );
};

subtest 'window and replay' => sub {
  my $totp = totp();
  my $bob  = { id => 'bob' };
  $clock = 1_700_000_000;
  my $now_step = int( $clock / 30 );

  is( $totp->verify( $bob, $totp->code_at( $rfc_secret, $now_step - 2 ) ), 0, 'two steps back is outside the window' );
  is( $totp->verify( $bob, $totp->code_at( $rfc_secret, $now_step + 2 ) ), 0, 'two steps ahead is outside the window' );
  is( $totp->verify( $bob, $totp->code_at( $rfc_secret, $now_step + 1 ) ), 1, 'one step ahead is accepted' );
  is( $totp->verify( $bob, $totp->code_at( $rfc_secret, $now_step ) ),     0, 'an older step than the accepted one is refused' );
  is( $totp->verify( $bob, $totp->code_at( $rfc_secret, $now_step - 1 ) ), 0, 'and so is the one before' );

  my $strict = totp( window => 0 );
  my $carol  = { id => 'carol' };
  is( $strict->verify( $carol, $strict->code_at( $rfc_secret, $now_step - 1 ) ), 0, 'window 0 refuses the previous step' );
  is( $strict->verify( $carol, $strict->code_at( $rfc_secret, $now_step ) ),     1, 'window 0 accepts the current step' );
};

subtest 'not enrolled' => sub {
  my $totp = totp();
  is( $totp->available_for( { id => 'nobody' } ), 0, 'not available' );
  is( $totp->available_for( { id => 'alice' } ),  1, 'available' );
  is( $totp->verify( { id => 'nobody' }, '123456' ), 0, 'verify is false, not an exception' );
};

subtest 'enrolment helpers' => sub {
  my $totp = totp();
  is( length $totp->generate_secret, 20, 'twenty bytes' );
  isnt( $totp->generate_secret, $totp->generate_secret, 'random' );
  is( $totp->base32(''),       '',                 'RFC 4648: empty' );
  is( $totp->base32('f'),      'MY',               'RFC 4648: f' );
  is( $totp->base32('fo'),     'MZXQ',             'RFC 4648: fo' );
  is( $totp->base32('foo'),    'MZXW6',            'RFC 4648: foo' );
  is( $totp->base32('foob'),   'MZXW6YQ',          'RFC 4648: foob' );
  is( $totp->base32('fooba'),  'MZXW6YTB',         'RFC 4648: fooba' );
  is( $totp->base32('foobar'), 'MZXW6YTBOI',       'RFC 4648: foobar' );
  is(
    $totp->otpauth_uri( secret => $rfc_secret, account => 'getty@example.org', issuer => 'Mother Ship' ),
    'otpauth://totp/Mother%20Ship:getty%40example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Mother%20Ship&algorithm=SHA1&digits=6&period=30',
    'otpauth URI'
  );
  ok( !eval { $totp->otpauth_uri( secret => $rfc_secret, account => 'a' ); 1 }, 'missing issuer croaks' );
  like( $@, qr/otpauth_uri needs issuer/, 'and says what is missing' );
};

subtest 'construction' => sub {
  ok( !eval { Airlock::Factor::TOTP->new( secret => sub { }, last_step => sub { } ); 1 }, 'accept_step is required' );
  ok( !eval { Airlock::Factor::TOTP->new( secret => sub { }, accept_step => sub { } ); 1 }, 'last_step is required' );
};

done_testing;
