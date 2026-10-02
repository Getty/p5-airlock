#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use lib 't/lib';

use Airlock::Factor::Callback;
use Airlock::Factor::Upstream;
use AirlockTest;

my @pin_calls;

sub fixture {
  my ( %arg ) = @_;
  @pin_calls = ();
  my $t;
  $t = AirlockTest->new(
    policy  => { step_up => { admin => ['pin'] } },
    factors => [
      Airlock::Factor::Callback->new(
        name      => 'pin',
        amr       => 'pin',
        verify    => sub { push @pin_calls, $_[1]; $_[1] eq '4711' },
        available => sub { $_[0]{id} ne 'nopin' }
      ),
      Airlock::Factor::Upstream->new( max_age => 300, now => sub { $t->clock } )
    ],
    %arg
  );
  return $t;
}

my $alice = { id => 'alice', amr => ['pwd'] };

subtest 'a scope without step-up needs no factor' => sub {
  my $t    = fixture();
  my $data = $t->start( scope => 'read' );
  is_deeply( $t->airlock->requirements( $t->airlock->inspect( $data->{user_code} ), $alice ), [], 'requirements' );
  ok( $t->airlock->approve( $data->{user_code}, subject => $alice )->ok, 'approved without proof' );
  is( scalar @pin_calls, 0, 'the factor was never asked' );
};

subtest 'a step-up scope asks for the factor' => sub {
  my $t    = fixture();
  my $data = $t->start( scope => 'read admin' );
  is_deeply( $t->airlock->requirements( $t->airlock->inspect( $data->{user_code} ), $alice ), ['pin'], 'requirements' );

  my $asked = $t->airlock->approve( $data->{user_code}, subject => $alice );
  is( $asked->status, 'factor_required', 'without proof: factor_required' );
  is_deeply( $asked->missing, ['pin'], 'and names the factor' );
  is( scalar @pin_calls, 0, 'a missing proof is not a verification' );
  is( $t->row( $data->{device_code} )->{factor_failures}, 0, 'nor a failure' );

  my $wrong = $t->airlock->approve( $data->{user_code}, subject => $alice, proofs => { pin => '1234' } );
  is( $wrong->status, 'factor_failed', 'wrong proof: factor_failed' );
  is_deeply( $wrong->missing, ['pin'], 'names the factor' );
  is( $t->row( $data->{device_code} )->{factor_failures}, 1, 'counted' );
  is( $t->row( $data->{device_code} )->{state}, 'pending', 'still pending' );

  my $right = $t->airlock->approve( $data->{user_code}, subject => $alice, proofs => { pin => '4711' } );
  ok( $right->ok, 'right proof: approved' );
  my $token = $t->airlock->redeem( device_code => $data->{device_code}, client_id => 'cli' )->data->{access_token};
  is_deeply( $t->airlock->verify_token($token)->{amr}, [qw( pwd pin )], 'the grant carries the factor amr after the subject amr' );
  is_deeply( $t->event_names, [qw( opened factor_failed approved redeemed )], 'events' );
  is( $t->events->[1]{factor}, 'pin', 'the failure event names the factor' );
  ok( !grep( { /4711|1234/ } map { values %$_ } @{ $t->events } ), 'and no event carries a proof' );
};

subtest 'too many failures deny the request' => sub {
  my $t    = fixture( max_factor_failures => 3 );
  my $data = $t->start( scope => 'admin' );
  my $try  = sub { $t->airlock->approve( $data->{user_code}, subject => $alice, proofs => { pin => $_[0] } )->status };
  is( $try->('0001'), 'factor_failed',     'first' );
  is( $try->('0002'), 'factor_failed',     'second' );
  is( $try->('0003'), 'too_many_failures', 'third is final' );
  is( $t->row( $data->{device_code} )->{state}, 'denied', 'the request is denied' );
  is( $try->('4711'), 'unknown_code', 'the right proof comes too late' );
  is( $t->airlock->redeem( device_code => $data->{device_code}, client_id => 'cli' )->status, 'access_denied', 'the client is told' );
};

subtest 'a factor the subject does not have' => sub {
  my $t      = fixture();
  my $data   = $t->start( scope => 'admin' );
  my $result = $t->airlock->approve( $data->{user_code}, subject => { id => 'nopin' }, proofs => { pin => '4711' } );
  is( $result->status, 'factor_unavailable', 'factor_unavailable' );
  is_deeply( $result->missing, ['pin'], 'names the factor' );
  is( scalar @pin_calls, 0, 'and it is not verified' );
  is( $t->row( $data->{device_code} )->{factor_failures}, 0, 'nor counted as a failure' );
};

subtest 'upstream factor: no proof, no failure count' => sub {
  my $t    = fixture( policy => { always => ['upstream'] } );
  my $data = $t->start;
  is( $t->airlock->approve( $data->{user_code}, subject => { id => 'a', amr => ['pwd'], auth_time => $t->clock } )->status,
    'reauth_required', 'weak login: reauth_required' );
  is( $t->airlock->approve( $data->{user_code}, subject => { id => 'a', amr => ['otp'], auth_time => $t->clock - 301 } )->status,
    'reauth_required', 'old login: reauth_required' );
  is( $t->row( $data->{device_code} )->{factor_failures}, 0, 'neither counts as a failure' );
  ok( $t->airlock->approve( $data->{user_code}, subject => { id => 'a', amr => [qw( pwd otp )], auth_time => $t->clock - 10 } )->ok, 'strong, fresh login: approved' );
  my $token = $t->airlock->redeem( device_code => $data->{device_code}, client_id => 'cli' )->data->{access_token};
  is_deeply( $t->airlock->verify_token($token)->{amr}, [qw( pwd otp mfa )], 'amr without duplicates' );
};

subtest 'two factors: upstream and pin' => sub {
  my $t      = fixture( policy => { always => ['upstream'], step_up => { admin => ['pin'] } } );
  my $data   = $t->start( scope => 'admin' );
  my $strong = { id => 'a', amr => ['otp'], auth_time => $t->clock };
  is_deeply( $t->airlock->requirements( $t->airlock->inspect( $data->{user_code} ), $strong ), [qw( upstream pin )], 'requirements' );
  my $asked = $t->airlock->approve( $data->{user_code}, subject => $strong );
  is( $asked->status, 'factor_required', 'upstream holds, pin is still missing' );
  is_deeply( $asked->missing, ['pin'], 'only the pin is asked for' );
  ok( $t->airlock->approve( $data->{user_code}, subject => $strong, proofs => { pin => '4711' } )->ok, 'both: approved' );
};

subtest 'max_auth_age refuses any approval from an old login' => sub {
  my $t    = fixture( policy => { max_auth_age => 60 } );
  my $data = $t->start;
  is( $t->airlock->approve( $data->{user_code}, subject => { id => 'a', auth_time => $t->clock - 61 } )->status, 'reauth_required', 'too old' );
  is( $t->airlock->approve( $data->{user_code}, subject => { id => 'a' } )->status, 'reauth_required', 'no auth_time' );
  ok( $t->airlock->approve( $data->{user_code}, subject => { id => 'a', auth_time => $t->clock - 60 } )->ok, 'fresh enough' );
};

subtest 'a policy naming an unknown factor is a programming error' => sub {
  my $t    = fixture( policy => { always => ['fingerprint'] } );
  my $data = $t->start;
  ok( !eval { $t->airlock->approve( $data->{user_code}, subject => $alice ); 1 }, 'croaks' );
  like( $@, qr/unknown factor fingerprint/, 'and names it' );
};

done_testing;
