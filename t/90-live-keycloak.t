#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Live test against a real Keycloak. Off unless TEST_AIRLOCK_KEYCLOAK_URL is
# set to its base URL (for example http://localhost:8080) and the realm from
# t/keycloak/realm.json is imported. See t/keycloak/README.md.

BEGIN {
  plan skip_all => 'set TEST_AIRLOCK_KEYCLOAK_URL to run the Keycloak live test'
    unless $ENV{TEST_AIRLOCK_KEYCLOAK_URL};
}

use HTTP::Tiny;
use JSON::MaybeXS;
use MIME::Base64 qw( decode_base64url );
use Airlock::Client;
use Airlock::Factor::TOTP;
use Airlock::Upstream::Keycloak;

my $issuer = $ENV{TEST_AIRLOCK_KEYCLOAK_URL} =~ s{/+\z}{}r.'/realms/airlock-test';
my $http   = HTTP::Tiny->new( timeout => 20 );

sub claims {
  my ( $jwt ) = @_;
  return decode_json( decode_base64url( ( split /\./, $jwt )[1] ) );
}

sub password_login {
  my ( $token_endpoint, %form ) = @_;
  my $response = $http->post_form( $token_endpoint, { grant_type => 'password', client_id => 'airlock-test-cli', scope => 'openid', %form } );
  ok( $response->{success}, 'direct grant for '.$form{username} ) or diag $response->{content};
  return decode_json( $response->{content} );
}

my $client = Airlock::Client->new(
  issuer    => $issuer,
  client_id => 'airlock-test-cli',
  scope     => 'openid',
  sleep     => sub { sleep 1 },
  on_prompt => sub { }
);

subtest 'the client runs against Keycloak\'s device endpoint' => sub {
  like( $client->device_endpoint, qr{\Ahttp}, 'discovery finds the device authorization endpoint' );
  my $start = $client->start;
  ok( length $start->{device_code}, 'device_code' );
  ok( length $start->{user_code},   'user_code' );
  like( $start->{verification_uri}, qr{\Ahttp}, 'verification_uri' );
  diag 'Keycloak device response keys: '.join( ', ', sort keys %$start );

  # Nobody approves in this test. A poll that outlives a short deadline proves
  # Keycloak answered authorization_pending (and slow_down, if it did) the way
  # the client expects; any other answer would croak with "poll failed".
  ok( !eval { $client->poll( { %$start, interval => 1, expires_in => 3 } ); 1 }, 'polling without approval ends' );
  like( $@, qr/the code expired before anyone approved it/, 'because the code ran out, not because of an unexpected answer' );
};

subtest 'what Keycloak says about a login with and without a second factor' => sub {
  my $keycloak = Airlock::Upstream::Keycloak->new;
  my $factor   = $keycloak->factor;
  my $totp     = Airlock::Factor::TOTP->new( secret => sub { }, last_step => sub { }, accept_step => sub { } );

  my $plain = password_login( $client->token_endpoint, username => 'plain', password => 'plain-password' );
  my $otp   = password_login(
    $client->token_endpoint,
    username => 'otp',
    password => 'otp-password',
    totp     => $totp->code_at( '12345678901234567890', int( time / 30 ) )
  );

  for my $case ( [ plain => $plain ], [ otp => $otp ] ) {
    my ( $name, $tokens ) = @$case;
    for my $kind (qw( id_token access_token )) {
      next unless $tokens->{$kind};
      my $claims = claims( $tokens->{$kind} );
      diag $name.' '.$kind.': acr='.( $claims->{acr} // '(none)' ).' amr='.( ref $claims->{amr} ? join( ',', @{ $claims->{amr} } ) : $claims->{amr} // '(none)' ).' auth_time='.( $claims->{auth_time} // '(none)' );
    }
  }

  my $plain_subject = $keycloak->subject( claims( $plain->{id_token} ) );
  my $otp_subject   = $keycloak->subject( claims( $otp->{id_token} ) );
  ok( length $plain_subject->{id}, 'the subject has an id' );
  isnt( $plain_subject->{id}, $otp_subject->{id}, 'two users, two ids' );
  is( $factor->verify($plain_subject), 0, 'a password login does not satisfy the upstream factor' );
  is( $factor->verify($otp_subject),   1, 'a login with TOTP does' );
};

done_testing;
