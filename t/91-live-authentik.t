#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Live test against a real authentik. Off unless TEST_AIRLOCK_AUTHENTIK_URL
# and TEST_AIRLOCK_AUTHENTIK_TOKEN are set and t/authentik/setup.pl has run
# against that instance. See t/authentik/README.md.

BEGIN {
  plan skip_all => 'set TEST_AIRLOCK_AUTHENTIK_URL and TEST_AIRLOCK_AUTHENTIK_TOKEN to run the authentik live test'
    unless $ENV{TEST_AIRLOCK_AUTHENTIK_URL} && $ENV{TEST_AIRLOCK_AUTHENTIK_TOKEN};
}

# The login and the TOTP enrolment go through authentik's flow executor,
# whose shape belongs to authentik and changes with its versions. The helper
# for it lives with WWW::Authentik, which is also what sets the fixtures up;
# Airlock does not carry a copy of either. Point AIRLOCK_AUTHENTIK_LIB and
# AIRLOCK_WWW_AUTHENTIK_LIB at that checkout.
my ( $executor_lib, $client_lib );

BEGIN {
  my $neighbour = $ENV{AIRLOCK_WWW_AUTHENTIK} || "$ENV{HOME}/dev/p5-www-authentik";
  $executor_lib = $ENV{AIRLOCK_AUTHENTIK_LIB}     || $neighbour.'/t/lib';
  $client_lib   = $ENV{AIRLOCK_WWW_AUTHENTIK_LIB} || $neighbour.'/lib';
  plan skip_all => "the WWW::Authentik checkout is needed for the flow executor and the fixtures; looked in $neighbour"
    unless -f $executor_lib.'/AuthentikExecutor.pm' && -f $client_lib.'/WWW/Authentik.pm';
}

use lib $executor_lib, $client_lib;

use AuthentikExecutor;
use JSON::MaybeXS;
use MIME::Base64 qw( decode_base64url );
use WWW::Authentik;
use Airlock;
use Airlock::Client;
use Airlock::Upstream::Authentik;

my $base  = $ENV{TEST_AIRLOCK_AUTHENTIK_URL} =~ s{/+\z}{}r;
my $slug  = 'airlock-test';
my $api   = WWW::Authentik->new( base_url => $base, token => $ENV{TEST_AIRLOCK_AUTHENTIK_TOKEN} )->api;

my $provider = eval { $api->find_oauth2_provider($slug) };
BAIL_OUT( 'no provider "'.$slug.'": run t/authentik/setup.pl against '.$base.' first' ) unless $provider;
my $client_id = $provider->{client_id};

sub claims {
  my ( $jwt ) = @_;
  return decode_json( decode_base64url( ( split /\./, $jwt )[1] ) );
}

sub client {
  return Airlock::Client->new(
    issuer    => $base.'/application/o/'.$slug,
    client_id => $client_id,
    scope     => 'openid email profile',
    sleep     => sub { sleep 1 },
    on_prompt => sub { }
  );
}

# What a person does after the device showed its code: log in, then open the
# verification link, which authentik turns into one run of the authorization
# flow. Returns '' when the device was approved, otherwise what went wrong.
sub approve_in_browser {
  my ( $start, %login ) = @_;
  my $browser = AuthentikExecutor->new( base_url => $base );
  eval { $browser->login( username => $login{username}, password => $login{password},
    totp_secret => $login{totp} ); 1 } or return 'the login failed: '.( $@ =~ s/\n.*//sr );
  my $who = $browser->whoami;
  return 'the login did not make a session' unless $who && $who->{username} eq $login{username};

  my $response = $browser->ua->get( $start->{verification_uri_complete} );
  my $location = $response->header('Location')
    or return 'the verification link answered '.$response->status_line.' instead of a redirect';
  my ( $flow ) = $location =~ m{/if/flow/([^/?]+)};
  return 'the verification link went to '.$location.' instead of a flow' unless $flow;
  my ( $query ) = $location =~ m{\?(.*)\z};
  my $challenge = eval { $browser->start( $flow, $query ) } or return 'the flow executor failed: '.( $@ =~ s/\n.*//sr );
  return 'the approval flow stopped at '.( $challenge->{component} // 'nothing' ).' ('
    .( $challenge->{error_message} // 'no message' ).')'
    unless ( $challenge->{component} // '' ) eq 'ak-provider-oauth2-device-code-finish';
  return '';
}

# a device of an earlier run would make the password-only login ask for a code
sub forget_totp {
  my ( $username ) = @_;
  my $user = $api->find_user($username) or return;
  for my $device ( @{ $api->list_authenticators( $user->{pk} ) || [] } ) {
    next unless ( $device->{type} // '' ) =~ /totp/i;
    eval { $api->call( DELETE => '/authenticators/admin/totp/'.$device->{pk}.'/' ) };
  }
  return;
}

forget_totp('airlock-otp');
forget_totp('airlock-plain');
END { forget_totp('airlock-otp') if $api }

subtest 'discovery and a poll nobody answers' => sub {
  my $client = client();
  like( $client->device_endpoint, qr{\Ahttp}, 'discovery finds the device authorization endpoint' );
  my $start = $client->start;
  ok( length $start->{device_code}, 'device_code' );
  ok( length $start->{user_code},   'user_code' );
  like( $start->{verification_uri_complete}, qr{\Ahttp.+\Q$start->{user_code}\E}, 'verification_uri_complete carries the code' );

  # A poll that outlives a short deadline proves authentik answered
  # authorization_pending the way the client expects; any other answer would
  # croak with "poll failed".
  ok( !eval { $client->poll( { %$start, interval => 1, expires_in => 3 } ); 1 }, 'polling without approval ends' );
  like( $@, qr/the code expired before anyone approved it/, 'because the code ran out, not because of an unexpected answer' );
};

my ( %subject, $totp_secret );

subtest 'enrol TOTP for the second person' => sub {
  my $browser = AuthentikExecutor->new( base_url => $base );
  ok( eval { $browser->login( username => 'airlock-otp', password => 'airlock-otp-password' ); 1 },
    'a password login first' ) or return diag $@;
  $totp_secret = eval { $browser->enroll_totp };
  ok( $totp_secret, 'the setup flow hands out a secret' ) or return diag $@;
  my $user = $api->find_user('airlock-otp');
  ok( scalar @{ $api->list_authenticators( $user->{pk} ) }, 'and the device shows up in the API' );
};

for my $case (
  { name => 'password only',     username => 'airlock-plain', amr => ['pwd'] },
  { name => 'password and TOTP', username => 'airlock-otp',   amr => [qw( pwd mfa )], totp => \$totp_secret }
  )
{
  subtest 'the whole device flow, logging in with '.$case->{name} => sub {
    my %login = ( username => $case->{username}, password => $case->{username}.'-password',
      $case->{totp} ? ( totp => ${ $case->{totp} } ) : () );
    my $client = client();
    my $start  = $client->start;
    my $before = time;
    is( approve_in_browser( $start, %login ), '', 'a person logs in and grants the device access' ) or return;
    my $token = eval { $client->poll( { %$start, interval => 1, expires_in => 30 } ) };
    ok( $token && $token->{access_token}, 'the client gets its token' ) or return diag $@;

    my $claims = claims( $token->{id_token} );
    diag $case->{username}.': acr='.( $claims->{acr} // '(none)' ).' amr='.join( ',', @{ $claims->{amr} || [] } )
      .' auth_time='.( $claims->{auth_time} // '(none)' );
    is( $claims->{preferred_username}, $case->{username}, 'for the person who logged in' );
    is_deeply( $claims->{amr}, $case->{amr}, 'amr says how, with nothing configured for it' );
    is( $claims->{acr}, 'goauthentik.io/providers/oauth2/default', 'acr is the one constant value' );
    cmp_ok( $claims->{auth_time} // 0, '>=', $before - 60, 'auth_time is the login just made' );
    is_deeply( claims( $token->{access_token} )->{amr}, $case->{amr}, 'the access token says the same' );
    $subject{ $case->{username} } = Airlock::Upstream::Authentik->new->subject($claims);
  };
}

subtest 'the upstream factor on real authentik claims' => sub {
  plan skip_all => 'needs both logins' unless $subject{'airlock-plain'} && $subject{'airlock-otp'};
  my $factor = Airlock::Upstream::Authentik->new->factor( max_age => 300 );
  isnt( $subject{'airlock-plain'}{id}, $subject{'airlock-otp'}{id}, 'two people, two ids' );
  is( $factor->verify( $subject{'airlock-plain'} ), 0, 'a password login does not hold' );
  is( $factor->verify( $subject{'airlock-otp'} ),   1, 'a login with TOTP does' );
  my $stale = Airlock::Upstream::Authentik->new->factor( max_age => 300, now => sub { time + 400 } );
  is( $stale->verify( $subject{'airlock-otp'} ), 0, 'but not once it is older than max_age' );
};

subtest 'an Airlock approval with a subject from a real login' => sub {
  plan skip_all => 'needs both logins' unless $subject{'airlock-plain'} && $subject{'airlock-otp'};
  my $upstream = Airlock::Upstream::Authentik->new;
  my $airlock  = Airlock->new(
    clients          => { 'airlock-test-device' => { scopes => ['admin'] } },
    verification_uri => 'https://example.org/airlock',
    policy           => { always => ['upstream'] },
    factors          => [ $upstream->factor( max_age => 300 ) ]
  );

  my $refused = $airlock->open( client_id => 'airlock-test-device', scope => 'admin' );
  ok( $refused->ok, 'a device opens a request' );
  my $answer = $airlock->approve( $refused->data->{user_code}, subject => $subject{'airlock-plain'} );
  is( $answer->status, 'reauth_required', 'the password-only login may not approve it' );
  is_deeply( $answer->missing, ['upstream'], 'and is told which factor is missing' );

  my $granted = $airlock->open( client_id => 'airlock-test-device', scope => 'admin' );
  is( $airlock->approve( $granted->data->{user_code}, subject => $subject{'airlock-otp'} )->status,
    'approved', 'the login with TOTP may' );
  my $token = $airlock->redeem( device_code => $granted->data->{device_code}, client_id => 'airlock-test-device' );
  ok( $token->ok && $token->data->{access_token}, 'and the device redeems its token' );
  like( $token->data->{amr} // '', qr/\bmfa\b/, 'the grant records the second factor' )
    if exists $token->data->{amr};
};

subtest 'an old session with a fresh token' => sub {
  plan skip_all => 'needs the TOTP login' unless $subject{'airlock-otp'} && $totp_secret;
  # authentik mints a new token from the session that is already there, and
  # auth_time stays the moment that session began
  my $browser = AuthentikExecutor->new( base_url => $base );
  ok( eval { $browser->login( username => 'airlock-otp', password => 'airlock-otp-password',
    totp_secret => $totp_secret ); 1 }, 'log in once' ) or return diag $@;
  my $oidc = WWW::Authentik->new( base_url => $base, application => $slug )->oidc;
  my %authorize = ( client_id => $client_id, redirect_uri => 'http://127.0.0.1:1/callback',
    scope => 'openid', state => 's', nonce => 'n' );
  my $first = claims( $oidc->exchange_authorization_code( client_id => $client_id,
    redirect_uri => $authorize{redirect_uri}, code => $browser->authorization_code(%authorize) )->{id_token} );
  sleep 3;
  my $later = claims( $oidc->exchange_authorization_code( client_id => $client_id,
    redirect_uri => $authorize{redirect_uri}, code => $browser->authorization_code(%authorize) )->{id_token} );
  is( $later->{auth_time}, $first->{auth_time}, 'the second token carries the auth_time of the first login' );
  cmp_ok( $later->{iat}, '>', $first->{iat}, 'although it was minted later' );

  my $upstream = Airlock::Upstream::Authentik->new;
  my $subject  = $upstream->subject($later);
  is( $upstream->factor( max_age => 300 )->verify($subject), 1, 'a young session holds' );
  is( $upstream->factor( max_age => 300, now => sub { $later->{auth_time} + 400 } )->verify($subject), 0,
    'an old one does not, however fresh the token is' );
  is( $upstream->factor( max_age => 1 )->verify($subject), 0,
    'and max_age measures the authentication, not the token' );

  # the finding the POD warns about: authentik hands back a code at once
  my $forced = claims( $oidc->exchange_authorization_code( client_id => $client_id,
    redirect_uri => $authorize{redirect_uri},
    code => $browser->authorization_code( %authorize, max_age => 0 ) )->{id_token} );
  is( $forced->{auth_time}, $first->{auth_time}, 'max_age=0 does not make authentik authenticate again' );
};

done_testing;
