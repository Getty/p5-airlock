#!/usr/bin/env perl

# Makes the test realm report how someone logged in.
#
#   perl t/keycloak/setup.pl http://localhost:8080 [admin-user] [admin-password]
#
# Keycloak only puts an "amr" claim into a token when two things are in place:
# the client has the AMR protocol mapper (that part is in realm.json), and the
# steps of the authentication flow each carry a reference value. The second
# part cannot be imported without spelling out every built-in flow, so this
# script sets it through the Admin REST API. It can be run any number of times.
#
# Checked against Keycloak 26.8.0.

use strict;
use warnings;
use HTTP::Tiny;
use JSON::MaybeXS;

my ( $base, $user, $password ) = @ARGV;
die 'usage: setup.pl KEYCLOAK_URL [admin-user] [admin-password]'."\n" unless $base;
$base =~ s{/+\z}{};
$user     //= 'admin';
$password //= 'admin';

my $realm = 'airlock-test';
my $http  = HTTP::Tiny->new( timeout => 20 );
my $json  = JSON::MaybeXS->new( utf8 => 1, canonical => 1 );

# flow alias => { authenticator => amr value }
my %reference = (
  'browser'      => { 'auth-username-password-form'    => 'pwd', 'auth-otp-form'             => 'otp' },
  'direct grant' => { 'direct-grant-validate-password' => 'pwd', 'direct-grant-validate-otp' => 'otp' }
);

# how long, in seconds, a step counts towards amr after it was passed
my $max_age = 3600;

my $login = $http->post_form(
  $base.'/realms/master/protocol/openid-connect/token',
  { grant_type => 'password', client_id => 'admin-cli', username => $user, password => $password }
);
die 'admin login failed: '.$login->{status}.' '.$login->{content}."\n" unless $login->{success};
my $token = $json->decode( $login->{content} )->{access_token};

sub admin {
  my ( $method, $path, $body ) = @_;
  my $response = $http->request(
    $method, $base.'/admin/realms/'.$realm.$path,
    {
      headers => { Authorization => 'Bearer '.$token, 'Content-Type' => 'application/json' },
      defined $body ? ( content => $json->encode($body) ) : ()
    }
  );
  die $method.' '.$path.' failed: '.$response->{status}.' '.$response->{content}."\n" unless $response->{success};
  return length $response->{content} ? $json->decode( $response->{content} ) : undef;
}

for my $flow ( sort keys %reference ) {
  my $executions = admin( GET => '/authentication/flows/'.( $flow =~ s/ /%20/gr ).'/executions' );
  for my $authenticator ( sort keys %{ $reference{$flow} } ) {
    my ( $execution ) = grep { ( $_->{providerId} // '' ) eq $authenticator } @$executions;
    die 'flow "'.$flow.'" has no step '.$authenticator."\n" unless $execution;
    my $config = {
      alias  => 'amr '.$flow.' '.$authenticator,
      config => {
        'default.reference.value'  => $reference{$flow}{$authenticator},
        'default.reference.maxAge' => $max_age
      }
    };
    if ( my $id = $execution->{authenticationConfig} ) {
      admin( PUT => '/authentication/config/'.$id, { %$config, id => $id } );
      print 'updated  ';
    }
    else {
      admin( POST => '/authentication/executions/'.$execution->{id}.'/config', $config );
      print 'created  ';
    }
    print $flow.' / '.$authenticator.' => '.$reference{$flow}{$authenticator}."\n";
  }
}
