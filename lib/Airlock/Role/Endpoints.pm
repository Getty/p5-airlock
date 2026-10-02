package Airlock::Role::Endpoints;

# ABSTRACT: The two machine endpoints of Airlock, framework-neutral and as PSGI

use JSON::MaybeXS;
use Moo::Role;

our $VERSION = '0.001';

=synopsis

    # PSGI
    builder { mount '/airlock' => $airlock->to_app; mount '/' => $app };

    # anything else
    my ( $status, $headers, $json ) = @{ $airlock->respond( 'POST', '/device', \%params, { ip => $ip, ua => $ua } ) };

=description

The device authorization endpoint and the token endpoint of RFC 8628, answered
in one place: L</respond>. L</to_app> is a thin PSGI skin over it that needs
neither Plack nor any other framework. L<Airlock::HTTPMessage> is the same for
L<HTTP::Request> and L<HTTP::Response>.

Routes are matched on the last path segment, so the endpoints can be mounted
anywhere: C<POST .../device> and C<POST .../token>.

=cut

requires qw( open redeem );

sub device_grant_type { 'urn:ietf:params:oauth:grant-type:device_code' }

sub max_body { 16384 }

=method max_body

Largest request body, in bytes, the endpoints read. 16384.

=cut

has _json => (
  is       => 'lazy',
  init_arg => undef
);

sub _build__json { JSON::MaybeXS->new( utf8 => 1, canonical => 1, convert_blessed => 1 ) }

sub respond {
  my ( $self, $method, $path, $param, $origin ) = @_;
  my ( $route ) = ( $path // '' ) =~ m{([^/]*)/?\z};
  return $self->_reply( 404, { error => 'not_found' } )
    unless $route eq 'device' || $route eq 'token';
  return $self->_reply( 405, { error => 'invalid_request' }, Allow => 'POST' )
    unless uc( $method // '' ) eq 'POST';
  return $self->_reply( 400, { error => 'invalid_request' } ) unless ref $param eq 'HASH';
  return $self->_reply( 400, { error => 'unsupported_grant_type' } )
    if $route eq 'token' && ( $param->{grant_type} // '' ) ne $self->device_grant_type;
  my $result = $route eq 'device'
    ? $self->open( client_id => $param->{client_id}, scope => $param->{scope}, origin => $origin )
    : $self->redeem( device_code => $param->{device_code}, client_id => $param->{client_id} );
  return $self->_reply( @{ $result->oauth } );
}

=method respond

    my ( $status, $headers, $json ) = @{ $airlock->respond( $method, $path, \%params, \%origin ) };

Answers one request. C<%params> are the decoded form parameters, or anything
that is not a hash when the body could not be parsed. Returns the HTTP status,
a hash of headers and the response body as a data structure.

=cut

sub encode_body {
  my ( $self, $json ) = @_;
  return $self->_json->encode($json);
}

=method encode_body

    my $bytes = $airlock->encode_body($json);

The response body as JSON bytes.

=cut

sub parse_form {
  my ( $self, $body ) = @_;
  my %param;
  for my $pair ( split /&/, $body // '' ) {
    next unless length $pair;
    my ( $key, $value ) = map { $self->_unescape($_) } split /=/, $pair, 2;
    return if exists $param{$key};
    $param{$key} = $value // '';
  }
  return \%param;
}

=method parse_form

    my $params = $airlock->parse_form($body);

Decodes an C<application/x-www-form-urlencoded> body. Returns nothing when a
parameter appears twice, which RFC 6749 forbids.

=cut

sub to_app {
  my ( $self ) = @_;
  return sub {
    my ( $env ) = @_;
    my $length = $env->{CONTENT_LENGTH} || 0;
    return $self->_psgi( $self->_reply( 413, { error => 'invalid_request' } ) ) if $length > $self->max_body;
    my $body = '';
    if ( $length && ( $env->{CONTENT_TYPE} // '' ) =~ m{\Aapplication/x-www-form-urlencoded\b}i ) {
      while ( length $body < $length ) {
        my $read = $env->{'psgi.input'}->read( my $chunk, $length - length $body );
        last unless $read;
        $body .= $chunk;
      }
    }
    return $self->_psgi( $self->respond(
      $env->{REQUEST_METHOD}, $env->{PATH_INFO}, scalar $self->parse_form($body),
      { ip => $env->{REMOTE_ADDR}, ua => $env->{HTTP_USER_AGENT} }
    ) );
  };
}

=method to_app

    my $app = $airlock->to_app;

The two endpoints as a PSGI application.

=cut

sub _reply {
  my ( $self, $status, $json, %header ) = @_;
  return [
    $status,
    { 'Content-Type' => 'application/json', 'Cache-Control' => 'no-store', 'Pragma' => 'no-cache', %header },
    $json
  ];
}

sub _psgi {
  my ( $self, $reply ) = @_;
  my ( $status, $headers, $json ) = @$reply;
  return [ $status, [ map { $_ => $headers->{$_} } sort keys %$headers ], [ $self->encode_body($json) ] ];
}

sub _unescape {
  my ( $self, $text ) = @_;
  return unless defined $text;
  $text =~ tr/+/ /;
  $text =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
  return $text;
}

1;
