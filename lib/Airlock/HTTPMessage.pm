package Airlock::HTTPMessage;

# ABSTRACT: Airlock's machine endpoints for HTTP::Request and HTTP::Response

use Moo;
use HTTP::Response;
use HTTP::Status qw( status_message );
use Types::Standard qw( InstanceOf );
use namespace::autoclean;

our $VERSION = '0.001';

=synopsis

    my $http     = Airlock::HTTPMessage->new( airlock => $airlock );
    my $response = $http->handle( $request, ip => $remote_address );

=description

For a host application that is neither PSGI nor anything Airlock knows about,
but can produce an L<HTTP::Request> and send an L<HTTP::Response>. This is a
separate class so that L<Airlock> itself does not depend on L<HTTP::Message>.

=cut

has airlock => (
  is       => 'ro',
  isa      => InstanceOf['Airlock'],
  required => 1
);

=attr airlock

Required. The L<Airlock> to answer for.

=cut

sub handle {
  my ( $self, $request, %origin ) = @_;
  my $airlock = $self->airlock;
  my $content = $request->content // '';
  my $form    = ( $request->header('Content-Type') // '' ) =~ m{\Aapplication/x-www-form-urlencoded\b}i;
  my ( $status, $headers, $json ) = @{
    length $content > $airlock->max_body
      ? [ 413, { 'Content-Type' => 'application/json' }, { error => 'invalid_request' } ]
      : $airlock->respond(
        $request->method, $request->uri->path, scalar $airlock->parse_form( $form ? $content : '' ),
        { ua => scalar $request->header('User-Agent'), %origin }
      )
  };
  return HTTP::Response->new(
    $status, status_message($status), [ map { $_ => $headers->{$_} } sort keys %$headers ],
    $airlock->encode_body($json)
  );
}

=method handle

    my $response = $http->handle( $request, ip => $remote_address );

Answers an L<HTTP::Request> for C<POST .../device> or C<POST .../token> with an
L<HTTP::Response>. Pass the remote address, which a request object does not
carry.

=cut

1;
