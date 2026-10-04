package Airlock::QR;

# ABSTRACT: QR codes as SVG, terminal blocks or data URI, in pure Perl

use Moo;
use Carp qw( croak );
use GD::Barcode::QRcode;
use MIME::Base64 qw( encode_base64 );
use Types::Standard qw( ArrayRef CodeRef Enum Int Str );
use namespace::autoclean;

our $VERSION = '0.002';

=synopsis

    my $qr = Airlock::QR->new( text => $verification_uri_complete );

    print $qr->svg;                                  # for the web
    print '<img src="'.$qr->data_uri.'">';           # inline
    binmode STDOUT, ':encoding(UTF-8)';
    print $qr->terminal;                             # for a CLI

=description

Two places in a device flow want a QR code: the link to the approval page, so
a phone can scan what a laptop or a CLI shows, and the C<otpauth://> URI when
someone enrols a TOTP secret. This class renders both without an image
library.

Encoding is done by L<GD::Barcode::QRcode>, which is pure Perl and needs no GD
for the matrix.

=cut

has text => (
  is       => 'ro',
  isa      => Str,
  required => 1
);

=attr text

Required. What the code says. Characters outside ASCII are encoded as UTF-8.

=cut

has ecc => (
  is      => 'ro',
  isa     => Enum[qw( L M Q H )],
  default => 'M'
);

=attr ecc

Error correction level: C<L>, C<M>, C<Q> or C<H>. Default C<M>.

=cut

has quiet => (
  is      => 'ro',
  isa     => Int,
  default => 4
);

=attr quiet

Width of the empty border, in modules. Default 4, which is what the standard
asks for.

=cut

has encoder => (
  is        => 'ro',
  isa       => CodeRef,
  predicate => 'has_encoder'
);

=attr encoder

Optional. Coderef called with the bytes and the error correction level,
returning the code as lines of C<0> and C<1>. Replaces the built-in encoder.

=cut

has matrix => (
  is       => 'lazy',
  isa      => ArrayRef[ArrayRef],
  init_arg => undef
);

=attr matrix

The code as rows of 0 and 1, without border. For own renderings.

=cut

sub max_bytes { 1000 }

=method max_bytes

Longest text, in bytes, this class encodes. 1000.

=cut

sub _build_matrix {
  my ( $self ) = @_;
  my $bytes = $self->text;
  utf8::encode($bytes) if utf8::is_utf8($bytes);
  croak __PACKAGE__.'->matrix needs a text' unless length $bytes;
  croak __PACKAGE__.'->matrix text is longer than '.$self->max_bytes.' bytes'
    if length $bytes > $self->max_bytes;
  my $pattern = $self->has_encoder ? $self->encoder->( $bytes, $self->ecc ) : $self->_encode($bytes);
  my @rows    = map { [ split // ] } grep { length } split /\n/, $pattern // '';
  croak __PACKAGE__.'->matrix encoder returned no square pattern of 0 and 1'
    if !@rows || grep { @$_ != @rows || grep { $_ ne '0' && $_ ne '1' } @$_ } @rows;
  while ( @rows > 21 && !grep { $_ } @{ $rows[0] }, @{ $rows[-1] }, map { $_->[0], $_->[-1] } @rows ) {
    @rows = map { [ @{$_}[ 1 .. $#$_ - 1 ] ] } @rows[ 1 .. $#rows - 1 ];
  }
  return [ map { [ map { $_ + 0 } @$_ ] } @rows ];
}

sub _encode {
  my ( $self, $bytes ) = @_;
  my $qr = GD::Barcode::QRcode->new( $bytes, { Ecc => $self->ecc, ModuleSize => 1 } )
    or croak __PACKAGE__.'->matrix cannot encode: '.( $GD::Barcode::errStr // 'unknown error' );
  return $qr->barcode;
}

sub size { scalar @{ $_[0]->matrix } }

=method size

Modules per side, without border.

=cut

sub svg {
  my ( $self ) = @_;
  my $quiet = $self->quiet;
  my $side  = $self->size + 2 * $quiet;
  my @path;
  my $y = $quiet;
  for my $row ( @{ $self->matrix } ) {
    my $line = join '', @$row;
    push @path, 'M'.( $-[0] + $quiet ).' '.$y.'h'.( $+[0] - $-[0] ).'v1h-'.( $+[0] - $-[0] ).'z' while $line =~ /1+/g;
    $y++;
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '.$side.' '.$side.'" shape-rendering="crispEdges">'
    .'<rect width="'.$side.'" height="'.$side.'" fill="#fff"/>'
    .'<path fill="#000" d="'.join( '', @path ).'"/></svg>';
}

=method svg

    my $svg = $qr->svg;

The code as a standalone SVG element, black on white, one unit per module.
Scale it with CSS.

=cut

sub data_uri {
  my ( $self ) = @_;
  return 'data:image/svg+xml;base64,'.encode_base64( $self->svg, '' );
}

=method data_uri

    my $src = $qr->data_uri;

The SVG as a C<data:> URI for an C<img> element.

=cut

sub terminal {
  my ( $self, %arg ) = @_;
  my $ansi  = exists $arg{ansi} ? $arg{ansi} : 1;
  my $quiet = $self->quiet;
  my $side  = $self->size + 2 * $quiet;
  my @rows  = (
    ( [ (0) x $side ] ) x $quiet,
    ( map { [ (0) x $quiet, @$_, (0) x $quiet ] } @{ $self->matrix } ),
    ( [ (0) x $side ] ) x $quiet
  );
  push @rows, [ (0) x $side ] if @rows % 2;
  my @glyph = $ansi ? ( ' ', "\x{2584}", "\x{2580}", "\x{2588}" ) : ( "\x{2588}", "\x{2580}", "\x{2584}", ' ' );
  my $out   = '';
  while ( my ( $top, $bottom ) = splice @rows, 0, 2 ) {
    my $line = join '', map { $glyph[ $top->[$_] * 2 + $bottom->[$_] ] } 0 .. $side - 1;
    $out .= $ansi ? "\e[30;47m".$line."\e[0m\n" : $line."\n";
  }
  return $out;
}

=method terminal

    binmode STDOUT, ':encoding(UTF-8)';
    print $qr->terminal;
    print $qr->terminal( ansi => 0 );

The code as Unicode half blocks, two modules per line of text. Returns
characters, so the output handle needs an encoding layer. With ANSI colours,
the default, it is black on white whatever the terminal theme; C<< ansi => 0 >>
leaves the colours out and assumes light text on a dark background.

=cut

1;
