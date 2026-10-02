#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

for (qw(
  Airlock
  Airlock::QR
)) {
  use_ok($_);
}

done_testing;
