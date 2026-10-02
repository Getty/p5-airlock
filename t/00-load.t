#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

for (qw(
  Airlock
  Airlock::Code
  Airlock::QR
  Airlock::Store::Memory
  Airlock::Test::Store
)) {
  use_ok($_);
}

done_testing;
