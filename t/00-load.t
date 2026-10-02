#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

for (qw(
  Airlock
  Airlock::Code
  Airlock::Factor
  Airlock::Factor::Callback
  Airlock::Factor::TOTP
  Airlock::Factor::Upstream
  Airlock::Policy
  Airlock::QR
  Airlock::Store::Memory
  Airlock::Test::Store
)) {
  use_ok($_);
}

done_testing;
