#!/usr/local/bin/perl
use lib 'lib';

use strict;
use warnings;

#
# Test that the primitive operators are working
#

BEGIN { require './t/funcs.pl' }

use Convert::ASN1;

print "1..1\n";
my $asn;
$asn = Convert::ASN1->new or warn $asn->error;
$asn->prepare(' seq SEQUENCE OF SEQUENCE { str STRING, val SEQUENCE OF STRING } ')
  or warn $asn->error;

my $result = pack("C*",
  0x30, 0x25,
    0x30, 0x11,
      0x04, 0x04, ord('f'), ord('r'), ord('e'), ord('d'),
      0x30, 0x09,
	0x04, 0x01, ord('a'),
	0x04, 0x01, ord('b'),
	0x04, 0x01, ord('c'),
    0x30, 0x10,
      0x04, 0x03, ord('j'), ord('o'), ord('e'),
      0x30, 0x09,
	0x04, 0x01, ord('q'),
	0x04, 0x01, ord('w'),
	0x04, 0x01, ord('e'),
);
stest 1, $result, $asn->encode(
		seq => [
		  { str => 'fred', val => [qw(a b c)] },
		  { str => 'joe',  val => [qw(q w e)] }
		]) or warn $asn->error;
