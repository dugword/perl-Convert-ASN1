#!/usr/local/bin/perl
use lib 'lib';

#
# Test that the primitive operators are working
#

use Convert::ASN1;
BEGIN { require 't/funcs.pl' }

print "1..1\n"; # This testcase needs more tests

$asn = Convert::ASN1->new or warn $asn->error;
$asn->prepare( q(
  SEQUENCE {
    bar [0] SET OF INTEGER OPTIONAL,
    str OCTET STRING
  }
)) or warn $asn->error;

$result = pack "H*", "3011a009020101020105020103040446726564";
%input = (str => 'Fred', bar => [1,5,3]);
stest 1, $result, $asn->encode(%input);
exit;
