use v6;

use Test;

use lib 'lib';

use Convert::ASN1P6;

my $asn = Convert::ASN1P6.new;

isa-ok $asn, Convert::ASN1P6, 'Successfully created a Convert::ASN1P6 object';
is $asn.encoding, 'BER', 'Default encoding is BER';
is $asn.tag-default, 'IMPLICIT', 'Default tag is IMPLICIT';
done-testing;
