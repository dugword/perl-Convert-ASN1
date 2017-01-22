use v6;

use Test;

use lib 'lib';

use Convert::ASN1:from<Perl5> (':all');
use Convert::ASN1P6 :ALL;

plan 31;

is asn-encode-tag(ASN_BOOLEAN), asn_encode_tag(ASN_BOOLEAN).encode(), 'ASN_BOOLEAN is the same between modules';
is asn-encode-tag(ASN_INTEGER), asn_encode_tag(ASN_INTEGER).encode(), 'ASN_INTEGER is the same between modules';
is asn-encode-tag(ASN_BIT_STR), asn_encode_tag(ASN_BIT_STR).encode(), 'ASN_BIT_STR is the same between modules';
is asn-encode-tag(ASN_OCTET_STR), asn_encode_tag(ASN_OCTET_STR).encode(), 'ASN_OCTET_STR is the same between modules';
is asn-encode-tag(ASN_OCTET_STR), asn_encode_tag(ASN_OCTET_STR).encode(), 'ASN_OCTET_STR is the same between modules';
is asn-encode-tag(ASN_NULL), asn_encode_tag(ASN_NULL).encode(), 'ASN_NULL is the same between modules';
is asn-encode-tag(ASN_OBJECT_ID), asn_encode_tag(ASN_OBJECT_ID).encode(), 'ASN_OBJECT_ID is the same between modules';
is asn-encode-tag(ASN_REAL), asn_encode_tag(ASN_REAL).encode(), 'ASN_REAL is the same between modules';
is asn-encode-tag(ASN_ENUMERATED), asn_encode_tag(ASN_ENUMERATED).encode(), 'ASN_ENUMERATED is the same between modules';
is asn-encode-tag(ASN_ENUMERATED), asn_encode_tag(ASN_ENUMERATED).encode(), 'ASN_ENUMERATED is the same between modules';
is asn-encode-tag(ASN_RELATIVE_OID), asn_encode_tag(ASN_RELATIVE_OID).encode(), 'ASN_RELATIVE_OID is the same between modules';

is asn-encode-tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), asn_encode_tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR).encode(), 'ASN_SEQUENCE +| ASN_CONSTRUCTOR is the same between modules';
is asn-encode-tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), asn_encode_tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR).encode(), 'ASN_SEQUENCE +| ASN_CONSTRUCTOR is the same between modules';
is asn-encode-tag(ASN_SET      +| ASN_CONSTRUCTOR), asn_encode_tag(ASN_SET      +| ASN_CONSTRUCTOR).encode(), 'ASN_SET      +| ASN_CONSTRUCTOR is the same between modules';

 is asn-encode-tag(ASN_UNIVERSAL() +|  7),
    asn_encode_tag(ASN_UNIVERSAL() +|  7).encode(),
    'ASN_UNIVERSAL() +|  7 is the same between modules';

is asn-encode-tag(ASN_UNIVERSAL() +| 12), asn_encode_tag(ASN_UNIVERSAL() +| 12).encode(), 'ASN_UNIVERSAL() +| 12 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 18), asn_encode_tag(ASN_UNIVERSAL() +| 18).encode(), 'ASN_UNIVERSAL() +| 18 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 19), asn_encode_tag(ASN_UNIVERSAL() +| 19).encode(), 'ASN_UNIVERSAL() +| 19 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 20), asn_encode_tag(ASN_UNIVERSAL() +| 20).encode(), 'ASN_UNIVERSAL() +| 20 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 20), asn_encode_tag(ASN_UNIVERSAL() +| 20).encode(), 'ASN_UNIVERSAL() +| 20 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 21), asn_encode_tag(ASN_UNIVERSAL() +| 21).encode(), 'ASN_UNIVERSAL() +| 21 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 22), asn_encode_tag(ASN_UNIVERSAL() +| 22).encode(), 'ASN_UNIVERSAL() +| 22 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 23), asn_encode_tag(ASN_UNIVERSAL() +| 23).encode(), 'ASN_UNIVERSAL() +| 23 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 24), asn_encode_tag(ASN_UNIVERSAL() +| 24).encode(), 'ASN_UNIVERSAL() +| 24 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 25), asn_encode_tag(ASN_UNIVERSAL() +| 25).encode(), 'ASN_UNIVERSAL() +| 25 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 26), asn_encode_tag(ASN_UNIVERSAL() +| 26).encode(), 'ASN_UNIVERSAL() +| 26 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 26), asn_encode_tag(ASN_UNIVERSAL() +| 26).encode(), 'ASN_UNIVERSAL() +| 26 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 27), asn_encode_tag(ASN_UNIVERSAL() +| 27).encode(), 'ASN_UNIVERSAL() +| 27 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 28), asn_encode_tag(ASN_UNIVERSAL() +| 28).encode(), 'ASN_UNIVERSAL() +| 28 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 28), asn_encode_tag(ASN_UNIVERSAL() +| 28).encode(), 'ASN_UNIVERSAL() +| 28 is the same between modules';
 is asn-encode-tag(ASN_UNIVERSAL() +| 30), asn_encode_tag(ASN_UNIVERSAL() +| 30).encode(), 'ASN_UNIVERSAL() +| 30 is the same between modules';
# is asn-encode-tag(ASN_OCTET_STR), asn_encode_tag(ASN_OCTET_STR).encode(), 'ASN_OCTET_STR is the same between modules';



done-testing;
