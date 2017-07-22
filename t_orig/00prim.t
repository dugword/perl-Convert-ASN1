#!/usr/local/bin/perl

use 5.026;
use strict;
use warnings;

use Data::Dump;
use Test::More;
use POSIX qw(HUGE_VAL);
use lib 'lib';

#
# Test that the primitive operators are working
#

use Convert::ASN1 qw(:all);
use Convert::ASN1::Compiler;
use Convert::ASN1::Constants qw(:all);

is 129, asn_tag(ASN_CONTEXT, 1);
is 0x201f, asn_tag(ASN_UNIVERSAL, 32);
is 0x01825f, asn_tag(ASN_APPLICATION, 257);

is pack("C*", 129),            Convert::ASN1::Compiler::asn_encode_tag(129);
is pack("C*", 0x1f,0x20),      Convert::ASN1::Compiler::asn_encode_tag(0x201f);
is pack("C*", 0x5f,0x82,0x01), Convert::ASN1::Compiler::asn_encode_tag(0x01825f);

is 129, asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_CONTEXT, 1)));
is 0x201f, asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_UNIVERSAL, 32)));
is 0x01825f,  asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_APPLICATION, 257)));
is 1, (asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_CONTEXT, 1))))[0];
is 2, (asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_UNIVERSAL, 32))))[0];
is 3, (asn_decode_tag(Convert::ASN1::Compiler::asn_encode_tag(asn_tag(ASN_APPLICATION, 257))))[0];

is pack("C*", 45),             asn_encode_length(45);
is pack("C*", 0x81,0x8b),      asn_encode_length(139);
is pack("C*", 0x82,0x12,0x34), asn_encode_length(0x1234);

is 45,     asn_decode_length(asn_encode_length(45));
is 139,    asn_decode_length(asn_encode_length(139));
is 0x1234, asn_decode_length(asn_encode_length(0x1234));

is 1, (asn_decode_length(asn_encode_length(45)))[0];
is 2, (asn_decode_length(asn_encode_length(139)))[0];
is 3, (asn_decode_length(asn_encode_length(0x1234)))[0];

my $asn = Convert::ASN1->new;
ok $asn;

##
## NULL
##

print "# NULL\n";

my $buf = pack("C*", 0x05, 0x00);

my $lexed = $asn->my_lex(' null NULL ');
my $null_lexed = [
    { lval => "null", type => 1 },
    { lval => "NULL", type => 1 },
    { lval => undef,  type => 0 },
];

is_deeply $lexed, $null_lexed, 'lexed correct';

my $parsed = $asn->my_parse($lexed, 'IMPLICIT');
my $null_parsed = {
    "" => [
        [undef, "NULL", "null", undef, undef, undef]
    ]
};

is_deeply $parsed, $null_parsed, 'parsed correct';

my $verified = $asn->my_verify($parsed);
my $null_verified = {
    "" => [
        [undef, "NULL", "null", undef, undef, undef]
    ]
};

is_deeply $verified, $null_verified, 'verified correct';

my $compiled = $asn->my_compile($verified);
my $null_compiled = {
    "" => [
        bless(["\5", 5 ,"null", undef, undef, undef], "Convert::ASN1::Compiler"),
    ],
};

is_deeply $compiled, $null_compiled;

my $foo = $asn->prepare(' null NULL ') or warn $asn->error;
dd $foo;
dd $asn;
ok $foo;
my $buffed = $asn->encode(null => 1);
is $buf, $buffed or warn $asn->error;

dd $buf;
dd $buffed;

say "Here and exit";
exit;

my $result = $asn->encode( null => 1 );
my $ret = $asn->decode($buf) or warn $asn->error;
ok $ret;

# print "RET\n";
# dd $ret;
# die;

ok $ret->{'null'};

##
## BOOLEAN
##

for my $val (0, 1, -99) {
  print "# BOOLEAN $val\n";

  my $result = pack("C*", 0x01, 0x01, $val ? 0xFF : 0);

  ok $asn->prepare(' bool BOOLEAN') or warn $asn->error;
  is $result, $asn->encode(bool => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is !!$val, !!$ret->{'bool'};
}

##
## INTEGER (tests 13 - 21)
##

my %INTEGER = (
  pack("C*", 0x02, 0x02, 0x00, 0x80), 	      128,
  pack("C*", 0x02, 0x01, 0x80), 	      -128,
  pack("C*", 0x02, 0x02, 0xff, 0x01), 	      -255,
  pack("C*", 0x02, 0x01, 0x00), 	      0,
  pack("C*", 0x02, 0x03, 0x66, 0x77, 0x99),   0x667799,
  pack("C*", 0x02, 0x02, 0xFE, 0x37),	     -457,
  pack("C*", 0x02, 0x04, 0x40, 0x00, 0x00, 0x00),	     2**30,
  pack("C*", 0x02, 0x04, 0xC0, 0x00, 0x00, 0x00),	     -2**30,
);

while(my ($result,$val) = each %INTEGER) {
  print "# INTEGER $val\n";

  ok $asn->prepare(' integer INTEGER') or warn $asn->error;
  is $result, $asn->encode(integer => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{integer};
}

ok $asn->prepare('test ::= INTEGER ');

$result = pack("C*", 0x02, 0x01, 0x09);

is $result, $asn->encode(9) or warn $asn->error;
ok $ret = $asn->decode($result) or warn $asn->error;
ok $ret == 9;

##
## STRING
##

my %STRING = (
  pack("C*",   0x04, 0x00),		  "",
  pack("CCa*", 0x04, 0x08, "A string"),   "A string",
);

while( my ($result,$val) = each %STRING) {
  print "# STRING '$val'\n";

  ok $asn->prepare('str STRING') or warn $asn->error;
  is $result, $asn->encode(str => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{'str'};
}

##
## OBJECT_ID
##

my %OBJECT_ID = (
  pack("C*", 0x06, 0x04, 0x2A, 0x03, 0x04, 0x05), "1.2.3.4.5",
  pack("C*", 0x06, 0x03, 0x55, 0x83, 0x49),       "2.5.457",  
  pack("C*", 0x06, 0x07, 0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01), "0.0.17.773.1.1.1",
  pack("C*", 0x06, 0x04, 0x86, 0x8D, 0x6F, 0x63), "2.99999.99",
);


while( my ($result,$val) = each %OBJECT_ID) {
  print "# OBJECT_ID $val\n";

  ok $asn->prepare('oid OBJECT IDENTIFIER') or warn $asn->error;
  is $result, $asn->encode(oid => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{'oid'};
}

##
## ENUM
##

my %ENUM = (
  pack("C*", 0x0A, 0x01, 0x00),             0,	     
  pack("C*", 0x0A, 0x01, 0x9D),            -99,	     
  pack("C*", 0x0A, 0x03, 0x64, 0x4D, 0x90), 6573456,
);

while(my ($result,$val) = each %ENUM) {
  print "# ENUM $val\n";

  ok $asn->prepare('enum ENUMERATED') or warn $asn->error;
  is $result, $asn->encode(enum => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{'enum'};
}

##
## BIT STRING
##

my %BSTR = (
  pack("C*", 0x03, 0x02, 0x07, 0x00),
    [pack("B*",'0'), 1, pack("B*",'0')],

  pack("C*", 0x03, 0x02, 0x00, 0x33),
    pack("B*",'00110011'),

  pack("C*", 0x03, 0x04, 0x03, 0x6E, 0x5D, 0xC0),
    [pack("B*",'011011100101110111'), 21, pack("B*",'011011100101110111')],

  pack("C*", 0x03, 0x02, 0x01, 0x6E),
    [pack("B*",'011011111101110111'), 7, pack("B*", '01101110')]
);

while(my ($result,$val) = each %BSTR) {
    print "# BIT STRING ", unpack("B*", ref($val) ? $val->[0] : $val),
	" ",(ref($val) ? $val->[1] : $val),"\n";

  ok $asn->prepare('bit BIT STRING') or warn $asn->error;
  is $result, $asn->encode( bit => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is( (ref($val) ? $val->[2] : $val), $ret->{'bit'}[0]);
  is( (ref($val) ? $val->[1] : 8*length$val), $ret->{'bit'}[1]);

}

##
## REAL
##


my %REAL = (
  pack("C*", 0x09, 0x00),  0,
  pack("C*", 0x09, 0x03, 0x80, 0xf9, 0xc0),  1.5,
  pack("C*", 0x09, 0x03, 0xc0, 0xfb, 0xb0), -5.5,
  pack("C*", 0x09, 0x01, 0x40),		      HUGE_VAL(),
  pack("C*", 0x09, 0x01, 0x41),		    - HUGE_VAL(),
);

while(my ($result,$val) = each %REAL) {
  print "# REAL $val\n";
  ok $asn->prepare('real REAL') or warn $asn->error;
  is $result, $asn->encode( real => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{'real'};
}

##
## RELATIVE-OID
##

my %ROID = (
  pack("C*", 0x0D, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05), "1.2.3.4.5",
  pack("C*", 0x0D, 0x04, 0x02, 0x05, 0x83, 0x49),       "2.5.457",  
  pack("C*", 0x0D, 0x08, 0x00,  0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01), "0.0.17.773.1.1.1",
);


while(my ($result,$val) = each %ROID) {
  print "# RELATIVE-OID $val\n";

  ok $asn->prepare('roid RELATIVE-OID') or warn $asn->error;
  is $result, $asn->encode(roid => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  is $val, $ret->{'roid'};
}


##
## BCDString
##

my %BCD = (
  pack("C*", 0x04, 0x09, 0x12, 0x34, 0x56, 0x78, 0x91, 0x23, 0x45, 0x67, 0x89), "123456789123456789",
  pack("C*", 0x04, 0x04, 0x12, 0x34, 0x56, 0x78), 12345678,
  pack("C*", 0x04, 0x02, 0x56, 0x4f),             564,
  pack("C*", 0x04, 0x00),             "",
  pack("C*", 0x04, 0x00),             -1,
  pack("C*", 0x04, 0x01, 0x0f),             0,
  pack("C*", 0x04, 0x01, 0x2f),             2.2,
);


while(my ($result,$val) = each %BCD) {
  print "# BCDString $val\n";

  ok $asn->prepare('bcd BCDString') or warn $asn->error;
  is $result, $asn->encode(bcd => $val) or warn $asn->error;
  ok $ret = $asn->decode($result) or warn $asn->error;
  $val =~ s/\D.*//;
  is $val, $ret->{'bcd'};
}

done_testing();
