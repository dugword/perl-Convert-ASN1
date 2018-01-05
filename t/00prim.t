#!/usr/bin/env perl6

use Test;
# use Data::Dump;
use experimental :pack;

use lib 'lib';

use Convert::ASN1P6 (:constant, :debug);

# asn-tag tests
is-deeply asn-tag(ASN_CONTEXT, 1),
    129,
    'asn-tag(ASN_CONTEXT, 1)';

is-deeply asn-tag(ASN_UNIVERSAL, 32),
    0x201f,
    'asn-tag(ASN_UNIVERSAL, 32)';

is-deeply asn-tag(ASN_APPLICATION, 257),
    0x01825f,
    'asn-tag(ASN_APPLICATION, 257)';

# asn-encode-tag tests
is-deeply asn-encode-tag(129),
    Buf.new(129),
    'asn-encode-tag(129)';

is-deeply asn-encode-tag(0x201f),
    Buf.new(0x1f, 0x20),
    'asn-encode-tag(0x201f)';

is-deeply asn-encode-tag(0x01825f),
    Buf.new(0x5f, 0x82, 0x01),
    'asn-encode-tag(0x01825f)';

# asn-decode-tag tests
is-deeply asn-decode-tag(asn-encode-tag(asn-tag(ASN_CONTEXT, 1))),
    (1, 129),
    'asn-decode-tag(asn-encode-tag(asn-tag(ASN_CONTEXT, 1)))';

is-deeply asn-decode-tag(asn-encode-tag(asn-tag(ASN_UNIVERSAL, 32))),
    (2, 0x201f),
    'asn-decode-tag(asn-encode-tag(asn-tag(ASN_UNIVERSAL, 32)))';

is-deeply asn-decode-tag(asn-encode-tag(asn-tag(ASN_APPLICATION, 257))),
    (3, 0x01825f),
    'asn-decode-tag(asn-encode-tag(asn-tag(ASN_APPLICATION, 257)))';

# asn-encode-length
is-deeply asn-encode-length(45),
    Buf.new(45),
    'asn-encode-length(45)';

is-deeply asn-encode-length(139),
    Buf.new(0x81, 0x8b),
    'asn-encode-length(139)';

is-deeply asn-encode-length(0x1234),
    Buf.new(0x82, 0x12, 0x34),
    'asn-encode-length(0x1234)';

# asn-decode-length
is-deeply asn-decode-length(asn-encode-length(45)),
    (1, 45),
    'asn-decode-length(asn-encode-length(45))';

is-deeply asn-decode-length(asn-encode-length(139)),
    (2, 139),
    'asn-decode-length(asn-encode-length(139))';

is-deeply asn-decode-length(asn-encode-length(0x1234)),
    (3, 0x1234),
    'asn-decode-length(asn-encode-length(0x1234))';

# Object method tests
my $asn = Convert::ASN1P6.new();
isa-ok $asn, Convert::ASN1P6, 'Create a new instance of Convert::ASN1';

say "# NULL";
my $null-buf = Buf.new(0x05, 0x00);

my $lexed = lex(' null NULL ');
my $null-lexed = [
    { lval => "null", type => 1 },
    { lval => "NULL", type => 1 },
    { lval => Any,    type => 0 },
];

is-deeply $lexed,
    $null-lexed,
    'ASN " null NULL " lexed correctly';

my %parsed = parse($lexed, 'IMPLICIT');
my %null-parsed =
    "" => [
        [Any, "NULL", "null", Any, Any, Any],
    ]
;

is-deeply %parsed, %null-parsed, 'parsed correctly';

my %verified = verify(%parsed);
my %null-verified =
    "" => [
        [Any, "NULL", "null", Any, Any, Any],
    ]
;

is-deeply %verified,
    %null-verified,
    'ASN " null NULL " verified correctly';

# say %verified.perl;
my %compiled = compile(%verified);
my %null-compiled = "" => [Compiled.new(
    Buf.new(5),
    5,
    "null",
    Any,
    Any,
    Any,
),];

is-deeply %compiled,
    %null-compiled;


$asn.prepare(' null NULL ');
my $encoded = $asn.encode( (null => 1) );

is $encoded, Buf.new(5,0);


# is $encoded, Buf.new(0x5, 0x0), 'null encoded';
#
my $decoded = $asn.decode(Buf.new(0x5, 0x0));

say "# BOOLEAN";
for (0, 1, -99) -> $val {
    my $result = Buf.new(0x01, 0x01, $val ?? 0xff !! 0);
    $asn.prepare(' bool BOOLEAN ') or warn "some error";
    is $result, $asn.encode( (bool => $val) );
    my $ret;
    ok $ret = $asn.decode($result);
}

say "### Start ###";
say "# INTEGER";

my %integer = (
    Buf.new(0x02, 0x02, 0x00, 0x80).unpack('H*')             => 128,
    Buf.new(0x02, 0x01, 0x80).unpack('H*')                   => -128,
    Buf.new(0x02, 0x02, 0xff, 0x01).unpack('H*')             => -255,
    Buf.new(0x02, 0x01, 0x00).unpack('H*')                   => 0,
    Buf.new(0x02, 0x03, 0x66, 0x77, 0x99).unpack('H*')       => 0x667799,
    Buf.new(0x02, 0x02, 0xfe, 0x37).unpack('H*')             => -457,
    Buf.new(0x02, 0x04, 0x40, 0x00, 0x00, 0x00).unpack('H*') => 2 ** 30,
    Buf.new(0x02, 0x04, 0xc0, 0x00, 0x00, 0x00).unpack('H*') => -2 ** 30,
);

$asn.prepare(' integer INTEGER ') or warn "some error";
for %integer.kv -> $result, $value {
    say "# $result => $value";
    my $encoded_value = $asn.encode( (integer => $value) );
    is $encoded_value.unpack('H*'), $result;
    my $decoded_value = $asn.decode(pack('H*', $result));
    is $decoded_value<integer>, $value;
}

# say "#" x 80;
$asn.prepare('test ::= INTEGER ') or warn "some error";
{ 
    my $result = Buf.new(0x02, 0x01, 0x09);

    my $encoded = $asn.encode(9);
    is $result.unpack("H*"), $encoded.unpack("H*");;
    is $result, $encoded;
    my $ret = $asn.decode($result);
    exit;
    is $ret, 9;
}

