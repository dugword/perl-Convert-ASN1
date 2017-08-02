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

done-testing;

# is $encoded, Buf.new(0x5, 0x0), 'null encoded';
#
say "### Start ###";
my $decoded = $asn.decode(Buf.new(0x5, 0x0));
dd $decoded;
