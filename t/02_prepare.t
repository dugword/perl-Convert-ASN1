use v6;

use Test;
use Data::Dump;

use lib 'lib';

use Convert::ASN1P6 :debug;

my $asn  = Convert::ASN1P6.new;

my $asn-string = ' null NULL ';
$asn-string = ' seq SEQUENCE OF SEQUENCE { str STRING, val SEQUENCE OF STRING } ';
my %expected-yyparse-result =  "" => [[Any, "NULL", "null", Any, Any, Any],];
my $expected-result = Buf.new(0x05, 0x00);
my @expected-script = [[ Buf.new(0x05), 5, 'null', Any, Any, Any],];
my %stash = null => 1;

say $asn-string;
$asn.parse($asn.lex($asn-string));

# my %yyparse-result = yyparse($asn-string);
# is %yyparse-result.perl, %expected-yyparse-result.perl, 'yyparse';

# $asn.prepare($asn-string);
# is $asn.script.perl, @expected-script.perl, "Prepared { $asn-string } into { @expected-script }";
# is $asn.script.perl, @expected-script.perl, "Prepare { $asn-string } into { @expected-script.perl }";

# my $encoded-result = $asn.encode(%stash);
# is $encoded-result, $expected-result, "Encode { %stash.perl } into { $expected-result.perl }";
