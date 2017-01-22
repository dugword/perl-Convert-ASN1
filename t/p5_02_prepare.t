use 5.024;
use strict;
use warnings;

use Data::Dump;
use Test::More;

use lib 'lib';

use Convert::ASN1 ':all';

my $asn5 = Convert::ASN1->new;
my $string = ' null NULL ';
$string= ' seq SEQUENCE OF SEQUENCE { str STRING, val SEQUENCE OF STRING } ';
say $string;
#  $asn5->my_xxlex($string);
$asn5->prepare($string);
# say "#" x 40;
# my $foo = $asn5->prepare($string);
# my $result = $asn5->encode(null => 1);
# my $buf = pack("C*", 0x05, 0x00);
# say length $buf;
# say unpack('H*', $buf);
# say unpack('H*', $result);
# dd $asn5->get_tree();
# dd $asn5->get_script()->@[0]->[0];
# say $asn5->get_tree
