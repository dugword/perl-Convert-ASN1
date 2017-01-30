# Copyright (c) 2000-2002 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Convert::ASN1::Constants;

use 5.024;
use strict;
use warnings;

use Exporter;

our (@ISA, @EXPORT_OK, %EXPORT_TAGS);

# Standard export stuff
@ISA = qw(Exporter);

$EXPORT_TAGS{all} = [qw(
    ASN_BOOLEAN     ASN_INTEGER      ASN_BIT_STR      ASN_OCTET_STR
    ASN_NULL        ASN_OBJECT_ID    ASN_REAL         ASN_ENUMERATED
    ASN_SEQUENCE    ASN_SET          ASN_PRINT_STR    ASN_IA5_STR
    ASN_UTC_TIME    ASN_GENERAL_TIME ASN_RELATIVE_OID
    ASN_UNIVERSAL   ASN_APPLICATION  ASN_CONTEXT      ASN_PRIVATE
    ASN_PRIMITIVE   ASN_CONSTRUCTOR  ASN_LONG_LEN     ASN_EXTENSION_ID ASN_BIT
    cTAG
    cTYPE
    cVAR
    cLOOP
    cOPT
    cEXT
    cCHILD
    cDEFINE
    opUNKNOWN
    opBOOLEAN
    opINTEGER
    opBITSTR
    opSTRING
    opNULL
    opOBJID
    opREAL
    opSEQUENCE
    opEXPLICIT
    opSET
    opUTIME
    opGTIME
    opUTF8
    opANY
    opCHOICE
    opROID
    opBCD
    opEXTENSIONS
)];

@EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant {
    cTAG => 0,
    cTYPE => 1,
    cVAR => 2,
    cLOOP => 3,
    cOPT => 4,
    cEXT => 5,
    cCHILD => 6,
    cDEFINE => 7,
};

use constant {
    opUNKNOWN => 0,
    opBOOLEAN => 1,
    opINTEGER => 2,
    opBITSTR => 3,
    opSTRING => 4,
    opNULL => 5,
    opOBJID => 6,
    opREAL => 7,
    opSEQUENCE => 8,
    opEXPLICIT => 9,
    opSET => 10,
    opUTIME => 11,
    opGTIME => 12,
    opUTF8 => 13,
    opANY => 14,
    opCHOICE => 15,
    opROID => 16,
    opBCD => 17,
    opEXTENSIONS => 18,
};

use constant {
    ASN_BOOLEAN => 0x01,
    ASN_INTEGER => 0x02,
    ASN_BIT_STR => 0x03,
    ASN_OCTET_STR => 0x04,
    ASN_NULL => 0x05,
    ASN_OBJECT_ID => 0x06,
    ASN_REAL => 0x09,
    ASN_ENUMERATED => 0x0A,
    ASN_RELATIVE_OID => 0x0D,
    ASN_SEQUENCE => 0x10,
    ASN_SET => 0x11,
    ASN_PRINT_STR => 0x13,
    ASN_IA5_STR => 0x16,
    ASN_UTC_TIME => 0x17,
    ASN_GENERAL_TIME => 0x18,

    ASN_UNIVERSAL => 0x00,
    ASN_APPLICATION => 0x40,
    ASN_CONTEXT => 0x80,
    ASN_PRIVATE => 0xC0,

    ASN_PRIMITIVE => 0x00,
    ASN_CONSTRUCTOR => 0x20,

    ASN_LONG_LEN => 0x80,
    ASN_EXTENSION_ID => 0x1F,
    ASN_BIT => 0x80,
};

