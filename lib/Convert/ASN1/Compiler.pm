package Convert::ASN1::Compiler;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Data::Dump;

# Encode tag value for encoding.
# We assume that the tag has been correctly generated with asn_tag()

sub asn_encode_tag {
    my $tag = shift;

    if ($tag >> 8) {
        if ($tag & 0x8000) {
            if ($tag & 0x800000) {
                return pack("V",$tag)
            }
            return substr(pack("V",$tag),0,3)
        }
        return pack("v", $tag)
    }
    return pack("C",$tag);
}

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

my %base_type = (
  BOOLEAN        => [ asn_encode_tag(ASN_BOOLEAN),        opBOOLEAN ],
  INTEGER        => [ asn_encode_tag(ASN_INTEGER),        opINTEGER ],
  BIT_STRING        => [ asn_encode_tag(ASN_BIT_STR),        opBITSTR  ],
  OCTET_STRING        => [ asn_encode_tag(ASN_OCTET_STR),        opSTRING  ],
  STRING        => [ asn_encode_tag(ASN_OCTET_STR),        opSTRING  ],
  NULL             => [ asn_encode_tag(ASN_NULL),        opNULL    ],
  OBJECT_IDENTIFIER => [ asn_encode_tag(ASN_OBJECT_ID),        opOBJID   ],
  REAL            => [ asn_encode_tag(ASN_REAL),        opREAL    ],
  ENUMERATED        => [ asn_encode_tag(ASN_ENUMERATED),    opINTEGER ],
  ENUM            => [ asn_encode_tag(ASN_ENUMERATED),    opINTEGER ],
  'RELATIVE-OID'    => [ asn_encode_tag(ASN_RELATIVE_OID),    opROID      ],

  SEQUENCE        => [ asn_encode_tag(ASN_SEQUENCE | ASN_CONSTRUCTOR), opSEQUENCE ],
  EXPLICIT        => [ asn_encode_tag(ASN_SEQUENCE | ASN_CONSTRUCTOR), opEXPLICIT ],
  SET               => [ asn_encode_tag(ASN_SET      | ASN_CONSTRUCTOR), opSET ],

  ObjectDescriptor  => [ asn_encode_tag(ASN_UNIVERSAL |  7), opSTRING ],
  UTF8String        => [ asn_encode_tag(ASN_UNIVERSAL | 12), opUTF8 ],
  NumericString     => [ asn_encode_tag(ASN_UNIVERSAL | 18), opSTRING ],
  PrintableString   => [ asn_encode_tag(ASN_UNIVERSAL | 19), opSTRING ],
  TeletexString     => [ asn_encode_tag(ASN_UNIVERSAL | 20), opSTRING ],
  T61String         => [ asn_encode_tag(ASN_UNIVERSAL | 20), opSTRING ],
  VideotexString    => [ asn_encode_tag(ASN_UNIVERSAL | 21), opSTRING ],
  IA5String         => [ asn_encode_tag(ASN_UNIVERSAL | 22), opSTRING ],
  UTCTime           => [ asn_encode_tag(ASN_UNIVERSAL | 23), opUTIME ],
  GeneralizedTime   => [ asn_encode_tag(ASN_UNIVERSAL | 24), opGTIME ],
  GraphicString     => [ asn_encode_tag(ASN_UNIVERSAL | 25), opSTRING ],
  VisibleString     => [ asn_encode_tag(ASN_UNIVERSAL | 26), opSTRING ],
  ISO646String      => [ asn_encode_tag(ASN_UNIVERSAL | 26), opSTRING ],
  GeneralString     => [ asn_encode_tag(ASN_UNIVERSAL | 27), opSTRING ],
  CharacterString   => [ asn_encode_tag(ASN_UNIVERSAL | 28), opSTRING ],
  UniversalString   => [ asn_encode_tag(ASN_UNIVERSAL | 28), opSTRING ],
  BMPString         => [ asn_encode_tag(ASN_UNIVERSAL | 30), opSTRING ],
  BCDString         => [ asn_encode_tag(ASN_OCTET_STR), opBCD ],

  CHOICE => [ '', opCHOICE ],
  ANY    => [ '', opANY ],

  EXTENSION_MARKER => [ '', opEXTENSIONS ],
);

sub compile_loop {
    my $op = shift;
    my $tree = shift;
    my $name = shift;

    say "compile_loop op => ";
    dd $op;

    return unless ref($op) eq 'ARRAY';
    bless $op;
    my $type = $op->[cTYPE];
    say "Type => ", $type;


    if (exists $base_type{$type}) {
        $op->[cTYPE] = $base_type{$type}->[1];

        $op->[cTAG] = defined($op->[cTAG])
            ? asn_encode_tag($op->[cTAG])
            : $base_type{$type}->[0];

    }

    else {
        unless (exists $tree->{$type}) {
            die "Unknown type '$type'";
        }

        my $ref = compile_one(
            $tree,
            $tree->{$type},
            defined($op->[cVAR]) ? $name . "." . $op->[cVAR] : $name
            );

        if (defined($op->[cTAG]) && $ref->[0][cTYPE] == opCHOICE) {
            @{$op}[cTYPE,cCHILD] = (opSEQUENCE,$ref);
        }

        else {
            @{$op}[cTYPE,cCHILD,cLOOP] = @{$ref->[0]}[cTYPE,cCHILD,cLOOP];
        }

        $op->[cTAG] = defined($op->[cTAG]) ? asn_encode_tag($op->[cTAG]): $ref->[0][cTAG];
    }

    $op->[cTAG] |= pack("C",ASN_CONSTRUCTOR)
        if length $op->[cTAG]
            && ($op->[cTYPE] == opSET
            || $op->[cTYPE] == opEXPLICIT
            || $op->[cTYPE] == opSEQUENCE);


    if ($op->[cCHILD]) {
        # If we have children we are one of
        #  opSET opSEQUENCE opCHOICE opEXPLICIT

        compile_one(
            $tree,
            $op->[cCHILD],
            defined($op->[cVAR])
                ? $name . "." . $op->[cVAR]
                : $name);

        if ( @{$op->[cCHILD]} > 1) {
            #if ($op->[cTYPE] != opSEQUENCE) {
            # Here we need to flatten CHOICEs and check that SET and CHOICE
            # do not contain duplicate tags
            #}

            if ($op->[cTYPE] == opSET) {
                # In case we do CER encoding we order the SET elements by thier tags
                my @tags = map { 
                    length($_->[cTAG])
                    ? $_->[cTAG]
                    : $_->[cTYPE] == opCHOICE
                    ? (sort map { $_->[cTAG] } $_->[cCHILD])[0]
                    : ''
                } @{$op->[cCHILD]};

                @{$op->[cCHILD]} = @{$op->[cCHILD]}[sort
                    { $tags[$a] cmp $tags[$b] }
                    0..$#tags
                ];
            }
        }

        else {
            # A SET of one element can be treated the same as a SEQUENCE
            $op->[cTYPE] = opSEQUENCE if $op->[cTYPE] == opSET;
        }
    }
};

sub compile_one {
    my ($tree, $ops, $name) = @_;

    my $compile_loop;

    foreach my $op (@$ops) {
        say "Op => ";
        dd $op;
        compile_loop($op, $tree, $name);
    }

  return $ops;
}


sub compile {
    my $tree = shift;

    # The tree should be valid enough to be able to
    #  - resolve references
    #  - encode tags
    #  - verify CHOICEs do not contain duplicate tags

    # once references have been resolved, and also due to
    # flattening of COMPONENTS, it is possible for an op
    # to appear in multiple places. So once an op is
    # compiled we bless it. This ensure we dont try to
    # compile it again.

    while(my($k,$v) = each %$tree) {
        say "Key => ", $k;
        say "Value => ";
        dd $v;
        compile_one($tree,$v,$k);
    }

    return $tree;
}

1;
