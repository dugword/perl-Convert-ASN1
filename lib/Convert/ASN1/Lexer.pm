package Convert::ASN1::Lexer;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Data::Dump;
my $tagdefault = 1; # 0:IMPLICIT , 1:EXPLICIT default
sub need_explicit {
    ( defined($_[0]) && (defined($_[1]) ? $_[1] : $tagdefault ));
}
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
my %tag_class = (
  APPLICATION => ASN_APPLICATION,
  UNIVERSAL   => ASN_UNIVERSAL,
  PRIVATE     => ASN_PRIVATE,
  CONTEXT     => ASN_CONTEXT,
  ''          => ASN_CONTEXT # if not specified, its CONTEXT
);

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
    constWORD => 1,
    constCLASS => 2,
    constSEQUENCE => 3,
    constSET => 4,
    constCHOICE => 5,
    constOF => 6,
    constIMPLICIT => 7,
    constEXPLICIT => 8,
    constOPTIONAL => 9,
    constLBRACE => 10,
    constRBRACE => 11,
    constCOMMA => 12,
    constANY => 13,
    constASSIGN => 14,
    constNUMBER => 15,
    constENUM => 16,
    constCOMPONENTS => 17,
    constPOSTRBRACE => 18,
    constDEFINED => 19,
    constBY => 20,
    constEXTENSION_MARKER => 21,
    constYYERRCODE => 256,
    constYYFINAL => 5,
    constYYMAXTOKEN => 21,
    constYYTABLESIZE => 181,
};


my %reserved = (
  'OPTIONAL'   => constOPTIONAL,
  'CHOICE'     => constCHOICE,
  'OF'         => constOF,
  'IMPLICIT'   => constIMPLICIT,
  'EXPLICIT'   => constEXPLICIT,
  'SEQUENCE'   => constSEQUENCE,
  'SET'        => constSET,
  'ANY'        => constANY,
  'ENUM'       => constENUM,
  'ENUMERATED' => constENUM,
  'COMPONENTS' => constCOMPONENTS,
  '{'          => constLBRACE,
  '}'          => constRBRACE,
  ','          => constCOMMA,
  '::='        => constASSIGN,
  'DEFINED'    => constDEFINED,
  'BY'         => constBY,
);





my %type = (
    '10' => 'SEQUENCE',
    '01' => 'BOOLEAN',
    '0A' => 'ENUM',
    '0D' => 'RELATIVE-OID',
    '11' => 'SET',
    '02' => 'INTEGER',
    '03' => 'BIT STRING',
    'C0' => '[PRIVATE %d]',
    '04' => 'STRING',
    '40' => '[APPLICATION %d]',
    '05' => 'NULL',
    '06' => 'OBJECT ID',
    '80' => '[CONTEXT %d]',
);

sub asn_tag {
  my($class,$value) = @_;

  die sprintf "Bad tag class 0x%x",$class
    if $class & ~0xe0;

  unless ($value & ~0x1f or $value == 0x1f) {
    return (($class & 0xe0) | $value);
  }

  die sprintf "Tag value 0x%08x too big\n",$value
    if $value & 0xffe00000;

  $class = ($class | 0x1f) & 0xff;

  my @t = ($value & 0x7f);
  unshift @t, (0x80 | ($value & 0x7f)) while $value >>= 7;
  unpack("V",pack("C4",$class,@t,0,0));
}

sub asn_encode_tag {
    $_[0] >> 8
        ? $_[0] & 0x8000
            ? $_[0] & 0x800000
                ? pack("V",$_[0])
                : substr(pack("V",$_[0]),0,3)
            : pack("v", $_[0])
        : pack("C",$_[0]);
}


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


my $reserved = join("|", reverse sort grep { /\w/ } keys %reserved);


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

sub xxlex {
    # my $self = shift;

    my $asn = shift;

    my $pos;
    my @stacked;
    my $yylval;

    my @lex_array = ();

    while ($asn =~ /\G(?:
        (\s+|--[^\n]*)
        |
        ([,{}]|::=)
        |
        ($reserved)\b
        |
        (
            (?:OCTET|BIT)\s+STRING
        |
            OBJECT\s+IDENTIFIER
        |
            RELATIVE-OID
        )\b
        |
        (\w+(?:-\w+)*)
        |
            \[\s*
        (
        (?:(?:APPLICATION|PRIVATE|UNIVERSAL|CONTEXT)\s+)?
        \d+
            )
            \s*\]
        |
        \((\d+)\)
        |
        (\.\.\.)
        )/sxg
    ) {


        ($pos) = (pos($asn));

        next if defined $1; # comment or whitespace

        if (defined $2 or defined $3) {
            my $ret = $+;

            # A comma is not required after a '}' so to aid the
            # parser we insert a fake token after any '}'
            if ($ret eq '}') {
                # push @stacked = (@stacked, constPOSTRBRACE());
                push @stacked, constPOSTRBRACE();
            }

            my $yylval = $ret;

            push @lex_array, {
                type => $reserved{ $ret },
                lval => $yylval,
            };

            if (@stacked) {
                push @lex_array, {
                    type => (shift @stacked),
                    lval => undef,
                };
            }

            # return ($reserved{$yylval = $ret}, $yylval);
            next;
        }

        if (defined $4) {
            ($yylval = $+) =~ s/\s+/_/g;

            push @lex_array, {
                type => constWORD(),
                lval => $yylval,
            };

            # return (constWORD(), $yylval);
            next;
        }

        if (defined $5) {
            $yylval = $+;

            push @lex_array, {
                type => constWORD(),
                lval => $yylval,
            };

            # return (constWORD(), $yylval);
            next;
        }

        if (defined $6) {
            my($class,$num) = ($+ =~ /^([A-Z]*)\s*(\d+)$/);
            $yylval = asn_tag($tag_class{$class}, $num); 

            push @lex_array, {
                type => constCLASS(),
                lval => $yylval,
            };

            # return (constCLASS(), $yylval);
            next;
        }

        if (defined $7) {
            $yylval = $+;

            push @lex_array, {
                type => constNUMBER(),
                lval => $yylval,
            };

            # return (constNUMBER(), $yylval);
            next;
        }

        if (defined $8) {

            push @lex_array, {
                type => constEXTENSION_MARKER(),
                lval => undef,
            };

            # return (constEXTENSION_MARKER(), $yylval);
            next;
        }

        die "Internal error\n";
    }

    die "Parse error before ",substr($asn,$pos,40),"\n"
        unless $pos == length($asn);


    push @lex_array, {
        type => 0,
        lval => undef,
    };

    return \@lex_array;
        # return (0, undef);
}

1;
