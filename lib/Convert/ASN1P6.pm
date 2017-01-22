use v6;
use Data::Dump;
use experimental :pack;


module Convert::ASN1P6 {

# Some numbering system constants
    my @_dec_real_base = (2,8,16);

    constant constWORD = 1;
    constant constCLASS = 2;
    constant constSEQUENCE = 3;
    constant constSET = 4;
    constant constCHOICE = 5;
    constant constOF = 6;
    constant constIMPLICIT = 7;
    constant constEXPLICIT = 8;
    constant constOPTIONAL = 9;
    constant constLBRACE = 10;
    constant constRBRACE = 11;
    constant constCOMMA = 12;
    constant constANY = 13;
    constant constASSIGN = 14;
    constant constNUMBER = 15;
    constant constENUM = 16;
    constant constCOMPONENTS = 17;
    constant constPOSTRBRACE = 18;
    constant constDEFINED = 19;
    constant constBY = 20;
    constant constEXTENSION_MARKER = 21;
    constant constYYERRCODE = 256;
    constant constYYFINAL = 5;
    constant constYYMAXTOKEN = 21;
    constant constYYTABLESIZE = 181;

    constant ASN_BOOLEAN = 0x01;
    constant ASN_INTEGER = 0x02;
    constant ASN_BIT_STR = 0x03;
    constant ASN_OCTET_STR = 0x04;
    constant ASN_NULL = 0x05;
    constant ASN_OBJECT_ID = 0x06;
    constant ASN_REAL = 0x09;
    constant ASN_ENUMERATED = 0x0A;
    constant ASN_RELATIVE_OID = 0x0D;
    constant ASN_SEQUENCE = 0x10;
    constant ASN_SET = 0x11;
    constant ASN_PRINT_STR = 0x13;
    constant ASN_IA5_STR = 0x16;
    constant ASN_UTC_TIME = 0x17;
    constant ASN_GENERAL_TIME = 0x18;

    constant ASN_UNIVERSAL = 0x00;
    constant ASN_APPLICATION = 0x40;
    constant ASN_CONTEXT = 0x80;
    constant ASN_PRIVATE = 0xC0;

    constant ASN_PRIMITIVE = 0x00;
    constant ASN_CONSTRUCTOR = 0x20;

    constant ASN_LONG_LEN = 0x80;
    constant ASN_EXTENSION_ID = 0x1F;
    constant ASN_BIT = 0x80;

    constant cTAG = 0;
    constant cTYPE = 1;
    constant cVAR = 2;
    constant cLOOP = 3;
    constant cOPT = 4;
    constant cEXT = 5;
    constant cCHILD = 6;
    constant cDEFINE = 7;

    constant opUNKNOWN = 0;
    constant opBOOLEAN = 1;
    constant opINTEGER = 2;
    constant opBITSTR = 3;
    constant opSTRING = 4;
    constant opNULL = 5;
    constant opOBJID = 6;
    constant opREAL = 7;
    constant opSEQUENCE = 8;
    constant opEXPLICIT = 9;
    constant opSET = 10;
    constant opUTIME = 11;
    constant opGTIME = 12;
    constant opUTF8 = 13;
    constant opANY = 14;
    constant opCHOICE = 15;
    constant opROID = 16;
    constant opBCD = 17;
    constant opEXTENSIONS = 18;

# Some unneeded horse shit
    my %yystate = (
        'State51','',
        'State34' => '',
        'State11' => '',
        'State33' => '',
        'State24' => '',
        'State47' => '',
        'State40' => '',
        'State31' => '',
        'State37' => '',
        'State23' => '',
        'State22' => '',
        'State21' => '',
        'State57' => '',
        'State39' => '',
        'State56' => '',
        'State20' => '',
        'State25' => '',
        'State38' => '',
        'State62' => '',
        'State14' => '',
        'State19' => '',
        'State5'  => '',
        'State53' => '',
        'State26' => '',
        'State27' => '',
        'State50' => '',
        'State36' => '',
        'State4'  => '',
        'State3'  => '',
        'State32' => '',
        'State49' => '',
        'State43' => '',
        'State30' => '',
        'State35' => '',
        'State52' => '',
        'State55' => '',
        'State42' => '',
        'State28' => '',
        'State58' => '',
        'State61' => '',
        'State41' => '',
        'State18' => '',
        'State59' => '',
        'State1'  => '',
        'State60' => '',
    );

    my %tag_class = (
    APPLICATION => ASN_APPLICATION,
    UNIVERSAL   => ASN_UNIVERSAL,
    PRIVATE     => ASN_PRIVATE,
    CONTEXT     => ASN_CONTEXT,
    ''          => ASN_CONTEXT # if not specified, its CONTEXT
    );

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

    my @left_hand_side = (                                             -1,
        0,    0,    2,    2,    3,    3,    6,    6,    6,    6,
        8,   13,   13,   12,   14,   14,   14,    9,    9,    9,
        10,   18,   18,   18,   18,   18,   19,   19,   11,   16,
        16,   20,   20,   20,   21,   21,    1,    1,    1,   22,
        22,   22,   24,   24,   24,   24,   23,   23,   23,   23,
        15,   15,    4,    4,    5,    5,    5,   17,   17,   25,
        7,    7,
    );

    my @length = (                                                2,
        1,    1,    3,    4,    4,    1,    1,    1,    1,    1,
        3,    1,    1,    6,    1,    1,    1,    4,    4,    4,
        4,    1,    1,    1,    2,    1,    0,    3,    1,    1,
        2,    1,    3,    3,    4,    1,    0,    1,    2,    1,
        3,    3,    2,    1,    1,    1,    4,    1,    3,    1,
        0,    1,    0,    1,    0,    1,    1,    1,    3,    2,
        0,    1,
    );

    my @defred = (                                             0,
        0,   54,    0,   50,    0,    1,    0,    0,   48,    0,
    40,    0,    0,    0,    0,   57,   56,    0,    0,    0,
        3,    0,    6,    0,   11,    0,    0,    0,    0,   49,
        0,   41,   42,    0,   22,    0,    0,    0,    0,   46,
    44,    0,   45,    0,   29,   47,    4,    0,    0,    0,
        0,    7,    8,    9,   10,    0,   25,    0,   52,   43,
        0,    0,    0,    0,   36,    0,    0,   32,   62,    5,
        0,    0,    0,   58,    0,   18,   19,    0,   20,    0,
        0,   28,   60,   21,    0,    0,    0,   34,   33,   59,
        0,    0,   17,   15,   16,    0,   35,   14,
    );

    my @dgoto = (                                              5,
        6,    7,   21,    8,   18,   51,   70,    9,   52,   53,
    54,   55,   44,   96,   60,   66,   73,   45,   57,   67,
    68,   10,   11,   46,   74,
    );

    my @s_index = (                                             2,
    58,    0,    8,    0,    0,    0,   11,  123,    0,    3,
        0,   59,  123,   19,   73,    0,    0,   92,    7,    7,
        0,  123,    0,  119,    0,   59,  107,  109,  116,    0,
    82,    0,    0,  119,    0,  107,  109,   84,  126,    0,
        0,   90,    0,  132,    0,    0,    0,    7,    7,   10,
    139,    0,    0,    0,    0,  141,    0,  143,    0,    0,
    82,  156,  159,   82,    0,  160,    4,    0,    0,    0,
    171,  158,    6,    0,  123,    0,    0,  123,    0,   10,
    10,    0,    0,    0,  143,  124,  119,    0,    0,    0,
    107,  109,    0,    0,    0,   90,    0,    0,
    );

    my @r_index = (                                           155,
    105,    0,    0,    0,    0,    0,  174,  111,    0,   80,
        0,  105,  138,    0,    0,    0,    0,    0,  161,  145,
        0,  138,    0,    0,    0,  105,    0,    0,    0,    0,
    105,    0,    0,    0,    0,   29,   33,   70,   74,    0,
        0,   46,    0,    0,    0,    0,    0,   45,   45,    0,
    54,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    105,    0,    0,  105,    0,    0,  164,    0,    0,    0,
        0,    0,    0,    0,  138,    0,    0,  138,    0,    0,
    165,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    89,   93,    0,    0,    0,   25,    0,    0,
    );

    my @g_index = (                                             0,
    85,    0,  151,    1,  -12,   91,    0,   47,  -18,  -19,
    -17,  157,    0,    0,   83,    0,    0,    0,    0,    0,
    -3,    0,  127,    0,   95,
    );

    my @table = (                                             30,
    24,   13,    1,    2,   41,   40,   42,   31,    2,   34,
    64,   15,   22,   14,   19,   80,   84,   85,    3,   25,
    20,   81,    4,    3,   51,   51,   22,    4,   23,   23,
    65,   13,   24,   24,   12,   51,   51,   23,   13,   23,
    23,   24,   51,   24,   24,   51,   23,   53,   53,   53,
    24,   53,   53,   61,   61,   37,   51,   51,   23,    2,
        2,   75,   86,   51,   78,   87,   94,   93,   95,   27,
    27,   12,   23,   26,   26,    3,   88,   89,   27,   38,
    27,   27,   26,    2,   26,   26,   26,   27,   23,   23,
    38,   26,   24,   24,   27,   28,   29,   23,   59,   23,
    23,   24,   56,   24,   24,   53,   23,   53,   53,   53,
    24,   53,   53,   55,   55,   55,   48,   53,   49,   35,
    53,   36,   37,   29,   35,   50,   91,   92,   29,   16,
    17,   38,   62,   63,   39,   58,   38,   61,   55,   39,
    55,   55,   55,   72,   39,   32,   33,   53,   53,   53,
    55,   53,   53,   55,   37,   39,   69,   53,   53,   53,
    71,   53,   53,   53,   53,   53,   76,   53,   53,   77,
    79,   82,   83,    2,   30,   31,   47,   97,   98,   90,
    43,
    );

    my @check = (                                             18,
    13,    1,    1,    2,   24,   24,   24,    1,    2,   22,
        1,    1,   12,    6,   12,   12,   11,   12,   17,    1,
    18,   18,   21,   17,    0,    1,   26,   21,    0,    1,
    21,   31,    0,    1,    6,   11,   12,    9,    6,   11,
    12,    9,   18,   11,   12,    0,   18,    3,    4,    5,
    18,    7,    8,    0,    1,   11,   11,   12,   12,    2,
        2,   61,   75,   18,   64,   78,   86,   86,   86,    0,
        1,   14,   26,    0,    1,   17,   80,   81,    9,    0,
    11,   12,    9,    2,   11,   12,   14,   18,    0,    1,
    11,   18,    0,    1,    3,    4,    5,    9,    9,   11,
    12,    9,   19,   11,   12,    1,   18,    3,    4,    5,
    18,    7,    8,    3,    4,    5,   10,   13,   10,    1,
    16,    3,    4,    5,    1,   10,    3,    4,    5,    7,
        8,   13,   48,   49,   16,   10,   13,    6,    1,   16,
        3,    4,    5,    1,    0,   19,   20,    3,    4,    5,
    13,    7,    8,   16,    0,   11,   18,    3,    4,    5,
    20,    7,    8,    3,    4,    5,   11,    7,    8,   11,
    11,    1,   15,    0,   11,   11,   26,   87,   96,   85,
    24,
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


    my %base-type = (
    BOOLEAN        => [ asn-encode-tag(ASN_BOOLEAN),        opBOOLEAN ],
    INTEGER        => [ asn-encode-tag(ASN_INTEGER),        opINTEGER ],
    BIT_STRING        => [ asn-encode-tag(ASN_BIT_STR),        opBITSTR  ],
    OCTET_STRING        => [ asn-encode-tag(ASN_OCTET_STR),        opSTRING  ],
    STRING        => [ asn-encode-tag(ASN_OCTET_STR),        opSTRING  ],
    NULL             => [ asn-encode-tag(ASN_NULL),        opNULL    ],
    OBJECT_IDENTIFIER => [ asn-encode-tag(ASN_OBJECT_ID),        opOBJID   ],
    REAL            => [ asn-encode-tag(ASN_REAL),        opREAL    ],
    ENUMERATED        => [ asn-encode-tag(ASN_ENUMERATED),    opINTEGER ],
    ENUM            => [ asn-encode-tag(ASN_ENUMERATED),    opINTEGER ],
    'RELATIVE-OID'    => [ asn-encode-tag(ASN_RELATIVE_OID),    opROID      ],

    SEQUENCE        => [ asn-encode-tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), opSEQUENCE ],
    EXPLICIT        => [ asn-encode-tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), opEXPLICIT ],
    SET               => [ asn-encode-tag(ASN_SET      +| ASN_CONSTRUCTOR), opSET ],

    ObjectDescriptor  => [ asn-encode-tag(ASN_UNIVERSAL +|  7), opSTRING ],
    UTF8String        => [ asn-encode-tag(ASN_UNIVERSAL +| 12), opUTF8 ],
    NumericString     => [ asn-encode-tag(ASN_UNIVERSAL +| 18), opSTRING ],
    PrintableString   => [ asn-encode-tag(ASN_UNIVERSAL +| 19), opSTRING ],
    TeletexString     => [ asn-encode-tag(ASN_UNIVERSAL +| 20), opSTRING ],
    T61String         => [ asn-encode-tag(ASN_UNIVERSAL +| 20), opSTRING ],
    VideotexString    => [ asn-encode-tag(ASN_UNIVERSAL +| 21), opSTRING ],
    IA5String         => [ asn-encode-tag(ASN_UNIVERSAL +| 22), opSTRING ],
    UTCTime           => [ asn-encode-tag(ASN_UNIVERSAL +| 23), opUTIME ],
    GeneralizedTime   => [ asn-encode-tag(ASN_UNIVERSAL +| 24), opGTIME ],
    GraphicString     => [ asn-encode-tag(ASN_UNIVERSAL +| 25), opSTRING ],
    VisibleString     => [ asn-encode-tag(ASN_UNIVERSAL +| 26), opSTRING ],
    ISO646String      => [ asn-encode-tag(ASN_UNIVERSAL +| 26), opSTRING ],
    GeneralString     => [ asn-encode-tag(ASN_UNIVERSAL +| 27), opSTRING ],
    CharacterString   => [ asn-encode-tag(ASN_UNIVERSAL +| 28), opSTRING ],
    UniversalString   => [ asn-encode-tag(ASN_UNIVERSAL +| 28), opSTRING ],
    BMPString         => [ asn-encode-tag(ASN_UNIVERSAL +| 30), opSTRING ],
    BCDString         => [ asn-encode-tag(ASN_OCTET_STR), opBCD ],

    CHOICE => [ '', opCHOICE ],
    ANY    => [ '', opANY ],

    EXTENSION_MARKER => [ '', opEXTENSIONS ],
    );

    my $tagdefault = 1; # 0:IMPLICIT , 1:EXPLICIT default

    my @ctr;
# Some horse shit to fix later
# @ctr[opBITSTR, opSTRING, opUTF8] = (&_ctr_bitstring, &_ctr_string, &_ctr_string);

# Manage current position in lexer, make local
    my $pos;
    my $last_pos;
    my @stacked;

    sub asn-encode-tag($tag) is export {
        use experimental :pack;
        $tag +> 8
            ?? $tag & 0x8000
                ?? $tag & 0x800000
                    ?? pack('V', $tag)
                    !! substr(pack('V', $tag), 0, 3)
                !! pack('v', $tag)
            !! pack('C', $tag);
    }

    class Convert::ASN1P6 {
        has $.encoding;
        has $.tag-default;
        has $.tree;
        has @.script;

        # die unless $what =~ /timezone|time|bigint/;
        has $.type;


        method new(
            :$encoding where { $encoding ~~ /^[BER||DER]$/} = 'BER',
            # Implicit is the default, but should be changed
            :$tag-default
                where { $tag-default ~~ /^[IMPLICIT|EXPLICIT]$$/ }
                = 'IMPLICIT',
            :$type,

        ) {

            self.bless(
                :$encoding,
                :$tag-default,
                :$type,
            );
        }

        method prepare($asn) {
            $!tree = parse($asn, $!tag-default);
            @!script = $!tree.values[0];
            return self;
        }

        method parse(@lex) {
            say "### Tree ###";
            my %xxparsed = xxparse(@lex);
            say Dump(%xxparsed);

            my $compiled = compile(%xxparsed);

            say "### Compiled ###";
            say Dump($compiled);
            return $compiled;
        }

        method encode(%stash) {
            my @my_script = [
                [
                    "\x5",
                    5,
                    "null",
                    Any,
                    Any,
                    Any
                ],
            ];
            # blerg "sub encode";
            # Some old horse shit api where you can hae a default tag I think?
            # Lets you do *.encode(9) instead of *.encode(integer => 9) I think...
            # my $stash = @_ == 1 ? shift : { @_ };

            my $foo = _encode(
                { 'encoding' => $!encoding, 'tagdefault' => $!tag-default },
                @my_script, # @!script,
                %stash
            );

            return $foo;
        }

        method lex($asn) {
            return lex($asn);
        }

    }

    my @encode = (
    sub { die "internal error\n" },
    &_enc_boolean,
    &_enc_integer,
    &_enc_bitstring,
    &_enc_string,
    &_enc_null,
    &_enc_object_id,
    &_enc_real,
    &_enc_sequence,
    &_enc_sequence, # EXPLICIT is the same encoding as sequence
    &_enc_sequence, # SET is the same encoding as sequence
    &_enc_time,
    &_enc_time,
    &_enc_utf8,
    &_enc_any,
    &_enc_choice,
    &_enc_object_id,
    &_enc_bcd,
    );

    sub _enc_boolean {}
    sub _enc_integer {}
    sub _enc_bitstring {}
    sub _enc_string {}

    sub _enc_null(:%optn, :@op, :%stash, :$var, :$buf, :$loop, :@path) {
        # my $buf = @x[4];
        my $buf_buf = $buf.encode;
        $buf_buf ~= pack("C", 0);


        return $buf_buf;
    }

    sub _enc_real {}
    sub _enc_sequence {}
    sub _enc_time {}
    sub _enc_utf8 {}
    sub _enc_any {}
    sub _enc_choice {}
    sub _enc_object_id {}
    sub _enc_bcd {}

    sub _encode(%optn, @ops, %stash is copy, @path is copy = (), $buffer is copy = '') {
        my $var;

        for @ops -> @op {
            next if @op[cTYPE] == opEXTENSIONS;

            if (my $opt = @op[cOPT]).defined {
                next unless (%stash{$opt}).defined;
            }

            if ($var = @op[cVAR]).defined {
                @path.push($var);
                die @path.join('.') ~  "is undefined" unless %stash{$var}.defined;
            }


            $buffer ~= @op[cTAG];

            my %stash_one;
            my $stash_two;

            # More horse shit to handle single values with implied tags
            # Skipping for now and we'll refactor once it works without it
            # if (UNIVERSAL::isa($stash, 'HASH')) {
            if $var.defined {
                # @stash_val = (%stash, %stash{$var});
                %stash_one = %stash;
                $stash_two = %stash{$var};
            }
            else {
                # @stash_val = (%stash, Any);
                %stash_one = %stash;
                $stash_two = Any;
            }
            # }
            # else {
            #   @stash_val = ({}, $stash);
            # }


            $buffer = @encode[ @op[cTYPE] ](
                :%optn,
                :@op,
                # |@stash_val,
                :stash(%stash_one),
                :var($stash_two),
                :buf($buffer),
                :loop(@op[cLOOP]),
                :path(@path),
            );

            pop @path if $var.defined;
        }

        return $buffer;
    }

    sub parse($asn, $tag-default) is export(:debug) {
        die "for what";
        # my $tree = compile((yyparse($asn)));

        #return $tree;
    }

    sub compile(%tree) {

        # my $compile = $p5-asn.my_compile(%tree);

        # return $compile;

        # The tree should be valid enough to be able to
        #  - resolve references
        #  - encode tags
        #  - verify CHOICEs do not contain duplicate tags

        # once references have been resolved, and also due to
        # flattening of COMPONENTS, it is possible for an op
        # to appear in multiple places. So once an op is
        # compiled we bless it. This ensure we dont try to
        # compile it again.

        for %tree.kv -> $key, @values {
            compile-one(%tree, @values, $key);
        }

        return %tree;
    }

    sub compile-one(%tree, @ops, $name) {
        say "### t-Tree ###";
        say Dump(%tree);
        say "";

        say "### t-OPS ###";
        say Dump(@ops);
        say "";

        say "### t-Name ###";
        say Dump($name);
        say "";

        my $loop_death = 0;
        for @ops -> @op {
            $loop_death++;
            # next unless ref($op) eq 'ARRAY';
            # bless $op;

            # cType is the position of the Type name in the ASN (I think...);
            my $type = @op[cTYPE];

            if %base-type{$type}:exists {

                @op[cTYPE] = %base-type{$type}[1];

                @op[cTAG] = defined(@op[cTAG])
                    ?? asn-encode-tag(@op[cTAG])
                    !! %base-type{$type}[0];
            }

            else {
                die "Unknown type '$type'\n" unless %tree{$type}:exists;

                my @ref = compile-one(
                    %tree,
                    %tree{$type},
                    (@op[cVAR]).defined
                        ?? $name ~ "." ~ @op[cVAR]
                        !! $name
                );

                if (@op[cTAG]).defined && @ref[0][cTYPE] == opCHOICE {
                    @op[cTYPE, cCHILD] = (opSEQUENCE, @ref);
                }

                else {
                    @op[cTYPE,cCHILD,cLOOP] = @ref[0][cTYPE,cCHILD,cLOOP];
                }

                @op[cTAG] = @op[cTAG]
                    ?? asn-encode-tag(@op[cTAG])
                    !! @ref[0][cTAG];
            }

            if @op[cTAG].elems
                && (@op[cTYPE] == opSET
                || @op[cTYPE] == opEXPLICIT
                || @op[cTYPE] == opSEQUENCE) {

                @op[cTAG] +|= pack('C', ASN_CONSTRUCTOR);
            }

            if @op[cCHILD] {
                # If we have children we are one of
                #  opSET opSEQUENCE opCHOICE opEXPLICIT

                compile-one(
                    %tree,
                    @op[cCHILD],
                    (@op[cVAR]).defined
                    ?? $name ~ "." ~ @op[cVAR]
                    !! $name
                );

                # If a CHOICE is given a tag, then it must be EXPLICIT
                if @op[cTYPE] == opCHOICE
                    && (@op[cTAG]).defined
                    && (@op[cTAG]).elems {

                    # $op = bless explicit($op);
                    @op = explicit(@op);
                    @op[cTYPE] = opSEQUENCE;
                }

                if @op[cCHILD] > 1 {
                    if @op[cTYPE] == opSET {
                        # In case we do CER encoding we order the SET elements by thier tags
                        my @tags = map {
                            (@_[cTAG]).elems
                            ?? @_[cTAG]
                            !! @_[cTYPE] == opCHOICE
                            ?? (sort map { @_[cTAG] }, @_[cCHILD])[0]
                            !! ''
                        }, @op[cCHILD];

                        @op[cCHILD] = @op[cCHILD][sort {
                                @tags[$^a] cmp @tags[$^b]
                        }, 0..@tags.elems];
                    }
                }

                else {
                    # A SET of one element can be treated the same as a SEQUENCE
                    @op[cTYPE] = opSEQUENCE if @op[cTYPE] == opSET;
                }
            }
            say "herekls;h;";
            say Dump(@ops);
            die if $loop_death >= 2;
        }

        return @ops;
    }

    sub explicit(@op) {
        my @seq = @op;

        @seq[cTYPE,cCHILD,cVAR,cLOOP] = ('EXPLICIT', [@op], Any, Any);
        @op[cTAG,cOPT] = ();

        return @seq;
    }

    sub xxparse(@lex) {
        my $lval;

        my $char = -1;
        my $index;
        my $ssp = 0;
        my $vsp = 0;

        my @ss;
        my @vs;
        my $state = 0;
        my $yym;
        my $val;
        @ss[$ssp] = $state;

        use Data::Dump;

        while (1) {
            unless ($index = @defred[$state]) {

                if ($char < 0) {
                    my $item = shift @lex;
                    $char = $item{'type'};
                    $lval = $item{'lval'};

                    if ($char < 0) {
                        $char = 0;
                    }
                }

                if (($index = @s_index[$state])
                    && ($index += $char) >= 0
                    && @check[$index] == $char) {

                    @ss[++$ssp] = $state = @table[$index];
                    @vs[++$vsp] = $lval;
                    $char = -1;
                    next;
                }

                elsif (($index = @r_index[$state])
                    && ($index += $char) >= 0
                    && @check[$index] == $char) {

                    $index = @table[$index];
                }

                else {
                    die 'unknown error';
                }

            }

            $yym = @length[$index];
            $val = @vs[$vsp + 1 - $yym];

            if ($index == 1) {
                $val = { '' => @vs[ $vsp ] };
            }

            elsif ($index == 3) {
                $val = { @vs[ $vsp - 2 ], [ @vs[ $vsp ] ] };
            }

            elsif ($index == 4) {
                $val = @vs[ $vsp - 3 ];
                $val.{ '$vs'[ $vsp - 2 ] } = [ @vs[ $vsp ] ];
            }

            elsif ($index == 5) {
                @vs[ $vsp - 1 ].[cTAG] = @vs[ $vsp - 3 ];
                $val = need_explicit(@vs[ $vsp - 3 ], @vs[ $vsp - 2 ])
                    ?? explicit(@vs[ $vsp - 1 ])
                    !! @vs[ $vsp - 1 ];
            }

            elsif ($index == 11) {
                @($val = [])[ cTYPE, cCHILD ] = ('COMPONENTS', @vs[ $vsp ]);
            }

            elsif ($index == 14) {
                @vs[ $vsp - 1 ].[cTAG] = @vs[ $vsp - 3 ];
                @($val = [])[ cTYPE, cCHILD, cLOOP, cOPT ]
                    = (@vs[ $vsp - 5 ], [@vs[ $vsp - 1 ]], 1, @vs[ $vsp - 0 ]);

                $val = explicit($val) if need_explicit(@vs[ $vsp - 3], @vs[ $vsp - 2 ]);
            }

            elsif ($index == 18) {
                @($val = [])[cTYPE,cCHILD] = ('SEQUENCE', @vs[ $vsp - 1 ]);
            }

            elsif ($index == 19) {
                @($val = [])[cTYPE,cCHILD] = ('SET', @vs[ $vsp - 1 ]);
            }

            elsif ($index == 20) {
                @($val = [])[cTYPE,cCHILD] = ('CHOICE', @vs[ $vsp - 1 ]);
            }

            elsif ($index == 21) {
                @($val = [])[cTYPE] = ('ENUM');
            }

            elsif ($index == 22 || $index == 23 || $index == 24 || $index == 26)  {
                @($val = [])[cTYPE] = @vs[ $vsp ];
            }

            elsif ($index == 25) {
                @($val = [])[cTYPE,cCHILD,cDEFINE] = ('ANY', Any, @vs[ $vsp ]);
            }

            elsif ($index == 27) { $val = Any; }

            elsif ($index == 28 || $index == 30) {
                $val = @vs[ $vsp ];
            }

            elsif ($index == 31) {
                $val = @vs[ $vsp - 1 ];
            }

            elsif ($index == 32) {
                $val = [ @vs[ $vsp ] ];
            }

            elsif ($index == 33) {
                push @($val = @vs[ $vsp - 2 ]), @vs[ $vsp ];
            }

            elsif ($index == 34) {
                push @($val = @vs[$vsp - 2 ]), @vs[ $vsp ];
            }

            elsif ($index == 35) {
                @($val = @vs[ $vsp ])[ cVAR, cTAG ] = (@vs[ $vsp - 3 ], @vs[ $vsp - 2 ]);
                $val = explicit($val) if need_explicit(@vs[ $vsp - 2], @vs[ $vsp - 1 ]);
            }

            elsif ($index == 36) { @($val = [])[cTYPE] = 'EXTENSION_MARKER'; }

            elsif ($index == 37) { $val = []; }

            elsif ($index == 38) {
                my $extension = 0;
                $val = [];
                for (@(@vs[$vsp-0])) -> $i {
                    $extension = 1 if $i.[cTYPE] eq 'EXTENSION_MARKER';
                    $i.[cEXT] = $i.[cOPT];
                    $i.[cEXT] = 1 if $extension;
                    push @($val), $i unless $i.[cTYPE] eq 'EXTENSION_MARKER';
                }
                my $e = []; $e.[cTYPE] = 'EXTENSION_MARKER';
                push @($val), $e if $extension;
            }

            elsif ($index == 39) {
                my $extension = 0;
                $val = [];
                for (@(@vs[$vsp-1])) -> $i {
                    $extension = 1 if $i.[cTYPE] eq 'EXTENSION_MARKER';
                    $i.[cEXT] = $i.[cOPT];
                    $i.[cEXT] = 1 if $extension;
                    push @($val), $i unless $i.[cTYPE] eq 'EXTENSION_MARKER';
                }
                my $e = []; $e.[cTYPE] = 'EXTENSION_MARKER';
                push @($val), $e if $extension;
            }

            elsif ($index == 40) {
                $val = [ @vs[ $vsp ] ];
            }

            elsif ($index == 41) {
                push @( $val = @vs[ $vsp - 2 ]), @vs[ $vsp ];
            }

            elsif ($index == 42) {
                push @( $val = @vs[ $vsp - 2 ]), @vs[ $vsp ];
            }

            elsif ($index == 43) {
                @( $val = @vs[ $vsp -1 ])[cOPT] = (@vs[ $vsp ]);
            }

            elsif ($index == 47) {
                @($val=@vs[ $vsp ])[cVAR,cTAG] = (@vs[ $vsp - 3 ],@vs[ $vsp - 2 ]);
                $val.[cOPT] = @vs[ $vsp - 3] if $val.[cOPT];
                $val = explicit($val) if need_explicit(@vs[ $vsp - 2], @vs[ $vsp - 1 ]);
            }

            elsif ($index == 49) {
                @($val=@vs[ $vsp ])[cTAG] = (@vs[ $vsp - 2 ]);
                $val = explicit($val) if need_explicit(@vs[ $vsp - 2 ], @vs[ $vsp - 1 ]);
            }

            elsif ($index == 50) { @($val=[])[cTYPE] = 'EXTENSION_MARKER'; }

            elsif ($index == 51 || $index == 53 || $index == 55) { $val = Any; }

            elsif ($index == 52 || $index == 56 ) { $val = 1; }

            elsif ($index == 57) { $val = 0; }

            $ssp -= $yym;
            $state = @ss[$ssp];
            $vsp -= $yym;
            $yym = @left_hand_side[$index];

            if ($state == 0 && $yym == 0) {
                $state = constYYFINAL;
                @ss[++$ssp] = constYYFINAL;
                @vs[++$vsp] = $val;

                if ($char < 0) {
                    my $item = shift @lex;
                    $char = $item{'type'};
                    $lval = $item{'lval'};

                    if ($char < 0) { $char = 0; }
                }

                if $char == 0 {
                    my %tree = @vs[$vsp];
                    return %tree;
                }

                next;
            }

            if (($index = @g_index[$yym])
                && ($index += $state) >= 0
                && $index <= @check.end
                && @check[$index] == $state) {

                $state = @table[$index];
            }
            else {
                $state = @dgoto[$yym];
            }

            @ss[++$ssp] = $state;
            @vs[++$vsp] = $val;
        }
    }

    sub lex ($asn) {
        my token white-space { \s+ || '--'\N* };
        my token symbols { <[ , { } ]> || '::=' };
        my token tokens { \w+ [ '-'\w+ ]* };
        my token reserved {
            [ SET || SEQUENCE || OPTIONAL || OF || IMPLICIT || EXPLICIT
            || ENUMERATED || ENUM || DEFINED || COMPONENTS || CHOICE
            || BY || ANY ]
        };
        my token identifier-type {
            [ OCTET || BIT ] \s+ STRING
            || OBJECT \s+ IDENTIFIER
            || 'RELATIVE-OID'
        };
        my token classes {
            [[ APPLICATION || PRIVATE || UNIVERSAL || CONTEXT ] \s+ ]? \d+
        };
        my token integers {
            \d+
        };

        my @lex_array;
        while $asn ~~ m:c/
            $<white-space> = [ \s+ || '--'\N* ]
            ||
            $<symbol> = [ <[ , { } ]> || '::=' ]
            ||
            $<reserved> = [
                SET || SEQUENCE || OPTIONAL || OF || IMPLICIT || EXPLICIT
                || ENUMERATED || ENUM || DEFINED || COMPONENTS || CHOICE
                || BY || ANY
             ]
            ||
            $<identifier-type> = [
                [ OCTET || BIT ] \s+ STRING
                || OBJECT \s+ IDENTIFIER
                || 'RELATIVE-OID'
            ]<|w>
            ||
            $<token> = [ \w+ [ '-'\w+ ]* ]
            ||
            \[ \s*  # Literal '[' square bracket
            $<class> = [
                [[ APPLICATION || PRIVATE || UNIVERSAL || CONTEXT ] \s+ ]? \d+
            ]
            \s* \]  # Literal ']' closing square bracket
            ||
            \( $<integer> = [ \d+ ] \) # Literal parens around a number: '(42)'
            ||
            $<dot-dot-dot> = [\.\.\.]    # Literal '...' three dots
            /
        -> $tokens {

            if $<white-space> {
                next;
            }

            elsif $<symbol> {
                my $symbol = $<symbol>.Str;

                my @stacked;
                if $symbol eq '}' {
                    @stacked.push(constPOSTRBRACE);
                }

                @lex_array.push({
                    type => %reserved{ $symbol },
                    lval => $symbol,
                });

                if @stacked.elems {
                    @lex_array.push({
                        type => @stacked.shift,
                        lval => Any,
                    });

                }

                next;
            }

            elsif $<reserved> {
                my $reserved = $<reserved>.Str;

                @lex_array.push({
                    type => %reserved{ $reserved },
                    lval => $reserved,
                });

                next;
            }

            elsif $<identifier-type> {
                my $identifier-type = $<identifier-type>.Str;

                $identifier-type = S:g/\s+/_/ given $identifier-type;

                @lex_array.push({
                    type => constWORD,
                    lval => $identifier-type,
                });

                next;
            }

            elsif $<token> {
                my $token = $<token>.Str;

                @lex_array.push({
                    type => constWORD,
                    lval => $token,
                });

                next;
            }

            elsif $<class> {
                my ($class, $num);

                if $<class>.Str ~~ /^ ( <[A..Z]>* ) \s* (\d+) $/ {
                    $class = $0;
                    $num = $1;
                }

                my $lval = $class.Str;
                # asn_tag(%tag_class{$class}, $num);

                @lex_array.push({
                    type => constCLASS,
                    lval => $lval,
                });

                next;
            }

            elsif $<integer> {
                my $integer = $<integer>.Str;

                @lex_array.push({
                  type => constNUMBER,
                  lval => $integer,
                });

                next;
            }

            elsif $<dot-dot-dot> {
                @lex_array.push({
                    type => constEXTENSION_MARKER,
                    lval => Any,
                });

                next;
            }

            else {
                die "Invalid asn, can't lex";
            }
        }

        @lex_array.push({
            type => 0,
            lval => Any,
        });

        return @lex_array;
    }

    # TODO $ CHANGE THIS BACK!!!
    sub yyparse($asn is copy) is export(:debug) {
        my %yyparse;
        my $pos;

        my $yylval;
        my @stacked;

        $asn = ' null NULL, bool BOOLEAN ';
        $asn = ' test ::= INTEGER';
        $asn = ' roid RELATIVE-OID';
        $asn = 'SET {
                    integer INTEGER,
                    bool BOOLEAN,
                    str STRING
                }';
                # $asn = $ldap-asn;
        $asn = ' eq SEQUENCE OF SEQUENCE { str STRING, val SEQUENCE OF STRING } ';
        $asn = ' null NULL ';

    }



    # args: class,plicit
    sub need_explicit {
        ( defined(@_[0]) && (defined(@_[1]) ?? @_[1] !! $tagdefault ));
    }


}
