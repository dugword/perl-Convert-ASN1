use v6;
use Data::Dump;
use experimental :pack;

my $tagdefault = 'IMPLICIT';

class Compiled is Array {}

module Convert::ASN1P6 {

# Some numbering system constants
    my @_dec_real_base = (2,8,16);

    constant WORD = 1;
    constant CLASS = 2;
    constant SEQUENCE = 3;
    constant SET = 4;
    constant CHOICE = 5;
    constant OF = 6;
    constant IMPLICIT = 7;
    constant EXPLICIT = 8;
    constant OPTIONAL = 9;
    constant LBRACE = 10;
    constant RBRACE = 11;
    constant COMMA = 12;
    constant ANY = 13;
    constant ASSIGN = 14;
    constant NUMBER = 15;
    constant ENUM = 16;
    constant COMPONENTS = 17;
    constant POSTRBRACE = 18;
    constant DEFINED = 19;
    constant BY = 20;
    constant EXTENSION_MARKER = 21;
    constant YYERRCODE = 256;
    constant YYFINAL = 5;
    constant YYMAXTOKEN = 21;
    constant YYTABLESIZE = 181;

    constant ASN_BOOLEAN is export(:constant) = 0x01;
    constant ASN_INTEGER is export(:constant) = 0x02;
    constant ASN_BIT_STR is export(:constant) = 0x03;
    constant ASN_OCTET_STR is export(:constant) = 0x04;
    constant ASN_NULL is export(:constant) = 0x05;
    constant ASN_OBJECT_ID is export(:constant) = 0x06;
    constant ASN_REAL is export(:constant) = 0x09;
    constant ASN_ENUMERATED is export(:constant) = 0x0A;
    constant ASN_RELATIVE_OID is export(:constant) = 0x0D;
    constant ASN_SEQUENCE is export(:constant) = 0x10;
    constant ASN_SET is export(:constant) = 0x11;
    constant ASN_PRINT_STR is export(:constant) = 0x13;
    constant ASN_IA5_STR is export(:constant) = 0x16;
    constant ASN_UTC_TIME is export(:constant) = 0x17;
    constant ASN_GENERAL_TIME is export(:constant) = 0x18;

    constant ASN_UNIVERSAL is export(:constant) = 0x00;
    constant ASN_APPLICATION is export(:constant) = 0x40;
    constant ASN_CONTEXT is export(:constant) = 0x80;
    constant ASN_PRIVATE is export(:constant) = 0xC0;

    constant ASN_PRIMITIVE is export(:constant) = 0x00;
    constant ASN_CONSTRUCTOR is export(:constant) = 0x20;

    constant ASN_LONG_LEN is export(:constant) = 0x80;
    constant ASN_EXTENSION_ID is export(:constant) = 0x1F;
    constant ASN_BIT is export(:constant) = 0x80;

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

    my %tag_class = (
        APPLICATION => ASN_APPLICATION,
        UNIVERSAL   => ASN_UNIVERSAL,
        PRIVATE     => ASN_PRIVATE,
        CONTEXT     => ASN_CONTEXT,
        ''          => ASN_CONTEXT # if not specified, its CONTEXT
    );

    my %reserved = (
        'OPTIONAL'   => OPTIONAL,
        'CHOICE'     => CHOICE,
        'OF'         => OF,
        'IMPLICIT'   => IMPLICIT,
        'EXPLICIT'   => EXPLICIT,
        'SEQUENCE'   => SEQUENCE,
        'SET'        => SET,
        'ANY'        => ANY,
        'ENUM'       => ENUM,
        'ENUMERATED' => ENUM,
        'COMPONENTS' => COMPONENTS,
        '{'          => LBRACE,
        '}'          => RBRACE,
        ','          => COMMA,
        '::='        => ASSIGN,
        'DEFINED'    => DEFINED,
        'BY'         => BY,
    );

    my @left_hand_side = (                                   -1,
        0,    0,    2,    2,    3,    3,    6,    6,    6,    6,
        8,   13,   13,   12,   14,   14,   14,    9,    9,    9,
        10,   18,   18,   18,   18,   18,   19,   19,   11,   16,
        16,   20,   20,   20,   21,   21,    1,    1,    1,   22,
        22,   22,   24,   24,   24,   24,   23,   23,   23,   23,
        15,   15,    4,    4,    5,    5,    5,   17,   17,   25,
        7,    7,
    );

    my @length = (                                            2,
        1,    1,    3,    4,    4,    1,    1,    1,    1,    1,
        3,    1,    1,    6,    1,    1,    1,    4,    4,    4,
        4,    1,    1,    1,    2,    1,    0,    3,    1,    1,
        2,    1,    3,    3,    4,    1,    0,    1,    2,    1,
        3,    3,    2,    1,    1,    1,    4,    1,    3,    1,
        0,    1,    0,    1,    0,    1,    1,    1,    3,    2,
        0,    1,
    );

    my @defred = (                                            0,
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

    my @dgoto = (                                             5,
        6,    7,   21,    8,   18,   51,   70,    9,   52,   53,
       54,   55,   44,   96,   60,   66,   73,   45,   57,   67,
       68,   10,   11,   46,   74,
    );

    my @s_index = (                                            2,
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

    my @r_index = (                                         155,
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

    my @g_index = (                                            0,
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

    class Convert::ASN1P6 {
        has $.encoding;
        has $.tag-default;
        has %.tree;
        has @.script;
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
            my $explicit-flag = $!tag-default eq 'EXPLICIT' ?? 1 !! 0;

            my @lexxed = lex($asn);
            my %parsed = parse(@lexxed, $explicit-flag);
            my %verified = verify(%parsed);
            my %compiled = compile(%verified);

            %!tree = %compiled;
            @!script = |(%compiled.values)[0];
        }

        method encode(%stash) {
            # my $stash = @args == 1 ?? @args.shift !! { |@args };

            say "Check this:";
            dd %stash;
            my $foo = _encode($!encoding, @!script, %stash);

            return $foo;
        }

        method decode(Buf $pdu) {

        }

    }

    sub asn-tag($class is copy, $value is copy) is export(:debug) {
        die sprintf "Bad tag class 0x%x", $class
            if $class +& +^0xe0;

        unless ($value +& +^0x1f or $value == 0x1f) {
            return ($class +& 0xe0) +| $value;
        }

        die sprintf "Tag value 0x%08x too big\n", $value
            if $value +& 0xffe00000;

        $class = ($class +| 0x1f) +& 0xff;

        my @t = $value +& 0x7f;
        @t.unshift(0x80 +| ($value +& 0x7f)) while $value +>= 7;

        # Get class and up to first 3 values of t, pad with 0 if less
        # dd @t;
        # say $class;
        my @bytes = ($class, |@t, 0, 0)[0..3];

        # dd @bytes;
        # Unpack into an unsigned long value
        return Buf.new(|@bytes).unpack("V");
    }

    sub asn-encode-tag($tag) is export(:debug) {
        if $tag +> 8 {
            if $tag +& 0x8000 {
                if $tag +& 0x800000 {
                    return pack('V', $tag);
                }
                return pack('V', $tag).subbuf(0 , 3);
            }
            return pack('v', $tag)
        }
        return pack('C', $tag);
    }

    sub asn-decode-tag($raw_tag) is export(:debug) {
        return unless $raw_tag;

        my $tag = $raw_tag.unpack("C");
        my $n = 1;

        if (($tag +& 0x1f) == 0x1f) {
            my $b;
            repeat {
                return if $n >= $raw_tag.bytes;
                $b = $raw_tag.subbuf($n, 1).unpack('C');
                $tag +|= $b +< (8 * $n++);
            } while ($b +& 0x80);
         }
         ($n, $tag);
    }

    sub asn-encode-length($length) is export(:debug) {
        if ($length +> 7) {
            my $lenlen = num-length($length);

            return pack(
                "Ca*",
                $lenlen +| 0x80,
                pack("N", $length).subbuf(*-$lenlen),
            );
        }

        return pack("C", $length);
    }

    # How many bytes are needed to encode a number
    sub num-length($num) {
        $num +> 8
            ?? $num +> 16
                ?? $num +> 24
                    ?? 4
                    !! 3
                !! 2
            !! 1
    }

    sub asn-decode-length($raw-length) is export(:debug){
        return unless $raw-length;

        my $len = $raw-length.unpack('C');

        if ($len +& 0x80) {
            $len +&= 0x7f or return (1,-1);

            return if $len >= $raw-length.bytes;

            return (
                1 + $len,
                (Buf.new(0 xx (4 - $len))
                    ~ $raw-length.subbuf(1, $len)).unpack('N')
            );
        }

        return (1, $len);
    }

    sub lex($asn) is export(:debug) {
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
                [ [ OCTET || BIT ] \s+ STRING ]
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
                    @stacked.push(POSTRBRACE);
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

                $identifier-type = $identifier-type.subst(' ', '_', :g);

                @lex_array.push({
                    type => WORD,
                    lval => $identifier-type,
                });

                next;
            }

            elsif $<token> {
                my $token = $<token>.Str;

                @lex_array.push({
                    type => WORD,
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
                    type => CLASS,
                    lval => $lval,
                });

                next;
            }

            elsif $<integer> {
                my $integer = $<integer>.Str;

                @lex_array.push({
                  type => NUMBER,
                  lval => $integer,
                });

                next;
            }

            elsif $<dot-dot-dot> {
                @lex_array.push({
                    type => EXTENSION_MARKER,
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

    sub parse($lex, $tagdefault) is export(:debug) {

        my $char = (-1);
        my $state = 0;
        my $index;
        my $lval;
        my $ssp = 0;
        my $vsp = 0;

        my $ss = [];
        my $vs = [];
        my $yym;
        my $val;

        $ss.[$ssp] = $state;

        my (%tree) = parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);

        return %tree;
    }

    sub unless_loop(
        $char is copy,
        $lex,
        $state is copy,
        $index is copy,
        $lval is copy,
        $ssp is copy,
        $vsp is copy,
        $ss is copy,
        $vs is copy,
    ){

        my $parsed;

        # say "Char => $char";
        if ($char < 0) {
            my $item = shift @($lex);
            $char = $item.{'type'};
            $lval = $item.{'lval'};

            if ($char < 0) {
                $char = 0;
            }
        }

        if (($index = @s_index[$state])
            && ($index += $char) >= 0
            && @check[$index] == $char) {

            $ss.[ ++$ssp ] = $state = @table[$index];
            $vs.[ ++$vsp ] = $lval;
            $char = (-1);

            ($parsed, $char, $state, $index, $lval, $ssp, $vsp)
                = parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, Any, Any);

            return ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs)
        }

        elsif (($index = @r_index[$state])
            && ($index += $char) >= 0
            && @check[$index] == $char) {

            $index = @table[$index];
        }

        else {
            die 'unknown error';
        }

        return ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs);

    }

    sub parse_loop(
        $char is copy,
        $lex is copy,
        $state is copy,
        $index is copy,
        $lval is copy,
        $ssp is copy,
        $vsp is copy,
        $ss is copy,
        $vs is copy,
        $yym is copy,
        $val is copy,
    ){
        unless ($index = @defred[$state]) {
            my $parsed;
            ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs)
                = unless_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs);

                # @lex = @$lex;
            return ($parsed) if $parsed;
        }

        $yym = @length[$index];
        $val = $vs[$vsp + 1 - $yym];
        say "Original \$val";
        dd $val;

        say $val.WHAT;
        # if $val.WHAT eq Block {
        #     say "It's a block";
        #     exit;
        # }

        if ($index == 1) {
            $val = { '' => $vs.[ $vsp ] };
        }

        elsif ($index == 3) {
            $val = { $vs.[ $vsp - 2 ], [ $vs.[ $vsp ] ] };
        }

        elsif ($index == 4) {
            say "First \$val:";
            dd $val;

            $val = $vs[ $vsp - 3 ];
            # $val.{ $vs.[ $vsp - 2 ] } = [ $vs.[ $vsp ] ];

            say "Second \$val:";
            dd $val;
            say "\$vsp";
            dd $vsp;
            say "\$vs";
            dd $vs;

            my $foo = $vs[ $vsp - 2 ];
            my $bar = $vs[ $vsp ];

            say "\$foo";
            dd $foo;

            say "\$bar";
            dd $bar;

            $val{ $foo } = [ $bar ];
        }

        elsif ($index == 5) {
            $vs.[ $vsp - 1 ].[cTAG] = $vs.[ $vsp - 3 ];
            $val = need_explicit($vs.[ $vsp - 3 ], $vs.[ $vsp - 2 ])
                ?? explicit($vs.[ $vsp - 1 ])
                !! $vs.[ $vsp - 1 ];
        }

        elsif ($index == 11) {
            @($val = [])[ cTYPE, cCHILD ] = ('COMPONENTS', $vs.[ $vsp ]);
        }

        elsif ($index == 14) {
            $vs.[ $vsp - 1 ].[cTAG] = $vs.[ $vsp - 3 ];
            @($val = [])[ cTYPE, cCHILD, cLOOP, cOPT ]
                = ($vs.[ $vsp - 5 ], [$vs.[ $vsp - 1 ]], 1, $vs.[ $vsp - 0 ]);

            $val = explicit($val) if need_explicit($vs.[ $vsp - 3], $vs.[ $vsp - 2 ]);
        }

        elsif ($index == 18) {
            @($val = [])[cTYPE,cCHILD] = ('SEQUENCE', $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 19) {
            @($val = [])[cTYPE,cCHILD] = ('SET', $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 20) {
            @($val = [])[cTYPE,cCHILD] = ('CHOICE', $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 21) {
            @($val = [])[cTYPE] = ('ENUM');
        }

        elsif ($index == 22 || $index == 23 || $index == 24 || $index == 26)  {
            @($val = [])[cTYPE] = $vs.[ $vsp ];
        }

        elsif ($index == 25) {
            @($val = [])[cTYPE,cCHILD,cDEFINE] = ('ANY', Any, $vs.[ $vsp ]);
        }

        elsif ($index == 27) { $val = Any; }

        elsif ($index == 28 || $index == 30) {
            $val = $vs.[ $vsp ];
        }

        elsif ($index == 31) {
            $val = $vs.[ $vsp - 1 ];
        }

        elsif ($index == 32) {
            $val = [ $vs.[ $vsp ] ];
        }

        elsif ($index == 33) {
            push @($val=$vs.[ $vsp - 2 ]), $vs.[ $vsp ];
        }

        elsif ($index == 34) {
            push @($val=$vs.[$vsp - 2 ]), $vs.[ $vsp ];
        }

        elsif ($index == 35) {
            @($val=$vs.[ $vsp ])[ cVAR, cTAG ] = ($vs.[ $vsp - 3 ], $vs.[ $vsp - 2 ]);
            $val = explicit($val) if need_explicit($vs.[ $vsp - 2], $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 36) { @($val=[])[cTYPE] = 'EXTENSION_MARKER'; }

        elsif ($index == 37) { $val = []; }

        elsif ($index == 38) {
            my $extension = 0;
            $val = [];
            for (@($vs.[$vsp-0])) -> $i {
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
            for (@($vs.[$vsp-1])) -> $i {
                $extension = 1 if $i.[cTYPE] eq 'EXTENSION_MARKER';
                $i.[cEXT] = $i.[cOPT];
                $i.[cEXT] = 1 if $extension;
                push @($val), $i unless $i.[cTYPE] eq 'EXTENSION_MARKER';
            }
            my $e = []; $e.[cTYPE] = 'EXTENSION_MARKER';
            push @($val), $e if $extension;
        }

        elsif ($index == 40) {
            $val = [ $vs.[ $vsp ] ];
        }

        elsif ($index == 41) {
            push @( $val = $vs.[ $vsp - 2 ]), $vs.[ $vsp ];
        }

        elsif ($index == 42) {
            push @( $val = $vs.[ $vsp - 2 ]), $vs.[ $vsp ];
        }

        elsif ($index == 43) {
            @( $val = $vs.[ $vsp -1 ])[cOPT] = ($vs.[ $vsp ]);
        }

        elsif ($index == 47) {
            @($val=$vs.[ $vsp ])[cVAR,cTAG] = ($vs.[ $vsp - 3 ],$vs.[ $vsp - 2 ]);
            $val.[cOPT] = $vs.[ $vsp - 3] if $val.[cOPT];
            $val = explicit($val) if need_explicit($vs.[ $vsp - 2], $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 49) {
            @($val=$vs.[ $vsp ])[cTAG] = ($vs.[ $vsp - 2 ]);
            $val = explicit($val) if need_explicit($vs.[ $vsp - 2 ], $vs.[ $vsp - 1 ]);
        }

        elsif ($index == 50) { @($val=[])[cTYPE] = 'EXTENSION_MARKER'; }

        elsif ($index == 51 || $index == 53 || $index == 55) { $val = Any; }

        elsif ($index == 52 || $index == 56 ) { $val = 1; }

        elsif ($index == 57) { $val = 0; }

        $ssp -= $yym;
        $state = $ss.[$ssp];
        $vsp -= $yym;
        $yym = @left_hand_side[$index];

        if ($state == 0 && $yym == 0) {
            $state = YYFINAL;
            $ss.[++$ssp] = YYFINAL;
            $vs.[++$vsp] = $val;

            if ($char < 0) {
                my $item = shift @$lex;
                $char = $item.{'type'};
                $lval = $item.{'lval'};

                if ($char < 0) { $char = 0; }
            }

            if $char == 0 {
                my %tree = $vs.[$vsp];
                return %tree;
            }

            return parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);

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

        $ss.[++$ssp] = $state;
        $vs.[++$vsp] = $val;

        parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);
    }

    sub need_explicit {
        ( defined(@_[0]) && (defined(@_[1]) ?? @_[1] !! $tagdefault ));
    }

    sub explicit($op) {
        my @seq = @$op;

        @seq[cTYPE,cCHILD,cVAR,cLOOP] = ('EXPLICIT',[$op],Any,Any);
        @($op)[cTAG,cOPT] = ();

        @seq;
    }

    sub verify_inner_loop(
        %tree is copy,
        $name is copy,
        $ops is copy,
        $scope is copy,
        $idx is copy,
        $path is copy,
        $stash is copy,
    ) {

        my $ops_length = $ops.elems;
        if ($idx < $ops_length) {
            my $op = $ops.[$idx++];
            my $var = $op.[cVAR];

            if (defined $var) {
                $stash.{$var}++;
                if ($stash.{$var} > 1) {
                    die "$name: $path.$var used multiple times";
                }
            }

            if ($op.[cCHILD].defined) {

                # if (ref $op.[cCHILD] eq 'ARRAY') {
                if $op.[cCHILD].isa('Array') {
                    my $scipe = [$stash, $path, $ops, $idx];
                    push @$scope, $scipe;
                    if (defined $var) {
                        $stash = {};
                        $path ~= "." ~ $var;
                    }
                    $idx = 0;
                    $ops = $op.[cCHILD];
                }

                elsif ($op.[cTYPE] eq 'COMPONENTS') {
                    splice(@$ops, --$idx, 1, expand_ops(%tree, $op.[cCHILD]));
                }

                else {
                    die "Internal error\n";
                }
            }
        }
        else {
            if (@$scope) {
                my $s = pop @$scope;
                ($stash, $path, $ops, $idx) = @$s;
            }
            else {
                return;
            }
        }

        verify_inner_loop(
            %tree,
            $name,
            $ops,
            $scope,
            $idx,
            $path,
            $stash,
        );
    };

    sub verify_loop(
        %tree is copy,
        $name is copy,
        $ops is copy,
    ) {

        my $scope = [];
        my $idx = 0;
        my $path = '';
        my $stash = {};


        verify_inner_loop(
            %tree,
            $name,
            $ops,
            $scope,
            $idx,
            $path,
            $stash,
        );
    };

    sub verify(%tree) is export(:debug) {
        #  dd %tree;
        my $new_tree = {};

        # Well it parsed correctly, now we
        #  - check references exist
        #  - flatten COMPONENTS OF (checking for loops)
        #  - check for duplicate var names
        # use constant cVAR => 2;
        # use constant cCHILD => 6;
        # use constant cTYPE => 1;


        for %tree.kv -> $name, $ops {
            verify_loop(%tree, $name, $ops);
        }

        return %tree;
        # say "HERE";
    }

    sub expand_ops(
        %tree,
        $want,
        $seen,
    ) {

        die "COMPONENTS OF loop $want\n" if $seen.{$want}++;
        die "Undefined macro $want\n" unless %tree{$want}:exists;
        my $ops = %tree{$want};

        die "Bad macro for COMPUNENTS OF $want\n"
            unless @$ops == 1
                && ($ops.[0][cTYPE] eq 'SEQUENCE' || $ops.[0][cTYPE] eq 'SET');
        $ops = $ops.[0][cCHILD];

        loop (my $idx = 0 ; $idx < @$ops ; ) {
            my $op = $ops.[$idx++];
            if ($op.[cTYPE] eq 'COMPONENTS') {
                splice(@$ops,--$idx,1,expand_ops(%tree, $op.[cCHILD], $seen));
            }
        }

        return @$ops;
    }

    sub compile-loop($op is copy, $tree is copy, $name is copy) {
        say "Compile-loop op => ", $op;
        say "here";

        say $op.perl;
        if $op.isa('Array') {
            say "here I be yo";
        }
        else {
            say "blerg return";
            return;
        }

        say "### START LOOKING HERE ###";
        say |$op;
        say |$op;
        say $op.values;
        say $op.flat;
        say "there";
        say $op;
        say $op;
        say "there there";
        say |$op;
        say "pre-compiled op => ", $op.perl;
        say $op.WHAT;
        say |$op;
        $op = Compiled.new($op.values);
        say "Compiled op => ", $op.perl;
        say "Compiled \$op.isa(Compiled) => ", $op.isa(Compiled);

        for $op.values -> $value {
            if $value.perl eq 'Mu' {
                say "Found Mu";
                exit;
            }
        };

        my $type = $op[cTYPE];
        say "Type => ", $type;


        if ($type && (%base-type{$type}:exists)) {
            $op.[cTYPE] = %base-type{$type}.[1];
            $op.[cTAG] = defined($op.[cTAG])
                ?? asn-encode-tag($op.[cTAG])
                !! %base-type{$type}.[0];

        }

        else {
            unless ($type && ($tree.{$type}:exists)) {
                die "Unknown type { $type || '?' }";
            }

            my $ref = compile-one(
                $tree,
                $tree.{$type},
                defined($op.[cVAR]) ?? $name ~ "." ~ $op.[cVAR] !! $name
                );

            if (defined($op.[cTAG]) && $ref.[0][cTYPE] == opCHOICE) {
                @($op)[cTYPE,cCHILD] = (opSEQUENCE,$ref);
            }

            else {
                @($op)[cTYPE,cCHILD,cLOOP] = @($ref.[0])[cTYPE,cCHILD,cLOOP];
            }

            $op.[cTAG] = defined($op.[cTAG]) ?? asn-encode-tag($op.[cTAG])!! $ref.[0][cTAG];
        }

        $op.[cTAG] +|= pack("C",ASN_CONSTRUCTOR)
            if $op.[cTAG].elems
                && ($op.[cTYPE] == opSET
                || $op.[cTYPE] == opEXPLICIT
                || $op.[cTYPE] == opSEQUENCE);


        if ($op.[cCHILD]) {
            # If we have children we are one of
            #  opSET opSEQUENCE opCHOICE opEXPLICIT

            compile-one(
                $tree,
                $op.[cCHILD],
                defined($op.[cVAR])
                    ?? $name ~ "." ~ $op.[cVAR]
                    !! $name);

            if ( @($op.[cCHILD]) > 1) {
                #if ($op->[cTYPE] != opSEQUENCE) {
                # Here we need to flatten CHOICEs and check that SET and CHOICE
                # do not contain duplicate tags
                #}

                if ($op.[cTYPE] == opSET) {
                    # In case we do CER encoding we order the SET elements by thier tags
                    my @tags = map { 
                        ($_.[cTAG]).elems
                        ?? $_.[cTAG]
                        !! $_.[cTYPE] == opCHOICE
                        ?? (sort map { $_.[cTAG] }, $_.[cCHILD])[0]
                        !! ''
                    }, @($op.[cCHILD]);

                    @($op.[cCHILD]) = @($op.[cCHILD])[sort
                        { @tags[$^a] leg @tags[$^b] },
                        0..@tags.end
                    ];
                }
            }

            else {
                # A SET of one element can be treated the same as a SEQUENCE
                $op.[cTYPE] = opSEQUENCE if $op.[cTYPE] == opSET;
            }
        }
        say "DONE op => ", $op;
        return $op;
    };

    sub compile-one(%tree, @ops, $name) {

        my @zops;
        for (@ops) -> $op is rw {
            say "Op => ", $op;
            my $zop = compile-loop($op, %tree, $name);
            @zops.push($zop);
        }
        dd @zops;

        return @zops;
    }


    sub compile(%tree) is export(:debug) {
        say "Compiling...";

        # The tree should be valid enough to be able to
        #  - resolve references
        #  - encode tags
        #  - verify CHOICEs do not contain duplicate tags

        # once references have been resolved, and also due to
        # flattening of COMPONENTS, it is possible for an op
        # to appear in multiple places. So once an op is
        # compiled we bless it. This ensure we dont try to
        # compile it again.

        for %tree.kv -> $k, @v {
            say "Key => ", $k;
            say "Value => ", @v;
            my @zv = compile-one(%tree, @v, $k);
            dd @zv;
            dd $k;
            say @zv[0];
            %tree{$k} = @zv;

        }

        dd %tree;
        return %tree;
    }

# Convert from a bigint to an octet string

    sub i2osp($num, $biclass) {
        $num = $biclass.new($num);
        my $neg = $num < 0
            and $num = abs($num+1);
        my $base = $biclass.new(256);
        my Buf $result;
        while ($num != 0) {
            my $r = $num % $base;
            $num = ($num-$r) / $base;
            $result ~= pack("C",$r);
        }
        $result +^= pack("C",255) x $result.bytes if $neg;
        return reverse $result;
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


    sub _encode($optn, @ops, %stash, @path = [], $buffer is copy = Buf.new) {
        my $var;

        say "here";
        dd @ops;
        dd %stash;
        for @ops -> $op {
            next if $op.[cTYPE] == opEXTENSIONS;

            if (defined(my $opt = $op.[cOPT])) {
                next unless defined %stash{$opt};
            }

            if (defined($var = $op.[cVAR])) {
                @path.push($var);
                say "stash here";
                dd %stash;
                die @path.join(".")," is undefined" unless defined %stash{$var};
            }

            $buffer ~= $op.[cTAG];

            my @stash_val;

            if (defined($var)) {
                @stash_val = (%stash, %stash{$var});
            }
            else {
                @stash_val = (%stash, Any);
            }

            # $buffer = &{ $encode[ $op->[cTYPE] ] }(
            $buffer = &( @encode[ $op.[cTYPE] ] )(
                $optn,
                $op,
                @stash_val,
                $buffer,
                $op.[cLOOP],
                @path,
            );

            @path.pop if defined $var;
        }

        return $buffer;
    }


    sub _enc_boolean {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        $buf ~= pack("CC",1, $var ?? :16<ff> !! 0);

        return $buf;
    }


    sub _enc_integer {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        if (abs($var) >= 2**31) {
            my $os = i2osp($var);

            my $len = $os.bytes;
            # my $msb = (vec($os, 0, 8) +& :16<80>) ?? 0 !! 255;
            my $msb = 255;

            $len++, $os = pack("C", $msb) ~ $os if $msb xor $var > 0;
            $buf ~= asn-encode-length($len);
            $buf ~= $os;
        }

        else {
            my $val = int($var);
            my $neg = ($val < 0);
            my $len = num-length($neg ?? +^$val !! $val);
            my $msb = $val +& (:16<80> +< (($len - 1) * 8));

            $len++ if $neg ?? ?^$msb !! $msb;

            $buf ~= asn-encode-length($len);
            $buf ~= substr(pack("N",$val), -$len);
        }

        return $buf;
    }


    sub _enc_bitstring {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        # my $vref = ref($var) ?? \($var.[0]) !! \$var;
        my $vref = ($var.isa(Array)) ?? ($var.[0]) !! $var;

    if (1 and Encode::is_utf8($$vref)) {
        utf8::encode(my $tmp = $$vref);
        $vref = $tmp;
    }

    if (($var.isa(Array))) {
        my $less = (8 - ($var.[1] +& 7)) +& 7;
        my $len = ($var.[1] + 7) +> 3;
        $buf ~= asn-encode-length(1+$len);
        $buf ~= pack("C",$less);
        $buf ~= substr($$vref, 0, $len);
        if ($less && $len) {
        substr($buf,-1) +&= pack("C",(:16<ff> +< $less) +& :16<ff>);
        }
    }
    else {
        $buf ~= asn-encode-length(1 + $$vref.elems);
        $buf ~= pack("C",0);
        $buf ~= $$vref;
    }

    return $buf;
    }


    sub _enc_string {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        if (Encode::is_utf8($var)) {
            utf8::encode(my $tmp = $var);
            $buf ~= asn-encode-length($tmp.elems);
            $buf~= $tmp;
        }
        else {
            $buf~= asn-encode-length($var.elems);
            $buf ~= $var;
        }

        return $buf;
    }


    sub _enc_null {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        $buf ~= pack("C",0);

        return $buf;
    }


    sub _enc_object_id {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        my @data = ($var ~~ m:c:P5/(\d+)/);

        if ($op.[cTYPE] == opOBJID) {
            if (@data < 2) {
            @data = (0);
            }
            else {
            my $first = @data[1] + (@data[0] * 40);
            splice(@data,0,2,$first);
            }
        }

        my $l = $buf.bytes;
        $buf ~= pack("cw*", 0, @data);
        substr($buf,$l,1) = asn-encode-length(($buf.bytes) - $l - 1);

        return $buf;
    }


    sub _enc_real {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;
        # 0      1    2       3     4     5      6
        # $optn, $op, $stash, $var, $buf, $loop, $path

        # Zero
        unless ($var) {
            $buf ~= pack("C",0);
            return $buf;
        }


        # +oo (well we use HUGE_VAL as Infinity is not avaliable to perl)
        if ($var >= POSIX::HUGE_VAL()) {
            $buf ~= pack("C*",:16<01>,:16<40>);
            return $buf;
        }

        # -oo (well we use HUGE_VAL as Infinity is not avaliable to perl)
        if ($var <= - POSIX::HUGE_VAL()) {
            $buf ~= pack("C*",:16<01>,:16<41>);
            return $buf;
        }

        # We have a real number.
        my $first = :16<80>;
        my ($mantissa, $exponent) = POSIX::frexp(@_[3]);

        if ($mantissa < 0.0) {
            $mantissa = -$mantissa;
            $first +|= :16<40>;
        }
        my ($eMant,$eExp);

        while ($mantissa > 0.0) {
            ($mantissa, my $int) = POSIX::modf($mantissa * (1+<8));
            $eMant ~= pack("C",$int);
        }
        $exponent -= 8 * $eMant.bytes;

        $eExp = _enc_integer(Any, Any, Any, $exponent, $eExp);

        # $eExp will br prefixed by a length byte
        if (5 > $eExp.bytes) {
            $eExp ~~ s:s:P5/\A.//;
            $first +|= ($eExp.bytes) - 1;
        }
        else {
            $first +|= :16<3>;
        }

        $buf ~= asn-encode-length(1 + ($eMant.bytes) + ($eExp.bytes));
        $buf ~= pack("C",$first);
        $buf ~= $eExp;
        $buf ~= $eMant;

        return $buf;
    }


    sub _enc_sequence(
        $optn,
        $op,
        $stash,
        $var,
        $buf,
        $loop,
        $path is rw,
    ) {
        if (my @ops = $op.[cCHILD]) {
            my $l = $buf.bytes;
            $buf ~= "\0\0"; # guess
            if (defined $loop) {
                my $op   = @ops[0]; # there should only be one
                my $enc  = @encode[$op.[cTYPE]];
                my $tag  = $op.[cTAG];
                my $loop = $op.[cLOOP];

                # Horseshit 6 == $path
                push @($path), -1;

                for @($var) -> $i_var {
                    $path.[*-1]++;
                    $buf ~= $tag;

                    # added the buf, maybe not
                    $buf = &($enc)(
                        $optn,
                        $op,
                        $stash,
                        $i_var,
                        $buf,
                        $loop,
                        $path,
                    );
                }

                pop @($path);
            }

            else {
                $buf = _encode(
                    $optn,
                    $op.[cCHILD],
                    defined($var)
                        ?? $var
                        !! $stash,
                    $path,
                    $buf,
                );
            }

            substr($buf,$l,2) = asn-encode-length(($buf.bytes) - $l - 2);
        }

        else {
            $buf ~= asn-encode-length($var.bytes);
            $buf ~= $var;
        }

        return $buf;
    }


    my %_enc_time_opt = ( utctime => 1, withzone => 0, raw => 2);

    sub _enc_time {
        die "Not implemented";
    }


    sub _enc_utf8 {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        my $tmp = $var;
        utf8::upgrade($tmp) unless Encode::is_utf8($tmp);
        utf8::encode($tmp);
        $buf ~= asn-encode-length($tmp.chars);
        $buf ~= $tmp;

        return $buf;
    }


    sub _enc_any {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        my $handler;
        if ($op.[cDEFINE] && $stash.{'$op'.[cDEFINE]}) {
            $handler = $optn.{'oidtable'}{ '$stash'.{ '$op'.[cDEFINE] } };

            $handler = $optn.{'handlers'}{ '$op'.[cVAR] }{ '$stash'.{ '$op'.[cDEFINE] } }
                unless $handler;
        }

        if ($handler) {
            $buf ~= $handler.encode($var);
        }
        else {
            $buf ~= $var;
        }

        return $buf;
    }


    sub _enc_choice {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

        $stash = defined($var) ?? $var !! $stash;

        for (@( $op.[cCHILD] )) -> $op {
            next if $op.[cTYPE] == opEXTENSIONS;
            my $var = defined $op.[cVAR] ?? $op.[cVAR] !! $op.[cCHILD].[0].[cVAR];

            if ($stash.{$var}:exists) {
            # Horse shit path
            push @(@_[6]), $var;
            # Horse shit path
            $buf = _encode($optn, [$op], $stash, @_[6], $buf);
            # Horse shit path
            pop @(@_[6]);
            return $buf;
            }
        }
        die "No value found for CHOICE " ~ join(".", @(@_[6]));
    }


    sub _enc_bcd {
        my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

    my $str = ($var ~~ m:P5/^(\d+)/) ?? $0 !! "";

    $str ~= "F" if ($str.chars) +& 1;
    $buf ~= asn-encode-length(($str.chars) / 2);
    $buf ~= pack("H*", $str);

    return $buf;
    }

# 
#     my @_dec_real_base = (2, 8, 16);
# 
#     my @decode = (
#     sub { die "internal error\n" },
#     \&_dec_boolean,
#     \&_dec_integer,
#     \&_dec_bitstring,
#     \&_dec_string,
#     \&_dec_null,
#     \&_dec_object_id,
#     \&_dec_real,
#     \&_dec_sequence,
#     \&_dec_explicit,
#     \&_dec_set,
#     \&_dec_time,
#     \&_dec_time,
#     \&_dec_utf8,
#     Any, # ANY
#     Any, # CHOICE
#     \&_dec_object_id,
#     \&_dec_bcd,
#     );
# 
#     my @ctr;
#     @ctr[opBITSTR, opSTRING, opUTF8] = (\&_ctr_bitstring,\&_ctr_string,\&_ctr_string);
# 
#     sub decode {
#         my $self  = shift;
#         my $pdu = shift;
# 
#         my %stash;
#         my $result;
#         my $script = $self.{'script'};
#         my $stash = \$result;
# 
#         # while ($script) {
#         my $while_decode;
# 
#         $while_decode = sub {
#             my $script = shift;
#             my $child = $script.[0] or return;
# 
#             if (@$script > 1 or defined $child.[cVAR]) {
#                 $result = $stash = \%stash;
#                 say "result =\>";
#                 dd $result;
# 
#                 return;
#                 # last;
#             }
# 
#             return if $child.[cTYPE] == opCHOICE or $child.[cLOOP];
#             $script = $child.[cCHILD];
# 
#             return &$while_decode($script);
#         };
# 
#         &$while_decode($script);
# 
#         say 'HERE IT BE GUY !';
#         dd $stash;
#         _decode(
#             $self.{'options'},
#             $self.{'script'},
#             $stash,
#             0,
#             length $pdu,
#             Any,
#             {},
#             $pdu,
#         );
# 
#         say "final result";
#         dd $result;
#         say "final stash";
#         dd $stash;
# 
#         return $result
#     }
# 
#     sub _decode {
#         my ($optn, $ops, $stash, $pos, $end, $seqof, $larr) = @_;
#         my $idx = 0;
# 
#         # we try not to copy the input buffer at any time
#         for (@_[*-1]) -> $buf {
#             OP:
#             foreach my $op (@($ops)) {
#             my $var = $op.[cVAR];
# 
#             if (length $op.[cTAG]) {
# 
#             TAGLOOP: {
#             my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
#                 or do {
#                 next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
#                 die "decode error";
#                 };
# 
#             if ($tag eq $op.[cTAG]) {
# 
#                 my ($int_flag, $x_result) = &(@decode[$op.[cTYPE]])(
#                 $optn,
#                 $op,
#                 $stash,
#                 # We send 1 if there is not var as if there is the decode
#                 # should be getting undef. So if it does not get undef
#                 # it knows it has no variable
#                 ($seqof ?? $seqof.[$idx++] !! defined($var) ?? $stash.{'$var'} !! ref($stash) eq 'SCALAR' ?? $$stash !! 1),
#                 $buf,$npos,$len, $larr
#                 );
# 
#                 if ($int_flag && $int_flag eq 'int') {
#                     $seqof ?? $seqof.[$idx - 1] !! defined($var) ?? $stash.{'$var'} !! ref($stash) eq 'SCALAR' ?? $$stash !! Any = $x_result;
#                 }
# 
#                 $pos = $npos+$len+$indef;
# 
#                 redo TAGLOOP if $seqof && $pos < $end;
#                 next OP;
#             }
# 
#             if ($tag eq ($op.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
#                 and my $ctr = @ctr[$op.[cTYPE]]) 
#             {
#                 _decode(
#                 $optn,
#                 [$op],
#                 Any,
#                 $npos,
#                 $npos+$len,
#                 (\my @ctrlist),
#                 $larr,
#                 $buf,
#                 );
# 
#                 ($seqof ?? $seqof.[$idx++] !! defined($var) ?? $stash.{'$var'} !! ref($stash) eq 'SCALAR' ?? $$stash !! Any)
#                 = &($ctr)(@ctrlist);
#                 $pos = $npos+$len+$indef;
# 
#                 redo TAGLOOP if $seqof && $pos < $end;
#                 next OP;
# 
#             }
# 
#             if ($seqof || defined $op.[cEXT]) {
#                 next OP;
#             }
# 
#             die "decode error " ~ unpack("H*",$tag) ~"\<=\>" ~ unpack("H*",$op.[cTAG]), " ",$pos," ",$op.[cTYPE]," ",$op.[cVAR]||'';
#                 }
#             }
#             else { # opTag length is zero, so it must be an ANY, CHOICE or EXTENSIONS
#             
#             if ($op.[cTYPE] == opANY) {
# 
#             ANYLOOP: {
# 
#                 my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
#                 or do {
#                 next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
#                 die "decode error";
#                 };
# 
#                 $len += $npos - $pos + $indef;
# 
#                     my $handler;
#                     if ($op.[cDEFINE]) {
#                     $handler = $optn.{'oidtable'} && $optn.{'oidtable'}{'$stash'.{'$op'.[cDEFINE]}};
#                     $handler ||= $optn.{'handlers'}{'$op'.[cVAR]}{'$stash'.{'$op'.[cDEFINE]}};
#                     }
# 
#                 ($seqof ?? $seqof.[$idx++] !! ref($stash) eq 'SCALAR' ?? $$stash !! $stash.{'$var'})
#                 = $handler ?? $handler.decode(substr($buf,$pos,$len)) !! substr($buf,$pos,$len);
# 
#                 $pos += $len;
# 
#                 redo ANYLOOP if $seqof && $pos < $end;
#             }
#             }
#             elsif ($op.[cTYPE] == opCHOICE) {
# 
#             CHOICELOOP: {
#                 my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
#                 or do {
#                 next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
#                 die "decode error";
#                 };
#                 my $extensions;
#                 for (@($op.[cCHILD])) -> $cop {
# 
#                 if ($tag eq $cop.[cTAG]) {
# 
#                 my $nstash = $seqof
#                     ?? ($seqof.[$idx++]={})
#                     !! defined($var)
#                         ?? ($stash.{'$var'}={})
#                         !! ref($stash) eq 'SCALAR'
#                             ?? ($$stash={}) !! $stash;
# 
#                 my ($int_flag, $x_result) = &(@decode[$cop.[cTYPE]])(
#                 $optn,
#                 $cop,
#                 $nstash,
#                 ($cop.[cVAR] ?? $nstash.{'$cop'.[cVAR]} !! Any),
#                 $buf,$npos,$len,$larr,
#                 );
#                 if ($int_flag && $int_flag eq 'int') {
#                     ($cop.[cVAR] ?? $nstash.{'$cop'.[cVAR]} !! Any) = $x_result;
# 
#                 }
# 
#                 $pos = $npos+$len+$indef;
# 
#                 redo CHOICELOOP if $seqof && $pos < $end;
#                 next OP;
#                 }
# 
#                 if ($cop.[cTYPE] == opEXTENSIONS) {
#                 $extensions = 1;
#                 next;
#                 }
# 
#                 unless (length $cop.[cTAG]) {
#                 _decode(
#                     $optn,
#                     [$cop],
#                     (\my %tmp_stash),
#                     $pos,
#                     $npos+$len+$indef,
#                     Any,
#                     $larr,
#                     $buf,
#                 );
# 
#                 my $nstash = $seqof
#                     ?? ($seqof.[$idx++]={})
#                     !! defined($var)
#                         ?? ($stash.{'$var'}={})
#                         !! ref($stash) eq 'SCALAR'
#                             ?? ($$stash={}) !! $stash;
# 
#                 @($nstash){keys %tmp_stash} = values %tmp_stash;
# 
#                 $pos = $npos+$len+$indef;
# 
#                 redo CHOICELOOP if $seqof && $pos < $end;
#                 next OP;
#                 }
# 
#                 if ($tag eq ($cop.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
#                 and my $ctr = @ctr[$cop.[cTYPE]]) 
#                 {
#                 my $nstash = $seqof
#                     ?? ($seqof.[$idx++]={})
#                     !! defined($var)
#                         ?? ($stash.{'$var'}={})
#                         !! ref($stash) eq 'SCALAR'
#                             ?? ($$stash={}) !! $stash;
# 
#                 _decode(
#                 $optn,
#                 [$cop],
#                 Any,
#                 $npos,
#                 $npos+$len,
#                 (\my @ctrlist),
#                 $larr,
#                 $buf,
#                 );
# 
#                 $nstash.{'$cop'.[cVAR]} = &($ctr)(@ctrlist);
#                 $pos = $npos+$len+$indef;
# 
#                 redo CHOICELOOP if $seqof && $pos < $end;
#                 next OP;
#                 }
#                 }
# 
#                 if ($pos < $end && $extensions) {
#                 $pos = $npos+$len+$indef;
# 
#                 redo CHOICELOOP if $seqof && $pos < $end;
#                 next OP;
#                 }
#             }
#             die "decode error" unless $op.[cEXT];
#             }
#             elsif ($op.[cTYPE] == opEXTENSIONS) {
#                 $pos = $end; # Skip over the rest
#                 }
#             else {
#             die "this point should never be reached";
#             }
#             }
#             }
#         }
#         die "decode error $pos $end" unless $pos == $end;
#     }
# 
#     sub _dec_boolean {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     @_[3] = unpack("C",substr(@_[4],@_[5],1)) ?? 1 !! 0;
#     1;
#     }
# 
# 
#     sub _dec_integer {
#         my ($optn, $op, $stash, $var, $buf, $pos, $len) = @_;
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     $buf = substr(@_[4],@_[5],@_[6]);
#     my $tmp = unpack("C",$buf) +& :16<80> ?? pack("C",255) !! pack("C",0);
#     if ($len > 4) {
#         $var = os2ip($buf, $optn.{'decode_bigint'} || 'Math::BigInt');
#     } else {
#         # N unpacks an unsigned value
#         $var = unpack("l",pack("l",unpack("N", $tmp x (4 - $len) ~ $buf)));
#     }
# 
#     return ('int', $var);
#     # 1;
#     }
# 
# 
#     sub _dec_bitstring {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     @_[3] = [ substr(@_[4],@_[5]+1,@_[6]-1), (@_[6]-1)*8-unpack("C",substr(@_[4],@_[5],1)) ];
#     1;
#     }
# 
# 
#     sub _dec_string {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     @_[3] = substr(@_[4],@_[5],@_[6]);
#     1;
#     }
# 
# 
#     sub _dec_null {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     @_[3] = exists(@_[0].{'decode_null'}) ?? @_[0].{'decode_null'} !! 1;
#     1;
#     }
# 
# 
#     sub _dec_object_id {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     my @data = unpack("w*",substr(@_[4],@_[5],@_[6]));
#     if (@_[1].[cTYPE] == opOBJID and @data > 1) {
#         if (@data[0] < 40) {
#         splice(@data, 0, 1, 0, @data[0]);
#         }
#         elsif (@data[0] < 80) {
#         splice(@data, 0, 1, 1, @data[0] - 40);
#         }
#         else {
#         splice(@data, 0, 1, 2, @data[0] - 80);
#         }
#     }
#     @_[3] = join(".", @data);
#     1;
#     }
# 
# 
# 
#     sub _dec_real {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     @_[3] = 0.0, return unless @_[6];
# 
#     my $first = unpack("C",substr(@_[4],@_[5],1));
#     if ($first +& :16<80>) {
#         # A real number
# 
#         my $exp;
#         my $expLen = $first +& :16<3>;
#         my $estart = @_[5]+1;
# 
#         if ($expLen == 3) {
#         $estart++;
#         $expLen = unpack("C",substr(@_[4],@_[5]+1,1));
#         }
#         else {
#         $expLen++;
#         }
#         (Any, $exp) = _dec_integer(Any, Any, Any, $exp, @_[4],$estart,$expLen);
# 
#         my $mant = 0.0;
#         for (reverse unpack("C*",substr(@_[4],$estart+$expLen,@_[6]-1-$expLen))) {
#         $exp +=8, $mant = (($mant+$_) / 256) ;
#         }
# 
#         $mant *= 1 +< (($first +> 2) +& :16<3>);
#         $mant = - $mant if $first +& :16<40>;
# 
#         @_[3] = $mant * POSIX::pow(@_dec_real_base[($first +> 4) +& :16<3>], $exp);
#         return;
#     }
#     elsif ($first +& :16<40>) {
#         @_[3] =   POSIX::HUGE_VAL(),return if $first == :16<40>;
#         @_[3] = - POSIX::HUGE_VAL(),return if $first == :16<41>;
#     }
# 
#     die "REAL decode error\n";
#     }
# 
# 
#     sub _dec_explicit {
# # 0      1    2       3     4     5     6     7
# # $optn, $op, $stash, $var, $buf, $pos, $len, $larr
# 
#     local @_[1][cCHILD][0][cVAR] = @_[1][cVAR] unless @_[1][cCHILD][0][cVAR];
# 
#     _decode(
#         @_[0], #optn
#         @_[1].[cCHILD],   #ops
#         @_[2], #stash
#         @_[5], #pos
#         @_[5]+@_[6], #end
#         Any, #loop
#         @_[7],
#         @_[4], #buf
#     );
#     1;
#     }
#     sub _dec_sequence {
# # 0      1    2       3     4     5     6     7
# # $optn, $op, $stash, $var, $buf, $pos, $len, $larr
# 
#     if (defined( my $ch = @_[1].[cCHILD])) {
#         _decode(
#         @_[0], #optn
#         $ch,   #ops
#         (defined(@_[3]) || @_[1].[cLOOP]) ?? @_[2] !! (@_[3]= {}), #stash
#         @_[5], #pos
#         @_[5]+@_[6], #end
#         @_[1].[cLOOP] && (@_[3]=[]), #loop
#         @_[7],
#         @_[4], #buf
#         );
#     }
#     else {
#         @_[3] = substr(@_[4],@_[5],@_[6]);
#     }
#     1;
#     }
# 
# 
#     sub _dec_set {
# # 0      1    2       3     4     5     6     7
# # $optn, $op, $stash, $var, $buf, $pos, $len, $larr
# 
#     # decode SET OF the same as SEQUENCE OF
#     my $ch = @_[1].[cCHILD];
#     goto &_dec_sequence if @_[1].[cLOOP] or ?^defined($ch);
# 
#     my ($optn, $pos, $larr) = @_[0,5,7];
#     my $stash = defined(@_[3]) ?? @_[2] !! (@_[3]={});
#     my $end = $pos + @_[6];
#     my @done;
#     my $extensions;
# 
#     while ($pos < $end) {
#         my ($tag,$len,$npos,$indef) = _decode_tl(@_[4],$pos,$end,$larr)
#         or die "decode error";
# 
#         my ($idx, $any, $done) = (-1);
# 
#     SET_OP:
#         foreach my $op (@$ch) {
#         $idx++;
#         if (length($op.[cTAG])) {
#         if ($tag eq $op.[cTAG]) {
#         my $var = $op.[cVAR];
#         my ($int_flag, $x_result) = &(@decode[$op.[cTYPE]])(
#             $optn,
#             $op,
#             $stash,
#             # We send 1 if there is not var as if there is the decode
#             # should be getting undef. So if it does not get undef
#             # it knows it has no variable
#             (defined($var) ?? $stash.{'$var'} !! 1),
#             @_[4],$npos,$len,$larr,
#         );
# 
#             if ($int_flag && $int_flag eq 'int') {
#                 defined($var) ?? $stash.{'$var'} !! Any = $x_result;
#             }
# 
#         $done = $idx;
#         last SET_OP;
#         }
#         if ($tag eq ($op.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
#             and my $ctr = @ctr[$op.[cTYPE]]) 
#         {
#         _decode(
#             $optn,
#             [$op],
#             Any,
#             $npos,
#             $npos+$len,
#             (\my @ctrlist),
#             $larr,
#             @_[4],
#         );
# 
#         $stash.{'$op'.[cVAR]} = &($ctr)(@ctrlist)
#             if defined $op.[cVAR];
#         $done = $idx;
#         last SET_OP;
#         }
#         next SET_OP;
#         }
#         elsif ($op.[cTYPE] == opANY) {
#         $any = $idx;
#         }
#         elsif ($op.[cTYPE] == opCHOICE) {
#         my $var = $op.[cVAR];
#         for (@($op.[cCHILD])) -> $cop {
#         if ($tag eq $cop.[cTAG]) {
#             my $nstash = defined($var) ?? ($stash.{'$var'}={}) !! $stash;
# 
#             my ($int_flag, $x_result) = &(@decode[$cop.[cTYPE]])(
#             $optn,
#             $cop,
#             $nstash,
#             $nstash.{'$cop'.[cVAR]},
#             @_[4],$npos,$len,$larr,
#             );
#             if ($int_flag && $int_flag eq 'int') {
#             $nstash.{'$cop'.[cVAR]} = $x_result;
# 
#             }
#             $done = $idx;
#             last SET_OP;
#         }
#         if ($tag eq ($cop.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
#             and my $ctr = @ctr[$cop.[cTYPE]]) 
#         {
#             my $nstash = defined($var) ?? ($stash.{'$var'}={}) !! $stash;
# 
#             _decode(
#             $optn,
#             [$cop],
#             Any,
#             $npos,
#             $npos+$len,
#             (\my @ctrlist),
#             $larr,
#             @_[4],
#             );
# 
#             $nstash.{'$cop'.[cVAR]} = &($ctr)(@ctrlist);
#             $done = $idx;
#             last SET_OP;
#         }
#         }
#         }
#         elsif ($op.[cTYPE] == opEXTENSIONS) {
#         $extensions = $idx;
#         }
#         else {
#         die "internal error";
#         }
#         }
# 
#         if (?^defined($done) and defined($any)) {
#         my $var = $ch.[$any][cVAR];
#         $stash.{'$var'} = substr(@_[4],$pos,$len+$npos-$pos) if defined $var;
#         $done = $any;
#         }
# 
#         if ( ?^defined($done) && defined($extensions) ) {
#         $done = $extensions;
#         }
# 
#         die "decode error" if ?^defined($done) or @done[$done]++;
# 
#         $pos = $npos + $len + $indef;
#     }
# 
#     die "decode error" unless $end == $pos;
# 
#     for (0..@($ch).end) -> $idx {
#         die "decode error" unless @done[$idx] or $ch.[$idx][cEXT] or $ch.[$idx][cTYPE] == opEXTENSIONS;
#     }
# 
#     1;
#     }
# 
# 
#     my %_dec_time_opt = ( unixtime => 0, withzone => 1, raw => 2);
# 
#     sub _dec_time {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     my $mode = %_dec_time_opt{'$_'[0].{'decode_time'} || ''} || 0;
# 
#     if ($mode == 2 or @_[6] == 0) {
#         @_[3] = substr(@_[4],@_[5],@_[6]);
#         return;
#     }
# 
#     my @bits = (substr(@_[4],@_[5],@_[6])
#         ~~ m:P5/^((?:\d\d)?\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)((?:\.\d{1,3})?)(([-+])(\d\d)(\d\d)|Z)/)
#         or die "bad time format";
# 
#     if (@bits[0] < 100) {
#         @bits[0] += 100 if @bits[0] < 50;
#     }
#     else {
#         @bits[0] -= 1900;
#     }
#     @bits[1] -= 1;
#     require Time::Local:from<Perl5>;
#     my $time = Time::Local::timegm(@bits[5,4,3,2,1,0]);
#     $time += @bits[6] if length @bits[6];
#     my $offset = 0;
#     if (@bits[7] ne 'Z') {
#         $offset = @bits[9] * 3600 + @bits[10] * 60;
#         $offset = -$offset if @bits[8] eq '-';
#         $time -= $offset;
#     }
#     @_[3] = $mode ?? [$time,$offset] !! $time;
#     }
# 
# 
#     sub _dec_utf8 {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
#     @_[3] = Encode::decode('utf8', substr(@_[4],@_[5],@_[6]));
#     }
# 
# 
#     sub _decode_tl {
#     my ($pos,$end,$larr) = @_[1,2,3];
# 
#     return if $pos >= $end;
# 
#     my $indef = 0;
# 
#     my $tag = substr(@_[0], $pos++, 1);
# 
#     if ((unpack("C",$tag) +& :16<1f>) == :16<1f>) {
#         my $b;
#         my $n=1;
#         do {
#         return if $pos >= $end;
#         $tag ~= substr(@_[0],$pos++,1);
#         $b = ord substr($tag,-1);
#         } while ($b +& :16<80>);
#     }
#     return if $pos >= $end;
# 
#     my $len = ord substr(@_[0],$pos++,1);
# 
#     if ($len +& :16<80>) {
#         $len +&= :16<7f>;
# 
#         if ($len) {
#         return if $pos+$len > $end ;
# 
#         my $padding = $len < 4 ?? "\0" x (4 - $len) !! "";
#         ($len,$pos) = (unpack("N", $padding ~ substr(@_[0],$pos,$len)), $pos+$len);
#         }
#         else {
#         unless (exists $larr.{'$pos'}) {
#             _scan_indef(@_[0],$pos,$end,$larr) or return;
#         }
#         $indef = 2;
#         $len = $larr.{'$pos'};
#         }
#     }
# 
#     return if $pos+$len+$indef > $end;
# 
#     # return the tag, the length of the data, the position of the data
#     # and the number of extra bytes for indefinate encoding
# 
#     ($tag, $len, $pos, $indef);
#     }
# 
#     sub _dec_bcd {
# # 0      1    2       3     4     5     6
# # $optn, $op, $stash, $var, $buf, $pos, $len
# 
#     (@_[3] = unpack("H*", substr(@_[4],@_[5],@_[6]))) ~~ s:P5/[fF]$//;
#     1;
#     }
# 
#     sub os2ip {
#         my ($os, $biclass) = @_;
#         my $base = $biclass.new(256);
#         my $result = $biclass.new(0);
#         my $neg = unpack("C",$os) >= :16<80>
#         and $os +^= pack("C",255) x length($os);
#         for (unpack("C*",$os)) {
#         $result = ($result * $base) + $_;
#         }
#         return $neg ?? ($result + 1) * -1 !! $result;
#     }
# 
#     sub _scan_indef {
#     my ($pos,$end,$larr) = @_[1,2,3];
#     my @depth = ( $pos );
# 
#     while (@depth) {
#         return if $pos+2 > $end;
# 
#         if (substr(@_[0],$pos,2) eq "\0\0") {
#         my $end = $pos;
#         my $stref = shift @depth;
#         # replace pos with length = end - pos
#         $larr.{'$stref'} = $end - $stref;
#         $pos += 2;
#         next;
#         }
# 
#         my $tag = substr(@_[0], $pos++, 1);
# 
#         if ((unpack("C",$tag) +& :16<1f>) == :16<1f>) {
#         my $b;
#         do {
#         $tag ~= substr(@_[0],$pos++,1);
#         $b = ord substr($tag,-1);
#         } while ($b +& :16<80>);
#         }
#         return if $pos >= $end;
# 
#         my $len = ord substr(@_[0],$pos++,1);
# 
#         if ($len +& :16<80>) {
#         if ($len +&= :16<7f>) {
#         return if $pos+$len > $end ;
# 
#         my $padding = $len < 4 ?? "\0" x (4 - $len) !! "";
#         $pos += $len + unpack("N", $padding ~ substr(@_[0],$pos,$len));
#         }
#         else {
#             # reserve another list element
#             unshift @depth, $pos;
#         }
#         }
#         else {
#         $pos += $len;
#         }
#     }
# 
#     }
# 
#     sub _ctr_string { join '', @_ }

}
