package Convert::ASN1::Parser;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Data::Dump;

use constant {
    constYYFINAL => 5,
};

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

my $tagdefault = 1; # 0:IMPLICIT , 1:EXPLICIT default

sub need_explicit {
    ( defined($_[0]) && (defined($_[1]) ? $_[1] : $tagdefault ));
}

sub explicit {
  my $op = shift;
  my @seq = @$op;

  @seq[cTYPE,cCHILD,cVAR,cLOOP] = ('EXPLICIT',[$op],undef,undef);
  @{$op}[cTAG,cOPT] = ();

  \@seq;
}

my @left_hand_side = (                                               -1,
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

# Standard export stuff
sub parse {
    my $lex = shift;
    my $my_tagdefault = shift;

    if (defined $my_tagdefault) {
        $tagdefault = $my_tagdefault;
    }

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

    $ss->[$ssp] = $state;

    my ($tree) = parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);

    return $tree;
}

sub unless_loop {

    my $char = shift;
    my $lex = shift;
    my $state = shift;
    my $index = shift;
    my $lval = shift;
    my $ssp = shift;
    my $vsp = shift;
    my $ss = shift;
    my $vs = shift;

    my $parsed;

    # say "Char => $char";
    if ($char < 0) {
        my $item = shift @{$lex};
        $char = $item->{type};
        $lval = $item->{lval};

        if ($char < 0) {
            $char = 0;
        }
    }

    if (($index = $s_index[$state])
        && ($index += $char) >= 0
        && $check[$index] == $char) {

        $ss->[++$ssp] = $state = $table[$index];
        $vs->[++$vsp] = $lval;
        $char = (-1);

        ($parsed, $char, $state, $index, $lval, $ssp, $vsp)
            = parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs);

        return ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs)
    }

    elsif (($index = $r_index[$state])
        && ($index += $char) >= 0
        && $check[$index] == $char) {

        $index = $table[$index];
    }

    else {
        die 'unknown error';
    }

    return ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs);

}

sub parse_loop {

    my $char = shift;
    my $lex = shift;
    my $state = shift;
    my $index = shift;
    my $lval = shift;
    my $ssp = shift;
    my $vsp = shift;
    my $ss = shift;
    my $vs = shift;

    my $yym = shift;
    my $val = shift;;

    # $index_stats{$index}++;


    unless ($index = $defred[$state]) {
        my $parsed;
        ($parsed, $char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs)
            = unless_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs);

            # @lex = @$lex;
        return ($parsed) if $parsed;
    }

    $yym = $length[$index];
    $val = $vs->[$vsp + 1 - $yym];

    if ($index == 1) {
        $val = { '' => $vs->[ $vsp ] };
    }

    elsif ($index == 3) {
        $val = { $vs->[ $vsp - 2 ], [ $vs->[ $vsp ] ] };
    }

    elsif ($index == 4) {
        $val = $vs->[ $vsp - 3 ];
        $val->{ $vs->[ $vsp - 2 ] } = [ $vs->[ $vsp ] ];
    }

    elsif ($index == 5) {
        $vs->[ $vsp - 1 ]->[cTAG] = $vs->[ $vsp - 3 ];
        $val = need_explicit($vs->[ $vsp - 3 ], $vs->[ $vsp - 2 ])
            ? explicit($vs->[ $vsp - 1 ])
            : $vs->[ $vsp - 1 ];
    }

    elsif ($index == 11) {
        @{$val = []}[ cTYPE, cCHILD ] = ('COMPONENTS', $vs->[ $vsp ]);
    }

    elsif ($index == 14) {
        $vs->[ $vsp - 1 ]->[cTAG] = $vs->[ $vsp - 3 ];
        @{$val = []}[ cTYPE, cCHILD, cLOOP, cOPT ]
            = ($vs->[ $vsp - 5 ], [$vs->[ $vsp - 1 ]], 1, $vs->[ $vsp - 0 ]);

        $val = explicit($val) if need_explicit($vs->[ $vsp - 3], $vs->[ $vsp - 2 ]);
    }

    elsif ($index == 18) {
        @{$val = []}[cTYPE,cCHILD] = ('SEQUENCE', $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 19) {
        @{$val = []}[cTYPE,cCHILD] = ('SET', $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 20) {
        @{$val = []}[cTYPE,cCHILD] = ('CHOICE', $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 21) {
        @{$val = []}[cTYPE] = ('ENUM');
    }

    elsif ($index == 22 || $index == 23 || $index == 24 || $index == 26)  {
        @{$val = []}[cTYPE] = $vs->[ $vsp ];
    }

    elsif ($index == 25) {
        @{$val = []}[cTYPE,cCHILD,cDEFINE] = ('ANY', undef, $vs->[ $vsp ]);
    }

    elsif ($index == 27) { $val = undef; }

    elsif ($index == 28 || $index == 30) {
        $val = $vs->[ $vsp ];
    }

    elsif ($index == 31) {
        $val = $vs->[ $vsp - 1 ];
    }

    elsif ($index == 32) {
        $val = [ $vs->[ $vsp ] ];
    }

    elsif ($index == 33) {
        push @{$val=$vs->[ $vsp - 2 ]}, $vs->[ $vsp ];
    }

    elsif ($index == 34) {
        push @{$val=$vs->[$vsp - 2 ]}, $vs->[ $vsp ];
    }

    elsif ($index == 35) {
        @{$val=$vs->[ $vsp ]}[ cVAR, cTAG ] = ($vs->[ $vsp - 3 ], $vs->[ $vsp - 2 ]);
        $val = explicit($val) if need_explicit($vs->[ $vsp - 2], $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 36) { @{$val=[]}[cTYPE] = 'EXTENSION_MARKER'; }

    elsif ($index == 37) { $val = []; }

    elsif ($index == 38) {
        my $extension = 0;
        $val = [];
        for my $i (@{$vs->[$vsp-0]}) {
            $extension = 1 if $i->[cTYPE] eq 'EXTENSION_MARKER';
            $i->[cEXT] = $i->[cOPT];
            $i->[cEXT] = 1 if $extension;
            push @{$val}, $i unless $i->[cTYPE] eq 'EXTENSION_MARKER';
        }
        my $e = []; $e->[cTYPE] = 'EXTENSION_MARKER';
        push @{$val}, $e if $extension;
    }

    elsif ($index == 39) {
        my $extension = 0;
        $val = [];
        for my $i (@{$vs->[$vsp-1]}) {
            $extension = 1 if $i->[cTYPE] eq 'EXTENSION_MARKER';
            $i->[cEXT] = $i->[cOPT];
            $i->[cEXT] = 1 if $extension;
            push @{$val}, $i unless $i->[cTYPE] eq 'EXTENSION_MARKER';
        }
        my $e = []; $e->[cTYPE] = 'EXTENSION_MARKER';
        push @{$val}, $e if $extension;
    }

    elsif ($index == 40) {
        $val = [ $vs->[ $vsp ] ];
    }

    elsif ($index == 41) {
        push @{ $val = $vs->[ $vsp - 2 ]}, $vs->[ $vsp ];
    }

    elsif ($index == 42) {
        push @{ $val = $vs->[ $vsp - 2 ]}, $vs->[ $vsp ];
    }

    elsif ($index == 43) {
        @{ $val = $vs->[ $vsp -1 ]}[cOPT] = ($vs->[ $vsp ]);
    }

    elsif ($index == 47) {
        @{$val=$vs->[ $vsp ]}[cVAR,cTAG] = ($vs->[ $vsp - 3 ],$vs->[ $vsp - 2 ]);
        $val->[cOPT] = $vs->[ $vsp - 3] if $val->[cOPT];
        $val = explicit($val) if need_explicit($vs->[ $vsp - 2], $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 49) {
        @{$val=$vs->[ $vsp ]}[cTAG] = ($vs->[ $vsp - 2 ]);
        $val = explicit($val) if need_explicit($vs->[ $vsp - 2 ], $vs->[ $vsp - 1 ]);
    }

    elsif ($index == 50) { @{$val=[]}[cTYPE] = 'EXTENSION_MARKER'; }

    elsif ($index == 51 || $index == 53 || $index == 55) { $val = undef; }

    elsif ($index == 52 || $index == 56 ) { $val = 1; }

    elsif ($index == 57) { $val = 0; }

    $ssp -= $yym;
    $state = $ss->[$ssp];
    $vsp -= $yym;
    $yym = $left_hand_side[$index];

    if ($state == 0 && $yym == 0) {
        $state = constYYFINAL();
        $ss->[++$ssp] = constYYFINAL();
        $vs->[++$vsp] = $val;

        if ($char < 0) {
            my $item = shift @$lex;
            $char = $item->{type};
            $lval = $item->{lval};

            if ($char < 0) { $char = 0; }
        }

        return $vs->[$vsp] if $char == 0;

        return parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);

    }

    if (($index = $g_index[$yym])
        && ($index += $state) >= 0
        && $index <= $#check
        && $check[$index] == $state) {

        $state = $table[$index];
    }
    else {
        $state = $dgoto[$yym];
    }

    $ss->[++$ssp] = $state;
    $vs->[++$vsp] = $val;

    parse_loop($char, $lex, $state, $index, $lval, $ssp, $vsp, $ss, $vs, $yym, $val);
}

1;
