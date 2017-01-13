# Copyright (c) 2000-2002 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

unit class Convert::ASN1;

use Carp:from<Perl5>;
use Exporter:from<Perl5>;
use Socket:from<Perl5>;
use bytes:from<Perl5>;
use Math::BigInt:from<Perl5>;

require Encode:from<Perl5>;

our ($VERSION, @ISA, @EXPORT_OK, %EXPORT_TAGS, @opParts, @opName, $AUTOLOAD,
  $asn, $yychar, $yyerrflag, $yynerrs, $yyn, @yyss,
  $yyssp, $yystate, @yyvs, $yyvsp, $yylval, $yys, $yym, $yyval
);

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

constant ASN_BOOLEAN = :16<01>;
constant ASN_INTEGER = :16<02>;
constant ASN_BIT_STR = :16<03>;
constant ASN_OCTET_STR = :16<04>;
constant ASN_NULL = :16<05>;
constant ASN_OBJECT_ID = :16<06>;
constant ASN_REAL = :16<09>;
constant ASN_ENUMERATED = :16<0A>;
constant ASN_RELATIVE_OID = :16<0D>;
constant ASN_SEQUENCE = :16<10>;
constant ASN_SET = :16<11>;
constant ASN_PRINT_STR = :16<13>;
constant ASN_IA5_STR = :16<16>;
constant ASN_UTC_TIME = :16<17>;
constant ASN_GENERAL_TIME = :16<18>;

constant ASN_UNIVERSAL = :16<00>;
constant ASN_APPLICATION = :16<40>;
constant ASN_CONTEXT = :16<80>;
constant ASN_PRIVATE = :16<C0>;

constant ASN_PRIMITIVE = :16<00>;
constant ASN_CONSTRUCTOR = :16<20>;

constant ASN_LONG_LEN = :16<80>;
constant ASN_EXTENSION_ID = :16<1F>;
constant ASN_BIT = :16<80>;

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
    'State60' => ''
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

my @yylhs = (                                               -1,
    0,    0,    2,    2,    3,    3,    6,    6,    6,    6,
    8,   13,   13,   12,   14,   14,   14,    9,    9,    9,
   10,   18,   18,   18,   18,   18,   19,   19,   11,   16,
   16,   20,   20,   20,   21,   21,    1,    1,    1,   22,
   22,   22,   24,   24,   24,   24,   23,   23,   23,   23,
   15,   15,    4,    4,    5,    5,    5,   17,   17,   25,
    7,    7,
);

my @yylen = (                                                2,
    1,    1,    3,    4,    4,    1,    1,    1,    1,    1,
    3,    1,    1,    6,    1,    1,    1,    4,    4,    4,
    4,    1,    1,    1,    2,    1,    0,    3,    1,    1,
    2,    1,    3,    3,    4,    1,    0,    1,    2,    1,
    3,    3,    2,    1,    1,    1,    4,    1,    3,    1,
    0,    1,    0,    1,    0,    1,    1,    1,    3,    2,
    0,    1,
);

my @yydefred = (                                             0,
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

my @yydgoto = (                                              5,
    6,    7,   21,    8,   18,   51,   70,    9,   52,   53,
   54,   55,   44,   96,   60,   66,   73,   45,   57,   67,
   68,   10,   11,   46,   74,
);

my @yysindex = (                                             2,
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

my @yyrindex = (                                           155,
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

my @yygindex = (                                             0,
   85,    0,  151,    1,  -12,   91,    0,   47,  -18,  -19,
  -17,  157,    0,    0,   83,    0,    0,    0,    0,    0,
   -3,    0,  127,    0,   95,
);

my @yytable = (                                             30,
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

my @yycheck = (                                             18,
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

# BEGIN {
# 
#   @ISA = qw (Exporter);
# 
#   %EXPORT_TAGS = (
#     io    => [qw (asn_recv asn_send asn_read asn_write asn_get asn_ready)],
# 
#     debug => [qw (asn_dump asn_hexdump)],
# 
#     const => [qw (
#         ASN_BOOLEAN     ASN_INTEGER      ASN_BIT_STR      ASN_OCTET_STR
#         ASN_NULL        ASN_OBJECT_ID    ASN_REAL         ASN_ENUMERATED
#         ASN_SEQUENCE    ASN_SET          ASN_PRINT_STR    ASN_IA5_STR
#         ASN_UTC_TIME    ASN_GENERAL_TIME ASN_RELATIVE_OID
#         ASN_UNIVERSAL   ASN_APPLICATION  ASN_CONTEXT      ASN_PRIVATE
#         ASN_PRIMITIVE   ASN_CONSTRUCTOR  ASN_LONG_LEN     ASN_EXTENSION_ID ASN_BIT)],
# 
#     tag   => [qw (asn_tag asn_decode_tag2 asn_decode_tag asn_encode_tag asn_decode_length asn_encode_length)]
#   );
# 
#   @EXPORT_OK = map { @$_ }, values %EXPORT_TAGS;
#   %EXPORT_TAGS{'all'} = \@EXPORT_OK;
# }




sub new {
  my $pkg = shift;
  my $self = bless {}, $pkg;

  $self.configure(@_);
  $self;
}


sub configure {
  my $self = shift;
  my %opt = @_;

  $self{'options'}{'encoding'} = uc(%opt{'encoding'} || 'BER');

  unless ($self{'options'}{'encoding'} ~~ m:P5/^[BD]ER$/) {
    die "Unsupported encoding format '%opt{"encoding"}'";
  }

  # IMPLICIT as defalt for backwards compatibility, even though it's wrong.
  $self{'options'}{'tagdefault'} = uc(%opt{'tagdefault'} || 'IMPLICIT');

  unless ($self{'options'}{'tagdefault'} ~~ m:P5/^(?:EXPLICIT|IMPLICIT)$/) {
    die "Default tagging must be EXPLICIT/IMPLICIT. Not %opt{"tagdefault"}";
  }


  for (qw (encode decode)) -> $type {
    if (exists %opt{'$type'}) {
      while (my ($what,$value) = each %(%opt{'$type'})) {
    $self{'options'}{'"{$type}_{$what}"'} = $value;
      }
    }
  }
}



sub find {
  my $self = shift;
  my $what = shift;
  return unless exists $self.{'tree'}{'$what'};
  my %new = %$self;
  %new{'script'} = %new{'tree'}.{'$what'};
  bless \%new, ref($self);
}


sub prepare {
  my $self = shift;
  my $asn  = shift;

  $self = $self.new unless ref($self);
  my $tree;
  if ref($asn) eq 'GLOB' {
    local $*IN.input-line-separator() = Any;
    my $txt = <$asn>;
    # $tree = Convert::ASN1::parser::parse($txt,$self->{options}{tagdefault});
    $tree = parse($txt,$self.{'options'}{'tagdefault'});
  }
  else {
    # $tree = Convert::ASN1::parser::parse($asn,$self->{options}{tagdefault});
    $tree = parse($asn,$self.{'options'}{'tagdefault'});
  }

  unless ($tree) {
    $self.{'error'} = $!;
    return;
    ### If $self has been set to a new object, not returning
    ### this object here will destroy the object, so the caller
    ### won't be able to get at the error.
  }

  $self.{'tree'} = _pack_struct($tree);
  $self.{'script'} = (values %$tree)[0];
  $self;
}

sub prepare_file {
  my $self = shift;
  my $asnp = shift;

  my $fh = open $asnp, :r
      or do { $self.{'error'} = $!; return; };
  my $ret = $self.prepare( $fh );
  close $fh;
  $ret;
}

sub registeroid {
  my $self = shift;
  my $oid  = shift;
  my $handler = shift;

  $self.{'options'}{'oidtable'}{'$oid'}=$handler;
  $self.{'oidtable'}{'$oid'}=$handler;
}

sub registertype {
   my $self = shift;
   my $def = shift;
   my $type = shift;
   my $handler = shift;

   $self.{'options'}{'handlers'}{'$def'}{'$type'}=$handler;
}

# In XS the will convert the tree between perl and C structs

sub _pack_struct { @_[0] }
sub _unpack_struct { @_[0] }

##
## Encoding
##

sub encode {
  my $self  = @_.shift;
  my $stash = @_.elems == 1 ?? @_.shift !! { @_ };
  my $buf = '';
  try { _encode($self.{'options'}, $self.{'script'}, $stash, [], $buf) }
    or do { $self.{'error'} = $!; Any }
}



# Encode tag value for encoding.
# We assume that the tag has been correctly generated with asn_tag()

sub asn_encode_tag {
  @_[0] +> 8
    ?? @_[0] +& :16<8000>
      ?? @_[0] +& :16<800000>
    ?? pack("V",@_[0])
    !! substr(pack("V",@_[0]),0,3)
      !! pack("v", @_[0])
    !! pack("C",@_[0]);
}


# Encode a length. If < 0x80 then encode as a byte. Otherwise encode
# 0x80 | num_bytes followed by the bytes for the number. top end
# bytes of all zeros are not encoded

sub asn_encode_length {

  if (@_[0] +> 7) {
    my $lenlen = &num_length;

    return pack("Ca*", $lenlen +| :16<80>,  substr(pack("N",@_[0]), -$lenlen));
  }

  return pack("C", @_[0]);
}


##
## Decoding
##

sub decode {
  my $self  = shift;
  my $ret;

  try {
    my (%stash, $result);
    my $script = $self{'script'};
    my $stash = $result;

    while ($script) {
      my $child = $script[0] or last;
      if (@$script > 1 or defined $child[cVAR]) {
        $result = $stash = %stash;
        last;
      }
      last if $child.[cTYPE] == opCHOICE or $child.[cLOOP];
      $script = $child.[cCHILD];
    }

    _decode(
    $self.{'options'},
    $self.{'script'},
    $stash,
    0,
    length @_[0], 
    Any,
    {},
    @_[0]);

    $ret = $result;
    1;
  } or $self.{'error'} = $! || 'Unknown error';

  $ret;
}


sub asn_decode_length {
  return unless length @_[0];

  my $len = unpack("C",@_[0]);

  if ($len +& :16<80>) {
    $len +&= :16<7f> or return (1,-1);

    return if $len >= length @_[0];

    return (1+$len, unpack("N", "\0" x (4 - $len) ~ substr(@_[0],1,$len)));
  }
  return (1, $len);
}


sub asn_decode_tag {
  return unless length @_[0];

  my $tag = unpack("C", @_[0]);
  my $n = 1;

  if (($tag +& :16<1f>) == :16<1f>) {
    my $b;
    do {
      return if $n >= length @_[0];
      $b = unpack("C",substr(@_[0],$n,1));
      $tag +|= $b +< (8 * $n++);
    } while ($b +& :16<80>);
  }
  ($n, $tag);
}


sub asn_decode_tag2 {
  return unless length @_[0];

  my $tag = unpack("C",@_[0]);
  my $num = $tag +& :16<1f>;
  my $len = 1;

  if ($num == :16<1f>) {
    $num = 0;
    my $b;
    do {
      return if $len >= length @_[0];
      $b = unpack("C",substr(@_[0],$len++,1));
      $num = ($num +< 7) + ($b +& :16<7f>);
    } while ($b +& :16<80>);
  }
  ($len, $tag, $num);
}


##
## Utilities
##

# How many bytes are needed to encode a number 

sub num_length {
  @_[0] +> 8
    ?? @_[0] +> 16
      ?? @_[0] +> 24
    ?? 4
    !! 3
      !! 2
    !! 1
}

# Convert from a bigint to an octet string

sub i2osp {
    my ($num, $biclass) = @_;
    $num = $biclass.new($num);
    my $neg = $num < 0
      and $num = abs($num+1);
    my $base = $biclass.new(256);
    my $result = '';
    while ($num != 0) {
        my $r = $num % $base;
        $num = ($num-$r) / $base;
        $result ~= pack("C",$r);
    }
    $result +^= pack("C",255) x length($result) if $neg;
    return scalar reverse $result;
}

# Convert from an octet string to a bigint

sub os2ip {
    my ($os, $biclass) = @_;
    # eval "require $biclass";
    my $base = $biclass.new(256);
    my $result = $biclass.new(0);
    my $neg = unpack("C",$os) >= :16<80>
      and $os +^= pack("C",255) x length($os);
    for (unpack("C*",$os)) {
      $result = ($result * $base) + $_;
    }
    return $neg ?? ($result + 1) * -1 !! $result;
}

# Given a class and a tag, calculate an integer which when encoded
# will become the tag. This means that the class bits are always
# in the bottom byte, so are the tag bits if tag < 30. Otherwise
# the tag is in the upper 3 bytes. The upper bytes are encoded
# with bit8 representing that there is another byte. This
# means the max tag we can do is 0x1fffff

sub asn_tag {
  my ($class,$value) = @_;

  die sprintf "Bad tag class 0x%x",$class
    if $class +& +^:16<e0>;

  unless ($value +& +^:16<1f> or $value == :16<1f>) {
    return (($class +& :16<e0>) +| $value);
  }

  die sprintf "Tag value 0x%08x too big\n",$value
    if $value +& :16<ffe00000>;

  $class = ($class +| :16<1f>) +& :16<ff>;

  my @t = ($value +& :16<7f>);
  unshift @t, (:16<80> +| ($value +& :16<7f>)) while $value +>= 7;
  unpack("V",pack("C4",$class,@t,0,0));
}

sub error { @_[0].{'error'} }

# These are the subs which do the encoding, they are called with
# 0      1    2       3     4     5
# $opt, $op, $stash, $var, $buf, $loop
# The order in the array must match the op definitions above

my @encode = (
  sub { die "internal error\n" },
  \&_enc_boolean,
  \&_enc_integer,
  \&_enc_bitstring,
  \&_enc_string,
  \&_enc_null,
  \&_enc_object_id,
  \&_enc_real,
  \&_enc_sequence,
  \&_enc_sequence, # EXPLICIT is the same encoding as sequence
  \&_enc_sequence, # SET is the same encoding as sequence
  \&_enc_time,
  \&_enc_time,
  \&_enc_utf8,
  \&_enc_any,
  \&_enc_choice,
  \&_enc_object_id,
  \&_enc_bcd,
);


sub _encode {
  my ($optn, $ops, $stash, $path) = @_;
  my $var;

  for (@($ops)) -> $op {
    next if $op.[cTYPE] == opEXTENSIONS;
    if (defined(my $opt = $op.[cOPT])) {
      next unless defined $stash.{'$opt'};
    }
    if (defined($var = $op.[cVAR])) {
      push @$path, $var;
      croak(join(".", @$path)," is undefined")  unless defined $stash.{'$var'};
    }
    @_[4] ~= $op.[cTAG];

    &(@encode[$op.[cTYPE]])(
      $optn,
      $op,
      (UNIVERSAL::isa($stash, 'HASH')
    ?? ($stash, defined($var) ?? $stash.{'$var'} !! Any)
    !! ({}, $stash)),
      @_[4],
      $op.[cLOOP],
      $path,
    );

    pop @$path if defined $var;
  }

  @_[4];
}


sub _enc_boolean {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  @_[4] ~= pack("CC",1, @_[3] ?? :16<ff> !! 0);
}


sub _enc_integer {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path
  if (abs(@_[3]) >= 2**31) {
    my $os = i2osp(@_[3], ref(@_[3]) || @_[0].{'encode_bigint'} || 'Math::BigInt');
    my $len = length $os;
    my $msb = (vec($os, 0, 8) +& :16<80>) ?? 0 !! 255;
    $len++, $os = pack("C",$msb) ~ $os if $msb xor @_[3] > 0;
    @_[4] ~= asn_encode_length($len);
    @_[4] ~= $os;
  }
  else {
    my $val = int(@_[3]);
    my $neg = ($val < 0);
    my $len = num_length($neg ?? +^$val !! $val);
    my $msb = $val +& (:16<80> +< (($len - 1) * 8));

    $len++ if $neg ?? ?^$msb !! $msb;

    @_[4] ~= asn_encode_length($len);
    @_[4] ~= substr(pack("N",$val), -$len);
  }
}


sub _enc_bitstring {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path
  my $vref = ref(@_[3]) ?? \(@_[3].[0]) !! \@_[3];

  if (1 and Encode::is_utf8($$vref)) {
    utf8::encode(my $tmp = $$vref);
    $vref = \$tmp;
  }

  if (ref(@_[3])) {
    my $less = (8 - (@_[3].[1] +& 7)) +& 7;
    my $len = (@_[3].[1] + 7) +> 3;
    @_[4] ~= asn_encode_length(1+$len);
    @_[4] ~= pack("C",$less);
    @_[4] ~= substr($$vref, 0, $len);
    if ($less && $len) {
      substr(@_[4],-1) +&= pack("C",(:16<ff> +< $less) +& :16<ff>);
    }
  }
  else {
    @_[4] ~= asn_encode_length(1+length $$vref);
    @_[4] ~= pack("C",0);
    @_[4] ~= $$vref;
  }
}


sub _enc_string {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  if (1 and Encode::is_utf8(@_[3])) {
    utf8::encode(my $tmp = @_[3]);
    @_[4] ~= asn_encode_length(length $tmp);
    @_[4] ~= $tmp;
  }
  else {
    @_[4] ~= asn_encode_length(length @_[3]);
    @_[4] ~= @_[3];
  }
}


sub _enc_null {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  @_[4] ~= pack("C",0);
}


sub _enc_object_id {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  my @data = (@_[3] ~~ m:c:P5/(\d+)/);

  if (@_[1].[cTYPE] == opOBJID) {
    if (@data < 2) {
      @data = (0);
    }
    else {
      my $first = @data[1] + (@data[0] * 40);
      splice(@data,0,2,$first);
    }
  }

  my $l = length @_[4];
  @_[4] ~= pack("cw*", 0, @data);
  substr(@_[4],$l,1) = asn_encode_length(length(@_[4]) - $l - 1);
}


sub _enc_real {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  # Zero
  unless (@_[3]) {
    @_[4] ~= pack("C",0);
    return;
  }

  require POSIX:from<Perl5>;

  # +oo (well we use HUGE_VAL as Infinity is not avaliable to perl)
  if (@_[3] >= POSIX::HUGE_VAL()) {
    @_[4] ~= pack("C*",:16<01>,:16<40>);
    return;
  }

  # -oo (well we use HUGE_VAL as Infinity is not avaliable to perl)
  if (@_[3] <= - POSIX::HUGE_VAL()) {
    @_[4] ~= pack("C*",:16<01>,:16<41>);
    return;
  }

  if (exists @_[0].{'encode_real'} && @_[0].{'encode_real'} ne 'binary') {
    my $tmp = sprintf("%g",@_[3]);
    @_[4] ~= asn_encode_length(1+length $tmp);
    @_[4] ~= pack("C",1); # NR1?
    @_[4] ~= $tmp;
    return;
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
  $exponent -= 8 * length $eMant;

  _enc_integer(Any, Any, Any, $exponent, $eExp);

  # $eExp will br prefixed by a length byte
  
  if (5 > length $eExp) {
    $eExp ~~ s:s:P5/\A.//;
    $first +|= length($eExp)-1;
  }
  else {
    $first +|= :16<3>;
  }

  @_[4] ~= asn_encode_length(1 + length($eMant) + length($eExp));
  @_[4] ~= pack("C",$first);
  @_[4] ~= $eExp;
  @_[4] ~= $eMant;
}


sub _enc_sequence {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  if (my $ops = @_[1].[cCHILD]) {
    my $l = length @_[4];
    @_[4] ~= "\0\0"; # guess
    if (defined @_[5]) {
      my $op   = $ops.[0]; # there should only be one
      my $enc  = @encode[$op.[cTYPE]];
      my $tag  = $op.[cTAG];
      my $loop = $op.[cLOOP];

      push @(@_[6]), -1;

      for (@(@_[3])) -> $var {
    @_[6].[*-1]++;
    @_[4] ~= $tag;

    &($enc)(
      @_[0], # $optn
      $op,   # $op
      @_[2], # $stash
      $var,  # $var
      @_[4], # $buf
      $loop, # $loop
      @_[6], # $path
    );
      }
      pop @(@_[6]);
    }
    else {
      _encode(@_[0],@_[1].[cCHILD], defined(@_[3]) ?? @_[3] !! @_[2], @_[6], @_[4]);
    }
    substr(@_[4],$l,2) = asn_encode_length(length(@_[4]) - $l - 2);
  }
  else {
    @_[4] ~= asn_encode_length(length @_[3]);
    @_[4] ~= @_[3];
  }
}


my %_enc_time_opt = ( utctime => 1, withzone => 0, raw => 2);

sub _enc_time {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  my $mode = %_enc_time_opt{'@_'[0].{'encode_time'} || ''} || 0;

  if ($mode == 2) {
    @_[4] ~= asn_encode_length(length @_[3]);
    @_[4] ~= @_[3];
    return;
  }

  my $time;
  my @time;
  my $offset;
  my $isgen = @_[1].[cTYPE] == opGTIME;

  if (ref(@_[3])) {
    $offset = int(@_[3].[1] / 60);
    $time = @_[3].[0] + @_[3].[1];
  }
  elsif ($mode == 0) {
    if (exists @_[0].{'encode_timezone'}) {
      $offset = int(@_[0].{'encode_timezone'} / 60);
      $time = @_[3] + @_[0].{'encode_timezone'};
    }
    else {
      @time = localtime(@_[3]);
      my @g = gmtime(@_[3]);
      
      $offset = (@time[1] - @g[1]) + (@time[2] - @g[2]) * 60;
      $time = @_[3] + $offset*60;
    }
  }
  else {
    $time = @_[3];
  }
  @time = gmtime($time);
  @time[4] += 1;
  @time[5] = $isgen ?? (@time[5] + 1900) !! (@time[5] % 100);

  my $tmp = sprintf("%02d"x6, @time[5,4,3,2,1,0]);
  if ($isgen) {
    my $sp = sprintf("%.03f",$time);
    $tmp ~= substr($sp,-4) unless $sp ~~ m:P5/\.000$/;
  }
  $tmp ~= $offset ?? sprintf("%+03d%02d",$offset / 60, abs($offset % 60)) !! 'Z';
  @_[4] ~= asn_encode_length(length $tmp);
  @_[4] ~= $tmp;
}


sub _enc_utf8 {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  if (1) {
    my $tmp = @_[3];
    utf8::upgrade($tmp) unless Encode::is_utf8($tmp);
    utf8::encode($tmp);
    @_[4] ~= asn_encode_length(length $tmp);
    @_[4] ~= $tmp;
  }
  else {
    @_[4] ~= asn_encode_length(length @_[3]);
    @_[4] ~= @_[3];
  }
}


sub _enc_any {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  my $handler;
  if (@_[1].[cDEFINE] && @_[2].{'@_'[1].[cDEFINE]}) {
    $handler=@_[0].{'oidtable'}{'@_'[2].{'@_'[1].[cDEFINE]}};
    $handler=@_[0].{'handlers'}{'@_'[1].[cVAR]}{'@_'[2].{'@_'[1].[cDEFINE]}} unless $handler;
  }
  if ($handler) {
    @_[4] ~= $handler.encode(@_[3]);
  } else {
    @_[4] ~= @_[3];
  }
}


sub _enc_choice {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

  my $stash = defined(@_[3]) ?? @_[3] !! @_[2];
  for (@(@_[1].[cCHILD])) -> $op {
    next if $op.[cTYPE] == opEXTENSIONS;
    my $var = defined $op.[cVAR] ?? $op.[cVAR] !! $op.[cCHILD].[0].[cVAR];

    if (exists $stash.{'$var'}) {
      push @(@_[6]), $var;
      _encode(@_[0],[$op], $stash, @_[6], @_[4]);
      pop @(@_[6]);
      return;
    }
  }
  croak("No value found for CHOICE " ~ join(".", @(@_[6])));
}


sub _enc_bcd {
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path
  my $str = ("$_[3]" ~~ m:P5/^(\d+)/) ?? $0 !! "";
  $str ~= "F" if length($str) +& 1;
  @_[4] ~= asn_encode_length(length($str) / 2);
  @_[4] ~= pack("H*", $str);
}



sub asn_recv { # $socket, $buffer, $flags

  my $peer;
  my $buf;
  my $n = 128;
  my $pos = 0;
  my $depth = 0;
  my $len = 0;
  my ($tmp,$tb,$lb);

  loop
  for(
    $peer = recv(@_[0],$buf,$n,MSG_PEEK);
    defined $peer;
    $peer = recv(@_[0],$buf,$n+<=1,MSG_PEEK)
  ) {

    if ($depth) { # Are we searching of "\0\0"

      unless (2+$pos <= length $buf) {
    next MORE if $n == length $buf;
    last MORE;
      }

      if (substr($buf,$pos,2) eq "\0\0") {
    unless (--$depth) {
      $len = $pos + 2;
      last MORE;
    }
      }
    }

    # If we can decode a tag and length we can detemine the length
    ($tb,$tmp) = asn_decode_tag(substr($buf,$pos));
    unless ($tb || $pos+$tb < length $buf) {
      next MORE if $n == length $buf;
      last MORE;
    }

    if (unpack("C",substr($buf,$pos+$tb,1)) == :16<80>) {
      # indefinite length, grrr!
      $depth++;
      $pos += $tb + 1;
      redo MORE;
    }

    ($lb,$len) = asn_decode_length(substr($buf,$pos+$tb));

    if ($lb) {
      if ($depth) {
    $pos += $tb + $lb + $len;
    redo MORE;
      }
      else {
    $len += $tb + $lb + $pos;
    last MORE;
      }
    }
  }

  if (defined $peer) {
    if ($len > length $buf) {
      # Check we can read the whole element
      goto error
    unless defined($peer = recv(@_[0],$buf,$len,MSG_PEEK));

      if ($len > length $buf) {
    # Cannot get whole element
    @_[1]='';
    return $peer;
      }
    }
    elsif ($len == 0) {
      @_[1] = '';
      return $peer;
    }

    if (@_[2] +& MSG_PEEK) {
      @_[1] =  substr($buf,0,$len);
    }
    elsif (?^defined($peer = recv(@_[0],@_[1],$len,0))) {
      goto error;
    }

    return $peer;
  }

error:
    @_[1] = Any;
}

sub asn_read { # $fh, $buffer, $offset

  # We need to read one packet, and exactly only one packet.
  # So we have to read the first few bytes one at a time, until
  # we have enough to decode a tag and a length. We then know
  # how many more bytes to read

  if (@_[2]) {
    if (@_[2] > length @_[1]) {
      ::carp("Offset beyond end of buffer");
      return;
    }
    substr(@_[1],@_[2]) = '';
  }
  else {
    @_[1] = '';
  }

  my $pos = 0;
  my $need = 0;
  my $depth = 0;
  my $ch;
  my $n;
  my $e;
  

  while (1) {
    $need = ($pos + ($depth * 2)) || 2;

    while (($n = $need - length @_[1]) > 0) {
      $e = sysread(@_[0],@_[1],$n,length @_[1]) or
    goto READ_ERR;
    }

    my $tch = unpack("C",substr(@_[1],$pos++,1));
    # Tag may be multi-byte
    if (($tch +& :16<1f>) == :16<1f>) {
      my $ch;
      do {
        $need++;
    while (($n = $need - length @_[1]) > 0) {
      $e = sysread(@_[0],@_[1],$n,length @_[1]) or
          goto READ_ERR;
    }
    $ch = unpack("C",substr(@_[1],$pos++,1));
      } while ($ch +& :16<80>);
    }

    $need = $pos + 1;

    while (($n = $need - length @_[1]) > 0) {
      $e = sysread(@_[0],@_[1],$n,length @_[1]) or
      goto READ_ERR;
    }

    my $len = unpack("C",substr(@_[1],$pos++,1));

    if ($len +& :16<80>) {
      unless ($len +&= :16<7f>) {
    $depth++;
    next;
      }
      $need = $pos + $len;

      while (($n = $need - length @_[1]) > 0) {
    $e = sysread(@_[0],@_[1],$n,length @_[1]) or
        goto READ_ERR;
      }

      $pos += $len + unpack("N", "\0" x (4 - $len) ~ substr(@_[1],$pos,$len));
    }
    elsif (?^$len && ?^$tch) {
      die "Bad ASN PDU" unless $depth;
      unless (--$depth) {
    last;
      }
    }
    else {
      $pos += $len;
    }

    last unless $depth;
  }

  while (($n = $pos - length @_[1]) > 0) {
    $e = sysread(@_[0],@_[1],$n,length @_[1]) or
      goto READ_ERR;
  }

  return length @_[1];

READ_ERR:
    $! = defined($e) ?? "Unexpected EOF" !! "I/O Error $!"; # . CORE::unpack("H*",$_[1]);
    return Any;
}

sub asn_send { # $sock, $buffer, $flags, $to

  @_ == 4
    ?? send(@_[0],@_[1],@_[2],@_[3])
    !! send(@_[0],@_[1],@_[2]);
}

sub asn_write { # $sock, $buffer

  syswrite(@_[0],@_[1], length @_[1]);
}

sub asn_get { # $fh

  my $fh = ref(@_[0]) ?? @_[0] !! \(@_[0]);
  my $href = \%(*$fh);

  $href.{'asn_buffer'} = '' unless exists $href.{'asn_buffer'};

  my $need = delete $href.{'asn_need'} || 0;
  while (1) {
    next if $need;
    my ($tb,$tag) = asn_decode_tag($href.{'asn_buffer'}) or next;
    my ($lb,$len) = asn_decode_length(substr($href.{'asn_buffer'},$tb,8)) or next;
    $need = $tb + $lb + $len;
  }
  continue {
    if ($need && $need <= length $href.{'asn_buffer'}) {
      my $ret = substr($href.{'asn_buffer'},0,$need);
      substr($href.{'asn_buffer'},0,$need) = '';
      return $ret;
    }

    my $get = $need > 1024 ?? $need !! 1024;

    sysread(@_[0], $href.{'asn_buffer'}, $get, length $href.{'asn_buffer'})
      or return Any;
  }
}

sub asn_ready { # $fh

  my $fh = ref(@_[0]) ?? @_[0] !! \(@_[0]);
  my $href = \%(*$fh);

  return 0 unless exists $href.{'asn_buffer'};
  
  return $href.{'asn_need'} <= length $href.{'asn_buffer'}
    if exists $href.{'asn_need'};

  my ($tb,$tag) = asn_decode_tag($href.{'asn_buffer'}) or return 0;
  my ($lb,$len) = asn_decode_length(substr($href.{'asn_buffer'},$tb,8)) or return 0;

  $href.{'asn_need'} = $tb + $lb + $len;

  $href.{'asn_need'} <= length $href.{'asn_buffer'};
}

# These are the subs that do the decode, they are called with
# 0      1    2       3     4
# $optn, $op, $stash, $var, $buf
# The order must be the same as the op definitions above

my @decode = (
  sub { die "internal error\n" },
  \&_dec_boolean,
  \&_dec_integer,
  \&_dec_bitstring,
  \&_dec_string,
  \&_dec_null,
  \&_dec_object_id,
  \&_dec_real,
  \&_dec_sequence,
  \&_dec_explicit,
  \&_dec_set,
  \&_dec_time,
  \&_dec_time,
  \&_dec_utf8,
  Any, # ANY
  Any, # CHOICE
  \&_dec_object_id,
  \&_dec_bcd,
);

my @ctr;
@ctr[opBITSTR, opSTRING, opUTF8] = (\&_ctr_bitstring,\&_ctr_string,\&_ctr_string);


sub _decode {
  my ($optn, $ops, $stash, $pos, $end, $seqof, $larr) = @_;
  my $idx = 0;

  # we try not to copy the input buffer at any time
  for (@_[*-1]) -> $buf {
    OP:
    foreach my $op (@($ops)) {
      my $var = $op.[cVAR];

      if (length $op.[cTAG]) {

    TAGLOOP: {
      my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
        or do {
          next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
          die "decode error";
        };

      if ($tag eq $op.[cTAG]) {

        &(@decode[$op.[cTYPE]])(
          $optn,
          $op,
          $stash,
          # We send 1 if there is not var as if there is the decode
          # should be getting undef. So if it does not get undef
          # it knows it has no variable
          ($seqof ?? $seqof.[$idx++] !! defined($var) ?? $stash.{'$var'} !! ref($stash) eq 'SCALAR' ?? $$stash !! 1),
          $buf,$npos,$len, $larr
        );

        $pos = $npos+$len+$indef;

        redo TAGLOOP if $seqof && $pos < $end;
        next OP;
      }

      if ($tag eq ($op.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
          and my $ctr = @ctr[$op.[cTYPE]]) 
      {
        _decode(
          $optn,
          [$op],
          Any,
          $npos,
          $npos+$len,
          (\my @ctrlist),
          $larr,
          $buf,
        );

        ($seqof ?? $seqof.[$idx++] !! defined($var) ?? $stash.{'$var'} !! ref($stash) eq 'SCALAR' ?? $$stash !! Any)
        = &($ctr)(@ctrlist);
        $pos = $npos+$len+$indef;

        redo TAGLOOP if $seqof && $pos < $end;
        next OP;

      }

      if ($seqof || defined $op.[cEXT]) {
        next OP;
      }

      die "decode error " ~ unpack("H*",$tag) ~"\<=\>" ~ unpack("H*",$op.[cTAG]), " ",$pos," ",$op.[cTYPE]," ",$op.[cVAR]||'';
        }
      }
      else { # opTag length is zero, so it must be an ANY, CHOICE or EXTENSIONS
    
    if ($op.[cTYPE] == opANY) {

      ANYLOOP: {

        my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
          or do {
        next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
        die "decode error";
          };

        $len += $npos - $pos + $indef;

            my $handler;
            if ($op.[cDEFINE]) {
              $handler = $optn.{'oidtable'} && $optn.{'oidtable'}{'$stash'.{'$op'.[cDEFINE]}};
              $handler ||= $optn.{'handlers'}{'$op'.[cVAR]}{'$stash'.{'$op'.[cDEFINE]}};
            }

        ($seqof ?? $seqof.[$idx++] !! ref($stash) eq 'SCALAR' ?? $$stash !! $stash.{'$var'})
          = $handler ?? $handler.decode(substr($buf,$pos,$len)) !! substr($buf,$pos,$len);

        $pos += $len;

        redo ANYLOOP if $seqof && $pos < $end;
      }
    }
    elsif ($op.[cTYPE] == opCHOICE) {

      CHOICELOOP: {
        my ($tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr)
          or do {
        next OP if $pos==$end and ($seqof || defined $op.[cEXT]);
        die "decode error";
          };
        my $extensions;
        for (@($op.[cCHILD])) -> $cop {

          if ($tag eq $cop.[cTAG]) {

        my $nstash = $seqof
            ?? ($seqof.[$idx++]={})
            !! defined($var)
                ?? ($stash.{'$var'}={})
                !! ref($stash) eq 'SCALAR'
                    ?? ($$stash={}) !! $stash;

        &(@decode[$cop.[cTYPE]])(
          $optn,
          $cop,
          $nstash,
          ($cop.[cVAR] ?? $nstash.{'$cop'.[cVAR]} !! Any),
          $buf,$npos,$len,$larr,
        );

        $pos = $npos+$len+$indef;

        redo CHOICELOOP if $seqof && $pos < $end;
        next OP;
          }

          if ($cop.[cTYPE] == opEXTENSIONS) {
        $extensions = 1;
        next;
          }

          unless (length $cop.[cTAG]) {
        EVAL {
          _decode(
            $optn,
            [$cop],
            (\my %tmp_stash),
            $pos,
            $npos+$len+$indef,
            Any,
            $larr,
            $buf,
          );

          my $nstash = $seqof
              ?? ($seqof.[$idx++]={})
              !! defined($var)
                  ?? ($stash.{'$var'}={})
                  !! ref($stash) eq 'SCALAR'
                      ?? ($$stash={}) !! $stash;

          @($nstash){keys %tmp_stash} = values %tmp_stash;

        } or next;

        $pos = $npos+$len+$indef;

        redo CHOICELOOP if $seqof && $pos < $end;
        next OP;
          }

          if ($tag eq ($cop.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
          and my $ctr = @ctr[$cop.[cTYPE]]) 
          {
        my $nstash = $seqof
            ?? ($seqof.[$idx++]={})
            !! defined($var)
                ?? ($stash.{'$var'}={})
                !! ref($stash) eq 'SCALAR'
                    ?? ($$stash={}) !! $stash;

        _decode(
          $optn,
          [$cop],
          Any,
          $npos,
          $npos+$len,
          (\my @ctrlist),
          $larr,
          $buf,
        );

        $nstash.{'$cop'.[cVAR]} = &($ctr)(@ctrlist);
        $pos = $npos+$len+$indef;

        redo CHOICELOOP if $seqof && $pos < $end;
        next OP;
          }
        }

        if ($pos < $end && $extensions) {
          $pos = $npos+$len+$indef;

          redo CHOICELOOP if $seqof && $pos < $end;
          next OP;
        }
      }
      die "decode error" unless $op.[cEXT];
    }
    elsif ($op.[cTYPE] == opEXTENSIONS) {
        $pos = $end; # Skip over the rest
        }
    else {
      die "this point should never be reached";
    }
      }
    }
  }
  die "decode error $pos $end" unless $pos == $end;
}


sub _dec_boolean {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  @_[3] = unpack("C",substr(@_[4],@_[5],1)) ?? 1 !! 0;
  1;
}


sub _dec_integer {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  my $buf = substr(@_[4],@_[5],@_[6]);
  my $tmp = unpack("C",$buf) +& :16<80> ?? pack("C",255) !! pack("C",0);
  if (@_[6] > 4) {
      @_[3] = os2ip($buf, @_[0].{'decode_bigint'} || 'Math::BigInt');
  } else {
      # N unpacks an unsigned value
      @_[3] = unpack("l",pack("l",unpack("N", $tmp x (4-@_[6]) ~ $buf)));
  }
  1;
}


sub _dec_bitstring {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  @_[3] = [ substr(@_[4],@_[5]+1,@_[6]-1), (@_[6]-1)*8-unpack("C",substr(@_[4],@_[5],1)) ];
  1;
}


sub _dec_string {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  @_[3] = substr(@_[4],@_[5],@_[6]);
  1;
}


sub _dec_null {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  @_[3] = exists(@_[0].{'decode_null'}) ?? @_[0].{'decode_null'} !! 1;
  1;
}


sub _dec_object_id {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  my @data = unpack("w*",substr(@_[4],@_[5],@_[6]));
  if (@_[1].[cTYPE] == opOBJID and @data > 1) {
    if (@data[0] < 40) {
      splice(@data, 0, 1, 0, @data[0]);
    }
    elsif (@data[0] < 80) {
      splice(@data, 0, 1, 1, @data[0] - 40);
    }
    else {
      splice(@data, 0, 1, 2, @data[0] - 80);
    }
  }
  @_[3] = join(".", @data);
  1;
}


my @_dec_real_base = (2,8,16);

sub _dec_real {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  @_[3] = 0.0, return unless @_[6];

  my $first = unpack("C",substr(@_[4],@_[5],1));
  if ($first +& :16<80>) {
    # A real number

    require POSIX:from<Perl5>;

    my $exp;
    my $expLen = $first +& :16<3>;
    my $estart = @_[5]+1;

    if ($expLen == 3) {
      $estart++;
      $expLen = unpack("C",substr(@_[4],@_[5]+1,1));
    }
    else {
      $expLen++;
    }
    _dec_integer(Any, Any, Any, $exp, @_[4],$estart,$expLen);

    my $mant = 0.0;
    for (reverse unpack("C*",substr(@_[4],$estart+$expLen,@_[6]-1-$expLen))) {
      $exp +=8, $mant = (($mant+$_) / 256) ;
    }

    $mant *= 1 +< (($first +> 2) +& :16<3>);
    $mant = - $mant if $first +& :16<40>;

    @_[3] = $mant * POSIX::pow(@_dec_real_base[($first +> 4) +& :16<3>], $exp);
    return;
  }
  elsif ($first +& :16<40>) {
    @_[3] =   POSIX::HUGE_VAL(),return if $first == :16<40>;
    @_[3] = - POSIX::HUGE_VAL(),return if $first == :16<41>;
  }
  elsif (substr(@_[4],@_[5],@_[6]) ~~ m:s:P5/^.([-+]?)0*(\d+(?:\.\d+(?:[Ee][-+]?\d+)?)?)$/) {
    @_[3] = EVAL "$1$2";
    return;
  }

  die "REAL decode error\n";
}


sub _dec_explicit {
# 0      1    2       3     4     5     6     7
# $optn, $op, $stash, $var, $buf, $pos, $len, $larr

  local @_[1][cCHILD][0][cVAR] = @_[1][cVAR] unless @_[1][cCHILD][0][cVAR];

  _decode(
    @_[0], #optn
    @_[1].[cCHILD],   #ops
    @_[2], #stash
    @_[5], #pos
    @_[5]+@_[6], #end
    Any, #loop
    @_[7],
    @_[4], #buf
  );
  1;
}
sub _dec_sequence {
# 0      1    2       3     4     5     6     7
# $optn, $op, $stash, $var, $buf, $pos, $len, $larr

  if (defined( my $ch = @_[1].[cCHILD])) {
    _decode(
      @_[0], #optn
      $ch,   #ops
      (defined(@_[3]) || @_[1].[cLOOP]) ?? @_[2] !! (@_[3]= {}), #stash
      @_[5], #pos
      @_[5]+@_[6], #end
      @_[1].[cLOOP] && (@_[3]=[]), #loop
      @_[7],
      @_[4], #buf
    );
  }
  else {
    @_[3] = substr(@_[4],@_[5],@_[6]);
  }
  1;
}


sub _dec_set {
# 0      1    2       3     4     5     6     7
# $optn, $op, $stash, $var, $buf, $pos, $len, $larr

  # decode SET OF the same as SEQUENCE OF
  my $ch = @_[1].[cCHILD];
  goto &_dec_sequence if @_[1].[cLOOP] or ?^defined($ch);

  my ($optn, $pos, $larr) = @_[0,5,7];
  my $stash = defined(@_[3]) ?? @_[2] !! (@_[3]={});
  my $end = $pos + @_[6];
  my @done;
  my $extensions;

  while ($pos < $end) {
    my ($tag,$len,$npos,$indef) = _decode_tl(@_[4],$pos,$end,$larr)
      or die "decode error";

    my ($idx, $any, $done) = (-1);

SET_OP:
    foreach my $op (@$ch) {
      $idx++;
      if (length($op.[cTAG])) {
    if ($tag eq $op.[cTAG]) {
      my $var = $op.[cVAR];
      &(@decode[$op.[cTYPE]])(
        $optn,
        $op,
        $stash,
        # We send 1 if there is not var as if there is the decode
        # should be getting undef. So if it does not get undef
        # it knows it has no variable
        (defined($var) ?? $stash.{'$var'} !! 1),
        @_[4],$npos,$len,$larr,
      );
      $done = $idx;
      last SET_OP;
    }
    if ($tag eq ($op.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
        and my $ctr = @ctr[$op.[cTYPE]]) 
    {
      _decode(
        $optn,
        [$op],
        Any,
        $npos,
        $npos+$len,
        (\my @ctrlist),
        $larr,
        @_[4],
      );

      $stash.{'$op'.[cVAR]} = &($ctr)(@ctrlist)
        if defined $op.[cVAR];
      $done = $idx;
      last SET_OP;
    }
    next SET_OP;
      }
      elsif ($op.[cTYPE] == opANY) {
    $any = $idx;
      }
      elsif ($op.[cTYPE] == opCHOICE) {
    my $var = $op.[cVAR];
    for (@($op.[cCHILD])) -> $cop {
      if ($tag eq $cop.[cTAG]) {
        my $nstash = defined($var) ?? ($stash.{'$var'}={}) !! $stash;

        &(@decode[$cop.[cTYPE]])(
          $optn,
          $cop,
          $nstash,
          $nstash.{'$cop'.[cVAR]},
          @_[4],$npos,$len,$larr,
        );
        $done = $idx;
        last SET_OP;
      }
      if ($tag eq ($cop.[cTAG] +| pack("C",ASN_CONSTRUCTOR))
          and my $ctr = @ctr[$cop.[cTYPE]]) 
      {
        my $nstash = defined($var) ?? ($stash.{'$var'}={}) !! $stash;

        _decode(
          $optn,
          [$cop],
          Any,
          $npos,
          $npos+$len,
          (\my @ctrlist),
          $larr,
          @_[4],
        );

        $nstash.{'$cop'.[cVAR]} = &($ctr)(@ctrlist);
        $done = $idx;
        last SET_OP;
      }
    }
      }
      elsif ($op.[cTYPE] == opEXTENSIONS) {
      $extensions = $idx;
      }
      else {
    die "internal error";
      }
    }

    if (?^defined($done) and defined($any)) {
      my $var = $ch.[$any][cVAR];
      $stash.{'$var'} = substr(@_[4],$pos,$len+$npos-$pos) if defined $var;
      $done = $any;
    }

    if ( ?^defined($done) && defined($extensions) ) {
      $done = $extensions;
    }

    die "decode error" if ?^defined($done) or @done[$done]++;

    $pos = $npos + $len + $indef;
  }

  die "decode error" unless $end == $pos;

  for (0..@($ch).end) -> $idx {
    die "decode error" unless @done[$idx] or $ch.[$idx][cEXT] or $ch.[$idx][cTYPE] == opEXTENSIONS;
  }

  1;
}


my %_dec_time_opt = ( unixtime => 0, withzone => 1, raw => 2);

sub _dec_time {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  my $mode = %_dec_time_opt{'@_'[0].{'decode_time'} || ''} || 0;

  if ($mode == 2 or @_[6] == 0) {
    @_[3] = substr(@_[4],@_[5],@_[6]);
    return;
  }

  my @bits = (substr(@_[4],@_[5],@_[6])
     ~~ m:P5/^((?:\d\d)?\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)((?:\.\d{1,3})?)(([-+])(\d\d)(\d\d)|Z)/)
     or die "bad time format";

  if (@bits[0] < 100) {
    @bits[0] += 100 if @bits[0] < 50;
  }
  else {
    @bits[0] -= 1900;
  }
  @bits[1] -= 1;
  require Time::Local:from<Perl5>;
  my $time = Time::Local::timegm(@bits[5,4,3,2,1,0]);
  $time += @bits[6] if length @bits[6];
  my $offset = 0;
  if (@bits[7] ne 'Z') {
    $offset = @bits[9] * 3600 + @bits[10] * 60;
    $offset = -$offset if @bits[8] eq '-';
    $time -= $offset;
  }
  @_[3] = $mode ?? [$time,$offset] !! $time;
}


sub _dec_utf8 {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len
  @_[3] = Encode::decode('utf8', substr(@_[4],@_[5],@_[6]));
}


sub _decode_tl {
  my ($pos,$end,$larr) = @_[1,2,3];

  return if $pos >= $end;

  my $indef = 0;

  my $tag = substr(@_[0], $pos++, 1);

  if ((unpack("C",$tag) +& :16<1f>) == :16<1f>) {
    my $b;
    my $n=1;
    do {
      return if $pos >= $end;
      $tag ~= substr(@_[0],$pos++,1);
      $b = ord substr($tag,-1);
    } while ($b +& :16<80>);
  }
  return if $pos >= $end;

  my $len = ord substr(@_[0],$pos++,1);

  if ($len +& :16<80>) {
    $len +&= :16<7f>;

    if ($len) {
      return if $pos+$len > $end ;

      my $padding = $len < 4 ?? "\0" x (4 - $len) !! "";
      ($len,$pos) = (unpack("N", $padding ~ substr(@_[0],$pos,$len)), $pos+$len);
    }
    else {
      unless (exists $larr.{'$pos'}) {
        _scan_indef(@_[0],$pos,$end,$larr) or return;
      }
      $indef = 2;
      $len = $larr.{'$pos'};
    }
  }

  return if $pos+$len+$indef > $end;

  # return the tag, the length of the data, the position of the data
  # and the number of extra bytes for indefinate encoding

  ($tag, $len, $pos, $indef);
}

sub _scan_indef {
  my ($pos,$end,$larr) = @_[1,2,3];
  my @depth = ( $pos );

  while (@depth) {
    return if $pos+2 > $end;

    if (substr(@_[0],$pos,2) eq "\0\0") {
      my $end = $pos;
      my $stref = shift @depth;
      # replace pos with length = end - pos
      $larr.{'$stref'} = $end - $stref;
      $pos += 2;
      next;
    }

    my $tag = substr(@_[0], $pos++, 1);

    if ((unpack("C",$tag) +& :16<1f>) == :16<1f>) {
      my $b;
      do {
    $tag ~= substr(@_[0],$pos++,1);
    $b = ord substr($tag,-1);
      } while ($b +& :16<80>);
    }
    return if $pos >= $end;

    my $len = ord substr(@_[0],$pos++,1);

    if ($len +& :16<80>) {
      if ($len +&= :16<7f>) {
    return if $pos+$len > $end ;

    my $padding = $len < 4 ?? "\0" x (4 - $len) !! "";
    $pos += $len + unpack("N", $padding ~ substr(@_[0],$pos,$len));
      }
      else {
        # reserve another list element
        unshift @depth, $pos;
      }
    }
    else {
      $pos += $len;
    }
  }

  1;
}

sub _ctr_string { join '', @_ }

sub _ctr_bitstring {
  [ join('', map { $_.[0] }, @_), @_[*-1].[1] ]
}

sub _dec_bcd {
# 0      1    2       3     4     5     6
# $optn, $op, $stash, $var, $buf, $pos, $len

  (@_[3] = unpack("H*", substr(@_[4],@_[5],@_[6]))) ~~ s:P5/[fF]$//;
  1;
}
1;


##
## just for debug :-)
##

sub _hexdump {
  my ($fmt,$pos) = @_[1,2]; # Don't copy buffer

  $pos ||= 0;

  my $offset  = 0;
  my $cnt     = 1 +< 4;
  my $len     = length(@_[0]);
  my $linefmt = ("%02X " x $cnt) ~ "%s\n";

  "\n".print();

  while ($offset < $len) {
    my $data = substr(@_[0],$offset,$cnt);
    my @y = unpack("C*",$data);

    printf $fmt,$pos if $fmt;

    # On the last time through replace '%02X ' with '__ ' for the
    # missing values
    substr($linefmt, 5*@y,5*($cnt-@y)) = "__ " x ($cnt - @y)
    if @y != $cnt;

    # Change non-printable chars to '.'
    $data ~~ s:sc:P5/[\x00-\x1f\x7f-\xff]/./;
    printf $linefmt, @y,$data;

    $offset += $cnt;
    $pos += $cnt;
  }
}

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

sub asn_dump {
  my $fh = @_>1 ?? shift !! \*STDERR;

  my $ofh = select($fh);

  my $pos = 0;
  my $indent = "";
  my @seqend = ();
  my $length = length(@_[0]);
  my $fmt = $length > :16<ffff> ?? "%08X" !! "%04X";

  while (1) {
    while (@seqend && $pos >= @seqend[0]) {
      $indent = substr($indent,2);
      warn "Bad sequence length " unless $pos == shift @seqend;
      printf "$fmt     : %s\}\n",$pos,$indent;
    }
    last unless $pos < $length;
    
    my $start = $pos;
    my ($tb,$tag,$tnum) = asn_decode_tag2(substr(@_[0],$pos,10));
    last unless defined $tb;
    $pos += $tb;
    my ($lb,$len) = asn_decode_length(substr(@_[0],$pos,10));
    $pos += $lb;

    if ($tag == 0 && $len == 0) {
      @seqend[0] = $pos;
      redo;
    }
    printf $fmt~ " %4d: %s",$start,$len,$indent;

    my $label = %type{'sprintf'("%02X",$tag +& +^:16<20>)}
        || %type{'sprintf'("%02X",$tag +& :16<C0>)}
        || "[UNIVERSAL %d]";
    printf $label, $tnum;

    if ($tag +& ASN_CONSTRUCTOR) {
      " \{\n".print();
      if ($len < 0) {
          unshift(@seqend, length @_[0]);
      }
      else {
          unshift(@seqend, $pos + $len);
      }
      $indent ~= "  ";
      next;
    }

    my $tmp;

    for ($label) { # switch
      m:P5/^(INTEGER|ENUM)/ && do {
    Convert::ASN1::_dec_integer({},[],{},$tmp,@_[0],$pos,$len);
    printf " = %d\n",$tmp;
        last;
      };

      m:P5/^BOOLEAN/ && do {
    Convert::ASN1::_dec_boolean({},[],{},$tmp,@_[0],$pos,$len);
    printf " = %s\n",$tmp ?? 'TRUE' !! 'FALSE';
        last;
      };

      m:P5/^(?:(OBJECT ID)|(RELATIVE-OID))/ && do {
    my @op; @op[cTYPE] = $0 ?? opOBJID !! opROID;
    Convert::ASN1::_dec_object_id({},\@op,{},$tmp,@_[0],$pos,$len);
    printf " = %s\n",$tmp;
        last;
      };

      m:P5/^NULL/ && do {
    "\n".print();
        last;
      };

      m:P5/^STRING/ && do {
    Convert::ASN1::_dec_string({},[],{},$tmp,@_[0],$pos,$len);
    if ($tmp ~~ m:s:P5/[\x00-\x1f\x7f-\xff]/) {
        _hexdump($tmp,$fmt ~ "     :   "~$indent, $pos);
    }
    else {
      printf " = '%s'\n",$tmp;
    }
        last;
      };

#      /^BIT STRING/ && do {
#    Convert::BER::BIT_STRING->unpack($ber,\$tmp);
#    print " = ",$tmp,"\n";
#        last;
#      };

      # default -- dump hex data
      _hexdump(substr(@_[0],$pos,$len),$fmt ~ "     :   "~$indent, $pos);
    }
    $pos += $len;
  }
  printf "Buffer contains %d extra bytes\n", $length - $pos if $pos < $length;

  select($ofh);
}

sub asn_hexdump {
    my $fh = @_>1 ?? shift !! \*STDERR;
    my $ofh = select($fh);

    _hexdump(@_[0]);
    "\n".print();
    select($ofh);
}

sub dump {
  my $self = shift;
  
  for (@($self.{'script'})) {
    dump_op($_,"",{},1);
  }
}

sub dump_all {
  my $self = shift;
  
  while (my ($k,$v) = each %($self.{'tree'})) {
    $*ERR.print("$k:\n");
    for (@$v) {
      dump_op($_,"",{},1);
    }
  }
}


sub dump_op {
  my ($op,$indent,$done,$line) = @_;
  $indent ||= "";
  printf $*ERR "%3d: ",$line;
  if ($done.{'$op'}) {
    $*ERR.print("    $indent=",$done.{'$op'},"\n");
    return ++$line;
  }
  $done.{'$op'} = $line++;
  $*ERR.print($indent,"[ '",unpack("H*",$op.[cTAG]),"', ");
  $*ERR.print($op.[cTYPE] ~~ m:P5/\D/ ?? $op.[cTYPE] !! @opName[$op.[cTYPE]]);
  $*ERR.print(", ",defined($op.[cVAR]) ?? $op.[cVAR] !! "_");
  $*ERR.print(", ",defined($op.[cLOOP]) ?? $op.[cLOOP] !! "_");
  $*ERR.print(", ",defined($op.[cOPT]) ?? $op.[cOPT] !! "_");
  $*ERR.print("]");
  if ($op.[cCHILD]) {
    $*ERR.print(" ",scalar @($op.[cCHILD]),"\n");
    for (@($op.[cCHILD])) {
      $line = dump_op($_,$indent ~ " ",$done,$line);
    }
  }
  else {
    $*ERR.print("\n");
  }
  $*ERR.print("\n") unless length $indent;
  $line;
}

my $yydebug=0;

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

  SEQUENCE        => [ asn_encode_tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), opSEQUENCE ],
  EXPLICIT        => [ asn_encode_tag(ASN_SEQUENCE +| ASN_CONSTRUCTOR), opEXPLICIT ],
  SET               => [ asn_encode_tag(ASN_SET      +| ASN_CONSTRUCTOR), opSET ],

  ObjectDescriptor  => [ asn_encode_tag(ASN_UNIVERSAL +|  7), opSTRING ],
  UTF8String        => [ asn_encode_tag(ASN_UNIVERSAL +| 12), opUTF8 ],
  NumericString     => [ asn_encode_tag(ASN_UNIVERSAL +| 18), opSTRING ],
  PrintableString   => [ asn_encode_tag(ASN_UNIVERSAL +| 19), opSTRING ],
  TeletexString     => [ asn_encode_tag(ASN_UNIVERSAL +| 20), opSTRING ],
  T61String         => [ asn_encode_tag(ASN_UNIVERSAL +| 20), opSTRING ],
  VideotexString    => [ asn_encode_tag(ASN_UNIVERSAL +| 21), opSTRING ],
  IA5String         => [ asn_encode_tag(ASN_UNIVERSAL +| 22), opSTRING ],
  UTCTime           => [ asn_encode_tag(ASN_UNIVERSAL +| 23), opUTIME ],
  GeneralizedTime   => [ asn_encode_tag(ASN_UNIVERSAL +| 24), opGTIME ],
  GraphicString     => [ asn_encode_tag(ASN_UNIVERSAL +| 25), opSTRING ],
  VisibleString     => [ asn_encode_tag(ASN_UNIVERSAL +| 26), opSTRING ],
  ISO646String      => [ asn_encode_tag(ASN_UNIVERSAL +| 26), opSTRING ],
  GeneralString     => [ asn_encode_tag(ASN_UNIVERSAL +| 27), opSTRING ],
  CharacterString   => [ asn_encode_tag(ASN_UNIVERSAL +| 28), opSTRING ],
  UniversalString   => [ asn_encode_tag(ASN_UNIVERSAL +| 28), opSTRING ],
  BMPString         => [ asn_encode_tag(ASN_UNIVERSAL +| 30), opSTRING ],
  BCDString         => [ asn_encode_tag(ASN_OCTET_STR), opBCD ],

  CHOICE => [ '', opCHOICE ],
  ANY    => [ '', opANY ],

  EXTENSION_MARKER => [ '', opEXTENSIONS ],
);

my $tagdefault = 1; # 0:IMPLICIT , 1:EXPLICIT default

;# args: class,plicit
sub need_explicit {
  (defined(@_[0]) && (defined(@_[1])??@_[1]!!$tagdefault));
}

;# Given an OP, wrap it in a SEQUENCE

sub explicit {
  my $op = shift;
  my @seq = @$op;

  @seq[cTYPE,cCHILD,cVAR,cLOOP] = ('EXPLICIT',[$op],Any,Any);
  @($op)[cTAG,cOPT] = ();

  \@seq;
}




sub yyclearin { $yychar = -1; }
sub yyerrok { $yyerrflag = 0; }
sub YYERROR { ++$yynerrs; &yy_err_recover; }
sub yy_err_recover
{
  if ($yyerrflag < 3)
  {
    $yyerrflag = 3;
    while (1)
    {
      if (($yyn = @yysindex[@yyss[$yyssp]]) && 
          ($yyn += constYYERRCODE()) >= 0 && 
          $yyn <= @yycheck.end && @yycheck[$yyn] == constYYERRCODE())
      {




        @yyss[++$yyssp] = $yystate = @yytable[$yyn];
        @yyvs[++$yyvsp] = $yylval;
        next yyloop;
      }
      else
      {




        return(1) if $yyssp <= 0;
        --$yyssp;
        --$yyvsp;
      }
    }
  }
  else
  {
    return (1) if $yychar == 0;
    $yychar = -1;
    next yyloop;
  }
0;
} # yy_err_recover

sub yyparse
{

  if ($yys = %*ENV{'YYDEBUG'})
  {
    $yydebug = int($0) if $yys ~~ m:P5/^(\d)/;
  }


  $yynerrs = 0;
  $yyerrflag = 0;
  $yychar = (-1);

  $yyssp = 0;
  $yyvsp = 0;
  @yyss[$yyssp] = $yystate = 0;

yyloop: while (1)
  {
    yyreduce: {
      last yyreduce if ($yyn = @yydefred[$yystate]);
      if ($yychar < 0)
      {
        if (($yychar = &yylex) < 0) { $yychar = 0; }
      }
      if (($yyn = @yysindex[$yystate]) && ($yyn += $yychar) >= 0 &&
              $yyn <= @yycheck.end && @yycheck[$yyn] == $yychar)
      {




        @yyss[++$yyssp] = $yystate = @yytable[$yyn];
        @yyvs[++$yyvsp] = $yylval;
        $yychar = (-1);
        --$yyerrflag if $yyerrflag > 0;
        next yyloop;
      }
      if (($yyn = @yyrindex[$yystate]) && ($yyn += $yychar) >= 0 &&
            $yyn <= @yycheck.end && @yycheck[$yyn] == $yychar)
      {
        $yyn = @yytable[$yyn];
        last yyreduce;
      }
      if (?^ $yyerrflag) {
        &yyerror('syntax error');
        ++$yynerrs;
      }
      return Any if &yy_err_recover;
    } # yyreduce




    $yym = @yylen[$yyn];
    $yyval = @yyvs[$yyvsp+1-$yym];
    switch:
    {
my $label = "State$yyn";
goto $label if exists %yystate{'$label'};
last switch;
State1: {
# 107 "parser.y"
{ $yyval = { '' => @yyvs[$yyvsp-0] }; 
last switch;
} }
State3: {
# 112 "parser.y"
{
          $yyval = { @yyvs[$yyvsp-2], [@yyvs[$yyvsp-0]] };
        
last switch;
} }
State4: {
# 116 "parser.y"
{
          $yyval=@yyvs[$yyvsp-3];
          $yyval.{'@yyvs'[$yyvsp-2]} = [@yyvs[$yyvsp-0]];
        
last switch;
} }
State5: {
# 123 "parser.y"
{
          @yyvs[$yyvsp-1].[cTAG] = @yyvs[$yyvsp-3];
          $yyval = need_explicit(@yyvs[$yyvsp-3],@yyvs[$yyvsp-2]) ?? explicit(@yyvs[$yyvsp-1]) !! @yyvs[$yyvsp-1];
        
last switch;
} }
State11: {
# 137 "parser.y"
{
          @($yyval = [])[cTYPE,cCHILD] = ('COMPONENTS', @yyvs[$yyvsp-0]);
        
last switch;
} }
State14: {
# 147 "parser.y"
{
          @yyvs[$yyvsp-1].[cTAG] = @yyvs[$yyvsp-3];
          @($yyval = [])[cTYPE,cCHILD,cLOOP,cOPT] = (@yyvs[$yyvsp-5], [@yyvs[$yyvsp-1]], 1, @yyvs[$yyvsp-0]);
          $yyval = explicit($yyval) if need_explicit(@yyvs[$yyvsp-3],@yyvs[$yyvsp-2]);
        
last switch;
} }
State18: {
# 160 "parser.y"
{
          @($yyval = [])[cTYPE,cCHILD] = ('SEQUENCE', @yyvs[$yyvsp-1]);
        
last switch;
} }
State19: {
# 164 "parser.y"
{
          @($yyval = [])[cTYPE,cCHILD] = ('SET', @yyvs[$yyvsp-1]);
        
last switch;
} }
State20: {
# 168 "parser.y"
{
          @($yyval = [])[cTYPE,cCHILD] = ('CHOICE', @yyvs[$yyvsp-1]);
        
last switch;
} }
State21: {
# 174 "parser.y"
{
          @($yyval = [])[cTYPE] = ('ENUM');
        
last switch;
} }
State22: {
# 179 "parser.y"
{ @($yyval = [])[cTYPE] = @yyvs[$yyvsp-0]; 
last switch;
} }
State23: {
# 180 "parser.y"
{ @($yyval = [])[cTYPE] = @yyvs[$yyvsp-0]; 
last switch;
} }
State24: {
# 181 "parser.y"
{ @($yyval = [])[cTYPE] = @yyvs[$yyvsp-0]; 
last switch;
} }
State25: {
# 183 "parser.y"
{
          @($yyval = [])[cTYPE,cCHILD,cDEFINE] = ('ANY',Any,@yyvs[$yyvsp-0]);
        
last switch;
} }
State26: {
# 186 "parser.y"
{ @($yyval = [])[cTYPE] = @yyvs[$yyvsp-0]; 
last switch;
} }
State27: {
# 189 "parser.y"
{ $yyval=Any; 
last switch;
} }
State28: {
# 190 "parser.y"
{ $yyval=@yyvs[$yyvsp-0]; 
last switch;
} }
State30: {
# 196 "parser.y"
{ $yyval = @yyvs[$yyvsp-0]; 
last switch;
} }
State31: {
# 197 "parser.y"
{ $yyval = @yyvs[$yyvsp-1]; 
last switch;
} }
State32: {
# 201 "parser.y"
{
          $yyval = [ @yyvs[$yyvsp-0] ];
        
last switch;
} }
State33: {
# 205 "parser.y"
{
          push @($yyval=@yyvs[$yyvsp-2]), @yyvs[$yyvsp-0];
        
last switch;
} }
State34: {
# 209 "parser.y"
{
          push @($yyval=@yyvs[$yyvsp-2]), @yyvs[$yyvsp-0];
        
last switch;
} }
State35: {
# 215 "parser.y"
{
          @($yyval=@yyvs[$yyvsp-0])[cVAR,cTAG] = (@yyvs[$yyvsp-3],@yyvs[$yyvsp-2]);
          $yyval = explicit($yyval) if need_explicit(@yyvs[$yyvsp-2],@yyvs[$yyvsp-1]);
        
last switch;
} }
State36: {
# 220 "parser.y"
{
            @($yyval=[])[cTYPE] = 'EXTENSION_MARKER';
        
last switch;
} }
State37: {
# 226 "parser.y"
{ $yyval = []; 
last switch;
} }
State38: {
# 228 "parser.y"
{
          my $extension = 0;
          $yyval = [];
          for (@(@yyvs[$yyvsp-0])) -> $i {
            $extension = 1 if $i.[cTYPE] eq 'EXTENSION_MARKER';
            $i.[cEXT] = $i.[cOPT];
            $i.[cEXT] = 1 if $extension;
            push @($yyval), $i unless $i.[cTYPE] eq 'EXTENSION_MARKER';
          }
          my $e = []; $e.[cTYPE] = 'EXTENSION_MARKER';
          push @($yyval), $e if $extension;
        
last switch;
} }
State39: {
# 241 "parser.y"
{
          my $extension = 0;
          $yyval = [];
          for (@(@yyvs[$yyvsp-1])) -> $i {
            $extension = 1 if $i.[cTYPE] eq 'EXTENSION_MARKER';
            $i.[cEXT] = $i.[cOPT];
            $i.[cEXT] = 1 if $extension;
            push @($yyval), $i unless $i.[cTYPE] eq 'EXTENSION_MARKER';
          }
          my $e = []; $e.[cTYPE] = 'EXTENSION_MARKER';
          push @($yyval), $e if $extension;
        
last switch;
} }
State40: {
# 256 "parser.y"
{
          $yyval = [ @yyvs[$yyvsp-0] ];
        
last switch;
} }
State41: {
# 260 "parser.y"
{
          push @($yyval=@yyvs[$yyvsp-2]), @yyvs[$yyvsp-0];
        
last switch;
} }
State42: {
# 264 "parser.y"
{
          push @($yyval=@yyvs[$yyvsp-2]), @yyvs[$yyvsp-0];
        
last switch;
} }
State43: {
# 270 "parser.y"
{
          @($yyval=@yyvs[$yyvsp-1])[cOPT] = (@yyvs[$yyvsp-0]);
        
last switch;
} }
State47: {
# 279 "parser.y"
{
          @($yyval=@yyvs[$yyvsp-0])[cVAR,cTAG] = (@yyvs[$yyvsp-3],@yyvs[$yyvsp-2]);
          $yyval.[cOPT] = @yyvs[$yyvsp-3] if $yyval.[cOPT];
          $yyval = explicit($yyval) if need_explicit(@yyvs[$yyvsp-2],@yyvs[$yyvsp-1]);
        
last switch;
} }
State49: {
# 286 "parser.y"
{
          @($yyval=@yyvs[$yyvsp-0])[cTAG] = (@yyvs[$yyvsp-2]);
          $yyval = explicit($yyval) if need_explicit(@yyvs[$yyvsp-2],@yyvs[$yyvsp-1]);
        
last switch;
} }
State50: {
# 291 "parser.y"
{
            @($yyval=[])[cTYPE] = 'EXTENSION_MARKER';
        
last switch;
} }
State51: {
# 296 "parser.y"
{ $yyval = Any; 
last switch;
} }
State52: {
# 297 "parser.y"
{ $yyval = 1;     
last switch;
} }
State53: {
# 301 "parser.y"
{ $yyval = Any; 
last switch;
} }
State55: {
# 305 "parser.y"
{ $yyval = Any; 
last switch;
} }
State56: {
# 306 "parser.y"
{ $yyval = 1;     
last switch;
} }
State57: {
# 307 "parser.y"
{ $yyval = 0;     
last switch;
} }
State58: {
# 310 "parser.y"
{
last switch;
} }
State59: {
# 311 "parser.y"
{
last switch;
} }
State60: {
# 314 "parser.y"
{
last switch;
} }
State61: {
# 317 "parser.y"
{
last switch;
} }
State62: {
# 318 "parser.y"
{
last switch;
} }
    } # switch
    $yyssp -= $yym;
    $yystate = @yyss[$yyssp];
    $yyvsp -= $yym;
    $yym = @yylhs[$yyn];
    if ($yystate == 0 && $yym == 0)
    {




      $yystate = constYYFINAL();
      @yyss[++$yyssp] = constYYFINAL();
      @yyvs[++$yyvsp] = $yyval;
      if ($yychar < 0)
      {
        if (($yychar = &yylex) < 0) { $yychar = 0; }
      }
      return @yyvs[$yyvsp] if $yychar == 0;
      next yyloop;
    }
    if (($yyn = @yygindex[$yym]) && ($yyn += $yystate) >= 0 &&
        $yyn <= @yycheck.end && @yycheck[$yyn] == $yystate)
    {
        $yystate = @yytable[$yyn];
    } else {
        $yystate = @yydgoto[$yym];
    }




    @yyss[++$yyssp] = $yystate;
    @yyvs[++$yyvsp] = $yyval;
  } # yyloop
} # yyparse
# 322 "parser.y"


my $reserved = join("|", reverse sort grep { m:P5/\w/ }, keys %reserved);


##
## This is NOT thread safe !!!!!!
##

my $pos;
my $last_pos;
my @stacked;

sub parse {
  local(*asn) = \(@_[0]);
  $tagdefault = @_[1] eq 'EXPLICIT' ?? 1 !! 0;
  ($pos,$last_pos,@stacked) = ();

  EVAL {
    compile(verify(yyparse()));
  }
}

sub compile_one {
  my $tree = shift;
  my $ops = shift;
  my $name = shift;
  for (@$ops) -> $op {
    next unless ref($op) eq 'ARRAY';
    bless $op;
    my $type = $op.[cTYPE];
    if (exists %base_type{'$type'}) {
      $op.[cTYPE] = %base_type{'$type'}.[1];
      $op.[cTAG] = defined($op.[cTAG]) ?? asn_encode_tag($op.[cTAG])!! %base_type{'$type'}.[0];
    }
    else {
      die "Unknown type '$type'\n" unless exists $tree.{'$type'};
      my $ref = compile_one(
          $tree,
          $tree.{'$type'},
          defined($op.[cVAR]) ?? $name ~ "." ~ $op.[cVAR] !! $name
        );
      if (defined($op.[cTAG]) && $ref.[0][cTYPE] == opCHOICE) {
        @($op)[cTYPE,cCHILD] = (opSEQUENCE,$ref);
      }
      else {
        @($op)[cTYPE,cCHILD,cLOOP] = @($ref.[0])[cTYPE,cCHILD,cLOOP];
      }
      $op.[cTAG] = defined($op.[cTAG]) ?? asn_encode_tag($op.[cTAG])!! $ref.[0][cTAG];
    }
    $op.[cTAG] +|= pack("C",ASN_CONSTRUCTOR)
      if length $op.[cTAG] && ($op.[cTYPE] == opSET || $op.[cTYPE] == opEXPLICIT || $op.[cTYPE] == opSEQUENCE);

    if ($op.[cCHILD]) {
      ;# If we have children we are one of
      ;#  opSET opSEQUENCE opCHOICE opEXPLICIT

      compile_one($tree, $op.[cCHILD], defined($op.[cVAR]) ?? $name ~ "." ~ $op.[cVAR] !! $name);

      ;# If a CHOICE is given a tag, then it must be EXPLICIT
      if ($op.[cTYPE] == opCHOICE && defined($op.[cTAG]) && length($op.[cTAG])) {
    $op = bless explicit($op);
    $op.[cTYPE] = opSEQUENCE;
      }

      if ( @($op.[cCHILD]) > 1) {
        ;#if ($op->[cTYPE] != opSEQUENCE) {
        ;# Here we need to flatten CHOICEs and check that SET and CHOICE
        ;# do not contain duplicate tags
        ;#}
    if ($op.[cTYPE] == opSET) {
      ;# In case we do CER encoding we order the SET elements by thier tags
      my @tags = map { 
        length($_.[cTAG])
        ?? $_.[cTAG]
        !! $_.[cTYPE] == opCHOICE
            ?? (sort map { $_.[cTAG] }, $_.[cCHILD])[0]
            !! ''
      }, @($op.[cCHILD]);
      @($op.[cCHILD]) = @($op.[cCHILD])[sort { @tags[$a] leg @tags[$b] } 0..@tags.end];
    }
      }
      else {
    ;# A SET of one element can be treated the same as a SEQUENCE
    $op.[cTYPE] = opSEQUENCE if $op.[cTYPE] == opSET;
      }
    }
  }
  $ops;
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

  while (my ($k,$v) = each %$tree) {
    compile_one($tree,$v,$k);
  }

  $tree;
}

sub verify {
  my $tree = shift or return;
  my $err = "";

  # Well it parsed correctly, now we
  #  - check references exist
  #  - flatten COMPONENTS OF (checking for loops)
  #  - check for duplicate var names

  while (my ($name,$ops) = each %$tree) {
    my $stash = {};
    my @scope = ();
    my $path = "";
    my $idx = 0;

    while ($ops) {
        if ($idx < @$ops) {
            my $op = $ops.[$idx++];
            my $var;

            if (defined ($var = $op.[cVAR])) {

                $err ~= "$name: $path.$var used multiple times\n"
                if $stash.{'$var'}++;

            }

            if (defined $op.[cCHILD]) {
                if (ref $op.[cCHILD]) {
                    push @scope, [$stash, $path, $ops, $idx];
                    if (defined $var) {
                        $stash = {};
                        $path ~= "." ~ $var;
                    }
                    $idx = 0;
                    $ops = $op.[cCHILD];
                }

                elsif ($op.[cTYPE] eq 'COMPONENTS') {
                    splice(@$ops,--$idx,1,expand_ops($tree, $op.[cCHILD]));
                }

                else {
                    die "Internal error\n";
                }
            }
        }
        else {
            my $s = pop @scope or last;
            ($stash,$path,$ops,$idx) = @$s;
        }
    }

  }

  die $err if length $err;
  $tree;
}

sub expand_ops {
  my $tree = shift;
  my $want = shift;
  my $seen = shift || { };
  
  die "COMPONENTS OF loop $want\n" if $seen.{'$want'}++;
  die "Undefined macro $want\n" unless exists $tree.{'$want'};
  my $ops = $tree.{'$want'};
  die "Bad macro for COMPUNENTS OF '$want'\n"
    unless @$ops == 1
        && ($ops.[0][cTYPE] eq 'SEQUENCE' || $ops.[0][cTYPE] eq 'SET')
        && ref $ops.[0][cCHILD];
  $ops = $ops.[0][cCHILD];
  loop (my $idx = 0 ; $idx < @$ops ; ) {
    my $op = $ops.[$idx++];
    if ($op.[cTYPE] eq 'COMPONENTS') {
      splice(@$ops,--$idx,1,expand_ops($tree, $op.[cCHILD], $seen));
    }
  }

  @$ops;
}

sub _yylex {
  my $ret = &_yylex;
  warn $ret;
  $ret;
}

sub yylex {
  return shift @stacked if @stacked;

  while ($asn ~~ m:sxc:P5/\G(?:
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
    )/
  ) {

    ($last_pos,$pos) = ($pos,pos($asn));

    next if defined $0; # comment or whitespace

    if (defined $1 or defined $2) {
      my $ret = $/[$/.end];

      # A comma is not required after a '}' so to aid the
      # parser we insert a fake token after any '}'
      if ($ret eq '}') {
        my $p   = pos($asn);
        my @tmp = @stacked;
        @stacked = ();
        pos($asn) = $p if yylex() != constCOMMA();    # swallow it
        @stacked = (@tmp, constPOSTRBRACE());
      }

      return %reserved{'$yylval' = $ret};
    }

    if (defined $3) {
      ($yylval = $/[$/.end]) ~~ s:c:P5/\s+/_/;
      return constWORD();
    }

    if (defined $4) {
      $yylval = $/[$/.end];
      return constWORD();
    }

    if (defined $5) {
      my ($class,$num) = ($/[$/.end] ~~ m:P5/^([A-Z]*)\s*(\d+)$/);
      $yylval = asn_tag(%tag_class{'$class'}, $num); 
      return constCLASS();
    }

    if (defined $6) {
      $yylval = $/[$/.end];
      return constNUMBER();
    }

    if (defined $7) {
      return constEXTENSION_MARKER();
    }

    die "Internal error\n";

  }

  die "Parse error before ",substr($asn,$pos,40),"\n"
    unless $pos == length($asn);

  0;
}

sub yyerror {
  die @_," ",substr($asn,$last_pos,40),"\n";
}

1;
