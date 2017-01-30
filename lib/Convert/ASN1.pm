# Copyright (c) 2000-2002 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Convert::ASN1;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Data::Dump;

use Convert::ASN1::Parser;
use Convert::ASN1::Lexer;
use Convert::ASN1::Verifier;
use Convert::ASN1::Compiler;
use Convert::ASN1::Decoder;
use Convert::ASN1::Encoder;

use Exporter;
use Socket;
use Math::BigInt;
use POSIX;

# Figure out how to not use this
use bytes;

# Figure out how to not use this
require Encode;

our ($VERSION, @ISA, @EXPORT_OK, %EXPORT_TAGS, );

# Standard export stuff
@ISA = qw(Exporter);

%EXPORT_TAGS = (
io    => [qw(asn_recv asn_send asn_read asn_write asn_get asn_ready)],

debug => [qw(asn_dump asn_hexdump)],

    tag   => [qw(asn_tag  asn_decode_tag asn_encode_tag asn_decode_length asn_encode_length)]
);

@EXPORT_OK = map { @$_ } values %EXPORT_TAGS;
$EXPORT_TAGS{all} = \@EXPORT_OK;

# Create new object
sub new {
    my $class = shift;
    my $self = bless {}, $class;

    $self->configure(@_);
    $self;
}

sub configure {
    my $self = shift;
    my %opt = @_;

    $self->{options}{encoding} = uc($opt{encoding} || 'BER');

    unless ($self->{options}{encoding} =~ /^[BD]ER$/) {
        die "Unsupported encoding format '$opt{encoding}'";
    }

    # IMPLICIT as defalt for backwards compatibility, even though it's wrong.
    $self->{options}{tagdefault} = uc($opt{tagdefault} || 'IMPLICIT');

    unless ($self->{options}{tagdefault} =~ /^(?:EXPLICIT|IMPLICIT)$/) {
        die "Default tagging must be EXPLICIT/IMPLICIT. Not $opt{tagdefault}";
    }


    for my $type (qw(encode decode)) {
        if (exists $opt{ $type }) {
            while ( my ($what, $value) = each %{ $opt{ $type } } ) {
                die unless $what =~ /timezone|time|bigint/;
                $self->{options}{"${type}_${what}"} = $value;
            }
        }
    }
}

# Find "what" in the parsed tree and return it as a new object
sub find {
    my $self = shift;
    my $what = shift;

    return unless exists $self->{tree}{$what};

    my %new = %$self;

    $new{script} = $new{tree}->{$what};
    bless \%new, ref($self);
}

sub prepare {
    my $self = shift;
    my $asn  = shift;

    my $tree = parse($asn, $self->{options}{tagdefault});

    die 'Could not prepare tree' unless $tree;

    $self->{tree} = $tree;
    $self->{script} = (values %$tree)[0];

    return $self;
}

sub registeroid {
    my $self = shift;
    my $oid  = shift;
    my $handler = shift;

    $self->{options}{oidtable}{$oid} = $handler;
    $self->{oidtable}{$oid} = $handler;
}


##
## Encoding
##

sub encode {
    return Convert::ASN1::Encoder::encode(@_);
}


# Encode a length. If < 0x80 then encode as a byte. Otherwise encode
# 0x80 | num_bytes followed by the bytes for the number. top end
# bytes of all zeros are not encoded

sub asn_encode_length {
    my $length = shift;

    if($length >> 7) {
        my $lenlen = num_length($length);

        return pack(
            "Ca*",
            $lenlen | 0x80,
            substr(pack("N" ,$length), -$lenlen)
        );
    }

    return pack("C", $length);
}


##
## Decoding
##

sub decode {
    return Convert::ASN1::Decoder::decode(@_);
}


sub asn_decode_length {
    return unless length $_[0];

    my $len = unpack("C",$_[0]);

    if($len & 0x80) {
        $len &= 0x7f or return (1,-1);

        return if $len >= length $_[0];

        return (1+$len, unpack("N", "\0" x (4 - $len) . substr($_[0],1,$len)));
    }

    return (1, $len);
}


sub asn_decode_tag {
    say "raw_tag => ", unpack('H*', $_[0]);
  return unless length $_[0];

  my $tag = unpack("C", $_[0]);
  say "tag => ", $tag;
  my $n = 1;

  if(($tag & 0x1f) == 0x1f) {
    my $b;
    do {
      say "returnin'" && return if $n >= length $_[0];
      $b = unpack("C",substr($_[0],$n,1));
      $tag |= $b << (8 * $n++);
    } while($b & 0x80);
  }
  say "n => ", $n;
  say "tag (now) => ", $tag;
  return ($n, $tag);
}




##
## Utilities
##

# How many bytes are needed to encode a number 

sub num_length {
  $_[0] >> 8
    ? $_[0] >> 16
      ? $_[0] >> 24
    ? 4
    : 3
      : 2
    : 1
}

# Convert from a bigint to an octet string

sub i2osp {
    my($num, $biclass) = @_;
    $num = $biclass->new($num);
    my $neg = $num < 0
      and $num = abs($num+1);
    my $base = $biclass->new(256);
    my $result = '';
    while($num != 0) {
        my $r = $num % $base;
        $num = ($num-$r) / $base;
        $result .= pack("C",$r);
    }
    $result ^= pack("C",255) x length($result) if $neg;
    return scalar reverse $result;
}

# Convert from an octet string to a bigint

sub os2ip {
    my($os, $biclass) = @_;
    my $base = $biclass->new(256);
    my $result = $biclass->new(0);
    my $neg = unpack("C",$os) >= 0x80
      and $os ^= pack("C",255) x length($os);
    for (unpack("C*",$os)) {
      $result = ($result * $base) + $_;
    }
    return $neg ? ($result + 1) * -1 : $result;
}

# Given a class and a tag, calculate an integer which when encoded
# will become the tag. This means that the class bits are always
# in the bottom byte, so are the tag bits if tag < 30. Otherwise
# the tag is in the upper 3 bytes. The upper bytes are encoded
# with bit8 representing that there is another byte. This
# means the max tag we can do is 0x1fffff

sub asn_tag {
  my($class,$value) = @_;

  die sprintf "Bad tag class 0x%x",$class
    if $class & ~0xe0;

  unless ($value & ~0x1f or $value == 0x1f) {
      say "THERE";
    return (($class & 0xe0) | $value);
  }

  die sprintf "Tag value 0x%08x too big\n",$value
    if $value & 0xffe00000;

  $class = ($class | 0x1f) & 0xff;

  my @t = ($value & 0x7f);
  unshift @t, (0x80 | ($value & 0x7f)) while $value >>= 7;

  # dd \@t;
  # say $class;
  my $bytes = pack("C4",$class,@t,0,0);
  # my $bytes = pack("C4",95,130,1,0,0);
  # dd $bytes;
  # say "HERE";
  return unpack("V", $bytes);
}

sub asn_recv { # $socket, $buffer, $flags
    my ($socket, $buffer, $flags) = @_;

    my $peer;
    my $buf;
    my $n = 128;
    my $pos = 0;
    my $depth = 0;
    my $len = 0;
    my($tmp,$tb,$lb);

    MORE:
    for(
        $peer = recv($socket, $buf ,$n, MSG_PEEK);
        defined $peer;
        $peer = recv($socket, $buf, $n<<=1, MSG_PEEK)
    ) {

        if ($depth) { # Are we searching of "\0\0"
            unless (2+$pos <= length $buf) {
            next MORE if $n == length $buf;
            last MORE;
        }

        if (substr($buf, $pos, 2) eq "\0\0") {
            unless (--$depth) {
                $len = $pos + 2;
                last MORE;
            }
        }
        }

        # If we can decode a tag and length we can detemine the length
        ($tb,$tmp) = asn_decode_tag(substr($buf, $pos));
        unless ($tb || $pos+$tb < length $buf) {
            next MORE if $n == length $buf;
            last MORE;
        }

        if (unpack("C",substr($buf, $pos+$tb, 1)) == 0x80) {
            # indefinite length, grrr!
            $depth++;
            $pos += $tb + 1;
            redo MORE;
        }

        ($lb,$len) = asn_decode_length(substr($buf, $pos+$tb));

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
                unless defined($peer = recv($socket, $buf, $len, MSG_PEEK));

            if ($len > length $buf) {
                # Cannot get whole element
                $_[1] = '';
                return $peer;
            }
        }
        elsif ($len == 0) {
            $_[1] = '';
            return $peer;
        }

        if ($flags & MSG_PEEK) {
            $_[1] = substr($buf, 0, $len);
        }
        elsif (!defined($peer = recv($socket, $_[1], $len, 0))) {
            goto error;
        }

        return $peer;
    }

    error:
        $_[1] = undef;
}

sub asn_read { # $fh, $buffer, $offset
    my ($fh, $buffer, $offset) = @_;

    # We need to read one packet, and exactly only one packet.
    # So we have to read the first few bytes one at a time, until
    # we have enough to decode a tag and a length. We then know
    # how many more bytes to read

    if ($offset) {
        if ($offset > length $_[1]) {
            die "Offset beyond end of buffer";
            return;
        }
        substr($_[1], $offset) = '';
    }
    else {
        $_[1] = '';
    }

    my $pos = 0;
    my $need = 0;
    my $depth = 0;
    my $ch;
    my $n;
    my $e;

    while(1) {
        $need = ($pos + ($depth * 2)) || 2;

        while(($n = $need - length $_[1]) > 0) {
            $e = sysread($fh, $_[1], $n, length $_[1]) or
            goto READ_ERR;
        }

        my $tch = unpack("C",substr($_[1],$pos++,1));
        # Tag may be multi-byte
        if(($tch & 0x1f) == 0x1f) {
            my $ch;
            do {
                $need++;
                while(($n = $need - length $_[1]) > 0) {
                    $e = sysread($fh, $_[1], $n, length $_[1]) or
                    goto READ_ERR;
                }
                $ch = unpack("C", substr($_[1], $pos++, 1));
            }
            while($ch & 0x80);
        }

        $need = $pos + 1;

        while(($n = $need - length $_[1]) > 0) {
            $e = sysread($fh, $_[1], $n, length $_[1]) or
            goto READ_ERR;
        }

        my $len = unpack("C",substr($_[1],$pos++,1));

        if($len & 0x80) {
            unless ($len &= 0x7f) {
                $depth++;
                next;
            }
            $need = $pos + $len;

            while(($n = $need - length $_[1]) > 0) {
                $e = sysread($fh, $_[1], $n, length $_[1]) or
                    goto READ_ERR;
            }

            $pos += $len + unpack("N", "\0" x (4 - $len)
                . substr($_[1], $pos, $len));
        }

        elsif (!$len && !$tch) {
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

    while(($n = $pos - length $_[1]) > 0) {
        $e = sysread($fh, $_[1], $n, length $_[1]) or
            goto READ_ERR;
    }

    return length $_[1];

    READ_ERR:
        $@ = defined($e)
            ? "Unexpected EOF"
            : "I/O Error $!"; # . CORE::unpack("H*",$_[1]);
        return;
}

sub asn_send { # $sock, $buffer, $flags, $to
    my ($sock, $buffer, $flags, $to) = @_;

    @_ == 4
        ? send($sock, $buffer, $flags, $to)
        : send($sock, $buffer, $flags);
}

sub asn_write { # $sock, $buffer
    my ($sock, $buffer) = @_;

    syswrite($sock ,$buffer, length $buffer);
}

sub asn_get { # $fh

    my $fh = ref($_[0]) ? $_[0] : \($_[0]);
    my $href = \%{*$fh};

    $href->{'asn_buffer'} = '' unless exists $href->{'asn_buffer'};

    my $need = delete $href->{'asn_need'} || 0;
    while(1) {
        next if $need;
        my($tb, $tag) = asn_decode_tag($href->{'asn_buffer'}) or next;
        my($lb, $len) = asn_decode_length(substr($href->{'asn_buffer'}, $tb, 8)) or next;
        $need = $tb + $lb + $len;
    }
    continue {
        if ($need && $need <= length $href->{'asn_buffer'}) {
            my $ret = substr($href->{'asn_buffer'}, 0, $need);
            substr($href->{'asn_buffer'}, 0, $need) = '';
            return $ret;
        }

        my $get = $need > 1024 ? $need : 1024;

        sysread($fh, $href->{'asn_buffer'}, $get, length $href->{'asn_buffer'})
            or return;
    }
}

sub asn_ready { # $fh

    my $fh = ref($_[0]) ? $_[0] : \($_[0]);
    my $href = \%{*$fh};

    return 0 unless exists $href->{'asn_buffer'};

    return $href->{'asn_need'} <= length $href->{'asn_buffer'}
        if exists $href->{'asn_need'};

    my($tb,$tag) = asn_decode_tag($href->{'asn_buffer'}) or return 0;
    my($lb,$len) = asn_decode_length(substr($href->{'asn_buffer'},$tb,8)) or return 0;

    $href->{'asn_need'} = $tb + $lb + $len;

    $href->{'asn_need'} <= length $href->{'asn_buffer'};
}

sub my_lex {
    my $self = shift;
    my $asn = shift;
    return Convert::ASN1::Lexer::xxlex($asn);
}

sub my_parse {
    my $self = shift;
    my $lex = shift;
    my $tagdefault = shift;
    return Convert::ASN1::Parser::parse($lex, $tagdefault);
}

sub my_verify {
    my $self = shift;
    my $yyparse = shift;
    return Convert::ASN1::Verifier::verify($yyparse);
}

sub my_compile {
    my $self = shift;
    my $verified = shift;
    return Convert::ASN1::Compiler::compile($verified);
}

sub parse {
    my $asn = $_[0];

    my $tagdefault = $_[1] eq 'EXPLICIT' ? 1 : 0;

    my $lex = Convert::ASN1::Lexer::xxlex($asn);

    my $yyparse = Convert::ASN1::Parser::parse($lex, $tagdefault);

    my $verified = Convert::ASN1::Verifier::verify($yyparse);

    my $compile = Convert::ASN1::Compiler::compile($verified);

    return $compile;
}

sub error { $_[0]->{error} }

1;
