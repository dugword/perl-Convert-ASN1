package Convert::ASN1::Decoder;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Convert::ASN1::Constants qw(:all);

use Data::Dump;

my @_dec_real_base = (2, 8, 16);

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
    undef, # ANY
    undef, # CHOICE
    \&_dec_object_id,
    \&_dec_bcd,
);

my @ctr;
@ctr[opBITSTR, opSTRING, opUTF8] = (\&_ctr_bitstring, \&_ctr_string, \&_ctr_string);

my $tag_loop;

$tag_loop = sub {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;;
    my $idx = shift;
    my $var = shift;

    my($error, $tag, $len, $npos, $indef) = _decode_tl($buf, $pos, $end, $larr);

    if ($error) {
        if (($pos == $end) and ($seqof || defined $op->[cEXT])) {
            return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
        }
        die "decode error";
    }

    if ($tag eq $op->[cTAG]) {

        # We send 1 if there is not var as if there is the decode
        # should be getting undef. So if it does not get undef
        # it knows it has no variable
        # my $foo = ($seqof ? $seqof->[$idx++] : defined($var) ? $stash->{$var} : ref($stash) eq 'SCALAR' ? $$stash : 1);

        my ($int_flag, $x_result) = &{$decode[$op->[cTYPE]]}(
            $optn,
            $op,
            $stash,
            ($seqof ? $seqof->[$idx++] : defined($var) ? $stash->{$var} : ref($stash) eq 'SCALAR' ? $$stash : 1),
            # $foo,
            $buf,
            $npos,
            $len,
            $larr,
        );

        if ($int_flag && ($int_flag eq 'int' || $int_flag eq 'bcd')) {
            if ($seqof) {
                $seqof->[$idx - 1] = $x_result;
            }
            elsif (defined($var)) {
                $stash->{$var} = $x_result;
            }
            elsif (ref($stash) eq 'SCALAR') {
                $$stash = $x_result;
            }
        }

        $pos = $npos + $len + $indef;

        if ($seqof && $pos < $end) {
            return &$tag_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
        }

        return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
    }

    if ($tag eq ($op->[cTAG] | pack("C",ASN_CONSTRUCTOR))) {
        my $ctr = $ctr[$op->[cTYPE]];

        _decode(
            $optn,
            [$op],
            undef,
            $npos,
            $npos+$len,
            (\my @ctrlist),
            $larr,
            $buf,
        );

        ($seqof ? $seqof->[$idx++] : defined($var) ? $stash->{$var} : ref($stash) eq 'SCALAR' ? $$stash : undef) = &{$ctr}(@ctrlist);

        $pos = $npos + $len + $indef;

        if ($seqof && $pos < $end) {
            return &$tag_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
        }

        return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
    }

    if ($seqof || defined $op->[cEXT]) {
        return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
    }

    die "decode error " . unpack("H*",$tag) ."<=>" . unpack("H*",$op->[cTAG]), " ", $pos, " ", $op->[cTYPE], " ", $op->[cVAR] || '';

};


my $any_loop;

$any_loop = sub {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;;
    my $idx = shift;
    my $var = shift;

    my($error, $tag,$len,$npos,$indef) = _decode_tl($buf,$pos,$end,$larr);
    if ($error) {

        if ($pos == $end and ($seqof || defined $op->[cEXT])) {
            return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
        }

        die "decode error";
    }

    $len += $npos - $pos + $indef;

        my $handler;
        if ($op->[cDEFINE]) {
            $handler = $optn->{oidtable} && $optn->{oidtable}{$stash->{$op->[cDEFINE]}};
            $handler ||= $optn->{handlers}{$op->[cVAR]}{$stash->{$op->[cDEFINE]}};
        }

    ($seqof ? $seqof->[$idx++] : ref($stash) eq 'SCALAR' ? $$stash : $stash->{$var})
        = $handler ? $handler->decode(substr($buf,$pos,$len)) : substr($buf,$pos,$len);

    $pos += $len;

    if ($seqof && $pos < $end) {
        return &$any_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
    }

    return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
};

my $while_decode;

$while_decode = sub {
    my $script = shift;
    my $result = shift;
    my $stash = shift;
    my $stash_hash = shift;

    my $child = $script->[0] or return ($script, $result, $stash, $stash_hash);

    if (@$script > 1 or defined $child->[cVAR]) {
        $result = $stash = $stash_hash;

        return ($script, $result, $stash, $stash_hash);
    }

    return ($script, $result, $stash, $stash_hash) if $child->[cTYPE] == opCHOICE or $child->[cLOOP];
    $script = $child->[cCHILD];

    return &$while_decode($script, $result, $stash, $stash_hash);
};

sub decode {
    my $self  = shift;
    my $pdu = shift;

    my $stash_hash = {};
    my $result;
    my $script = $self->{script};
    my $stash = \$result;

    ($script, $result, $stash, $stash_hash) = &$while_decode($script, $result, $stash, $stash_hash);

    _decode(
        $self->{options},
        $self->{script},
        $stash,
        0,
        length $pdu,
        undef,
        {},
        $pdu,
    );


    return $result
}


my $choice_loop_alpha;
$choice_loop_alpha = sub {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;;
    my $idx = shift;
    my $var = shift;
    my $tag = shift;
    my $len = shift;
    my $npos = shift;
    my $indef = shift;
    my $cop = shift;

    my $nstash = $seqof
        ? ($seqof->[$idx++]={})
        : defined($var)
            ? ($stash->{$var}={})
            : ref($stash) eq 'SCALAR'
                ? ($$stash={}) : $stash;

    my ($int_flag, $x_result) = &{$decode[$cop->[cTYPE]]}(
        $optn,
        $cop,
        $nstash,
        ($cop->[cVAR] ? $nstash->{$cop->[cVAR]} : undef),
        $buf,
        $npos,
        $len,
        $larr,
    );

    if ($int_flag && ($int_flag eq 'int' || $int_flag eq 'bcd')) {
        ($cop->[cVAR] ? $nstash->{$cop->[cVAR]} : undef) = $x_result;
    }

    $pos = $npos + $len + $indef;

    return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop);
};

my $choice_loop_beta;
$choice_loop_beta = sub {

    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;;
    my $idx = shift;
    my $var = shift;
    my $tag = shift;
    my $len = shift;
    my $npos = shift;
    my $indef = shift;
    my $cop = shift;

    _decode(
        $optn,
        [$cop],
        (\my %tmp_stash),
        $pos,
        $npos+$len+$indef,
        undef,
        $larr,
        $buf,
    );

    my $nstash = $seqof
        ? ($seqof->[$idx++]={})
        : defined($var)
            ? ($stash->{$var}={})
            : ref($stash) eq 'SCALAR'
                ? ($$stash={}) : $stash;

    @{$nstash}{keys %tmp_stash} = values %tmp_stash;

    $pos = $npos + $len + $indef;

    return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop);
};

my $choice_loop_gamma;
$choice_loop_gamma = sub {

    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;;
    my $idx = shift;
    my $var = shift;
    my $tag = shift;
    my $len = shift;
    my $npos = shift;
    my $indef = shift;
    my $cop = shift;

    my $ctr = $ctr[$cop->[cTYPE]];

    my $nstash = $seqof
        ? ($seqof->[$idx++]={})
        : defined($var)
            ? ($stash->{$var}={})
            : ref($stash) eq 'SCALAR'
                ? ($$stash={}) : $stash;

    _decode(
        $optn,
        [$cop],
        undef,
        $npos,
        $npos+$len,
        (\my @ctrlist),
        $larr,
        $buf,
    );

    $nstash->{$cop->[cVAR]} = &{$ctr}(@ctrlist);
    $pos = $npos + $len + $indef;

    return ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop);
};

my $choice_loop_for_loop;
# foreach my $cop (@{$op->[cCHILD]}) 
$choice_loop_for_loop = sub {
    my $cop = shift;
my $extensions = shift;
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;
    my $idx = shift;
    my $var = shift;
    my $tag = shift;
    my $len = shift; 
    my $npos = shift;
    my $indef = shift;


    if ($cop->[cTYPE] == opEXTENSIONS) {
        $extensions = 1;
        return        ('next', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef);
        # next;
    }

    elsif ($tag eq $cop->[cTAG]) {

        ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop)
            = &$choice_loop_alpha($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var,$tag,$len,$npos,$indef, $cop);

        return ('choice loop', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef) if $seqof && $pos < $end;
        return         ('op',  $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef);
    }


    elsif (! length $cop->[cTAG]) {
        ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop)
            = &$choice_loop_beta($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var,$tag,$len,$npos,$indef, $cop);

        return ('choice loop', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef) if $seqof && $pos < $end;
        return          ('op', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef);
    }

    elsif ($tag eq ($cop->[cTAG] | pack("C",ASN_CONSTRUCTOR))) {

        ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef, $cop)
            = &$choice_loop_gamma($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var,$tag,$len,$npos,$indef, $cop);

        return ('choice loop', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef) if $seqof && $pos < $end;
        return          ('op', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef);
    }

    return          ('next', $cop, $extensions, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var, $tag, $len, $npos, $indef);
};

my $choice_loop;

$choice_loop = sub {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;
    my $seqof = shift;
    my $op = shift;
    my $optn = shift;
    my $stash = shift;
    my $idx = shift;
    my $var = shift;


    my($error, $tag, $len, $npos, $indef) = _decode_tl($buf, $pos, $end, $larr);
    if ($error) {
            return
    ('op', $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)

            if $pos == $end and ($seqof || defined $op->[cEXT]);
            die "decode error";
    }

    my $extensions;


    for my $cop (@{$op->[cCHILD]}) {
        my $result;

        ($result, $cop, $extensions, $buf,  $pos,  $end,  $larr,  $seqof,  $op,  $optn,  $stash,  $idx,  $var,  $tag,  $len,  $npos,  $indef)
            = &$choice_loop_for_loop($cop, $extensions, $buf,  $pos,  $end,  $larr,  $seqof,  $op,  $optn,  $stash,  $idx,  $var,  $tag,  $len,  $npos,  $indef);


        if ($result eq 'op') {
            return
    ('op', $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
            ;
        }

        if ($result eq 'choice loop') {
            return &$choice_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
        }
    }

    if ($pos < $end && $extensions) {
        $pos = $npos + $len + $indef;

        return &$choice_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var) if $seqof && $pos < $end;
        # return 'op';
        return ('op', $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
    }

    return ('', $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
};

my $decode_top_for_loop;
$decode_top_for_loop = sub {
    my $buf = shift;
    my $idx = shift;

    my $optn = shift;
    my $ops = shift;
    my $stash = shift;
    my $pos = shift;
    my $end = shift;
    my $seqof = shift;
    my $larr = shift;

    my $decode_op_for_loop;
    $decode_op_for_loop = sub {
        my $op = shift;
        my $var = $op->[cVAR];

        if (length $op->[cTAG]) {
            ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
                = &$tag_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);
        }
        else { # opTag length is zero, so it must be an ANY, CHOICE or EXTENSIONS
            if ($op->[cTYPE] == opANY) {
                ($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
                    = &$any_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
            }
            elsif ($op->[cTYPE] == opCHOICE) {


                my $choice_result;
                ($choice_result, $buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var)
                    = &$choice_loop($buf, $pos, $end, $larr, $seqof, $op, $optn, $stash, $idx, $var);

                if ($choice_result eq 'op') {
                    return 'op';
                }

                die "decode error" unless $op->[cEXT];
            }


            elsif ($op->[cTYPE] == opEXTENSIONS) {
                $pos = $end; # Skip over the rest
            }
            else {
                die "this point should never be reached";
            }
        }

    };

    foreach my $op (@{$ops}) {
        &$decode_op_for_loop($op);
    }

    return ($buf, $idx, $optn, $ops, $stash, $pos, $end, $seqof, $larr);
};

sub _decode {
    my ($optn, $ops, $stash, $pos, $end, $seqof, $larr) = @_;

    my $idx = 0;

    # we try not to copy the input buffer at any time


    foreach my $buf ($_[-1]) {
        ($buf, $idx, $optn, $ops, $stash, $pos, $end, $seqof, $larr)
            = &$decode_top_for_loop($buf, $idx, $optn, $ops, $stash, $pos, $end, $seqof, $larr);
    }

    die "decode error $pos $end" unless $pos == $end;
}

sub _dec_boolean {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $var = unpack("C", substr($buf, $pos, 1)) ? 1 : 0;

    return ('int', $var);
}


sub _dec_integer {
    my ($optn, $op, $stash, $var, $buf, $pos, $len) = @_;

    $buf = substr($_[4],$_[5],$_[6]);
    my $tmp = unpack("C",$buf) & 0x80 ? pack("C",255) : pack("C",0);
    if ($len > 4) {
        $var = os2ip($buf, $optn->{decode_bigint} || 'Math::BigInt');
    } else {
        # N unpacks an unsigned value
        $var = unpack("l",pack("l",unpack("N", $tmp x (4 - $len) . $buf)));
    }

    return ('int', $var);
}


sub _dec_bitstring {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $var = [ substr($buf, $pos + 1, $len - 1), ($len - 1 ) * 8 - unpack("C", substr($buf, $pos, 1)) ];

    return ('int', $var);
}


sub _dec_string {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $var = substr($buf, $pos, $len);

    return ('int', $var);
}


sub _dec_null {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $var = exists($optn->{decode_null}) ? $optn->{decode_null} : 1;

    return ('int', $var);
}


sub _dec_object_id {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    my @data = unpack("w*", substr($buf, $pos, $len));

    if ($op->[cTYPE] == opOBJID and @data > 1) {
        if ($data[0] < 40) {
            splice(@data, 0, 1, 0, $data[0]);
        }
        elsif ($data[0] < 80) {
            splice(@data, 0, 1, 1, $data[0] - 40);
        }
        else {
            splice(@data, 0, 1, 2, $data[0] - 80);
        }
    }

    $var = join(".", @data);

    return ('int', $var);
}



sub _dec_real {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $var = 0.0, return ('int', $var) unless $len;

    my $first = unpack("C", substr($buf, $pos, 1));

    if ($first & 0x80) {
        # A real number

    my $exp;
    my $expLen = $first & 0x3;
    my $estart = $pos + 1;

    if($expLen == 3) {
        $estart++;
        $expLen = unpack("C", substr($buf, $pos + 1, 1));
    }
    else {
      $expLen++;
    }

    (undef, $exp) = _dec_integer(undef, undef, undef, $exp, $buf, $estart, $expLen);

    my $mant = 0.0;

    for (reverse unpack("C*", substr($buf, $estart + $expLen, $len - 1 - $expLen))) {
      $exp +=8, $mant = (($mant + $_) / 256) ;
    }

    $mant *= 1 << (($first >> 2) & 0x3);
    $mant = - $mant if $first & 0x40;

    $buf = $mant * POSIX::pow($_dec_real_base[($first >> 4) & 0x3], $exp);
    return ('int', $buf);
  }
  elsif($first & 0x40) {
    $buf =   POSIX::HUGE_VAL(), return ('int', $buf) if $first == 0x40;
    $buf = - POSIX::HUGE_VAL(), return ('int', $buf) if $first == 0x41;
    return ('int', $buf);
  }

  die "REAL decode error\n";
}

sub _dec_explicit {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    $op->[cCHILD][0][cVAR] = $op->[cVAR] unless $op->[cCHILD][0][cVAR];

    _decode(
        $optn,
        $op->[cCHILD],
        $stash,
        $pos,
        $pos + $len, #end
        undef, #loop
        $larr,
        $buf,
    );

    1;
}

sub _dec_sequence {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

  if (defined( my $ch = $op->[cCHILD])) {
    _decode(
      $optn,
      $ch,   #ops
      (defined($var) || $op->[cLOOP]) ? $stash : ($var= {}), #stash
      $pos, #pos
      $pos+$len, #end
      $op->[cLOOP] && ($var=[]), #loop
      $larr,
      $buf, #buf
    );
  }
  else {
    $var = substr($buf ,$pos, $len);
  }

  return ('int', $var);
}


sub _dec_set {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;
    my $larr = shift;

    # decode SET OF the same as SEQUENCE OF
    my $ch = $op->[cCHILD];
    return &_dec_sequence($optn, $op, $stash, $var, $buf, $pos, $len, $larr) if $op->[cLOOP] or !defined($ch);


    $stash = defined($var) ? $stash : ($var = {});
    my $end = $pos + $len;
    my $at_done = [];

    my $extensions;

    while ($pos < $end) {
        my ($error, $tag, $len, $npos, $indef) = _decode_tl($buf, $pos, $end, $larr);

        if ($error) {
            die "decode error";
        }

        my ($idx, $any, $done) = (-1);

        # SET_OP:
        # foreach my $op (@$ch)
        my $set_op_loop;

        $set_op_loop = sub {
            my $op = shift;
            my $optn = shift;
            my $stash = shift;
            my $var = shift;
            my $buf = shift;
            my $pos = shift;
            my $len = shift;
            my $larr = shift;
            my $ch = shift;
            my $end = shift;
            my $at_done = shift;
            my $extensions = shift;
            my $error = shift;
            my $tag = shift;
            my $npos = shift;
            my $indef = shift;
            my $idx = shift;
            my $any = shift;
            my $done = shift;


            $idx++;

            if (length($op->[cTAG])) {

                if ($tag eq $op->[cTAG]) {
                    my $var = $op->[cVAR];
                    my ($int_flag, $x_result) = &{$decode[$op->[cTYPE]]}(
                        $optn,
                        $op,
                        $stash,
                        # We send 1 if there is not var as if there is the decode
                        # should be getting undef. So if it does not get undef
                        # it knows it has no variable
                        (defined($var) ? $stash->{$var} : 1),
                        $buf,
                        $npos,
                        $len,
                        $larr,
                    );

                    if ($int_flag && ($int_flag eq 'int' || $int_flag eq 'bcd')) {
                        defined($var) ? $stash->{$var} : undef = $x_result;
                    }

                    $done = $idx;
                    # last SET_OP;
                    return ('last', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);

                }

                if ($tag eq ($op->[cTAG] | pack("C",ASN_CONSTRUCTOR)) and my $ctr = $ctr[$op->[cTYPE]]) {
                    _decode(
                        $optn,
                        [$op],
                        undef,
                        $npos,
                        $npos + $len,
                        (\my @ctrlist),
                        $larr,
                        $buf,
                    );

                    $stash->{$op->[cVAR]} = &{$ctr}(@ctrlist) if defined $op->[cVAR];
                    $done = $idx;
                    # last SET_OP;
                    return ('last', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);
                }

                return ('next', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);
                # next SET_OP;
            }
            elsif ($op->[cTYPE] == opANY) {
                $any = $idx;
            }
            elsif ($op->[cTYPE] == opCHOICE) {
                my $var = $op->[cVAR];

                foreach my $cop (@{$op->[cCHILD]}) {
                    if ($tag eq $cop->[cTAG]) {
                        my $nstash = defined($var) ? ($stash->{$var}={}) : $stash;

                        my ($int_flag, $x_result) = &{$decode[$cop->[cTYPE]]}(
                            $optn,
                            $cop,
                            $nstash,
                            $nstash->{$cop->[cVAR]},
                            $buf,
                            $npos,
                            $len,
                            $larr,
                        );

                        if ($int_flag && ($int_flag eq 'int' || $int_flag eq 'bcd')) {
                            $nstash->{$cop->[cVAR]} = $x_result;

                        }

                        $done = $idx;
                        # last SET_OP;
                        return ('last', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);
                    }

                    if ($tag eq ($cop->[cTAG] | pack("C",ASN_CONSTRUCTOR)) and my $ctr = $ctr[$cop->[cTYPE]]) {
                        my $nstash = defined($var) ? ($stash->{$var}={}) : $stash;

                        _decode(
                            $optn,
                            [$cop],
                            undef,
                            $npos,
                            $npos + $len,
                            (\my @ctrlist),
                            $larr,
                            $buf,
                        );

                        $nstash->{$cop->[cVAR]} = &{$ctr}(@ctrlist);
                        $done = $idx;
                        # last SET_OP;
                        return ('last', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);
                    }
                }
            }
            elsif ($op->[cTYPE] == opEXTENSIONS) {
                $extensions = $idx;
            }
            else {
                die "internal error";
            }

            return ('next', $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);
        };


        foreach my $op (@$ch) {
            my $set_op_loop_result;

            ($set_op_loop_result, $op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done) =

                &$set_op_loop($op, $optn, $stash, $var, $buf, $pos, $len, $larr, $ch, $end, $at_done, $extensions, $error, $tag, $npos, $indef, $idx, $any, $done);

            if ($set_op_loop_result eq 'last') {
                last;
            }
        }

        if (!defined($done) and defined($any)) {
            my $var = $ch->[$any][cVAR];
            $stash->{$var} = substr($buf, $pos, $len + $npos - $pos) if defined $var;
            $done = $any;
        }

        if ( !defined($done) && defined($extensions) ) {
            $done = $extensions;
        }

        die "decode error" if !defined($done) or $at_done->[$done]++;

        $pos = $npos + $len + $indef;
    }

    die "decode error" unless $end == $pos;

    foreach my $idx (0..$#{$ch}) {
        die "decode error" unless $at_done->[$idx] or $ch->[$idx][cEXT] or $ch->[$idx][cTYPE] == opEXTENSIONS;
    }

  1;
}


my %_dec_time_opt = ( unixtime => 0, withzone => 1, raw => 2);

sub _dec_time {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;

    my $mode = $_dec_time_opt{$optn->{'decode_time'} || ''} || 0;

    if ($mode == 2 or $len == 0) {
        $var = substr($buf, $pos, $len);
        return;
    }

    my @bits = (substr($buf, $pos, $len)
        =~ /^((?:\d\d)?\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)((?:\.\d{1,3})?)(([-+])(\d\d)(\d\d)|Z)/)
        or die "bad time format";

    if ($bits[0] < 100) {
        $bits[0] += 100 if $bits[0] < 50;
    }
    else {
        $bits[0] -= 1900;
    }

    $bits[1] -= 1;
    require Time::Local;
    my $time = Time::Local::timegm(@bits[5,4,3,2,1,0]);
    $time += $bits[6] if length $bits[6];
    my $offset = 0;

    if ($bits[7] ne 'Z') {
        $offset = $bits[9] * 3600 + $bits[10] * 60;
        $offset = -$offset if $bits[8] eq '-';
        $time -= $offset;
    }

    $var = $mode ? [$time, $offset] : $time;

    return ('int', $var);
}


sub _dec_utf8 {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;

    $var = Encode::decode('utf8', substr($buf, $pos, $len));

    return ('int', $var);
}


sub _decode_tl {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;

    if ($pos >= $end) {
        return 'error 1';
    }

    my $indef = 0;

    my $tag = substr($buf, $pos++, 1);

    if((unpack("C",$tag) & 0x1f) == 0x1f) {
        my $b;
        my $n = 1;
        do {

            if ($pos >= $end) {
                return 'error 2';
            }

            $tag .= substr($buf, $pos++, 1);
            $b = ord substr($tag, -1);
        } while($b & 0x80);
    }

    if ($pos >= $end) {
        return 'error 3';
    }

    my $len = ord substr($buf, $pos++, 1);

    if($len & 0x80) {
        $len &= 0x7f;

        if ($len) {
            if ($pos + $len > $end) {
                return 'error 4';
            }

            my $padding = $len < 4 ? "\0" x (4 - $len) : "";
            ($len, $pos) = (unpack("N", $padding . substr($buf, $pos, $len)), $pos + $len);
        }
        else {
            unless (exists $larr->{$pos}) {
                _scan_indef($buf, $pos, $end, $larr) or return 'error 5';
            }
            $indef = 2;
            $len = $larr->{$pos};
        }
    }

    if ($pos + $len + $indef > $end) {
        return 'error 6';
    }

    # return the tag, the length of the data, the position of the data
    # and the number of extra bytes for indefinate encoding

    return (undef, $tag, $len, $pos, $indef);
}

sub _dec_bcd {
    my $optn = shift;
    my $op = shift;
    my $stash = shift;
    my $var = shift;
    my $buf = shift;
    my $pos = shift;
    my $len = shift;

    $var = unpack("H*", substr($buf, $pos, $len));
    $var =~ s/[fF]$//;

    return ('bcd', $var);
}

sub os2ip {
    my $os = shift;
    my $biclass = shift;

    my $base = $biclass->new(256);
    my $result = $biclass->new(0);

    my $neg = unpack("C", $os) >= 0x80;

    if ($neg) {
        $os ^= pack("C", 255) x length($os);
    }

    for (unpack("C*", $os)) {
        $result = ($result * $base) + $_;
    }

    if ($neg) {
        return -($result + 1);
    }

    return $result;
}

sub _scan_indef {
    my $buf = shift;
    my $pos = shift;
    my $end = shift;
    my $larr = shift;

    my @depth = $pos;

    while (@depth) {
        return if $pos + 2 > $end;

        if (substr($buf, $pos, 2) eq "\0\0") {
            my $end = $pos;
            my $stref = shift @depth;
            # replace pos with length = end - pos
            $larr->{$stref} = $end - $stref;
            $pos += 2;
            next;
        }

        my $tag = substr($buf, $pos++, 1);

        if((unpack("C", $tag) & 0x1f) == 0x1f) {
            my $b;
            do {
                $tag .= substr($buf, $pos++, 1);
                $b = ord substr($tag, -1);
            } while ($b & 0x80);
        }
        return if $pos >= $end;

        my $len = ord substr($buf, $pos++, 1);

        if($len & 0x80) {
            if ($len &= 0x7f) {
                return if $pos+$len > $end;

                my $padding = $len < 4 ? "\0" x (4 - $len) : "";
                $pos += $len + unpack("N", $padding . substr($buf, $pos, $len));
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

1;
