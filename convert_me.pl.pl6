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

# Encode a length. If < 0x80 then encode as a byte. Otherwise encode
# 0x80 | num_bytes followed by the bytes for the number. top end
# bytes of all zeros are not encoded

sub asn_encode_length {
    my $length = shift;

    if ($length +> 7) {
        my $lenlen = num_length($length);

        return pack(
            "Ca*",
            $lenlen +| :16<80>,
            substr(pack("N" ,$length), -$lenlen)
        );
    }

    return pack("C", $length);
}

sub num_length {
  @_[0] +> 8
    ?? @_[0] +> 16
      ?? @_[0] +> 24
    ?? 4
    !! 3
      !! 2
    !! 1
}

sub encode {
    my $self  = shift;
    my $stash = @_ == 1 ?? shift !! { @_ };

    my $foo = _encode($self.{'options'}, $self.{'script'}, $stash);
    return $foo;
}

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
    my ($optn, $ops, $stash, $path, $buffer) = @_;
    my $var;

    for (@($ops)) -> $op {
        say "IEYE =\> ", ref($op);
        next if $op.[cTYPE] == opEXTENSIONS;

        if (defined(my $opt = $op.[cOPT])) {
            next unless defined $stash.{'$opt'};
        }

        if (defined($var = $op.[cVAR])) {
            push @$path, $var;
            die join(".", @$path)," is undefined" unless defined $stash.{'$var'};
        }

        $buffer ~= $op.[cTAG];

        my @stash_val;

        # Horse shit
        if (UNIVERSAL::isa($stash, 'HASH')) {
            if (defined($var)) {
                @stash_val = ($stash, $stash.{'$var'});
            }
            else {
                @stash_val = ($stash, Any);
            }
        }
        else {
            @stash_val = ({}, $stash);
        }

        # $buffer = &{ $encode[ $op->[cTYPE] ] }(
        $buffer = &( @encode[ $op.[cTYPE] ] )(
            $optn,
            $op,
            @stash_val,
            $buffer,
            $op.[cLOOP],
            $path,
        );

        pop @$path if defined $var;
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
        my $os = i2osp($var, ref($var)
            || 'Math::BigInt');

        my $len = length $os;
        my $msb = (vec($os, 0, 8) +& :16<80>) ?? 0 !! 255;

        $len++, $os = pack("C",$msb) ~ $os if $msb xor $var > 0;
        $buf ~= asn_encode_length($len);
        $buf ~= $os;
    }

    else {
        my $val = int($var);
        my $neg = ($val < 0);
        my $len = num_length($neg ?? +^$val !! $val);
        my $msb = $val +& (:16<80> +< (($len - 1) * 8));

        $len++ if $neg ?? ?^$msb !! $msb;

        $buf ~= asn_encode_length($len);
        $buf ~= substr(pack("N",$val), -$len);
    }

    return $buf;
}


sub _enc_bitstring {
    my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

  my $vref = ref($var) ?? \($var.[0]) !! \$var;

  if (1 and Encode::is_utf8($$vref)) {
    utf8::encode(my $tmp = $$vref);
    $vref = \$tmp;
  }

  if (ref($var)) {
    my $less = (8 - ($var.[1] +& 7)) +& 7;
    my $len = ($var.[1] + 7) +> 3;
    $buf ~= asn_encode_length(1+$len);
    $buf ~= pack("C",$less);
    $buf ~= substr($$vref, 0, $len);
    if ($less && $len) {
      substr($buf,-1) +&= pack("C",(:16<ff> +< $less) +& :16<ff>);
    }
  }
  else {
    $buf ~= asn_encode_length(1+length $$vref);
    $buf ~= pack("C",0);
    $buf ~= $$vref;
  }

  return $buf;
}


sub _enc_string {
    my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

    if (Encode::is_utf8($var)) {
        utf8::encode(my $tmp = $var);
        $buf ~= asn_encode_length(length $tmp);
        $buf~= $tmp;
    }
    else {
        $buf~= asn_encode_length(length $var);
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

    my $l = length $buf;
    $buf ~= pack("cw*", 0, @data);
    substr($buf,$l,1) = asn_encode_length(length($buf) - $l - 1);

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
    $exponent -= 8 * length $eMant;

    $eExp = _enc_integer(Any, Any, Any, $exponent, $eExp);

    # $eExp will br prefixed by a length byte
    if (5 > length $eExp) {
        $eExp ~~ s:s:P5/\A.//;
        $first +|= length($eExp)-1;
    }
    else {
        $first +|= :16<3>;
    }

    $buf ~= asn_encode_length(1 + length($eMant) + length($eExp));
    $buf ~= pack("C",$first);
    $buf ~= $eExp;
    $buf ~= $eMant;

    return $buf;
}


sub _enc_sequence {
    my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;
# 0      1    2       3     4     5      6
# $optn, $op, $stash, $var, $buf, $loop, $path

    if (my $ops = $op.[cCHILD]) {
        my $l = length $buf;
        $buf ~= "\0\0"; # guess
        if (defined $loop) {
            my $op   = $ops.[0]; # there should only be one
            my $enc  = @encode[$op.[cTYPE]];
            my $tag  = $op.[cTAG];
            my $loop = $op.[cLOOP];

            # Horseshit 6 == $path
            push @(@_[6]), -1;

            for (@($var)) -> $var {
                @_[6].[*-1]++;
                $buf ~= $tag;

                # added the buf, maybe not
                $buf = &($enc)(
                    $optn,
                    $op,
                    $stash,
                    $var,
                    $buf,
                    $loop,
                    $path,
                );
            }

            pop @(@_[6]);
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

        substr($buf,$l,2) = asn_encode_length(length($buf) - $l - 2);
    }

    else {
        $buf ~= asn_encode_length(length @_[3]);
        $buf ~= $var;
    }

    return $buf;
}


my %_enc_time_opt = ( utctime => 1, withzone => 0, raw => 2);

sub _enc_time {
    my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

    my $mode = %_enc_time_opt{'$optn'.{'encode_time'} || ''} || 0;

    if ($mode == 2) {
        $buf ~= asn_encode_length(length $var);
        $buf ~= $var;
        return;
    }

    my $time;
    my @time;
    my $offset;
    my $isgen = $op.[cTYPE] == opGTIME;

  if (ref($var)) {
    $offset = int($var.[1] / 60);
    $time = $var.[0] + $var.[1];
  }
  elsif ($mode == 0) {
    if (exists $optn.{'encode_timezone'}) {
      $offset = int($optn.{'encode_timezone'} / 60);
      $time = $var + $optn.{'encode_timezone'};
    }
    else {
      @time = localtime($var);
      my @g = gmtime($var);

      $offset = (@time[1] - @g[1]) + (@time[2] - @g[2]) * 60;
      $time = $var + $offset*60;
    }
  }
  else {
    $time = $var;
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
  $buf ~= asn_encode_length(length $tmp);
  $buf ~= $tmp;

  return $buf;
}


sub _enc_utf8 {
    my ($optn, $op, $stash, $var, $buf, $loop, $path) = @_;

    my $tmp = $var;
    utf8::upgrade($tmp) unless Encode::is_utf8($tmp);
    utf8::encode($tmp);
    $buf ~= asn_encode_length(length $tmp);
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

        if (exists $stash.{'$var'}) {
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

  $str ~= "F" if length($str) +& 1;
  $buf ~= asn_encode_length(length($str) / 2);
  $buf ~= pack("H*", $str);

  return $buf;
}

1;
