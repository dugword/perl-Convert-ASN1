sub verify {
    blerg "sub verify";
    my $tree = shift or return;

    # Well it parsed correctly, now we
    #  - check references exist
    #  - flatten COMPONENTS OF (checking for loops)
    #  - check for duplicate var names

    while(my($name,$ops) = each %$tree) {
        my $stash = {};
        my @scope = ();
        my $path = "";
        my $idx = 0;

        while(1) {

            if ($idx < @$ops) {
                my $op = $ops->[$idx++];
                my $var = $op->[cVAR];

                if (defined $var) {
                    $stash->{$var}++;
                    if ($stash->{$var} > 1) {
                        die "$name: $path.$var used multiple times";
                    }
                }

                if (defined $op->[cCHILD]) {

                    if (ref $op->[cCHILD]) {
                        push @scope, [$stash, $path, $ops, $idx];
                        if (defined $var) {
                            $stash = {};
                            $path .= "." . $var;
                        }
                        $idx = 0;
                        $ops = $op->[cCHILD];
                    }

                    elsif ($op->[cTYPE] eq 'COMPONENTS') {
                        splice(@$ops, --$idx, 1, expand_ops($tree, $op->[cCHILD]));
                    }

                    else {
                        die "Internal error\n";
                    }
                }
            }
            else {
                my $s = pop @scope or last;
                ($stash, $path, $ops, $idx) = @$s;
            }
        }
    }

    return $tree;
}

sub expand_ops {
    blerg "sub expand_ops";
    my $tree = shift;
    my $want = shift;
    my $seen = shift || { };

    die "COMPONENTS OF loop $want\n" if $seen->{$want}++;
    die "Undefined macro $want\n" unless exists $tree->{$want};
    my $ops = $tree->{$want};

    die "Bad macro for COMPUNENTS OF '$want'\n"
        unless @$ops == 1
            && ($ops->[0][cTYPE] eq 'SEQUENCE' || $ops->[0][cTYPE] eq 'SET')
            && ref $ops->[0][cCHILD];
    $ops = $ops->[0][cCHILD];

    for(my $idx = 0 ; $idx < @$ops ; ) {
        my $op = $ops->[$idx++];
        if ($op->[cTYPE] eq 'COMPONENTS') {
            splice(@$ops,--$idx,1,expand_ops($tree, $op->[cCHILD], $seen));
        }
    }

    return @$ops;
}
