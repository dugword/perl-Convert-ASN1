sub compile_loop {
    my $op = shift;
    my $tree = shift;
    my $name = shift;

    return unless ref($op) eq 'ARRAY';
    bless $op;
    my $type = $op->[cTYPE];


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
        compile_one($tree,$v,$k);
    }

    return $tree;
}
