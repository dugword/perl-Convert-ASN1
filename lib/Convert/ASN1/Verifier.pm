package Convert::ASN1::Verifier;

use 5.024;
use strict;
use warnings;
no warnings 'recursion';

use Data::Dump;

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

sub verify_inner_loop {
    my $tree = shift;
    my $name = shift;
    my $ops = shift;

    my $scope = shift;
    my $idx = shift;
    my $path = shift;
    my $stash = shift;

    my $ops_length = scalar @$ops;
    if ($idx < $ops_length) {
        my $op = $ops->[$idx++];
        my $var = $op->[cVAR];

        if (defined $var) {
            $stash->{$var}++;
            if ($stash->{$var} > 1) {
                die "$name: $path.$var used multiple times";
            }
        }

        if (defined $op->[cCHILD]) {

            if (ref $op->[cCHILD] eq 'ARRAY') {
                my $scipe = [$stash, $path, $ops, $idx];
                push @$scope, $scipe;
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
        if (@$scope) {
            my $s = pop @$scope;
            ($stash, $path, $ops, $idx) = @$s;
        }
        else {
            return;
        }
    }

    verify_inner_loop(
        $tree,
        $name,
        $ops,
        $scope,
        $idx,
        $path,
        $stash,
    );
};

sub verify_loop {
    my $tree = shift;
    my $name = shift;
    my $ops = shift;

    my $scope = [];
    my $idx = 0;
    my $path = '';
    my $stash = {};


    verify_inner_loop(
        $tree,
        $name,
        $ops,
        $scope,
        $idx,
        $path,
        $stash,
    );
};

sub verify {
    my $tree = shift or return;
    #  dd $tree;
    my $new_tree = {};

    # Well it parsed correctly, now we
    #  - check references exist
    #  - flatten COMPONENTS OF (checking for loops)
    #  - check for duplicate var names
    # use constant cVAR => 2;
    # use constant cCHILD => 6;
    # use constant cTYPE => 1;


    while ( my($name, $ops) = each %$tree) {
        verify_loop($tree, $name, $ops);
    }


    return $tree;
    # say "HERE";
}

sub expand_ops {
    my $tree = shift;
    my $want = shift;
    my $seen = shift || { };

    die "COMPONENTS OF loop $want\n" if $seen->{$want}++;
    die "Undefined macro $want\n" unless exists $tree->{$want};
    my $ops = $tree->{$want};

    die "Bad macro for COMPUNENTS OF '$want'\n"
        unless @$ops == 1
            && ($ops->[0][cTYPE] eq 'SEQUENCE' || $ops->[0][cTYPE] eq 'SET');
    $ops = $ops->[0][cCHILD];

    for(my $idx = 0 ; $idx < @$ops ; ) {
        my $op = $ops->[$idx++];
        if ($op->[cTYPE] eq 'COMPONENTS') {
            splice(@$ops,--$idx,1,expand_ops($tree, $op->[cCHILD], $seen));
        }
    }

    return @$ops;
}

1;
