sub verify {
    blerg "sub verify";
    my $tree = shift or return;
    my $err = "";

    # Well it parsed correctly, now we
    #  - check references exist
    #  - flatten COMPONENTS OF (checking for loops)
    #  - check for duplicate var names

    while(my($name,$ops) = each %$tree) {
        my $stash = {};
        my @scope = ();
        my $path = "";
        my $idx = 0;

        while($ops) {
            if ($idx < @$ops) {
                my $op = $ops->[$idx++];
                my $var;

                if (defined ($var = $op->[cVAR])) {

                    $err .= "$name: $path.$var used multiple times\n"
                    if $stash->{$var}++;

                }

                if (defined $op->[cCHILD]) {
                    push @scope, [$stash, $path, $ops, $idx];
                    if (defined $var) {
                        $stash = {};
                        $path .= "." . $var;
                    }
                    $idx = 0;
                    $ops = $op->[cCHILD];
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
