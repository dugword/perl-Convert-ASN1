# Utilities.pm
module Fancy::Utilities {
    # sub lolgreet($who) is export {
    # k$lolgreet = 'heya';
    sub lolgreet($who) is export(:debug) {
      say "O HAI " ~ uc $who;
    }
}
