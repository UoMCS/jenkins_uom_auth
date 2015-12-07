#!/usr/bin/perl

## Authentication script for Jenkins.
# This script is intended to be invoked by the "Security Realm by custom script"
# plugin when users log in. It does an LDAP query against the configured LDAP
# server, and returns 0 if the user is valid, 1 if the user is not.
#
# This script can be used instead of the default LDAP security realm plugin to
# allow more flexible group handling, potentially support multiple auth sources,
# and to actually do LDAP with TLS rather than relying on LDAPS or clear.

use v5.20;
use strict;

use lib qw(/var/www/webperl);

use Webperl::Utils qw(path_join);
use Webperl::ConfigMicro;
use Webperl::AuthMethod::LDAP;

use FindBin;             # Work out where we are
my $path;
BEGIN {
    $ENV{"PATH"} = "/bin:/usr/bin"; # safe path.

    # $FindBin::Bin is tainted by default, so we may need to fix that
    # NOTE: This may be a potential security risk, but the chances
    # are honestly pretty low...
    if ($FindBin::Bin =~ /(.*)/) {
        $path = $1;
    }
}

# Slurp the settings, so we know all the other details
my $settings = Webperl::ConfigMicro -> new(path_join($path, "config", "config.cfg"))
    or die "Unable to load configuration. Error was: $ConfigMicro::errstr\n";

# LDAP auth handling via the standard module
my $ldap = Webperl::AuthMethod::LDAP -> new(minimal     => 1,
                                            server      => $settings -> {"LDAP"} -> {"server"},
                                            base        => $settings -> {"LDAP"} -> {"base"},
                                            searchfield => $settings -> {"LDAP"} -> {"searchfield"},
                                            usetls      => $settings -> {"LDAP"} -> {"usetls"},
                                            fnfield     => $settings -> {"LDAP"} -> {"fnfield"},
                                            emailfield  => $settings -> {"LDAP"} -> {"emailfield"})
    or die "Unable to create LDAP auth module: ".$Webperl::SystemModule::errstr."\n";

my ($valid, $extra) = $ldap -> authenticate($ENV{"U"}, $ENV{"P"}, $ldap);

# script should exit with 0 on success, nonzero on failure.
die "Unable to authenticate user against LDAP server"
    unless($valid);

exit 0;