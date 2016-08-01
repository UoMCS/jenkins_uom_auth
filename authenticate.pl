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
use DBI;

use lib qw(/var/www/webperl);

use Webperl::Utils qw(path_join);
use Webperl::ConfigMicro;
use Webperl::AuthMethod::LDAP;
use Webperl::AuthMethod::Database;

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

## @fn $ database_auth($username, $password, $settings)
# Attempt to authenticate the specified user against the database.
#
# @param username The name of the user to authenticate
# @param password The password for the user
# @param settings A reference to the global settings object.
# @return true if the user is valid, false otherwise.
sub database_auth {
    my $username = shift;
    my $password = shift;
    my $settings = shift;

    my $dbh = DBI -> connect($settings -> {"authdb"} -> {"database"},
                             $settings -> {"authdb"} -> {"username"},
                             $settings -> {"authdb"} -> {"password"},
                             { RaiseError => 0, AutoCommit => 1, mysql_enable_utf8 => 1 })
        or die "Unable to connect to database: ".$DBI::errstr."\n";

    my $db = Webperl::AuthMethod::Database -> new(minimal   => 1,
                                                  dbh       => $dbh,
                                                  table     => 'users',
                                                  userfield => 'username',
                                                  passfield => 'password')
        or die "Unable to create database auth object: ".$Webperl::SystemModule::errstr."\n";

    return $db -> authenticate($username, $password);
}


## @fn $ ldap_auth($username, $password, $settings)
# Attempt to authenticate the specified user against LDAP.
#
# @param username The name of the user to authenticate
# @param password The password for the user
# @param settings A reference to the global settings object.
# @return true if the user is valid, false otherwise.
sub ldap_auth {
    my $username = shift;
    my $password = shift;
    my $settings = shift;

    # LDAP auth handling via the standard module
    my $ldap = Webperl::AuthMethod::LDAP -> new(minimal     => 1,
                                                server      => $settings -> {"LDAP"} -> {"server"},
                                                base        => $settings -> {"LDAP"} -> {"base"},
                                                searchfield => $settings -> {"LDAP"} -> {"searchfield"},
                                                usetls      => $settings -> {"LDAP"} -> {"usetls"},
                                                fnfield     => $settings -> {"LDAP"} -> {"fnfield"},
                                                emailfield  => $settings -> {"LDAP"} -> {"emailfield"})
        or die "Unable to create LDAP auth module: ".$Webperl::SystemModule::errstr."\n";

    $ldap -> {"auth"} = $ldap;

    my ($valid, $extra) = $ldap -> authenticate($username, $password, $ldap);

    return $valid;
}


# Slurp the settings, so we know all the other details
my $settings = Webperl::ConfigMicro -> new(path_join($path, "config", "config.cfg"))
    or die "Unable to load configuration. Error was: $ConfigMicro::errstr\n";

print "Checking '".$ENV{"U"}."', '".$ENV{"P"}."'\n";
if(!database_auth($ENV{"U"}, $ENV{"P"}, $settings)) {
    if(!ldap_auth($ENV{"U"}, $ENV{"P"}, $settings)) {
        die "User is not valid\n";
    }
}

exit 0;