#!/usr/bin/perl

## Authentication script for Jenkins.
# This script is intended to be invoked by the "Security Realm by custom script"
# plugin when users log in. It looks up the user's level and configured groups
# to determine whether the user is a member of staff or a student, and which
# groups they may belong to.

use v5.20;
use strict;
use experimental qw(smartmatch);

use DBI;

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


## @fn $ get_max_yearid($dbh, $settings)
# Attempt to determine the current year from the user data database.
# This assumes that the maximum year id in the student_year_level
# table corresponds to the current year.
#
# @param dbh      A reference to a DBI object to issue queries through.
# @param settings A reference to the global settings object
# @return The current year Id on success, dies on error.
sub get_max_yearid {
    my $dbh      = shift;
    my $settings = shift;

    my $yearh = $dbh -> prepare("SELECT MAX(`year_id`)
                                 FROM `".$settings -> {"database"} -> {"studentyear"}."`");
    $yearh -> execute()
        or die "Unable to fetch maximum year ID: ".$dbh -> errstr."\n";

    my $year = $yearh -> fetchrow_arrayref()
        or die "No result available for maximum year ID lookup. This should not happen!\n";

    return $year -> [0];
}


## @fn $ get_user_level($dbh, $settings, $username, $yearid)
# Determine what academic level the specified user has in the year given.
#
# @param dbh      A reference to a DBI object to issue queries through.
# @param settings A reference to the global settings object
# @param username The username of the user to look up.
# @param yearid   The ID of the year to look up the user's level for.
# @return An integer indicating the user's level on success, undef if the
#         user does not exist. Errors will kill the program.
sub get_user_level {
    my $dbh      = shift;
    my $settings = shift;
    my $username = shift;
    my $yearid   = shift;

    my $levelh = $dbh -> prepare("SELECT `l`.`level`
                                  FROM `".$settings -> {"database"} -> {"studentyear"}."` AS `l`,
                                       `".$settings -> {"database"} -> {"students"}."` AS `u`
                                  WHERE `u`.`username` LIKE ?
                                  AND `l`.`student_id` = `u`.`id`
                                  AND `l`.`year_id` = ?");
    $levelh -> execute($username, $yearid)
        or die "Unable to fetch user level: ".$dbh -> errstr."\n";

    my $level = $levelh -> fetchrow_arrayref();
    return $level ? $level -> [0] : undef;
}


## @fn $ get_user_groups($dbh, $settings, $username, $yearid)
# Given a username, determine the groups the user is a member of.
#
# @param username The name of the user to fetch groups for.
# @return A reference to an array of group names.
sub get_user_groups {
    my $dbh      = shift;
    my $settings = shift;
    my $username = shift;
    my $yearid   = shift;


    return undef;
}


# Usernames must only be alphanumerics
my ($username) = $ENV{"U"} =~ /^(\w+)$/;
die "No username specified, or username contains invalid characters.\n"
    unless($username);

# Slurp the settings, so we know all the other details
my $settings = Webperl::ConfigMicro -> new(path_join($path, "config", "config.cfg"))
    or die "Unable to load configuration. Error was: $ConfigMicro::errstr\n";

# Connect to the database that contains the group information.
my $dbh = DBI -> connect($settings -> {"database"} -> {"database"},
                         $settings -> {"database"} -> {"username"},
                         $settings -> {"database"} -> {"password"},
                         { RaiseError => 0, AutoCommit => 1, mysql_enable_utf8 => 1 })
    or die "Unable to connect to database: ".$DBI::errstr."\n";

# First we need a year ID to get anything useful out of the database
my $current_year = get_max_yearid($dbh, $settings);

my @groups;
my $level = get_user_level($dbh, $settings, $username, $current_year);
given($level) {
    when("255") { push(@groups, "staff"); }
    when("0")   { push(@groups, "student", "phd"); }
    default     { push(@groups, "student"); }
}

my $course_groups = get_user_groups($dbh, $settings, $username, $current_year);
push(@groups, @{$course_groups})
    if($course_groups);

print join(",", @groups);
exit 0;
