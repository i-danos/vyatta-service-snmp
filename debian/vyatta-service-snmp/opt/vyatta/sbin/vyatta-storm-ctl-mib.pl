#! /usr/bin/perl
#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# By virtue of the following entry in the snmpd.conf file, this script
# is launched by the SNMP daemon when it needs access to the Storm Control
# sub-tree.
#
#    pass_persist .1.3.6.1.4.1.74.1.32.4 /opt/vyatta/sbin/vyatta-storm-ctl-mib
#
# The PassPersist class, as provided by the PassPersist library,
# is responsible for:
#
#    o building and maintaining the MIB sub-tree
#    o responding to individual "get" & "getnext" requests from SNMPd
#    o invoking a callback in order to periodically update the MIB
#
# This "wrapper" script collects the storm control details, parses the resultant
# JSON and populates the MIB using methods provided by the PassPersist class.
#
# For details on PassPersist see "man SNMP::Extension::PassPersist"
#
#    vyatta-storm-ctl-mib.pl --interval 1 --idle 1
#
# This will retrieve the storm control counters, create the MIB objects and
# then dump the MIB tree after 1 second.
#
use strict;
use warnings;
use Readonly;
use Sys::Syslog;

use lib "/opt/vyatta/share/perl5";

use Vyatta::Dataplane;
use Getopt::Long;
use File::Slurp;
use Scalar::Util qw( looks_like_number );
use JSON qw( decode_json );
use Data::Dumper;

use SNMP::Extension::PassPersist;

Readonly my $ATT_VROUTER_VYATTA_BASE_OID => ".1.3.6.1.4.1.74.1.32";

my $snmppp;
my $indices;
my %ifindexcache;
my $test_lastifindex;
my %profiles;

sub storm_ctl_oid {
    my ( $base, $oid ) = @_;

    return "$base.$oid";
}

Readonly my $attVrouterStormControlMIB => 4;

Readonly my $attVrStormCtlMIBObjects =>
  storm_ctl_oid( $attVrouterStormControlMIB, 1 );

Readonly my $attVrStormCtlConfigObjects =>
  storm_ctl_oid( $attVrStormCtlMIBObjects, 1 );

Readonly my $attVrStormCtlProfileTable =>
  storm_ctl_oid( $attVrStormCtlConfigObjects, 1 );
Readonly my $attVrStormCtlProfileEntry =>
  storm_ctl_oid( $attVrStormCtlProfileTable, 1 );
Readonly my $attVrStormCtlProfileName =>
  storm_ctl_oid( $attVrStormCtlProfileEntry, 1 );

Readonly my $attVrStormCtlThresholdTable =>
  storm_ctl_oid( $attVrStormCtlProfileEntry, 2 );
Readonly my $attVrStormCtlThresholdEntry =>
  storm_ctl_oid( $attVrStormCtlThresholdTable, 1 );
Readonly my $avscTrafficType =>
  storm_ctl_oid( $attVrStormCtlThresholdEntry, 1 );
Readonly my $avscThresholdType =>
  storm_ctl_oid( $attVrStormCtlThresholdEntry, 2 );
Readonly my $avscThreshold => storm_ctl_oid( $attVrStormCtlThresholdEntry, 3 );

Readonly my $attVrStormCtlActionTable =>
  storm_ctl_oid( $attVrStormCtlProfileEntry, 3 );
Readonly my $attVrStormCtlAction =>
  storm_ctl_oid( $attVrStormCtlActionTable, 1 );

Readonly my $attVrStormCtlIntfTable =>
  storm_ctl_oid( $attVrStormCtlConfigObjects, 2 );
Readonly my $attVrStormCtlIntfEntry =>
  storm_ctl_oid( $attVrStormCtlIntfTable, 1 );

Readonly my $avscInterface   => storm_ctl_oid( $attVrStormCtlIntfEntry, 1 );
Readonly my $avscVlan        => storm_ctl_oid( $attVrStormCtlIntfEntry, 2 );
Readonly my $avscProfileName => storm_ctl_oid( $attVrStormCtlIntfEntry, 3 );

Readonly my $attVrStormCtlStatusObjects =>
  storm_ctl_oid( $attVrStormCtlMIBObjects, 2 );

Readonly my $attVrStormCtlStatusTable =>
  storm_ctl_oid( $attVrStormCtlStatusObjects, 1 );

Readonly my $attVrStormCtlStatusEntry =>
  storm_ctl_oid( $attVrStormCtlStatusTable, 1 );

Readonly my $attVrStormCtlIntf => storm_ctl_oid( $attVrStormCtlStatusEntry, 1 );
Readonly my $attVrStormCtlTraffic =>
  storm_ctl_oid( $attVrStormCtlStatusEntry, 2 );
Readonly my $attVrStormCtlStatus =>
  storm_ctl_oid( $attVrStormCtlStatusEntry, 3 );
Readonly my $attVrStormCtlCurrentLevel =>
  storm_ctl_oid( $attVrStormCtlStatusEntry, 4 );
Readonly my $attVrStormCtlSuppressedPacket =>
  storm_ctl_oid( $attVrStormCtlStatusEntry, 5 );

my %TrafficTypes = (
    'broadcast' => 1,
    'multicast' => 2,
    'unicast'   => 3
);

my %BWTypeIds = (
    'bw_percent' => 1,
    'bw_level'   => 2
);

sub get_ifindex {
    my ($ifname) = @_;

    if ( !defined( $ifindexcache{$ifname} ) ) {
        my $ifindex;

        if ($test_lastifindex) {
            $test_lastifindex++;
            $ifindex = $test_lastifindex;
        } else {
            $ifindex = read_file("/sys/class/net/$ifname/ifindex");

            if ( defined($ifindex) ) {
                chomp $ifindex;
            } else {
                $ifindex = 0;
            }
        }

        $ifindexcache{$ifname} = $ifindex;
    }

    return $ifindexcache{$ifname};
}

sub oid_add {
    my ( $oid, $type, $value, $indices ) = @_;

    my $index = "";
    foreach my $idx (@$indices) {
        my $stridx = $idx;

        #
        # If the index is not a number, treat it as a string and
        # convert the whole thing to its binary representation.
        #
        if ( !looks_like_number($idx) ) {
            my $i;
            my $c;

            $stridx = length($idx);
            for ( my $i = 0 ; $i < length($idx) ; $i++ ) {
                $c = substr( $idx, $i, 1 );
                $stridx = sprintf( "%s.%s", $stridx, ord($c) );
            }
        }

        $index = sprintf( "%s.%s", $index, $stridx );
    }

    $snmppp->add_oid_entry( "$ATT_VROUTER_VYATTA_BASE_OID.$oid$index",
        $type, $value );
}

sub oid_add_str {
    my ( $oid, $value, $indices ) = @_;

    oid_add( $oid, "string", $value, $indices );
}

sub oid_add_cnt {
    my ( $oid, $value, $indices ) = @_;

    oid_add( $oid, "counter64", $value, $indices );
}

sub oid_add_int {
    my ( $oid, $value, $indices ) = @_;

    oid_add( $oid, "integer", $value, $indices );
}

sub collect_storm_ctl_data {
    my ( $dpids, $dpsocks ) = Vyatta::Dataplane::setup_fabric_conns();

    my $output = vplane_exec_cmd( "storm-ctl show", $dpids, $dpsocks, 1 );

    return ( decode_json( $output->[0] ) );
}

sub update_status_table {
    my ( $json, $ifindex, $vlan ) = @_;

    my %traffictypes = ( 'unicast' => 3, 'multicast' => 2, 'broadcast' => 1 );

    foreach my $traffictype ( keys %traffictypes ) {
        if ( exists( $json->{$traffictype} ) ) {
            my $ttid    = $traffictypes{$traffictype};
            my @indices = ( $ifindex, $vlan, $traffictype );
            my $sp      = $json->{$traffictype}{'pkts_dropped'};

            oid_add_int( $attVrStormCtlIntf,    $ifindex,     \@indices );
            oid_add_int( $attVrStormCtlTraffic, $traffictype, \@indices );
            oid_add_int( $attVrStormCtlStatus,  0,            \@indices );
            oid_add_cnt( $attVrStormCtlSuppressedPacket,
                $json->{$traffictype}->{'pkts_dropped'}, \@indices );
        }
    }
}

sub update_intf_table {
    my ( $json, $ifindex, $vlan, $pname ) = @_;

    my @indices = ( $ifindex, $vlan );

    oid_add_int( $avscInterface, $ifindex, \@indices );
    oid_add_int( $avscVlan,      $vlan,    \@indices );
    oid_add_str( $avscProfileName, $pname, \@indices );
}

sub process_storm_control_data {
    my ($json) = @_;

    my @indices = ();
    my $state   = $json->{'storm_ctl_state'};

    foreach my $intf ( @{ $state->{'intfs'} } ) {
        my $ifname  = $intf->{'ifname'};
        my $ifindex = get_ifindex($ifname);
        my $vlan    = 0;
        my $pname;
        my $entry = $intf->{'whole_interface'};

        #
        # Check for profile on the parent interface
        #
        if ( exists( $entry->{'profile'} ) ) {
            $pname = $entry->{'profile'};
            push( @{ $profiles{$pname}{'instances'} }, [ $ifindex, $vlan ] );

            update_intf_table( $entry, $ifindex, $vlan, $pname );
            update_status_table( $entry, $ifindex, $vlan );
        }

        #
        # And any vlans
        #
        foreach my $vt ( @{ $intf->{'vlan_table'} } ) {
            $pname = $vt->{'profile'};
            $vlan  = $vt->{'vlan'};
            push( @{ $profiles{$pname}{'instances'} }, [ $ifindex, $vlan ] );

            update_intf_table( $vt, $ifindex, $vlan, $pname );
            update_status_table( $vt, $ifindex, $vlan );
        }
    }
}

sub find_profiles {
    #
    # First get a list of profiles and attributes
    #
    my ( $dpids, $dpsocks ) = Vyatta::Dataplane::setup_fabric_conns();

    my $output =
      vplane_exec_cmd( "storm-ctl show profile", $dpids, $dpsocks, 1 );

    if ( !defined($output) ) {
        return;
    }

    my $ptjson = decode_json( $output->[0] );

    foreach my $entry ( @{ $ptjson->{'profile_table'} } ) {
        my $pname = $entry->{'profile_name'};
        $profiles{$pname}{'shutdown'}  = $entry->{'shutdown'};
        $profiles{$pname}{'unicast'}   = $entry->{'unicast'};
        $profiles{$pname}{'multicast'} = $entry->{'multicast'};
        $profiles{$pname}{'broadcast'} = $entry->{'broadcast'};
        $profiles{$pname}{'instances'} = [];
    }
}

sub update_profile_table {

    my @prof_indices = ();

    foreach my $pname ( keys %profiles ) {
        @prof_indices = ($pname);
        oid_add_str( $attVrStormCtlProfileName, $pname, \@prof_indices );

        #
        # Threshold table
        #
        my @inst = @{ $profiles{$pname}{'instances'} };
        foreach my $entry ( @{inst} ) {
            my @tuple   = @{$entry};
            my $ifindex = $tuple[0];
            my $vlan    = $tuple[1];

            foreach my $ttype ( keys %TrafficTypes ) {
                my $ttid = $TrafficTypes{$ttype};
                if ( !defined( $profiles{$pname}{$ttype} ) ) {
                    next;
                }
                my %te = %{ $profiles{$pname}{$ttype} };
                foreach my $thresholdname ( keys %te ) {
                    my $thrtid    = $BWTypeIds{$thresholdname};
                    my $threshold = $te{$thresholdname};

                    my @threshold_indices =
                      ( $ifindex, $vlan, $TrafficTypes{$ttype} );
                    oid_add_int( $avscTrafficType, $ttid, \@threshold_indices );
                    oid_add_int( $avscThresholdType, $thrtid,
                        \@threshold_indices );
                    oid_add_int( $avscThreshold, $threshold,
                        \@threshold_indices );
                }
            }
        }

        oid_add_int( $attVrStormCtlAction, $profiles{$pname}{'shutdown'},
            \@prof_indices );

    }
}

sub collect_and_update {

    my $json = collect_storm_ctl_data();
    if ( !defined($json) ) {
        return;
    }

    find_profiles();
    process_storm_control_data($json);
    update_profile_table();
}

sub usage {
    print "usage: $0 [--interval <secs>]\n";
    print "       $0 [--idle <count>]\n";
    print "       $0 [--statsfile <statsfile>]\n";
    print "\n";
    print "       1 <= interval <= 30\n";
    print "       0 <= idle <= 20 or 0\n";
    print "\n";
    print "       An idle count of 0 means that the script is permanent\n";
    print "\n";

    exit 1;
}

my ( $help, $debug, $interval, $idle, $statsfile );

GetOptions(
    "help"       => \$help,
    "debug"      => \$debug,
    "interval:i" => \$interval,
    "idle:i"     => \$idle,
) or usage();

usage() if ($help);

#
# Default collection interval is 10s, idle timeout is 120s.
#
$interval = 10 if ( !defined($interval) );
$idle     = 12 if ( !defined($idle) );

if ( $interval < 1 || $interval > 30 ) {
    print "Invalid refresh interval: $interval\n";
    usage();
}

if ( $idle < 0 || $idle > 20 ) {
    print "Invalid idle count: $idle\n";
    usage();
}

$snmppp = SNMP::Extension::PassPersist->new(
    backend_collect => \&collect_and_update,
    idle_count      => $idle,
    refresh         => $interval
);

$snmppp->run();

$snmppp->dump_oid_tree() if ($debug);

exit 0;
