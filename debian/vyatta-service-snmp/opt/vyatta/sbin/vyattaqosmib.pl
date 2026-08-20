#! /usr/bin/perl
#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# By virtue of the following entry in the snmpd.conf file, this script
# is launched by the SNMP daemon when it needs access to the QoS MIB
# sub-tree.
#
#    pass_persist .1.3.6.1.4.1.74.1.32.1 /opt/vyatta/sbin/vyattaqosmib
#
# The PassPersist class, as provided by the PassPersist library,
# is responsible for:
#
#    o building and maintaining the MIB sub-tree
#    o responding to individual "get" & "getnext" requests from SNMPd
#    o invoking a callback in order to periodically update the MIB
#
# This "wrapper" script simply collects the QoS details (via
# qos-op-mode.pl), parses the resultant JSON and populates the MIB
# using methods provided by the PassPersist class.
#
# For details on PassPersist see "man SNMP::Extension::PassPersist"
#
# Parsing of the JSON and populating the MIB can be checked manually
# by invoking the script directly and passing in a file containing the
# output from qos-op-mode.pl:
#
#    vyattaqosmib.pl --statsfile qos-stats.json --interval 1 --idle 1
#
# This will "suck in" the QoS counters, create the MIB objects and
# then dump the MIB tree after 1 second.
#
use strict;
use warnings;
use Readonly;

use lib "/opt/vyatta/share/perl5";

use Getopt::Long;
use File::Slurp;
use Scalar::Util qw( looks_like_number );
use JSON qw( decode_json );
use Data::Dumper;

use SNMP::Extension::PassPersist;

Readonly my $VYATTAQOSBASEOID => ".1.3.6.1.4.1.74.1.32.1";

sub qosoid {
    my ( $base, $oid ) = @_;

    return "$base.$oid";
}

Readonly my $vRouterQosShaperObjects       => 1;
Readonly my $vRouterQosTrafficClassStats   => 2;
Readonly my $vRouterQosClassMatchStats     => 3;
Readonly my $vRouterQosInterfaceQueueStats => 4;
Readonly my $vRouterQosDscpWredMapStats    => 5;
Readonly my $qosShaperProfileTable => qosoid( $vRouterQosShaperObjects,     1 );
Readonly my $qosShaperProfileEntry => qosoid( $qosShaperProfileTable,       1 );
Readonly my $qosShaperClass        => qosoid( $qosShaperProfileEntry,       1 );
Readonly my $qosInterface          => qosoid( $qosShaperProfileEntry,       2 );
Readonly my $qosProfileName        => qosoid( $qosShaperProfileEntry,       3 );
Readonly my $qosVlan               => qosoid( $qosShaperProfileEntry,       4 );
Readonly my $qosTCStatsTable       => qosoid( $vRouterQosTrafficClassStats, 1 );
Readonly my $qosTCStatsEntry       => qosoid( $qosTCStatsTable,             1 );
Readonly my $qosTCIndex            => qosoid( $qosTCStatsEntry,             1 );
Readonly my $qosTCSPkts            => qosoid( $qosTCStatsEntry,             2 );
Readonly my $qosTCSBytes           => qosoid( $qosTCStatsEntry,             3 );
Readonly my $qosTCSTailDropPkts    => qosoid( $qosTCStatsEntry,             4 );
Readonly my $qosTCSREDDropPkts     => qosoid( $qosTCStatsEntry,             5 );
Readonly my $qosClassMatchTable    => qosoid( $vRouterQosClassMatchStats,   1 );
Readonly my $qosClassMatchEntry    => qosoid( $qosClassMatchTable,          1 );
Readonly my $qosCMIndex            => qosoid( $qosClassMatchEntry,          1 );
Readonly my $qosCMTClass           => qosoid( $qosClassMatchEntry,          2 );
Readonly my $qosCMPkts             => qosoid( $qosClassMatchEntry,          3 );
Readonly my $qosCMBytes            => qosoid( $qosClassMatchEntry,          4 );
Readonly my $qosCMExceededPkts     => qosoid( $qosClassMatchEntry,          5 );
Readonly my $qosCMExceededBytes    => qosoid( $qosClassMatchEntry,          6 );
Readonly my $qosInterfaceQueueTable =>
  qosoid( $vRouterQosInterfaceQueueStats, 1 );
Readonly my $qosInterfaceQueueEntry => qosoid( $qosInterfaceQueueTable,     1 );
Readonly my $qosIfQShaperClass      => qosoid( $qosInterfaceQueueEntry,     1 );
Readonly my $qosIfQTrafficClass     => qosoid( $qosInterfaceQueueEntry,     2 );
Readonly my $qosIfQIndex            => qosoid( $qosInterfaceQueueEntry,     3 );
Readonly my $qosIfQLength           => qosoid( $qosInterfaceQueueEntry,     4 );
Readonly my $qosIfQPkts             => qosoid( $qosInterfaceQueueEntry,     5 );
Readonly my $qosIfQBytes            => qosoid( $qosInterfaceQueueEntry,     6 );
Readonly my $qosIfQTailDropPkts     => qosoid( $qosInterfaceQueueEntry,     7 );
Readonly my $qosIfQREDDropPkts      => qosoid( $qosInterfaceQueueEntry,     8 );
Readonly my $qosDSCPWREDMapTable    => qosoid( $vRouterQosDscpWredMapStats, 1 );
Readonly my $qosDSCPWREDMapEntry    => qosoid( $qosDSCPWREDMapTable,        1 );
Readonly my $qosDSCPWREDMapName     => qosoid( $qosDSCPWREDMapEntry,        1 );
Readonly my $qosDSCPWREDMapDropPkts => qosoid( $qosDSCPWREDMapEntry,        2 );

my $snmppp;
my %ifindexcache;
my $collect_cmd;
my $test_lastifindex;

sub get_ifindex {
    my ($ifname) = @_;

    if ( !defined( $ifindexcache{$ifname} ) ) {
        my $ifindex = undef;

        if ($test_lastifindex) {
            $test_lastifindex++;
            $ifindex = $test_lastifindex;
        } else {
            $ifindex = read_file("/sys/class/net/$ifname/ifindex")
              unless ( !-d "/sys/class/net/$ifname" );

            chomp $ifindex unless !defined($ifindex);
        }

        $ifindexcache{$ifname} = $ifindex;
    }

    return $ifindexcache{$ifname};
}

sub oid_add {
    my ( $oid, $type, $value, $indicies ) = @_;

    my $index = "";
    foreach my $idx (@$indicies) {
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

    $snmppp->add_oid_entry( "$VYATTAQOSBASEOID.$oid$index", $type, $value );
}

sub oid_add_str {
    my ( $oid, $value, $indicies ) = @_;

    oid_add( $oid, "string", $value, $indicies );
}

sub oid_add_cnt {
    my ( $oid, $value, $indicies ) = @_;

    oid_add( $oid, "counter64", $value, $indicies );
}

sub oid_add_int {
    my ( $oid, $value, $indicies ) = @_;

    oid_add( $oid, "integer", $value, $indicies );
}

sub oid_add_gau {
    my ( $oid, $value, $indicies ) = @_;

    oid_add( $oid, "gauge", $value, $indicies );
}

sub get_value {
    my ( $hash, $field, $default ) = @_;

    my $value = $hash->{$field};
    $value //= $default;
    return $value;
}

sub update_ifclassmatchstats {
    my ( $subint, $ifindex, $vlan ) = @_;

    my @indices = ();

    #
    # Process the groups and associated rules. The assumption is
    # that there is only a single group (its an artefact of NPF)
    #
    foreach my $grp ( @{ $subint->{'rules'}->{'groups'} } ) {
        foreach my $rule ( @{ $grp->{'rule'} } ) {
            my $ruleid = $rule->{'rule-number'};
            @indices = ( $ifindex, $vlan, $ruleid );

            oid_add_int( $qosCMIndex, $ruleid, \@indices );
            oid_add_int( $qosCMTClass, $rule->{'qos-class'}, \@indices );
            oid_add_cnt( $qosCMPkts,  $rule->{'packets'}, \@indices );
            oid_add_cnt( $qosCMBytes, $rule->{'bytes'},   \@indices );
            oid_add_cnt( $qosCMExceededPkts,
                get_value( $rule, 'exceeded-packets', 0 ), \@indices );
            oid_add_cnt( $qosCMExceededBytes,
                get_value( $rule, 'exceeded-bytes', 0 ), \@indices );
        }
    }
}

sub update_iftrafficclassstats {
    my ( $subint, $ifindex, $vlan ) = @_;

    my @indices = ();

    foreach my $tcl ( @{ $subint->{'traffic-class-list'} } ) {
        my $tclass = $tcl->{'traffic-class'};
        @indices = ( $ifindex, $vlan, $tclass );
        oid_add_int( $qosTCIndex, $tclass, \@indices );
        oid_add_cnt( $qosTCSPkts,         $tcl->{'packets-64'},     \@indices );
        oid_add_cnt( $qosTCSBytes,        $tcl->{'bytes-64'},       \@indices );
        oid_add_cnt( $qosTCSTailDropPkts, $tcl->{'dropped-64'},     \@indices );
        oid_add_cnt( $qosTCSREDDropPkts,  $tcl->{'random-drop-64'}, \@indices );
    }
}

sub update_ifdscpwredstats {
    my ( $qs, $ifindex, $vlan, $shaperclass, $tclass ) = @_;

    my @indices = ();
    my $count   = 0;
    my $qid     = $qs->{'queue'};

    for my $wredmap ( @{ $qs->{'wred-map-64'} } ) {
        $count++;
        my $name  = $wredmap->{'res-grp-64'};
        my $drops = $wredmap->{'random-dscp-drop-64'};
        @indices = ( $ifindex, $vlan, $shaperclass, $tclass, $qid, $name );

        oid_add_cnt( $qosDSCPWREDMapDropPkts, $drops, \@indices );
    }

    #
    # In the absence of any WRED map configuration, the PassPersist
    # module ends up generating an obscure message:
    #
    #  Error: OID not increasing: ATT-VROUTER-QOS-MIB::qosDSCPWREDMapTable
    #   >= ATT-VROUTER-QOS-MIB::qosShaperClass.11.0
    #
    # In an attempt to clarify the picture, generate a dummy counter,
    # with a non-existent WRED map name ("").
    #
    if ( $count == 0 ) {
        @indices = ( $ifindex, $vlan, $shaperclass, $tclass, $qid, "" );
        oid_add_cnt( $qosDSCPWREDMapDropPkts, 0, \@indices );
    }
}

sub update_ifqueuestats {
    my ( $tcql, $ifindex, $vlan, $shaperclass ) = @_;

    my @indices = ();

    my $tclass = $tcql->{'traffic-class'};
    foreach my $qs ( @{ $tcql->{'queue-statistics'} } ) {
        my $qid = $qs->{'queue'};

        @indices = ( $ifindex, $vlan, $shaperclass, $tclass, $qid );
        oid_add_int( $qosIfQShaperClass,  $shaperclass, \@indices );
        oid_add_int( $qosIfQTrafficClass, $tclass,      \@indices );
        oid_add_int( $qosIfQIndex,        $qid,         \@indices );
        oid_add_gau( $qosIfQLength, get_value( $qs, 'len', 0 ), \@indices );
        oid_add_cnt( $qosIfQPkts,         $qs->{'packets-64'},     \@indices );
        oid_add_cnt( $qosIfQBytes,        $qs->{'bytes-64'},       \@indices );
        oid_add_cnt( $qosIfQTailDropPkts, $qs->{'dropped-64'},     \@indices );
        oid_add_cnt( $qosIfQREDDropPkts,  $qs->{'random-drop-64'}, \@indices );

        update_ifdscpwredstats( $qs, $ifindex, $vlan, $shaperclass, $tclass );
    }
}

sub update_ifshaper {
    my ( $subifn, $ifindex, $vlan ) = @_;

    my @indices = ();

    foreach my $pipe ( @{ $subifn->{'pipe-list'} } ) {
        my $shaperclass = $pipe->{'qos-class'};
        @indices = ( $ifindex, $vlan, $shaperclass );
        oid_add_int( $qosShaperClass, $shaperclass, \@indices );
        oid_add_int( $qosInterface,   $ifindex,     \@indices );
        oid_add_int( $qosVlan,        $vlan,        \@indices );
        oid_add_str( $qosProfileName, $pipe->{'qos-profile'}, \@indices );

        foreach my $tcql ( @{ $pipe->{'traffic-class-queues-list'} } ) {
            update_ifqueuestats( $tcql, $ifindex, $vlan, $shaperclass );
        }
    }
}

sub update_interfaces {
    my ($json) = @_;

    foreach my $ifn ( @{ $json->{'if-list'} } ) {
        my @subportlist = @{ $ifn->{shaper}->{'subport-list'} };

        foreach my $subifn (@subportlist) {
            my ( $ifname, $vif, $vlan ) =
              split( ' ', $subifn->{'subport-name'} );
            $vlan = 0 unless defined($vif);

            my $ifindex = get_ifindex($ifname);

            next unless defined($ifindex);

            update_ifshaper( $subifn, $ifindex, $vlan );
            update_iftrafficclassstats( $subifn, $ifindex, $vlan );
            update_ifclassmatchstats( $subifn, $ifindex, $vlan );
        }
    }
}

sub collectstats {
    my $output = `$collect_cmd`;
    if ( $? == -1 ) {
        print "Failed to run '$collect_cmd': $?\n";
        return;
    }

    return decode_json($output);
}

sub collect_and_update {
    my $json = collectstats();
    return if ( !defined($json) );

    update_interfaces($json);
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
    "help"        => \$help,
    "debug"       => \$debug,
    "interval:i"  => \$interval,
    "idle:i"      => \$idle,
    "statsfile=s" => \$statsfile,
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

if ($statsfile) {
    if ( $idle == 0 ) {
        print "Must have a non-zero idle time when using a stats file\n";
        usage();
    }

    $test_lastifindex = 100;
    $collect_cmd      = "cat $statsfile";
} else {
    $collect_cmd = "/opt/vyatta/bin/qos-op-mode.pl --statistics";
}

$snmppp = SNMP::Extension::PassPersist->new(
    backend_collect => \&collect_and_update,
    idle_count      => $idle,
    refresh         => $interval
);

$snmppp->run();

$snmppp->dump_oid_tree() if ( $debug || $statsfile );

exit 0;
