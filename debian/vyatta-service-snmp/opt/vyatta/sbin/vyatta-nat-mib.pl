#! /usr/bin/perl

# Copyright (c) 2017-2019, AT&T Intellectual Property.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# Copyright (c) 2007-2010 Vyatta, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: script is run as net-snmp extension to retrieve data for
# NAT MIB (RFC 4008).
#
# snmpd.conf contains:
# pass_persist .1.3.6.1.2.1.123.1 /opt/vyatta/sbin/vyatta-nat-mib.pl
# Thus snmpd will launch this program when it needs to access an
# OID under this sub-tree and the program will keep running, allowing
# stats to be cached and updated periodically.
#
# Simple protocol between snmpd and this program:
# Handshake
#   + stdin: "PING\n"
#   + stdout: "PONG\n"
#
# GET request
#   + stdin: "get\n<OID>\n"
#   + stdout: "<OID>\n<TYPE>\n<VALUE>\n" or "NONE\n" where TYPE is
#             integer, gauge, counter32, counter64, timeticks, ipaddress,
#             objectid, or string
#
# GETNEXT request
#   + stdin: "getnext\n<OID>\n"
#   + stdout: "<OID>\n<TYPE>\n<VALUE>\n" or "NONE\n"
#
# SET request
#   + stdin: "set\n<OID>\<TYPE> <VALUE>\n"
#   + stdout: "DONE\n" or "not-writable\n" or "wrong-type\n" or
#             "wrong-length\n" or "wrong-value\n" or "inconsistent-value\n"
#
# Shutdown
#  + stdin: "\n"
use 5.012;

use strict;
use warnings;
use Readonly;

use lib "/opt/vyatta/share/perl5";

use Getopt::Long;
use Config::Tiny;
use JSON qw( decode_json );
use Socket qw(inet_ntoa inet_aton);
use Data::Dumper;
use Vyatta::Dataplane;
use Vyatta::Interface;
use Vyatta::Aggregate;
use Vyatta::NpfRuleset;

#Log to file
my $fh, my $log_to_file;
if ( open ($fh, '>', '/tmp/vyatta-nat-mib.log' )) {
    autoflush $fh 1;
    $log_to_file = 1;
}

#Work out command to show NAT sessions and the JSON format, which depends on
#the dataplane version
my $nat_session_prefix;
my $old_nat_map_json;
system("dpkg --compare-versions `dpkg-query --showformat='\${Version}' " . 
       "--show vyatta-dataplane-protocols-versions` ge 3.3.7");
if ( $? == 0 ) {
    $nat_session_prefix = "session-op show sessions full ";
} else {
    $nat_session_prefix = "npf-op fw list sessions nat ";
    $old_nat_map_json   = 1;
}

# Disable output buffering.
autoflush STDOUT 1;

#Debugging subroutines
#FUTUREWORK: remove or called less liberally
sub debug {
    my @msg = @_;
    if (defined $log_to_file) {
        print $fh scalar localtime(), ":  ", @msg, "\n";
    }
    return;
}

#NAT MIB OID [RFC4002]
Readonly my $BASE_OID       => '1.3.6.1.2.1.123.1';
Readonly my $BASE_OID_FIRST => "$BASE_OID.1";
Readonly my $BASE_OID_LAST  => "$BASE_OID.10.1.4.5";
Readonly my $INTERNET_OID => '1.3.6.1';

#Global hash table holding information about all OIDs in the MIB.
#Used to retrieve the types for all OIDs and values for non-tabular OIDs:
#Non-tabular OID:  %NAT_MIB_OBJECTS{OID} => [Name, Type, Syntax, Value]
#Tabular OID:      %NAT_MIB_OBJECTS{OID} => [Name, Type, Syntax]
my %NAT_MIB_OBJECTS = (
    "$BASE_OID.1"   => [ 'natDefTimeouts',         'GROUP',  'NA',         1 ],
    "$BASE_OID.1.1" => [ 'natBindDefIdleTimeout',  'SCALAR', 'Unsigned32', 0 ],
    "$BASE_OID.1.2" => [ 'natUdpDefIdleTimeout',   'SCALAR', 'Unsigned32', 60 ],
    "$BASE_OID.1.3" => [ 'natIcmpDefIdleTimeout',  'SCALAR', 'Unsigned32', 60 ],
    "$BASE_OID.1.4" => [ 'natOtherDefIdleTimeout', 'SCALAR', 'Unsigned32', 60 ],
    "$BASE_OID.1.5" => [ 'natTcpDefIdleTimeout', 'SCALAR', 'Unsigned32', 86400 ],
    "$BASE_OID.1.6" => [ 'natTcpDefNegTimeout', 'SCALAR', 'Unsigned32', 60 ],

    "$BASE_OID.2" => [ 'natNotifCtrl', 'GROUP', 'NA', 1 ],
    "$BASE_OID.2.1" => [ 'natNotifThrottlingInterval', 'SCALAR', 'Integer32', 0 ],

    "$BASE_OID.3"     => [ 'natInterfaceTable', 'TABLE',   'SEQUENCE OF', 1 ],
    "$BASE_OID.3.1"   => [ 'natInterfaceEntry', 'ENTRY',   'SEQUENCE',    1 ],
    "$BASE_OID.3.1.1" => [ 'natInterfaceRealm', 'TABULAR', 'INTEGER' ],
    "$BASE_OID.3.1.2" => [ 'natInterfaceServiceType',  'TABULAR', 'BITS' ],
    "$BASE_OID.3.1.3" => [ 'natInterfaceInTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.3.1.4" => [ 'natInterfaceOutTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.3.1.5" => [ 'natInterfaceDiscards', 'TABULAR', 'Counter64' ],
    "$BASE_OID.3.1.6" => [ 'natInterfaceStorageType', 'TABULAR', 'StorageType' ],
    "$BASE_OID.3.1.7" => [ 'natInterfaceRowStatus', 'TABULAR', 'RowStatus' ],

    "$BASE_OID.4"     => [ 'natAddrMapTable', 'TABLE',   'SEQUENCE OF', 1 ],
    "$BASE_OID.4.1"   => [ 'natAddrMapEntry', 'ENTRY',   'SEQUENCE',    1 ],
    "$BASE_OID.4.1.1" => [ 'natAddrMapIndex', 'TABULAR', 'NatAddrMapId' ],
    "$BASE_OID.4.1.2" => [ 'natAddrMapName', 'TABULAR', 'SnmpAdminString' ],
    "$BASE_OID.4.1.3" => [ 'natAddrMapEntryType', 'TABULAR', 'NatAssociationType' ],
    "$BASE_OID.4.1.4" => [ 'natAddrMapTranslationEntity', 'TABULAR', 'NatTranslationEntity' ],
    "$BASE_OID.4.1.5" => [ 'natAddrMapLocalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.4.1.6" => [ 'natAddrMapLocalAddrFrom', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.4.1.7" => [ 'natAddrMapLocalAddrTo', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.4.1.8" => [ 'natAddrMapLocalPortFrom', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.4.1.9" => [ 'natAddrMapLocalPortTo', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.4.1.10" => [ 'natAddrMapGlobalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.4.1.11" => [ 'natAddrMapGlobalAddrFrom', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.4.1.12" => [ 'natAddrMapGlobalAddrTo', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.4.1.13" => [ 'natAddrMapGlobalPortFrom', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.4.1.14" => [ 'natAddrMapGlobalPortTo', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.4.1.15" => [ 'natAddrMapProtocol', 'TABULAR', 'NatProtocolMap' ],
    "$BASE_OID.4.1.16" => [ 'natAddrMapInTranslates',  'TABULAR', 'Counter64' ],
    "$BASE_OID.4.1.17" => [ 'natAddrMapOutTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.4.1.18" => [ 'natAddrMapDiscards',      'TABULAR', 'Counter64' ],
    "$BASE_OID.4.1.19" => [ 'natAddrMapAddrUsed',      'TABULAR', 'Gauge32' ],
    "$BASE_OID.4.1.20" => [ 'natAddrMapStorageType', 'TABULAR', 'StorageType' ],
    "$BASE_OID.4.1.21" => [ 'natAddrMapRowStatus',   'TABULAR', 'RowStatus' ],

    "$BASE_OID.5" => [ 'natAddrBindNumberOfEntries', 'SCALAR', 'Gauge32', 0 ],

    "$BASE_OID.6"   => [ 'natAddrBindTable', 'TABLE', 'SEQUENCE OF', 1 ],
    "$BASE_OID.6.1" => [ 'natAddrBindEntry', 'ENTRY', 'SEQUENCE',    1 ],
    "$BASE_OID.6.1.1" => [ 'natAddrBindLocalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.6.1.2" => [ 'natAddrBindLocalAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.6.1.3" => [ 'natAddrBindGlobalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.6.1.4" => [ 'natAddrBindGlobalAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.6.1.5" => [ 'natAddrBindId',         'TABULAR', 'NatBindId' ],
    "$BASE_OID.6.1.6" => [ 'natAddrBindTranslationEntity', 'TABULAR', 'NatTranslationEntity' ],
    "$BASE_OID.6.1.7" => [ 'natAddrBindType', 'TABULAR', 'NatAssociationType' ],
    "$BASE_OID.6.1.8" => [ 'natAddrBindMapIndex', 'TABULAR', 'NatAddrMapId' ],
    "$BASE_OID.6.1.9" => [ 'natAddrBindSessions', 'TABULAR', 'Gauge32' ],
    "$BASE_OID.6.1.10" => [ 'natAddrBindMaxIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.6.1.11" => [ 'natAddrBindCurrentIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.6.1.12" => [ 'natAddrBindInTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.6.1.13" => [ 'natAddrBindOutTranslates', 'TABULAR', 'Counter64' ],

    "$BASE_OID.7" => [ 'natAddrPortBindNumberOfEntries', 'SCALAR', 'Gauge32', 0 ],

    "$BASE_OID.8"   => [ 'natAddrPortBindTable', 'TABLE', 'SEQUENCE OF', 1 ],
    "$BASE_OID.8.1" => [ 'natAddrPortBindEntry', 'ENTRY', 'SEQUENCE',    1 ],
    "$BASE_OID.8.1.1" => [ 'natAddrPortBindLocalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.8.1.2" => [ 'natAddrPortBindLocalAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.8.1.3" => [ 'natAddrPortBindLocalPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.8.1.4" => [ 'natAddrPortBindProtocol', 'TABULAR', 'NatProtocolType' ],
    "$BASE_OID.8.1.5" => [ 'natAddrPortBindGlobalAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.8.1.6" => [ 'natAddrPortBindGlobalAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.8.1.7" => [ 'natAddrPortBindGlobalPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.8.1.8" => [ 'natAddrPortBindId', 'TABULAR', 'NatBindId' ],
    "$BASE_OID.8.1.9" => [ 'natAddrPortBindTranslationEntity', 'TABULAR', 'NatTranslationEntity' ],
    "$BASE_OID.8.1.10" => [ 'natAddrPortBindType', 'TABULAR', 'NatAssociationType' ],
    "$BASE_OID.8.1.11" => [ 'natAddrPortBindMapIndex', 'TABULAR', 'NatAddrMapId' ],
    "$BASE_OID.8.1.12" => [ 'natAddrPortBindSessions', 'TABULAR', 'Gauge32' ],
    "$BASE_OID.8.1.13" => [ 'natAddrPortBindMaxIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.8.1.14" => [ 'natAddrPortBindCurrentIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.8.1.15" => [ 'natAddrPortBindInTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.8.1.16" => [ 'natAddrPortBindOutTranslates', 'TABULAR', 'Counter64' ],

    "$BASE_OID.9"     => [ 'natSessionTable', 'TABLE',   'SEQUENCE OF', 1 ],
    "$BASE_OID.9.1"   => [ 'natSessionEntry', 'ENTRY',   'SEQUENCE',    1 ],
    "$BASE_OID.9.1.1" => [ 'natSessionIndex', 'TABULAR', 'NatSessionId' ],
    "$BASE_OID.9.1.2" => [ 'natSessionPrivateSrcEPBindId', 'TABULAR', 'NatBindIdOrZero' ],
    "$BASE_OID.9.1.3" => [ 'natSessionPrivateSrcEPBindMode', 'TABULAR', 'NatBindMode' ],
    "$BASE_OID.9.1.4" => [ 'natSessionPrivateDstEPBindId', 'TABULAR', 'NatBindIdOrZero' ],
    "$BASE_OID.9.1.5" => [ 'natSessionPrivateDstEPBindMode', 'TABULAR', 'NatBindMode' ],
    "$BASE_OID.9.1.6" => [ 'natSessionDirection', 'TABULAR', 'INTEGER' ],
    "$BASE_OID.9.1.7" => [ 'natSessionUpTime',    'TABULAR', 'TimeTicks' ],
    "$BASE_OID.9.1.8" => [ 'natSessionAddrMapIndex', 'TABULAR', 'NatAddrMapId' ],
    "$BASE_OID.9.1.9" => [ 'natSessionProtocolType', 'TABULAR', 'NatProtocolType' ],
    "$BASE_OID.9.1.10" => [ 'natSessionPrivateAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.9.1.11" => [ 'natSessionPrivateSrcAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.9.1.12" => [ 'natSessionPrivateSrcPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.9.1.13" => [ 'natSessionPrivateDstAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.9.1.14" => [ 'natSessionPrivateDstPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.9.1.15" => [ 'natSessionPublicAddrType', 'TABULAR', 'InetAddressType' ],
    "$BASE_OID.9.1.16" => [ 'natSessionPublicSrcAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.9.1.17" => [ 'natSessionPublicSrcPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.9.1.18" => [ 'natSessionPublicDstAddr', 'TABULAR', 'InetAddress' ],
    "$BASE_OID.9.1.19" => [ 'natSessionPublicDstPort', 'TABULAR', 'InetPortNumber' ],
    "$BASE_OID.9.1.20" => [ 'natSessionMaxIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.9.1.21" => [ 'natSessionCurrentIdleTime', 'TABULAR', 'TimeTicks' ],
    "$BASE_OID.9.1.22" => [ 'natSessionInTranslates',  'TABULAR', 'Counter64' ],
    "$BASE_OID.9.1.23" => [ 'natSessionOutTranslates', 'TABULAR', 'Counter64' ],

    "$BASE_OID.10"   => [ 'natProtocolTable', 'TABLE', 'SEQUENCE OF', 1 ],
    "$BASE_OID.10.1" => [ 'natProtocolEntry', 'ENTRY', 'SEQUENCE',    1 ],
    "$BASE_OID.10.1.1" => [ 'natProtocol', 'TABULAR', 'NatProtocolType' ],
    "$BASE_OID.10.1.2" => [ 'natProtocolInTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.10.1.3" => [ 'natProtocolOutTranslates', 'TABULAR', 'Counter64' ],
    "$BASE_OID.10.1.4" => [ 'natProtocolDiscards', 'TABULAR', 'Counter64' ],
);

#FUTUREWORK: Investigate further and try to improve these type mappings
# RFC Type => NetSNMP pass/pass_persist Type
#             (integer, gauge, counter, timeticks, ipaddress, objectid, or string)
my %RFC_NetSNMP_type_mappings = (
    "BITS"               => "string",    #Bitmap
    "Counter64"          => "counter64",
    "Gauge32"            => "gauge",
    "InetAddress"        => "ipaddress",
    "InetAddressType"    => "integer",   #0:unknown, 1:IPv4, 2:1Pv6
    "InetPortNumber"     => "integer",
    "INTEGER"            => "integer",
    "Integer32"          => "integer",
    "NA"                 => "string",
    "NatAddrMapId"       => "gauge",
    "NatAssociationType" => "integer",   #1:static, 2:dynamic
    "NatBindId"          => "gauge",
    "NatBindIdOrZero"    => "gauge",     #0:symmetric NAT or bind ID
    "NatBindMode"        => "integer",   #1:addressBind, 2:addressPortBind
    "NatProtocolMap"     => "string",    #Bitmap 0:other, 1:ICMP, 2:UDP, 3:TCP
    "NatProtocolType"    => "integer",   #1:none, 2:other, 3:ICMP, 4: UDP, 5:TCP
    "NatSessionId"       => "gauge",
    "NatTranslationEntity" => "string"
    , #Bitmap 0:inboundSrcEndPoint, 1:outboundDstEndPoint, 2:inboundDstEndPoint, 3:outboundSrcEndPoint
    "RowStatus" =>
      "integer",    #1:active, 2:notinService, 3:notReady, 4:createandGo etc
    "SEQUENCE OF"     => "string",
    "SEQUENCE"        => "string",
    "SnmpAdminString" => "string",
    "StorageType" =>
      "integer",   #1:other, 2:volatile, 3:nonVolatile, 4: permanent, 5.readOnly
    "TimeTicks"  => "timeticks",
    "Unsigned32" => "gauge",
);

#Maintain interface name -> ifindex mapping
#Note actually contains all interfaces in the system. Restrict to only those relevant for NAT?
#Key: interface name (e.g. "dp0s4")
my %ifIndex;

#The following data structures are to hold the keys, key sets and values for tabular data:
#Key: $BASE_OID.3.1.x.ifIndex
my %natInterfaceTable;
my @natInterfaceTableKey1;
my %natInterfaceTableKey;

#Key: $BASE_OID.4.1.x.ifIndex.natAddrMapIndex
my %natAddrMapTable;
my @natAddrMapTableKey1;
my @natAddrMapTableKey2;
my %natAddrMapTableKeys;
my @natAddrMapTableOrderedKeys;

#Key: $BASE_OID.6.1.x.ifIndex.natAddrBindLocalAddrType.natAddrBindLocalAddr
my %natAddrBindTable;
my @natAddrBindTableKey1;
my @natAddrBindTableKey2;
my @natAddrBindTableKey3;
my %natAddrBindTableKeys;
my @natAddrBindTableOrderedKeys;

#Key: $BASE_OID.8.1.x.ifIndex.natAddrPortBindLocalAddrType.natAddrPortBindLocalAddr
#                    .natAddrPortBindLocalPort.natAddrPortBindProtocol
my %natAddrPortBindTable;
my @natAddrPortBindTableKey1;
my @natAddrPortBindTableKey2;
my @natAddrPortBindTableKey3;
my @natAddrPortBindTableKey4;
my @natAddrPortBindTableKey5;
my %natAddrPortBindTableKeys;
my @natAddrPortBindTableOrderedKeys;

#Key: $BASE_OID.9.1.x.ifIndex.natSessionIndex
my %natSessionTable;
my @natSessionTableKey1;
my @natSessionTableKey2;
my %natSessionTableKeys;
my @natSessionTableOrderedKeys;

#Key: $BASE_OID.10.1.x.natProtocol
my %natProtocolTable;
my @natProtocolTableKey1;
my %natProtocolTableKey;

#Used to distinguish between SNAT and DNAT rules in MIB, as need
#a unique identify and SNAT and DNAT rules may have same rule number
use constant SNAT_RULE_OFFSET => 10000;

#Defaults for IP addresses and ports
use constant LOWEST_IPV4_ADDR => "0.0.0.1";
use constant HIGHEST_IPV4_ADDR => "255.255.255.255";
use constant ANY_IPV4_NETWORK => "0.0.0.0";
use constant ANY_IPV4_NETMASK => 0;
use constant LOWEST_PORT => 1;
use constant HIGHEST_PORT => 65535;

#Default value assigned to currently unsupported OIDs
use constant UNSUPPORTED => 0;

#For efficiency, stats not extracted from NPF for every GET or GETNEXT request
#FUTUREWORK: Determine optimal stats refresh interval
my $stats_extraction_time = 0;      #last time stats extracted from NPF
my $stats_extraction_interval = 1;  #min duration (secs) between stats extraction

#Identify lexicographically lower OID
# Input: OID1, 01D2
# Outputs. 1 if OID1 lexicographically lower than 0ID2. 0 otherwise.
sub is_oid_lower {
    my ( $oid1, $oid2 ) = @_;

    #Strip any leading . and split OIDs into arrays of numbers
    $oid1 =~ s/^\.//;
    my @oid1_numbers = split( '\.', $oid1 );
    $oid2 =~ s/^\.//;
    my @oid2_numbers = split( '\.', $oid2 );

    #Do the comparison, up to size of shorter OID
    my $min_size = @oid1_numbers;
    if ( @oid1_numbers > @oid2_numbers ) {
        $min_size = @oid2_numbers;
    }

    for ( my $i = 0 ; $i < $min_size ; $i++ ) {
        if ( $oid1_numbers[$i] < $oid2_numbers[$i] ) {
            return 1;
        }

        if ( $oid1_numbers[$i] > $oid2_numbers[$i] ) {
            return 0;
        }
    }

    #If here, OIDs must be equal up to min_size.
    #Thus indicate the OID with shorter/equal length is lower.
    if ( $min_size ==  @oid1_numbers ) {
        return 1;
    }

    return 0;
}

#Determine if OID2 is in sub-tree for OID1
#Inputs: OID1, OID2
#Outputs: 1 if OID2 is in sub-tree for OID1. O otherwise
sub is_oid_in_subtree {
    my $oid = shift;
    my $sub_oid = shift;

    #Only interested in when index() returns 0
    #i.e. $sub_oid occurs a start of $oid
    if ( index($oid, $sub_oid)) {
        return 0;
    }

    return 1;
}

#Convert IP address in natAddrBindTable key from decimal to dotted decimal
#Input: a.b.c (where c is IP address numerical value)
#Output: a.b.c1.c2.c3.c4
sub natAddrBindTable_keys_convert {
    my $input_key   = shift;
    my @key_numbers = split( '\.', $input_key );
    my $ip_addr     = inet_ntoa( pack( "N", $key_numbers[2] ) );
    return "$key_numbers[0].$key_numbers[1].$ip_addr";
}

#Convert IP address in natAddrPortBindTable key from decimal to dotted decimal
#Input: a.b.c.d.e (where c is IP address numerical value)
#Output: a.b.c1.c2.c3.c4.d.e
sub natAddrPortBindTable_keys_convert {
    my $input_key   = shift;
    my @key_numbers = split( '\.', $input_key );
    my $ip_addr     = inet_ntoa( pack( "N", $key_numbers[2] ) );
    return
"$key_numbers[0].$key_numbers[1].$ip_addr.$key_numbers[3].$key_numbers[4]";
}

#Determine if MIB contents should be updated by extracting new stats from NPF
#Output: 1 if more than stats_extraction_interval secs elapsed since last NPF stats extraction
#        0 otherwise
sub stats_stale {
    my $current_time = time();
    if ( ( $stats_extraction_time + $stats_extraction_interval ) <
        $current_time )
    {
        $stats_extraction_time = $current_time;
        return 1;
    }
    return 0;
}

#Identify lexicographically next OID
#Input: OID
#Output: Lexographical next OID or 0 if none exists.
sub get_next_oid {
    my $oid = shift;

    #Sanity check if this OID under Internet MIB subtree
    if (!is_oid_in_subtree($oid, $INTERNET_OID)) {
        debug("$oid not under $INTERNET_OID");
        return 0;
    }

    #Does OID start with $BASE_OID?
    if ( $oid !~ s/^$BASE_OID// ) {
        debug("$oid not under $BASE_OID");

        if ( is_oid_lower( $oid, $BASE_OID_FIRST ) ) {
            debug("$oid lower than $BASE_OID_FIRST");
            return $BASE_OID_FIRST;
        }

        return 0;
    }

    #Now remove leading dot and split OID into array of numbers
    $oid =~ s/^\.//;
    my @oid_numbers = split( '\.', $oid );

    #Is OID lexicographically greater than largest OID in sub-tree?
    my $max_oid = $BASE_OID_LAST;
    $max_oid =~ s/$BASE_OID//;
    $max_oid =~ s/^\.//;
    if ( is_oid_lower( $max_oid, $oid ) ) {
        debug(
            "Cannot GETNEXT($BASE_OID.$oid); greater than max, $BASE_OID_LAST");
        return 0;
    }

    #Should MIB be updated by extracting stats from NPF now?
    if ( stats_stale() ) {
        if ( !refresh_stats() ) {
             debug("Not all MIB tables updated/exist");
	}
    }

    # Supplied OID not under NAT MIB tree.
    # Since already tested that OID is not larger than largest
    # allowable OID, return the first value
    #OID < $BASE_OID
    if ( !defined( $oid_numbers[0] ) ) {
        return $BASE_OID_FIRST;
    }

    #Finding next OIDs when
    #OID == $BASE_OID.1.* => natDefTimeouts
    if ( $oid_numbers[0] == 1 ) {

        #OID == $BASE_OID.1
        if ( !defined( $oid_numbers[1] ) ) {
            return "$BASE_OID.1.1";
        }

        my $i = $oid_numbers[1];

        #OID == $BASE_OID.1.1.i*, where 0 <  i <= 6
        if ( ( $i > 0 ) && ( $i < 6 ) ) {
            ++$i;
            return "$BASE_OID.1.$i";
        }

        #OID == $BASE_OID.1.[6-...]
        return "$BASE_OID.2";
    }

    #Finding next OIDs when
    #OID == $BASE_OID.2.* => natNotifCtrl
    if ( $oid_numbers[0] == 2 ) {

        #OID == $BASE_OID.2
        if ( !defined( $oid_numbers[1] ) ) {
            return "$BASE_OID.2.1";
        }

        #OID == $BASE_OID.2.[...]
        return "$BASE_OID.3";
    }

    #Finding next OIDs when
    #OID == $BASE_OID.3.* => natInterfaceTable
    #Valid natInterfaceTable OID = $BASE_OID.3.1.[1-7].key1
    # + @natInterfaceTableKey1[] = sorted unique key1 values
    # + %natInterfaceTableKey{key1} = relative position of key
    if ( $oid_numbers[0] == 3 ) {

        #OID == $BASE_OID.3 or $BASE_OID.3.0*
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.3.1";
        }

        #OID == $BASE_OID.3.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key = $natInterfaceTableKey1[0];
            my $key_count = @natInterfaceTableKey1;
            my $natInterfaceTable_columns = 7;    #$BASE_OID.3.1.[1-7]*

            #If table is empty return first OID after table
            if ( !defined $first_key ) {
                return "$BASE_OID.4";
            }

            #OID == $BASE_OID.3.1 or $BASE_OID.3.1.0
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.3.1.1.$first_key";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.3.1.i*, where 0 <  i <= $natInterfaceTable_columns
            if ( ( $i > 0 ) && ( $i <= $natInterfaceTable_columns ) ) {

                #OID == $BASE_OID.3.1.i
                #If no key specified, return first key
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.3.1.$i.$first_key";
                }

                #If key is specified, look up its relative position
                #and use this position to find next key
                my $key1;
                my $x        = $oid_numbers[3];
                my $position = $natInterfaceTableKey{$x};
                if ( defined $position ) {
                    $position++;

                    #If last key reached, return first OID either
                    #in next row in this table or next table
                    if ( $position >= $key_count ) {
                        if ( $i == $natInterfaceTable_columns ) {
                            return "$BASE_OID.4";
                        } else {
                            ++$i;
                            return "$BASE_OID.3.1.$i.$first_key";
                        }
                    }

                    #Return valid next key found
                    return "$BASE_OID.3.1.$i.$natInterfaceTableKey1[$position]";
                }

                #Quick lookup using specified key failed so try
                #to handle different inputs....

                #If x smaller than lowest OID in table, next OID
                #is the first OID
                if ( $x < $natInterfaceTableKey1[0] ) {
                    return "$BASE_OID.3.1.$i.$first_key";
                }

                #If x bigger than highest OID in table row, next OID
                #is first OID in next row or next table
                if ( $x > $natInterfaceTableKey1[-1] ) {
                    if ( $i == $natInterfaceTable_columns ) {
                        return "$BASE_OID.4";
                    } else {
                        ++$i;
                        return "$BASE_OID.3.1.$i.$first_key";
                    }
                }

                #If x within table range, find first key1 value larger than
                #or equal to x
                for (
                    my $key1_index = 0 ;
                    $key1_index < $key_count ;
                    $key1_index++
                  )
                {
                    if ( $x <= $natInterfaceTableKey1[$key1_index] ) {
                        $key1 = $natInterfaceTableKey1[$key1_index];
                        return "$BASE_OID.3.1.$i.$key1";
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }
            }
        }

        #OID == $BASE_OID.3.1.[8-...]
        #OID == $BASE_OID.3.[2-...]
        return "$BASE_OID.4";
    }

    #Finding next OIDs when
    #OID = $BASE_OID.4.* => natAddrMapTable
    # Valid natAddrMapTable OID = $BASE_OID.4.1.[1-21].key1.key2
    # + @natAddrMapTableKey1[] = sorted unique key1 values
    # + @natAddrMapTableKey2[] = sorted unique key2 values
    # + %natAddrMapTableKeys{key1.key2} = relative position of key-pair
    # + @natAddrMapTableOrderedKeys[position] = key1.key2
    if ( $oid_numbers[0] == 4 ) {

        #OID == $BASE_OID.4 or $BASE_OID.4.0*
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.4.1";
        }

        #OID == $BASE_OID.4.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key_pair = $natAddrMapTableOrderedKeys[0];
            #If table is empty return first OID after table
            if ( !defined $first_key_pair ) {
                return "$BASE_OID.5";
            }
            my $natAddrMap_columns = 21;    #$BASE_OID.4.1.[1-21]....

            #OID == $BASE_OID.4.1 or $BASE_OID.4.1.0
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.4.1.1.$first_key_pair";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.4.1.i*, where 0 <  i <= $natAddrMap_columns
            if ( ( $i > 0 ) && ( $i <= $natAddrMap_columns ) ) {

                #OID == $BASE_OID.4.1.i
                #If neither key1 nor key2 specified, return first
                #occurring key pair
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.4.1.$i.$first_key_pair";
                }

                #$BASE_OID.4.1.i.x(.y)
                my $x = $oid_numbers[3];    #definitely defined
                my $y = $oid_numbers[4];    #possibly defined
                my $key1;

                #Before diving into complex calculations to try
                #to find next OID for different unexpected inputs,
                #handle expected normal case of being given a
                #valid input key-pairing
                if ( defined $x && defined $y ) {

                    #Find relative position of input key pair
                    #in ordered array of all key pairings and
                    #increment index to find next if possible.
                    my $next_keys;
                    my $position = $natAddrMapTableKeys{"$x.$y"};
                    if ( defined $position ) {
                        $position++;

                        #If last key pair reached, return first OID
                        #either in next row in this table or next table
                        if ( $position >= @natAddrMapTableOrderedKeys ) {
                            if ( $i == $natAddrMap_columns ) {
                                return "$BASE_OID.5";
                            } else {
                                ++$i;
                                return
                                  "$BASE_OID.4.1.$i.$first_key_pair";
                            }
                        }

                        #Return valid next key pairing found
                        $next_keys = $natAddrMapTableOrderedKeys[$position];
                        return "$BASE_OID.4.1.$i.$next_keys";
                    }
                }

                #Quick lookup using specified key pairing failed so try
                #to handle different input combination....

                #If x smaller than lowest OID in table, next OID
                #is the first OID
                if ( $x < $natAddrMapTableKey1[0] ) {
                    return "$BASE_OID.4.1.$i.$first_key_pair";
                }

                #If x bigger than highest OID in row, next OID
                #is first OID in next row or after this table
                if ( $x > $natAddrMapTableKey1[-1] ) {
                    if ( $i == $natAddrMap_columns ) {
                        return "$BASE_OID.5";
                    } else {
                        ++$i;
                        return "$BASE_OID.4.1.$i.$first_key_pair";
                    }
                }

        #Given preceding checks, x must be within table range so find first key1
        #value larger than or equal to x
                my $key1_index;
                my $number_keys1 = @natAddrMapTableKey1;
                for (
                    $key1_index = 0 ;
                    $key1_index < $number_keys1 ;
                    $key1_index++
                  )
                {
                    if ( $x <= $natAddrMapTableKey1[$key1_index] ) {
                        $key1 = $natAddrMapTableKey1[$key1_index];
                        last;
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }

                #Now that key1 is known must find key2.  There are a number
                #of scenarios in which all that is needed is to find lowest
                #key2 for which key1.key2 is a valid key-pair:
                # + x != key1 (key1 must be next value for input x)
                # + y not defined (no key2 value input)
                # + y out of range (invalid key2 value input)
                if (   ( $x != $key1 )
                    || ( !defined $y )
                    || ( $y <= $natAddrMapTableKey2[0] )
                    || ( $y > $natAddrMapTableKey2[-1] ) )
                {

                    #Next key1 after x found.  Find lowest lowest
                    #key2 for which key1.key2 is a valid key-pair
                    foreach my $key2 (@natAddrMapTableKey2) {
                        if ( exists $natAddrMapTableKeys{"$key1.$key2"} ) {
                            return "$BASE_OID.4.1.$i.$key1.$key2";
                        }
                    }
                    return 0;
                }

                #Given preceding checks, y must be within table range,
                #so find first key2 value larger than or equal to y
                my $key2, my $key2_index;
                my $number_keys2 = @natAddrMapTableKey2;
                for (
                    $key2_index = 0 ;
                    $key2_index < $number_keys2 ;
                    $key2_index++
                  )
                {
                    if ( $y <= $natAddrMapTableKey2[$key2_index] ) {
                        $key2 = $natAddrMapTableKey2[$key2_index];
                        last;
                    }
                }

                if ( !defined $key2 ) {
                    return 0;
                }

                #At this point, input x must have matched key1 exactly.
                #If y matched key2 exactly, then both keys exist but
                #together they may not necessarily be a valid combination.
                #A valid combination should have been detected earlier
                #so return error if that is the case.
                if (   ( $y == $key2 )
                    && ( exists $natAddrMapTableKeys{"$key1.$key2"} ) )
                {
                    return 0;
                }

                #Starting with the key2 value found, try to find the first
                #valid key1.key2 pairing
                for ( my $j = $key2_index ; $j < $number_keys2 ; $j++ ) {
                    my $potential_key2 = $natAddrMapTableKey2[$j];
                    if ( exists $natAddrMapTableKeys{"$key1.$potential_key2"} )
                    {
                        return "$BASE_OID.4.1.$i.$key1.$potential_key2";
                    }
                }

                #No valid key1.key2 pairing found so must increment key1
                #and return the first valid pairing containing key1.  If
                #non found (i.e. at end of table) fall through and return
                #first OID in next table.
                my $potential_key1 = $natAddrMapTableKey1[ $key1_index + 1 ];

                if ( defined $potential_key1 ) {
                    for ( my $j = 0 ; $j < $number_keys2 ; $j++ ) {
                        my $potential_key2 = $natAddrMapTableKey2[$j];
                        if (
                            exists $natAddrMapTableKeys{
                                "$potential_key1.$potential_key2"} )
                        {
                            return
"$BASE_OID.4.1.$i.$potential_key1.$potential_key2";
                        }
                    }
                }

            }
        }

        #OID == $BASE_OID.4.1.[22-...]
        #OID == $BASE_OID.4.[2-...]
        return "$BASE_OID.5";
    }

    #Finding next OIDs when
    #OID == $BASE_OID.5.* => natAddrBindNumberOfEntries
    if ( $oid_numbers[0] == 5 ) {
        return "$BASE_OID.6";
    }

    #Finding next OIDs when
    #OID = $BASE_OID.6.* => natAddrBindTable
    # Valid natAddrBindTable OID = $BASE_OID.6.1.[1-13].key1.key2.key3
    # + @natAddrBindTableKey1[] = sorted unique key1 values
    # + @natAddrBindTableKey2[] = sorted unique key2 values
    # + @natAddrBindTableKey3[] = sorted unique key3 values
    # + %natAddrBindTableKeys{key1.key2.key3} = relative position of key set
    # + @natAddrBindTableOrderedKeys[position] = key1.key2.key3
    #Note key3 is an IP address which is stored in decimal in the
    #above structures but will be in dotted decimal as an input
    #into this subroutine
    if ( $oid_numbers[0] == 6 ) {

        #OID == $BASE_OID.6 or OID == $BASE_OID.6.0
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.6.1";
        }

        #OID == $BASE_OID.6.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key_set = $natAddrBindTableOrderedKeys[0];
            #If table is empty return first OID after table
            if ( !defined $first_key_set ) {
                return "$BASE_OID.7";
            }

            my $converted_first_key_set =
              natAddrBindTable_keys_convert($first_key_set);
            my $natAddrBind_columns = 13;    # $BASE_OID.6.1.[1-13]*

            #OID == $BASE_OID.6.1 or OID == $BASE_OID.6.1.0
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.6.1.1.$converted_first_key_set";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.6.1.i*, where 0 <  i <= $natAddrBind_columns
            if ( ( $i > 0 ) && ( $i <= $natAddrBind_columns ) ) {

                #OID == $BASE_OID.6.1.i
                #If neither key1 nor key2 nor key3 specified, return first
                #occurring key pair
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.6.1.$i.$converted_first_key_set";
                }

                #$BASE_OID.6.1.i.x(.y.z)
                #where z is actually IP address currently in in dotted decimal
                #which will be converted to decimal for finding next OID etc.
                my $x, my $y, my $z;
                my $key1, my $next_keys;
                $x = $oid_numbers[3];
                $y = $oid_numbers[4];
                my $octet1 = $oid_numbers[5];
                my $octet2 = $oid_numbers[6];
                my $octet3 = $oid_numbers[7];
                my $octet4 = $oid_numbers[8];
                if (   defined $octet1
                    && defined $octet2
                    && defined $octet3
                    && defined $octet4 )
                {
                    my $ip_addr = "$octet1.$octet2.$octet3.$octet4";
                    my $ip_addr_num = ( unpack( "N", inet_aton($ip_addr) ) );
                    if ( $ip_addr_num != 0 ) {
                        $z = $ip_addr_num;
                    }
                }

                #Before diving into complex calculations to try
                #to find next OID for different unexpected inputs,
                #handle expected normal case of being given a
                #valid input key set
                if ( defined $x && defined $y && defined $z ) {

                    #Find relative position of input key set
                    #in ordered array of all key pairings and
                    #increment index to find next if possible.
                    my $position = $natAddrBindTableKeys{"$x.$y.$z"};
                    if ( defined $position ) {
                        $position++;

                        #If last key pair reached, return first OID
                        #either in next row in this table or next table
                        if ( $position >= @natAddrBindTableOrderedKeys ) {
                            if ( $i == $natAddrBind_columns ) {
                                return "$BASE_OID.7";
                            } else {
                                ++$i;
                                return
"$BASE_OID.6.1.$i.$converted_first_key_set";
                            }
                        }

                        #Return valid next key pairing found
                        $next_keys = natAddrBindTable_keys_convert(
                            $natAddrBindTableOrderedKeys[$position] );
                        return "$BASE_OID.6.1.$i.$next_keys";
                    }
                }

                #Quick lookup using specified key set failed so try
                #to handle different input combination....

                #If x smaller than lowest OID in table, next OID
                #is the first OID
                if ( $x < $natAddrBindTableKey1[0] ) {
                    return "$BASE_OID.6.1.$i.$converted_first_key_set";
                }

                #If x bigger than highest OID in row, next OID
                #is first OID in next row or after this table
                if ( $x > $natAddrBindTableKey1[-1] ) {
                    if ( $i == $natAddrBind_columns ) {
                        return "$BASE_OID.7";
                    } else {
                        ++$i;
                        return
                          "$BASE_OID.6.1.$i.$converted_first_key_set";
                    }
                }

                #Given preceding checks, x must be within table range so
                #find first key1 value larger than or equal to x
                my $key1_index;
                my $number_keys1 = @natAddrBindTableKey1;
                for (
                    $key1_index = 0 ;
                    $key1_index < $number_keys1 ;
                    $key1_index++
                  )
                {
                    if ( $x <= $natAddrBindTableKey1[$key1_index] ) {
                        $key1 = $natAddrBindTableKey1[$key1_index];
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }

                #Now that key1 is known must find key2 & key3.  There are a
                #number of scenarios in which all that is needed is to find
                #lowest key2 & key3 for which key1.key2.key3 is a valid key set:
                # + x != key1 (key1 must be next value for input x)
                # + y not defined (no key2 value input)
                # + y out of range (invalid key2 value input)
                if (   ( $x != $key1 )
                    || ( !defined $y )
                    || ( $y <= $natAddrBindTableKey2[0] )
                    || ( $y > $natAddrBindTableKey2[-1] ) )
                {

                    #Next key1 after x found.  Find lowest key2 and key3
                    #for which key1.key2.key3 is a valid key set
                    foreach my $key2 (@natAddrBindTableKey2) {
                        foreach my $key3 (@natAddrBindTableKey3) {
                            $next_keys = natAddrBindTable_keys_convert(
                                "$key1.$key2.$key3");
                            if ( exists $natAddrBindTableKeys{"$next_keys"} ) {
                                return "$BASE_OID.6.1.$i.$next_keys";
                            }
                        }
                    }
                    return 0;
                }

 #At this point, handled GETNEXT when
 # + key1, key2, key3 specified and existing (expected input from SNMP agent)
 # + neither key1, key2 nor key3 specified
 # + key1 out of range
 # + key1 within range but key2 out of range or not specified
 #FUTUREWORK: Ideally should try to handle other theoretical scenarios here.....
            }
        }

        #OID == $BASE_OID.6.1.[22-...]
        #OID == $BASE_OID.6.[2-...]
        return "$BASE_OID.7";
    }

    #Finding next OIDs when
    #OID == $BASE_OID.7.* => natAddrPortBindNumberOfEntries
    if ( $oid_numbers[0] == 7 ) {
        return "$BASE_OID.8";
    }

#Finding next OIDs when
#OID = $BASE_OID.8.* => natAddrPortBindTable
# Valid natAddrPortBindTable OID = $BASE_OID.8.1.[1-15].key1.key2.key3.key4.key5
# + @natAddrPortBindTableKey1[] = sorted unique key1 values
# + @natAddrPortBindTableKey2[] = sorted unique key2 values
# + @natAddrPortBindTableKey3[] = sorted unique key3 values
# + @natAddrPortBindTableKey4[] = sorted unique key4 values
# + @natAddrPortBindTableKey5[] = sorted unique key5 values
# + %natAddrPortBindTableKeys{key1.key2.key3.key4.key5} = relative position of key set
# + @natAddrPortBindTableOrderedKeys[position] = key1.key2.key3.key4.key5
#Note key3 is an IP address which is stored in decimal in the
#above structures but will be in dotted decimal as an input
#into this subroutine
#OID = $BASE_OID.8.*
    if ( $oid_numbers[0] == 8 ) {

        #OID == $BASE_OID.8 or OID == $BASE_OID.8.0
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.8.1";
        }

        #OID == $BASE_OID.8.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key_set = $natAddrPortBindTableOrderedKeys[0];
            #If table is empty return first OID after table
            if ( !defined $first_key_set ) {
                return "$BASE_OID.9";
            }

            my $converted_first_key_set =
              natAddrPortBindTable_keys_convert($first_key_set);
            my $natAddrPortBind_columns = 16;    # $BASE_OID.8.1.[1-16]*

            #OID == $BASE_OID.8.1 or OID == $BASE_OID.8.1.0
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.8.1.1.$converted_first_key_set";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.8.1.i*, where 0 <  i <= $natAddrPortBind_columns
            if ( ( $i > 0 ) && ( $i <= $natAddrPortBind_columns ) ) {

                #OID == $BASE_OID.8.1.i
                #If no key specified, return first occurring key set
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.8.1.$i.$converted_first_key_set";
                }

                #$BASE_OID.8.1.i.p(.q.r.s.t)
                #where r is actually IP address currently in in dotted decimal
                #which will be converted to decimal for finding next OID etc.
                my $p, my $q, my $r, my $s, my $t;
                my $key1, my $next_keys;
                $p = $oid_numbers[3];
                $q = $oid_numbers[4];
                my $octet1 = $oid_numbers[5];
                my $octet2 = $oid_numbers[6];
                my $octet3 = $oid_numbers[7];
                my $octet4 = $oid_numbers[8];
                $s = $oid_numbers[9];
                $t = $oid_numbers[10];

                if (   defined $octet1
                    && defined $octet2
                    && defined $octet3
                    && defined $octet4 )
                {
                    my $ip_addr = "$octet1.$octet2.$octet3.$octet4";
                    my $ip_addr_num = ( unpack( "N", inet_aton($ip_addr) ) );
                    if ( $ip_addr_num != 0 ) {
                        $r = $ip_addr_num;
                    }
                }

                #Before diving into complex calculations to try
                #to find next OID for different unexpected inputs,
                #handle expected normal case of being given a
                #valid input key set
                if (   defined $p
                    && defined $q
                    && defined $r
                    && defined $s
                    && defined $t )
                {
                    #Find relative position of input key set
                    #in ordered array of all key pairings and
                    #increment index to find next if possible.
                    my $position = $natAddrPortBindTableKeys{"$p.$q.$r.$s.$t"};
                    if ( defined $position ) {
                        $position++;

                        #If last key pair reached, return first OID
                        #either in next row in this table or next table
                        if ( $position >= @natAddrPortBindTableOrderedKeys ) {
                            if ( $i == $natAddrPortBind_columns ) {
                                return "$BASE_OID.9";
                            } else {
                                ++$i;
                                return
"$BASE_OID.8.1.$i.$converted_first_key_set";
                            }
                        }

                        #Return valid next key pairing found
                        $next_keys = natAddrPortBindTable_keys_convert(
                            $natAddrPortBindTableOrderedKeys[$position] );
                        return "$BASE_OID.8.1.$i.$next_keys";
                    }
                }

                #Quick lookup using specified key set failed so try
                #to handle different input combination....

                #If a smaller than lowest OID in table, next OID
                #is the first OID
                if ( $p < $natAddrPortBindTableKey1[0] ) {
                    return "$BASE_OID.8.1.$i.$converted_first_key_set";
                }

                #If a bigger than highest OID in row, next OID
                #is first OID in next row or after this table
                if ( $p > $natAddrPortBindTableKey1[-1] ) {
                    if ( $i == $natAddrPortBind_columns ) {
                        return "$BASE_OID.9";
                    } else {
                        ++$i;
                        return
                          "$BASE_OID.8.1.$i.$converted_first_key_set";
                    }
                }

                #Given preceding checks, a must be within table range so
                #find first key1 value larger than or equal to a
                my $key1_index;
                my $number_keys1 = @natAddrPortBindTableKey1;
                for (
                    $key1_index = 0 ;
                    $key1_index < $number_keys1 ;
                    $key1_index++
                  )
                {
                    if ( $p <= $natAddrPortBindTableKey1[$key1_index] ) {
                        $key1 = $natAddrPortBindTableKey1[$key1_index];
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }

              #Now that key1 is known must find other keys  There are a
              #number of scenarios in which all that is needed is to find
              #lowest set for which key1.key2.key3.key4.key5 is a valid key set:
              # + p != key1 (key1 must be next value for input a)
              # + q not defined (no key2 value input)
              # + q out of range (invalid key2 value input)
                if (   ( $p != $key1 )
                    || ( !defined $q )
                    || ( $q <= $natAddrPortBindTableKey2[0] )
                    || ( $q > $natAddrPortBindTableKey2[-1] ) )
                {

                    #Next key1 after a found.  Find lowest key2, key3 and key4
                    #for which key1.key2.key3.key4.key5 is a valid key set
                    foreach my $key2 (@natAddrPortBindTableKey2) {
                        foreach my $key3 (@natAddrPortBindTableKey3) {
                            foreach my $key4 (@natAddrPortBindTableKey4) {
                                foreach my $key5 (@natAddrPortBindTableKey5) {
                                    $next_keys =
                                      natAddrPortBindTable_keys_convert(
                                        "$key1.$key2.$key3.$key4.$key5");
                                    if (
                                        exists $natAddrPortBindTableKeys{
                                            "$next_keys"} )
                                    {
                                        return "$BASE_OID.8.1.$i.$next_keys";
                                    }
                                }
                            }
                        }
                    }
                    return 0;
                }

#At this point, handled GETNEXT when
# + key1, key2, key3, key4 and key5 specified and existing (expected input from SNMP agent)
# + neither key1, key2, key3, key4 nor key5 specified
# + key1 out of range
# + key1 within range but key2 out of range or not specified
#FUTUREWORK: Ideally should try to handle other theoretical scenarios here.....

            }
        }

        #OID == $BASE_OID.8.1.[22-...]
        #OID == $BASE_OID.8.[2-...]
        return "$BASE_OID.9";
    }

    #OID = $BASE_OID.9.*
    #Finding next OIDs when
    #OID = $BASE_OID.9.* => natSessionTable
    # Valid natSessionTable OID = $BASE_OID.9.1.[1-23].key1.key2
    # + @natSessionTableKey1[] = sorted unique key1 values
    # + @natSessionTableKey2[] = sorted unique key2 values
    # + %natSessionTableKeys{key1.key2} = relative position of key-pair
    # + @natSessionTableOrderedKeys[position] = key1.key2
    if ( $oid_numbers[0] == 9 ) {

        #OID == $BASE_OID.9 or OID == $BASE_OID.9.0
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.9.1";
        }

        #OID == $BASE_OID.9.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key_pair = $natSessionTableOrderedKeys[0];
            #If table is empty return first OID after table
            if ( !defined $first_key_pair ) {
                return "$BASE_OID.10";
            }

            my $natSession_columns = 23;    #$BASE_OID.9.1.[1-23]*

            #OID == $BASE_OID.9.1 or OID == $BASE_OID.9.1.0
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.9.1.1.$first_key_pair";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.9.1.i*, where 0 <  i <= $natSession_columns
            if ( ( $i > 0 ) && ( $i <= $natSession_columns ) ) {

                #OID == $BASE_OID.9.1.i
                #If neither key1 nor key2 specified, return first
                #occurring key pair
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.9.1.$i.$first_key_pair";
                }

                #$BASE_OID.9.1.i.x(.y)
                my $x = $oid_numbers[3];    #definitely defined
                my $y = $oid_numbers[4];    #possibly defined
                my $key1;

                #Before diving into complex calculations to try
                #to find next OID for different unexpected inputs,
                #handle expected normal case of being given a
                #valid input key-pairing
                if ( defined $x && defined $y ) {

                    #Find relative position of input key pair
                    #in ordered array of all key pairings and
                    #increment index to find next if possible.
                    my $next_keys;
                    my $position = $natSessionTableKeys{"$x.$y"};
                    if ( defined $position ) {
                        $position++;

                        #If last key pair reached, return first OID
                        #either in next row in this table or next table
                        if ( $position >= @natSessionTableOrderedKeys ) {
                            if ( $i == $natSession_columns ) {
                                return "$BASE_OID.10";
                            } else {
                                ++$i;
                                return
                                  "$BASE_OID.9.1.$i.$first_key_pair";
                            }
                        }

                        #Return valid next key pairing found
                        $next_keys = $natSessionTableOrderedKeys[$position];
                        return "$BASE_OID.9.1.$i.$next_keys";
                    }
                }

                #Quick lookup using specified key pairing failed so try
                #to handle different input combination....

                #If x smaller than lowest OID in table, next OID
                #is the first OID
                if ( $x < $natSessionTableKey1[0] ) {
                    return "$BASE_OID.9.1.$i.$first_key_pair";
                }

                #If x bigger than highest OID in row, next OID
                #is first OID in next row or after this table
                if ( $x > $natSessionTableKey1[-1] ) {
                    if ( $i == $natSession_columns ) {
                        return "$BASE_OID.10";
                    } else {
                        ++$i;
                        return "$BASE_OID.9.1.$i.$first_key_pair";
                    }
                }

                #If x within table range, find first key1 value larger than
                #or equal to x
                my $key1_index;
                my $number_keys1 = @natSessionTableKey1;
                for (
                    $key1_index = 0 ;
                    $key1_index < $number_keys1 ;
                    $key1_index++
                  )
                {
                    if ( $x <= $natSessionTableKey1[$key1_index] ) {
                        $key1 = $natSessionTableKey1[$key1_index];
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }

                #Now that key1 is known must find key2.  There are a number
                #of scenarios in which all that is needed is to find lowest
                #key2 for which key1.key2 is a valid key-pair:
                # + x != key1 (key1 must be next value for input x)
                # + y not defined (no key2 value input)
                # + y out of range (invalid key2 value input)
                if (   ( $x != $key1 )
                    || ( !defined $y )
                    || ( $y <= $natSessionTableKey2[0] )
                    || ( $y > $natSessionTableKey2[-1] ) )
                {

                    #Next key1 after x found.  Find lowest lowest
                    #key2 for which key1.key2 is a valid key-pair
                    foreach my $key2 (@natSessionTableKey2) {
                        if ( exists $natSessionTableKeys{"$key1.$key2"} ) {
                            return "$BASE_OID.9.1.$i.$key1.$key2";
                        }
                    }
                    return 0;
                }

                #y within table range, so  find first key2 value larger than
                #or equal to y
                my $key2, my $key2_index;
                my $number_keys2 = @natSessionTableKey2;
                for (
                    $key2_index = 0 ;
                    $key2_index < $number_keys2 ;
                    $key2_index++
                  )
                {
                    if ( $y <= $natSessionTableKey2[$key2_index] ) {
                        $key2 = $natSessionTableKey2[$key2_index];
                    }
                }

                if ( !defined $key2 ) {
                    return 0;
                }

                #At this point, input x must have matched key1 exactly.
                #If y matched key2 exactly, then both keys exist but
                #together they may not necessarily be a valid combination.
                #A valid combination should have been detected earlier
                #so return error if that is the case.
                if (   ( $y == $key2 )
                    && ( exists $natSessionTableKeys{"$key1.$key2"} ) )
                {
                    return 0;
                }

                #Starting with the key2 value found, try to find the first
                #valid key1.key2 pairing
                for ( my $j = $key2_index ; $j < $number_keys2 ; $j++ ) {
                    my $potential_key2 = $natSessionTableKey2[$j];
                    if ( exists $natSessionTableKeys{"$key1.$potential_key2"} )
                    {
                        return "$BASE_OID.9.1.$i.$key1.$potential_key2";
                    }
                }

                #No valid key1.key2 pairing found so must increment key1
                #and return the first valid pairing containing key1.  If
                #non found (i.e. at end of table) fall through and return
                #first OID in next table.
                my $potential_key1 = $natSessionTableKey1[ $key1_index + 1 ];

                if ( defined $potential_key1 ) {
                    for ( my $j = 0 ; $j < $number_keys2 ; $j++ ) {
                        my $potential_key2 = $natSessionTableKey2[$j];
                        if (
                            exists $natSessionTableKeys{
                                "$potential_key1.$potential_key2"} )
                        {
                            return
"$BASE_OID.9.1.$i.$potential_key1.$potential_key2";
                        }
                    }
                }
            }
        }

        #OID == $BASE_OID.9.1.[22-...]
        #OID == $BASE_OID.9.[2-...]
        return "$BASE_OID.10";
    }

    #Finding next OIDs when
    #OID == $BASE_OID.10.* => natProtocolTable
    #Valid natProtocolTable OID = $BASE_OID.10.1.[1-4].key1
    # + @natProtocolTableKey1[] = sorted unique key1 values
    # + %natProtocolTableKey{key1} = relative position of key
    if ( $oid_numbers[0] == 10 ) {

        #OID == $BASE_OID.10 or $BASE_OID.10.0*
        if ( !defined( $oid_numbers[1] ) || ( $oid_numbers[1] == 0 ) ) {
            return "$BASE_OID.10.1";
        }

        #OID == $BASE_OID.10.1*
        if ( $oid_numbers[1] == 1 ) {

            my $first_key = $natProtocolTableKey1[0];
            #If table is empty return 0 to indicate end of MIB reached
            if ( !defined $first_key ) {
                return 0;
            }
            my $key_count = @natProtocolTableKey1;
            my $natProtocolTable_columns = 4;    #$BASE_OID.10.1.[1-4]*

            #OID == $BASE_OID.10.1 or $BASE_OID.10.1.0*
            if ( !defined( $oid_numbers[2] ) || ( $oid_numbers[2] == 0 ) ) {
                return "$BASE_OID.10.1.1.$first_key";
            }

            my $i = $oid_numbers[2];

            #OID == $BASE_OID.10.1.[1-4]
            if ( ( $i > 0 ) && ( $i <= $natProtocolTable_columns ) ) {

                #OID == $BASE_OID.10.1.i
                #If no key specified, return first key
                if ( !defined( $oid_numbers[3] ) ) {
                    return "$BASE_OID.10.1.$i.$first_key";
                }

                my $key1;
                my $x        = $oid_numbers[3];
                my $position = $natProtocolTableKey{$x};

                if ( defined $position ) {
                    $position++;

                    if ( $position >= $key_count ) {
                        if ( $i == $natProtocolTable_columns ) {
                            return 0;
                        } else {
                            ++$i;
                            return "$BASE_OID.10.1.$i.$first_key";
                        }
                    }

                    #Return valid next key found
                    return "$BASE_OID.10.1.$i.$natProtocolTableKey1[$position]";
                }

                #Quick lookup using specified key pair failed so try
                #to handle different inputs....

                #If x smaller than lowest OID in table, next OID
                #is the first OID
                if ( $x < $natProtocolTableKey1[0] ) {
                    return "$BASE_OID.10.1.$i.$first_key";
                }

                #If x bigger than highest OID in table row, next OID
                #is first OID in next row after this table
                if ( $x > $natProtocolTableKey1[-1] ) {
                    if ( $i == $natProtocolTable_columns ) {
                        return 0;
                    } else {
                        ++$i;
                        return "$BASE_OID.10.1.$i.$first_key";
                    }
                }

                #If x within table range, find first key1 value larger than
                #or equal to x
                for (
                    my $key1_index = 0 ;
                    $key1_index < $key_count ;
                    $key1_index++
                  )
                {
                    if ( $x <= $natProtocolTableKey1[$key1_index] ) {
                        $key1 = $natProtocolTableKey1[$key1_index];
                        return "$BASE_OID.10.1.$i.$key1";
                    }
                }

                if ( !defined $key1 ) {
                    return 0;
                }
            }
        }

        #OID == $BASE_OID.10.1.[8-...]
        #OID == $BASE_OID.10.[2-...]
        return 0;
    }
}

#Determine whether this OID is potentially in the MIB and, if so, check whether
#the MIB contents should be refreshed by extracting stats from NPF.
#Input: OID
#Outputs: TRUE if OID in NAT MIB, FALSE otherwise
sub validate_oid {
    my $oid = shift;

    #Does OID start with $BASE_OID?
    if ( !is_oid_in_subtree($oid, $BASE_OID)) {
        debug("$oid not under $BASE_OID");
        return 0;
    }

    $oid =~ s/^$BASE_OID//;
    if ( $oid eq "" ) {
        debug("OID is $BASE_OID, i.e. base OID");
        return 0;
    }

    #Is OID lexicographically greater than largest OID in sub-tree?
    my $max_oid = $BASE_OID_LAST;
    $max_oid =~ s/$BASE_OID//;
    $max_oid =~ s/^\.//;
    if ( is_oid_lower( $max_oid, $oid ) ) {
        return 0;
    }

    #Is OID lexicographically lower than smallest OID in sub-tree?
    my $min_oid = $BASE_OID_FIRST;
    $min_oid =~ s/$BASE_OID//;
    $min_oid =~ s/^\.//;
    if ( is_oid_lower( $oid, $min_oid ) ) {
        return 0;
    }

    #Should MIB be updated by extracting stats from NPF now?
    if ( stats_stale() ) {
        refresh_stats();
    }

    return 1;
}

#Find the IP address on an interface using 'ip address show <intf_name>'.
#Address assumed to be translation address when masquerade NAT configured.
#Input: Interface name
#Output: IP address or 0 if none found
sub get_intf_ip_address {
    my $intf_name = shift;

    #Run "ip address show <intf_name>" to find IP address
    if ( open( my $ip_addr, '-|', "ip address show $intf_name" ) ) {
        while (<$ip_addr>) {
            if (/inet ((\d{1,3}\.){3}\d{1,3})/) {
                close $ip_addr;
                return $1;
            }
        }
        close $ip_addr;
    }
    return 0;
}

#Find the interface name to ifIndex mapping using 'ip link show' and store
#in hash table: %ifIndex{intf_name} = ifIndex. Note hash table contains all
#interfaces in the system.
#FUTUREWORK: Restrict to only interfaces on which NAT configured?
#Output: %ifIndex
sub refresh_intf_name_index_mapping {
    my @name_string;

    #Purge the current mappings
    my %backup_ifIndex = %ifIndex;
    %ifIndex = ();

    #Run "ip link show" to find current mappings
    if ( open( my $ip, '-|', 'ip link show' ) ) {
        while (<$ip>) {
            if (/^(\d+): ([^:]*): /) {
                @name_string =  split ('@', $2);
                $ifIndex{$name_string[0]} = $1;
            }
        }
        close $ip;
    } else {
        debug("Cannot execute 'ip link show'; restoring ifIndex hash table");
        %ifIndex = %backup_ifIndex;
        return 0;
    }

    return 1;
}

#Parse "match" line (i.e. filter information) from NPF rule data
#Input: "[addr[/mask]] [port <low_port | (low_port : high_port)>]"
#Output: addr, mask, low_port, high_port
sub match_line_parser {
    my $filter = shift;

    #Default is to match any
    my $addr      = ANY_IPV4_NETWORK;
    my $mask      = ANY_IPV4_NETMASK;
    my $low_port  = LOWEST_PORT;
    my $high_port = HIGHEST_PORT;

    if ( $filter =~ s/^((\d{1,3}\.){3}\d{1,3})// ) {
        $addr = $1;
        $mask = 32;
        if ( $filter =~ s/^\/(\d+)// ) {
            $mask = $1;
        }
    }

    if ( $filter =~ s/^ port (\d+)// ) {
        $low_port = $high_port = $1;
        if ( $filter =~ s/^: (\d+)// ) {
            $high_port = $1;
        }
    }

    my @match_parameters = ( $addr, $mask, $low_port, $high_port );
    return @match_parameters;
}

#Parse "map" line (i.e. translation information) from NPF rule data
#Input: "low_addr[- high_addr] [port low_port[-high_port]"
#Output: low_addr, high_addr, low_port, high_port
sub map_line_parser {
    my $map = shift;

    #Default is to tranlate any
    my $low_addr  = LOWEST_IPV4_ADDR;
    my $high_addr = HIGHEST_IPV4_ADDR;
    my $low_port  = LOWEST_PORT;
    my $high_port = HIGHEST_PORT;

    if ( $map =~ s/^((\d{1,3}\.){3}\d{1,3})// ) {
        $low_addr = $high_addr = $1;
    } else {
        debug("Map $map does not contain valid low IPv4 address");
        return 0;
    }

    if ( $map =~ s/^-// ) {
        if ( $map !~ s/^((\d{1,3}\.){3}\d{1,3})// ) {
            debug("Map $map does not contain valid high IPv4 address");
            return 0;
        }
        $high_addr = $1;
    }

    if ( $map =~ s/^ port // ) {
        if ( $map =~ s/(\d+)// ) {
            $low_port = $high_port = $1;

            if ( $map =~ s/^-// ) {
                if ( $map !~ s/(\d+)// ) {
                    debug("Map $map does not contain valid high port");
                    return 0;
                }
                $high_port = $1;
            }
        }
    }

    my @map_parameters = ( $low_addr, $high_addr, $low_port, $high_port );
    return @map_parameters;
}

#When parsing the stats from NPF and populating the different MIB tables,
#the keys for every row in each table were stored in arrays in the
#order NPF delivered the stats.  No assumption is made about the
#ordering of the stats from NPF therefore to support GETNEXT requests,
#it is essential to sort the arrays of keys, remove duplicate keys,
#and create a list of unique key combinations sorted in lexicographical
#order.  The following organise_<MIB_table_name> subroutines carry out
#these step for each table:


#Every time NPF data is parsed and a row is added to a table,
#each occurring key is stored in a global array.  So, for ExampleTable,
#with 2 keys, @ExampleTableKey1 & @ExampleTableKey2 would contain
#every key extracted from the NPF data.  So the following key
#pairs {3,10}, {12,8}, {6,7}, {3,8}, {3,7}, {4,8}, {14,10} {1,7}
#would lead to:
#ExampleTableKey1 = [3, 12, 6, 3, 3, 4, 14, 1]
#ExampleTableKey2 = [10, 8, 7, 8, 7, 8, 10, 7]
#
#In organise_ExampleTable(), unique keys will be sought, giving
#%uniqueKey1 containing hash keys of 3, 12, 6, 4, 14, 1
#%uniqueKey2 containing hash keys of 10, 8, 7
#%ExampleTableKeys containing hash keys of 3.10, 12.8, 6.7, 3.8 etc
#
#The globals ExampleTableKey1 and ExampleTableKey2 are cleared and
#the sorted hash keys to uniqueKey1 and uniqueKey2 are copied into
#these arrays, giving unique sorted key values:
#ExampleTableKey1 = [1, 3, 4, 6, 12, 14]
#ExampleTableKey2 = [7, 8, 10]
#
#All the possible key combinations are iterated over, allowing
#the values of ExampleTableKeys to be set to the relative
#position of each key pairs.  These positions are also stored
#in a array, @ExampleTableOrderedKeys[].  The result is
#%ExampleTableKeys{3.10} = 0
#%ExampleTableKeys{12.8} = 1
# etc and
#@ExampleTableOrderedKeys[0] = 3.10
#@ExampleTableOrderedKeys[1] = 12.8
#
#@ExampleTableKey1, @ExampleTableKey2, %ExampleTableKeys and
#@ExampleTableOrderedKeys will subsequently be used to find
#or calculate the next OID for a GETNEXT request for an OID
#in ExampleTable.


#Outputs:
# + @natInterfaceTableKey1 - sorted unique key1 values
# + %natInterfaceTableKey{key1} = relative position
sub organise_natInterfaceTable {
    my $key_count  = @natInterfaceTableKey1;
    my %uniqueKey1 = ();

    #Find unique keys.  Note only interested in the hash keys
    #at this point.  The values (incidentally number of times
    #table key occurs) is inconsequential.
    for ( my $i = 0 ; $i < $key_count ; $i++ ) {
        $uniqueKey1{ $natInterfaceTableKey1[$i] }++;
        $natInterfaceTableKey{ $natInterfaceTableKey1[$i] }++;
    }

    #Clear the global table of keys and replace with unique
    #keys, obtained by sorting the hash table keys numerically.
    @natInterfaceTableKey1 = ();
    @natInterfaceTableKey1 = sort { $a <=> $b } keys %uniqueKey1;

    #Store relative ordering of keys as hash table values.
    $key_count = @natInterfaceTableKey1;
    for ( my $i = 0 ; $i < $key_count ; $i++ ) {
        $natInterfaceTableKey{ $natInterfaceTableKey1[$i] } = $i;
    }

    return 1;
}

#Outputs:
# + @natAddrMapTableKey1 - sorted unique key1 values
# + @natAddrMapTableKey2 - sorted unique key2 values
# + %natAddrMapTableKeys{key1.key2} = relative position of each occurring key pair
# + @natAddrMapTableOrderedKeys[position] = key1.key2
sub organise_natAddrMapTable {
    my $position = 0;
    my $key;
    my $tuples_count = @natAddrMapTableKey1;
    my %uniqueKey1   = ();
    my %uniqueKey2   = ();

    #Arrays of keys must be same size
    if ( scalar(@natAddrMapTableKey1) != scalar(@natAddrMapTableKey2) ) {
        debug("Incomplete tuples for natAddrMapTable key");
        return 0;
    }

    #Find unique keys and unique key pairs that occur
    for ( my $i = 0 ; $i < $tuples_count ; $i++ ) {
        $uniqueKey1{ $natAddrMapTableKey1[$i] }++;
        $uniqueKey2{ $natAddrMapTableKey2[$i] }++;
        $natAddrMapTableKeys{
            "$natAddrMapTableKey1[$i].$natAddrMapTableKey2[$i]"}++;
    }

#Now clear arrays containing every key in tuple and replace with sorted unique keys
    @natAddrMapTableKey1 = ();
    @natAddrMapTableKey1 = sort { $a <=> $b } keys %uniqueKey1;
    my $key1_number = @natAddrMapTableKey1;
    @natAddrMapTableKey2 = ();
    @natAddrMapTableKey2 = sort { $a <=> $b } keys %uniqueKey2;
    my $key2_number = @natAddrMapTableKey2;

    #Find the relative ordering of each key combination
    for ( my $i = 0 ; $i < $key1_number ; $i++ ) {
        for ( my $j = 0 ; $j < $key2_number ; $j++ ) {
            if (
                exists $natAddrMapTableKeys{
                    "$natAddrMapTableKey1[$i].$natAddrMapTableKey2[$j]"} )
            {
                $natAddrMapTableKeys{
                    "$natAddrMapTableKey1[$i].$natAddrMapTableKey2[$j]"} =
                  $position;
                $natAddrMapTableOrderedKeys[$position] =
                  "$natAddrMapTableKey1[$i].$natAddrMapTableKey2[$j]";
                $position++;
            }
        }
    }

    return 1;
}

#Outputs:
# + @natAddrBindTableKey1 - sorted unique key1 values
# + @natAddrBindTableKey2 - sorted unique key2 values
# + @natAddrBindTableKey3 - sorted unique key3 values
# + %natAddrBindTableKeys{key1.key2.key3} = relative position of each key combination
# + @natAddrBindTableOrderedKeys[position] = key1.key2.key3
#Note number of entries in table now known so can set natAddrBindNumberOfEntries in MIB
sub organise_natAddrBindTable {
    my $position = 0;
    my $key, my $keys_string;
    my $tuples_count = @natAddrBindTableKey1;
    my %uniqueKey1   = ();
    my %uniqueKey2   = ();
    my %uniqueKey3   = ();

    #Arrays of keys must be same size
    if (   ( $tuples_count != scalar(@natAddrBindTableKey2) )
        || ( scalar(@natAddrBindTableKey2) != scalar(@natAddrBindTableKey3) ) )
    {
        debug("Incomplete tuples for natAddrBindTable key");
        return 0;
    }

    #Find unique keys and unique key pairs that occur
    for ( my $i = 0 ; $i < $tuples_count ; $i++ ) {
        $uniqueKey1{ $natAddrBindTableKey1[$i] }++;
        $uniqueKey2{ $natAddrBindTableKey2[$i] }++;
        $uniqueKey3{ $natAddrBindTableKey3[$i] }++;
        $keys_string = "$natAddrBindTableKey1[$i].$natAddrBindTableKey2[$i]."
          . "$natAddrBindTableKey3[$i]";
        $natAddrBindTableKeys{$keys_string}++;
    }

    #natAddrBindNumberOfEntries
    $NAT_MIB_OBJECTS{"$BASE_OID.5"}[3] = keys %natAddrBindTableKeys;

#Now clear arrays containing every key in tuple and replace with sorted unique keys
    @natAddrBindTableKey1 = ();
    @natAddrBindTableKey1 = sort { $a <=> $b } keys %uniqueKey1;
    my $key1_number = @natAddrBindTableKey1;
    @natAddrBindTableKey2 = ();
    @natAddrBindTableKey2 = sort { $a <=> $b } keys %uniqueKey2;
    my $key2_number = @natAddrBindTableKey2;
    @natAddrBindTableKey3 = ();
    @natAddrBindTableKey3 = sort { $a <=> $b } keys %uniqueKey3;
    my $key3_number = @natAddrBindTableKey3;

    #Find the relative ordering of each key combination
    for ( my $i = 0 ; $i < $key1_number ; $i++ ) {
        for ( my $j = 0 ; $j < $key2_number ; $j++ ) {
            for ( my $k = 0 ; $k < $key3_number ; $k++ ) {
                $keys_string =
                    "$natAddrBindTableKey1[$i].$natAddrBindTableKey2[$j]."
                  . "$natAddrBindTableKey3[$k]";
                if ( exists $natAddrBindTableKeys{$keys_string} ) {
                    $natAddrBindTableKeys{$keys_string} = $position;
                    $natAddrBindTableOrderedKeys[$position] = $keys_string;
                    $position++;
                }
            }
        }
    }

    return 1;
}

#Outputs:
# + @natAddrPortBindTableKey1 - sorted unique key1 values
# + @natAddrPortBindTableKey2 - sorted unique key2 values
# + @natAddrPortBindTableKey3 - sorted unique key3 values
# + @natAddrPortBindTableKey4 - sorted unique key4 values
# + @natAddrPortBindTableKey5 - sorted unique key5 values
# + %natAddrPortBindTableKeys{key1.key2.key3.key4.key5} = relative position of each key combination
# + @natAddrPortBindTableOrderedKeys[position] = key1.key2.key3.key4.key5
#Note number of entries in table now known so can set natAddrPortBindNumberOfEntries in MIB
sub organise_natAddrPortBindTable {
    my $position = 0;
    my $key, my $keys_string;
    my $tuples_count = @natAddrPortBindTableKey1;
    my %uniqueKey1   = ();
    my %uniqueKey2   = ();
    my %uniqueKey3   = ();
    my %uniqueKey4   = ();
    my %uniqueKey5   = ();

    #Arrays of keys must be same size
    if (
        ( $tuples_count != scalar(@natAddrPortBindTableKey2) )
        || (
            scalar(@natAddrPortBindTableKey2) !=
            scalar(@natAddrPortBindTableKey3) )
        || (
            scalar(@natAddrPortBindTableKey3) !=
            scalar(@natAddrPortBindTableKey4) )
        || (
            scalar(@natAddrPortBindTableKey4) !=
            scalar(@natAddrPortBindTableKey5) )
      )
    {
        debug("Incomplete tuples for natAddrPortBindTable key");
        return 0;
    }

    #Find unique keys and unique key pairs that occur
    for ( my $i = 0 ; $i < $tuples_count ; $i++ ) {
        $uniqueKey1{ $natAddrPortBindTableKey1[$i] }++;
        $uniqueKey2{ $natAddrPortBindTableKey2[$i] }++;
        $uniqueKey3{ $natAddrPortBindTableKey3[$i] }++;
        $uniqueKey4{ $natAddrPortBindTableKey4[$i] }++;
        $uniqueKey5{ $natAddrPortBindTableKey5[$i] }++;
        $keys_string =
            "$natAddrPortBindTableKey1[$i].$natAddrPortBindTableKey2[$i]."
          . "$natAddrPortBindTableKey3[$i].$natAddrPortBindTableKey4[$i]."
          . "$natAddrPortBindTableKey5[$i]";
        $natAddrPortBindTableKeys{$keys_string}++;
    }

    #natAddrPortBindNumberOfEntries
    $NAT_MIB_OBJECTS{"$BASE_OID.7"}[3] = keys %natAddrPortBindTableKeys;

#Now clear arrays containing every key in tuple and replace with sorted unique keys
    @natAddrPortBindTableKey1 = ();
    @natAddrPortBindTableKey1 = sort { $a <=> $b } keys %uniqueKey1;
    my $key1_number = @natAddrPortBindTableKey1;
    @natAddrPortBindTableKey2 = ();
    @natAddrPortBindTableKey2 = sort { $a <=> $b } keys %uniqueKey2;
    my $key2_number = @natAddrPortBindTableKey2;
    @natAddrPortBindTableKey3 = ();
    @natAddrPortBindTableKey3 = sort { $a <=> $b } keys %uniqueKey3;
    my $key3_number = @natAddrPortBindTableKey3;
    @natAddrPortBindTableKey4 = ();
    @natAddrPortBindTableKey4 = sort { $a <=> $b } keys %uniqueKey4;
    my $key4_number = @natAddrPortBindTableKey4;
    @natAddrPortBindTableKey5 = ();
    @natAddrPortBindTableKey5 = sort { $a <=> $b } keys %uniqueKey5;
    my $key5_number = @natAddrPortBindTableKey5;

    #Find the relative ordering of each key combination
    for ( my $i = 0 ; $i < $key1_number ; $i++ ) {
        for ( my $j = 0 ; $j < $key2_number ; $j++ ) {
            for ( my $k = 0 ; $k < $key3_number ; $k++ ) {
                for ( my $l = 0 ; $l < $key4_number ; $l++ ) {
                    for ( my $m = 0 ; $m < $key5_number ; $m++ ) {
                        $keys_string =
"$natAddrPortBindTableKey1[$i].$natAddrPortBindTableKey2[$j]."
                          . "$natAddrPortBindTableKey3[$k].$natAddrPortBindTableKey4[$l]."
                          . "$natAddrPortBindTableKey5[$m]";
                        if ( exists $natAddrPortBindTableKeys{$keys_string} ) {
                            $natAddrPortBindTableKeys{$keys_string} = $position;
                            $natAddrPortBindTableOrderedKeys[$position] =
                              $keys_string;
                            $position++;
                        }
                    }
                }
            }
        }
    }

    return 1;
}

#Outputs:
# + @natSessionTableKey1 - sorted unique key1 values
# + @natSessionTableKey2 - sorted unique key2 values
# + %natSessionTableKeys{key1.key2} = relative position of each occurring key pair
# + @natSessionTableOrderedKeys[position] = key1.key2
sub organise_natSessionTable {
    my $position = 0;
    my $key;
    my $tuples_count = @natSessionTableKey1;
    my %uniqueKey1   = ();
    my %uniqueKey2   = ();

    #Arrays of keys must be same size
    if ( scalar(@natSessionTableKey1) != scalar(@natSessionTableKey2) ) {
        debug("Incomplete tuples for natSessionTable key");
        return 0;
    }

    #Find unique keys and unique key pairs that occur
    for ( my $i = 0 ; $i < $tuples_count ; $i++ ) {
        $uniqueKey1{ $natSessionTableKey1[$i] }++;
        $uniqueKey2{ $natSessionTableKey2[$i] }++;
        $natSessionTableKeys{
            "$natSessionTableKey1[$i].$natSessionTableKey2[$i]"}++;
    }

#Now clear arrays containing every key in tuple and replace with sorted unique keys
    @natSessionTableKey1 = ();
    @natSessionTableKey1 = sort { $a <=> $b } keys %uniqueKey1;
    my $key1_number = @natSessionTableKey1;
    @natSessionTableKey2 = ();
    @natSessionTableKey2 = sort { $a <=> $b } keys %uniqueKey2;
    my $key2_number = @natSessionTableKey2;

    #Find the relative ordering of each key combination
    for ( my $i = 0 ; $i < $key1_number ; $i++ ) {
        for ( my $j = 0 ; $j < $key2_number ; $j++ ) {
            if (
                exists $natSessionTableKeys{
                    "$natSessionTableKey1[$i].$natSessionTableKey2[$j]"} )
            {
                $natSessionTableKeys{
                    "$natSessionTableKey1[$i].$natSessionTableKey2[$j]"} =
                  $position;
                $natSessionTableOrderedKeys[$position] =
                  "$natSessionTableKey1[$i].$natSessionTableKey2[$j]";
                $position++;
            }
        }
    }

    return 1;
}

#Outputs:
# + @natProtocolTableKey1 - sorted unique key1 values
# + %natProtocolTableKey{key1} = relative position
sub organise_natProtocolTable {
    my $key_count  = @natProtocolTableKey1;
    my %uniqueKey1 = ();

    #Find unique keys
    for ( my $i = 0 ; $i < $key_count ; $i++ ) {
        $uniqueKey1{ $natProtocolTableKey1[$i] }++;
        $natProtocolTableKey{ $natProtocolTableKey1[$i] }++;
    }

    @natProtocolTableKey1 = ();
    @natProtocolTableKey1 = sort { $a <=> $b } keys %uniqueKey1;

    $key_count = @natProtocolTableKey1;
    for ( my $i = 0 ; $i < $key_count ; $i++ ) {
        $natProtocolTableKey{ $natProtocolTableKey1[$i] } = $i;
    }

    return 1;
}

#Clear the MIB (apart from the static default values)
sub clear_mib {

    #natInterfaceTable (.1.3.6.1.2.1.123.1.3)
    %natInterfaceTable     = ();
    @natInterfaceTableKey1 = ();
    %natInterfaceTableKey  = ();

    #natAddrMapTable (.1.3.6.1.2.1.123.1.4)
    %natAddrMapTableKeys        = ();
    @natAddrMapTableOrderedKeys = ();
    @natAddrMapTableKey1        = ();
    @natAddrMapTableKey2        = ();

    #natAddrBindNumberOfEntries (.1.3.6.1.2.1.123.1.5)
    $NAT_MIB_OBJECTS{"$BASE_OID.5"}[3] = 0;

    #natAddrBindTable (.1.3.6.1.2.1.123.1.6)
    %natAddrBindTable            = ();
    @natAddrBindTableKey1        = ();
    @natAddrBindTableKey2        = ();
    @natAddrBindTableKey3        = ();
    %natAddrBindTableKeys        = ();
    @natAddrBindTableOrderedKeys = ();

    #natAddrPortBindNumberOfEntries (.1.3.6.1.2.1.123.1.7)
    $NAT_MIB_OBJECTS{"$BASE_OID.7"}[3] = 0;

    # natAddrPortBindTable (.1.3.6.1.2.1.123.1.8)
    %natAddrPortBindTable            = ();
    @natAddrPortBindTableKey1        = ();
    @natAddrPortBindTableKey2        = ();
    @natAddrPortBindTableKey3        = ();
    @natAddrPortBindTableKey4        = ();
    @natAddrPortBindTableKey5        = ();
    %natAddrPortBindTableKeys        = ();
    @natAddrPortBindTableOrderedKeys = ();

    # natSessionTable (.1.3.6.1.2.1.123.1.9)
    %natSessionTable            = ();
    @natSessionTableKey1        = ();
    @natSessionTableKey2        = ();
    %natSessionTableKeys        = ();
    @natSessionTableOrderedKeys = ();

    #natProtocolTable (.1.3.6.1.2.1.123.1.10)
    %natProtocolTable     = ();
    @natProtocolTableKey1 = ();
    %natProtocolTableKey  = ();
}

#Open socket to dataplane and extract NPF stats by issuing 'npf-op show'
#and 'npf-op fw list sessions nat' (old way) or 'session-op show sessions full'
#(new way).  Thereafter call subroutines to parse
#the NPF stats, update the MIB appropriately and then organise the
#MIB tables to easily support GETNEXT requests.
sub refresh_stats {

    #Initially update the intf name -> ifindex mapping
    refresh_intf_name_index_mapping();

    my ( $dpids, $dpsocks ) = Vyatta::Dataplane::setup_fabric_conns();

    #Clear MIB before attempting to update
    clear_mib();

    #Execute "npf-op show all: dnat snat" to populate
    #natInterfaceTable, natAddrMapTable & natProtocolTable
    my $dprsp = vplane_exec_cmd("npf-op show all: dnat snat", $dpids, $dpsocks, 1);
    my $decoded_npf_data = aggregate_npf_responses( $dpids, $dprsp,
	    "Vyatta::NpfRuleset" );

    if (   defined $decoded_npf_data
        && defined $decoded_npf_data->{config} )
    {
        process_npf_show($decoded_npf_data->{config});
    } else {
        debug("No NAT rules nor sessions; some empty tables in MIB");
        return 0;
    }

    organise_natInterfaceTable();
    organise_natAddrMapTable();
    organise_natProtocolTable();
    foreach my $dpid ( @{$dpids} ) {
        my $sock = ${$dpsocks}[$dpid];
        next unless $sock;

        #Execute command to dataplane to populate
        #natAddrBindTable, natAddrPortBindTable & natSessionTable
        my $start     = 0;
        my $req_count = 1000;
        my $ret_count;
        my $raw_npf_data;
        do {
            $raw_npf_data = $sock->execute(
                $nat_session_prefix . $start . " " . $req_count );
            if ( defined($raw_npf_data) && $raw_npf_data !~ /^\s*$/ ) {
                $decoded_npf_data = decode_json($raw_npf_data);
                $ret_count = process_npf_fw_list_sessions_nat($decoded_npf_data);
            } else {
                $ret_count = 0;
            }
            $start += $req_count;
        } while ( $ret_count == $req_count );

        #Theoretically possible for there to be no sessions
        if ( $ret_count == 0 ) {
            debug("vplane $dpid: no NAT sessions; some empty tables in MIB");
        }
    }

    organise_natAddrBindTable();
    organise_natAddrPortBindTable();
    organise_natSessionTable();

    return 1;
}

#Process output of command which retrieved the nat sessions by iterating over
#all entries and calling subroutine to parse each one.  Must return number of
#sessions processed to facilitate NPF's batched delivery of session data.
#Output: Number of sessions processed
sub process_npf_fw_list_sessions_nat {
    my $decoded_npf_data = shift;
    my $entry_count      = 0;
    my $sess_field;

    if ($old_nat_map_json) {
        $sess_field = 'nat_sessions';
    } else {
        $sess_field = 'sessions';
    }
    if (   defined $decoded_npf_data
        && defined $decoded_npf_data->{config}->{$sess_field} )
    {

        my %entries = %{ $decoded_npf_data->{config}->{$sess_field} };
        $entry_count = keys(%entries);

        foreach my $entry ( sort { $a <=> $b } keys %entries ) {
            if ( !$old_nat_map_json ) {
                my $features_count = $entries{$entry}->{features_count};

                #Loop through all feature records
                for ( my $i = 0; $i < $features_count; $i++ ) {
                    my $feature = $entries{$entry}->{features}->[$i];

                    # ensure this is an NPF feature containing NAT
                    next
                      if ( $feature->{type} != 3 || !defined $feature->{nat} );

                    parse_nat_entry( $entry, $entries{$entry},
                        $feature->{nat} );
                }
            } else {
                parse_nat_entry( $entry, $entries{$entry} );
            }
        }
    }
    return $entry_count;
}

#Parse per-session stats information from NPF code and use to update data in
#natAddrBindTable, natAddrPortBindTable and natSessionTable.
sub parse_nat_entry {
    my ( $entry_id, $entry, $nat_entry ) = @_;
    my $masquerade;
    my $trans_addr;
    my $trans_port;
    my $trans_type;

    if ( defined $nat_entry ) {

        # new style
        $masquerade = $nat_entry->{masquerade};
        $trans_addr = $nat_entry->{trans_addr};
        $trans_port = $nat_entry->{trans_port};
        $trans_type = $nat_entry->{trans_type};
    } else {

        # old style
        $masquerade = $entry->{masquerade};
        $trans_addr = $entry->{trans_addr};
        $trans_port = $entry->{trans_port};
        $trans_type = $entry->{trans_type};
    }
    
    my $src_addr            = $entry->{src_addr};
    my $src_port            = $entry->{src_port};
    my $dst_addr            = $entry->{dst_addr};
    my $dst_port            = $entry->{dst_port};
    my $interface           = $entry->{interface};
    my $parent              = $entry->{parent};
    my $proto               = $entry->{proto};
    my $state               = $entry->{state};
    my $state_expire_window = $entry->{state_expire_window};
    my $time_to_expire      = $entry->{time_to_expire};

    my $ifindex = $ifIndex{$interface};

    my $nat_type;
    if ( $trans_type == 2 ) {
        $nat_type = "snat";
    } else {
        $nat_type = "dnat";
    }

    #1:none, 2:other, 3:ICMP, 4: UDP, 5:TCP
    my $protocol = 2;
    if ( $proto == 1 ) {
        $protocol = 3;
    }
    if ( $proto == 17 ) {
        $protocol = 4;
    }
    if ( $proto == 6 ) {
        $protocol = 5;
    }

#SNAT: local source address: src_addr -> global source address: trans_addr
#DNAT: global destination address: dst_addr -> local destination address: trans_addr
#Translation entity:
#    Bitmap 0:inboundSrcEndPoint, 1:outboundDstEndPoint, 2:inboundDstEndPoint, 3:outboundSrcEndPoint
    my $local_addr, my $local_port, my $global_addr, my $global_port,
      my $translation_entity;
    my $private_src_addr, my $private_src_port, my $private_dest_addr,
      my $private_dest_port;
    my $public_src_addr, my $public_src_port, my $public_dest_addr,
      my $public_dest_port;
    my $sub_key;

    if ( $nat_type =~ /snat/ ) {
        $local_addr        = $src_addr;
        $local_port        = $src_port;
        $global_addr       = $trans_addr;
        $global_port       = $trans_port;
        $private_src_addr  = $src_addr;
        $private_src_port  = $src_port;
        $public_src_addr   = $trans_addr;
        $public_src_port   = $trans_port;
        $private_dest_addr = $public_dest_addr = $dst_addr;
        $private_dest_port = $public_dest_port = $dst_port;

        $translation_entity = 0b00010000;         #Bit 3 (MSB = bit 0 in octet)
    } else {
        $local_addr         = $trans_addr;
        $local_port         = $trans_port;
        $global_addr        = $dst_addr;
        $global_port        = $dst_port;
        $public_dest_addr   = $dst_addr;
        $public_dest_port   = $dst_port;
        $private_dest_addr  = $trans_addr;
        $private_dest_port  = $trans_port;
        $public_src_addr    = $private_src_addr = $src_addr;
        $public_src_port    = $private_src_port = $src_port;
        $translation_entity = 0b01000000;        #Bit 1
    }

    #Address type  (64NAT????)
    #0:unknown, 1:IPv4, 2:1Pv6
    my $addr_type = 1;

    #1: inbound, 2: outbound
    my $direction;
    if ( $nat_type =~ /snat/ ) {
        $direction = 2;
    } else {
        $direction = 1;
    }

    my $local_addr_num = ( unpack( "N", inet_aton($local_addr) ) );

    #Finally(!), all the parameters needed to update the MIB
    #have been extracted from the entry so update...

    #natAddrPortBindTable filled for only TCP and UDP sessions
    if ( $proto == 6 || $proto == 17 ) {

        ######################################################################################

        #natAddrPortBindTable ->  $BASE_OID.8.1.x.ifIndex.natAddrPortBindLocalAddrType
        #                                                .natAddrPortBindLocalAddr
        #                                                .natAddrPortBindLocalPort
        #                                                .natAddrPortBindProtocol

        $sub_key = "$ifindex.$addr_type.$local_addr.$local_port.$protocol";
        push @natAddrPortBindTableKey1, $ifindex;
        push @natAddrPortBindTableKey2, $addr_type;
        push @natAddrPortBindTableKey3, $local_addr_num;
        push @natAddrPortBindTableKey4, $local_port;
        push @natAddrPortBindTableKey5, $protocol;

        #natAddrPortBindLocalAddrType
        $natAddrPortBindTable{"$BASE_OID.8.1.1.$sub_key"} = $addr_type;

        #natAddrPortBindLocalAddr
        $natAddrPortBindTable{"$BASE_OID.8.1.2.$sub_key"} = $local_addr;

        #natAddrPortBindLocalPort
        $natAddrPortBindTable{"$BASE_OID.8.1.3.$sub_key"} = $local_port;

        #natAddrPortBindProtocol
        $natAddrPortBindTable{"$BASE_OID.8.1.4.$sub_key"} = $protocol;

        #natAddrPortBindGlobalAddrType
        $natAddrPortBindTable{"$BASE_OID.8.1.5.$sub_key"} = $addr_type;

        #natAddrPortBindGlobalAddr
        $natAddrPortBindTable{"$BASE_OID.8.1.6.$sub_key"} = $global_addr;

        #natAddrPortBindGlobalPort
        $natAddrPortBindTable{"$BASE_OID.8.1.7.$sub_key"} = $global_port;

        #natAddrPortBindId
        $natAddrPortBindTable{"$BASE_OID.8.1.8.$sub_key"} = $entry_id;

        #natAddrPortBindTranslationEntity
        $natAddrPortBindTable{"$BASE_OID.8.1.9.$sub_key"} = $translation_entity;

        #natAddrPortBindType
        #1:static, 2:dynamic
        $natAddrPortBindTable{"$BASE_OID.8.1.10.$sub_key"} = 2;

        #natAddrPortBindMapIndex
        $natAddrPortBindTable{"$BASE_OID.8.1.11.$sub_key"} = UNSUPPORTED;

        #natAddrPortBindSessions
        $natAddrPortBindTable{"$BASE_OID.8.1.12.$sub_key"} = UNSUPPORTED;

        #natAddrPortBindMaxIdleTime
        $natAddrPortBindTable{"$BASE_OID.8.1.13.$sub_key"} = $state_expire_window;

        #natAddrPortBindCurrentIdleTime
        $natAddrPortBindTable{"$BASE_OID.8.1.14.$sub_key"} = $time_to_expire;

        #natAddrPortBindInTranslates
        $natAddrPortBindTable{"$BASE_OID.8.1.15.$sub_key"} = UNSUPPORTED;

        #natAddrPortBindOutTranslates
        $natAddrPortBindTable{"$BASE_OID.8.1.16.$sub_key"} = UNSUPPORTED;

    } else {

        #natAddrBindTable filled for non-TCP and non-UDP sessions
        ######################################################################################

        #natAddrBindTable ->  $BASE_OID.6.1.x.ifIndex.natAddrBindLocalAddrType
        #                                            .natAddrBindLocalAddr

        $sub_key = "$ifindex.$addr_type.$local_addr";
        push @natAddrBindTableKey1, $ifindex;
        push @natAddrBindTableKey2, $addr_type;
        push @natAddrBindTableKey3, $local_addr_num;

        #natAddrBindLocalAddrType
        #0:unknown, 1:IPv4, 2:1Pv6
        $natAddrBindTable{"$BASE_OID.6.1.1.$sub_key"} = 1;

        #natAddrBindLocalAddr
        $natAddrBindTable{"$BASE_OID.6.1.2.$sub_key"} = $local_addr;

        #natAddrBindGlobalAddrType
        #0:unknown, 1:IPv4, 2:1Pv6
        $natAddrBindTable{"$BASE_OID.6.1.3.$sub_key"} = 1;

        #natAddrBindGlobalAddr
        $natAddrBindTable{"$BASE_OID.6.1.4.$sub_key"} = $global_addr;

        #natAddrBindId
        $natAddrBindTable{"$BASE_OID.6.1.5.$sub_key"} = $entry_id;

        #natAddrBindTranslationEntity
        $natAddrBindTable{"$BASE_OID.6.1.6.$sub_key"} = $translation_entity;

        #natAddrBindType
        #1:static, 2:dynamic
        $natAddrBindTable{"$BASE_OID.6.1.7.$sub_key"} = 2;

        #natAddrBindMapIndex
        $natAddrBindTable{"$BASE_OID.6.1.8.$sub_key"} = UNSUPPORTED;

        #natAddrBindSessions.
        $natAddrBindTable{"$BASE_OID.6.1.9.$sub_key"} = UNSUPPORTED;

        #natAddrBindMaxIdleTime
        $natAddrBindTable{"$BASE_OID.6.1.10.$sub_key"} = $state_expire_window;

        #natAddrBindCurrentIdleTime
        $natAddrBindTable{"$BASE_OID.6.1.11.$sub_key"} = $time_to_expire;

        #natAddrBindInTranslates
        $natAddrBindTable{"$BASE_OID.6.1.12.$sub_key"} = UNSUPPORTED;

        #natAddrBindOutTranslates
        $natAddrBindTable{"$BASE_OID.6.1.13.$sub_key"} = UNSUPPORTED;

    }

    ##########################################################################################
    #natSessionTable -> $BASE_OID.9.1.x.ifIndex.natSessionIndex

    $sub_key = "$ifindex.$entry_id";
    push @natSessionTableKey1, $ifindex;
    push @natSessionTableKey2, $entry_id;

    #natSessionIndex
    $natSessionTable{"$BASE_OID.9.1.1.$sub_key"} = $entry_id;

    #natSessionPrivateSrcEPBindId
    #0:symmetric NAT or bind ID
    $natSessionTable{"$BASE_OID.9.1.2.$sub_key"} = $entry_id;

    #natSessionPrivateSrcEPBindMode
    #1:addressBind, 2:addressPortBind
    $natSessionTable{"$BASE_OID.9.1.3.$sub_key"} = 2;

    #natSessionPrivateDstEPBindId
    #0:symmetric NAT or bind ID
    $natSessionTable{"$BASE_OID.9.1.4.$sub_key"} = $entry_id;

    #natSessionPrivateDstEPBindMode
    #1:addressBind, 2:addressPortBind
    $natSessionTable{"$BASE_OID.9.1.5.$sub_key"} = 2;

    #natSessionDirection
    $natSessionTable{"$BASE_OID.9.1.6.$sub_key"} = $direction;

    #natSessionUpTime
    $natSessionTable{"$BASE_OID.9.1.7.$sub_key"} = UNSUPPORTED;

    #natSessionAddrMapIndex
    $natSessionTable{"$BASE_OID.9.1.8.$sub_key"} = UNSUPPORTED;

    #natSessionProtocolType
    $natSessionTable{"$BASE_OID.9.1.9.$sub_key"} = $protocol;

    #natSessionPrivateAddrType
    $natSessionTable{"$BASE_OID.9.1.10.$sub_key"} = $addr_type;

    #natSessionPrivateSrcAddr
    $natSessionTable{"$BASE_OID.9.1.11.$sub_key"} = $private_src_addr;

    #natSessionPrivateSrcPort
    $natSessionTable{"$BASE_OID.9.1.12.$sub_key"} = $private_src_port;

    #natSessionPrivateDstAddr
    $natSessionTable{"$BASE_OID.9.1.13.$sub_key"} = $private_dest_addr;

    #natSessionPrivateDstPort
    $natSessionTable{"$BASE_OID.9.1.14.$sub_key"} = $private_dest_port;

    #natSessionPublicAddrType
    $natSessionTable{"$BASE_OID.9.1.15.$sub_key"} = $addr_type;

    #natSessionPublicSrcAddr
    $natSessionTable{"$BASE_OID.9.1.16.$sub_key"} = $public_src_addr;

    #natSessionPublicSrcPort
    $natSessionTable{"$BASE_OID.9.1.17.$sub_key"} = $public_src_port;

    #natSessionPublicDstAddr
    $natSessionTable{"$BASE_OID.9.1.18.$sub_key"} = $public_dest_addr;

    #natSessionPublicDstPort
    $natSessionTable{"$BASE_OID.9.1.19.$sub_key"} = $public_dest_port;

    #natSessionMaxIdleTime
    $natSessionTable{"$BASE_OID.9.1.20.$sub_key"} = $state_expire_window;

    #natSessionCurrentIdleTime
    $natSessionTable{"$BASE_OID.9.1.21.$sub_key"} = $time_to_expire;

    #natSessionInTranslates
    $natSessionTable{"$BASE_OID.9.1.22.$sub_key"} = UNSUPPORTED;

    #natSessionOutTranslates
    $natSessionTable{"$BASE_OID.9.1.23.$sub_key"} = UNSUPPORTED;

    return;
}

#Process "snat" or "dnat" output of "npf-op show all: dnat snat" command by
#iterating over all rules and calling subroutine to parse each one.
sub process_npf_nat {
    my ( $ruleset_type, $decoded_npf_data ) = @_;

    foreach my $attach_point ( @{$decoded_npf_data} ) {
        foreach my $ruleset ( @{ $attach_point->{rulesets} } ) {
            next if $ruleset->{ruleset_type} ne $ruleset_type;

            foreach my $group ( @{ $ruleset->{groups} } ) {

                foreach my $rule_num ( sort { $a <=> $b } keys
                    %{ $group->{rules} } ) {

                    parse_nat_rule( $attach_point->{attach_point},
                        $ruleset_type, $rule_num,
                        $group->{rules}{$rule_num} );
                }
            }
        }
    }
}

#Process output of "npf-op show all: dnat snat" command by calling
#a subroutine to handle parsing of SNAT and DNAT rules
sub process_npf_show {
    my $decoded_npf_data = shift;

    foreach my $ruleset_type ( 'snat', 'dnat' ) {
        process_npf_nat( $ruleset_type, $decoded_npf_data );
    }
}

#Parse per-rule stats information from NPF code and use to update data in
#natInterfaceTable, natProtocolTable and natAddrMapTable
sub parse_nat_rule {
    my ( $interface, $nat_type, $rule_id, $rule ) = @_;

    my $ifindex = $ifIndex{ $interface };

    #Handle offset applied to distinguish SNAT & DNAT rules
    if ( $nat_type =~ /snat/ ) {
        $rule_id += SNAT_RULE_OFFSET;
    }

#Bitmap 0:inboundSrcEndPoint, 1:outboundDstEndPoint, 2:inboundDstEndPoint, 3:outboundSrcEndPoint
    my $translation_entity = 0b01000000;      #Bit 1 (MSB = bit 0 in octet)
    if ( $nat_type =~ /snat/ ) {
        $translation_entity = 0b00010000;     #Bit 3
    }

#Map format
#dnat or snat: exclude
#dnat: [pinhole] dynamic low_addr[-high_addr] [port low_port[-high_port] <- any
#snat: [pinhole] dynamic any -> <masquerade | low_addr[- high_addr] [port low_port[-high_port]]>
    my $map_to_low_addr, my $map_to_high_addr, my $map_to_low_port,
      my $map_to_high_port;
    my $entry_type;
    my $map = $rule->{map};
    $map =~ s/^\s+|\s+$//g;

#snat: [pinhole] dynamic any -> <masquerade | low_addr[- high_addr] [port low_port[-high_port]]>
    if ( $nat_type =~ /snat/ ) {
        if ( $map !~ s/^pinhole dynamic any -> // ) {
            if ( $map !~ s/^dynamic any -> // ) {
                    debug("SNAT map does not start with '[pinhole] dynamic any -> '");
                    return 0;
            }
        }

        #1:static, 2:dynamic
        $entry_type = 2;

        if ( $map =~ /masquerade/ ) {

            #Use interface's main IP address
            $map_to_low_addr = $map_to_high_addr =
              get_intf_ip_address( $interface );
            $map_to_low_port = $map_to_high_port = 0;
        } else {
            (
                $map_to_low_addr, $map_to_high_addr,
                $map_to_low_port, $map_to_high_port
            ) = map_line_parser($map);
        }
    }

    #dnat: [pinhole] dynamic low_addr[-high_addr] [port low_port[-high_port] <- any
    if ( $nat_type =~ /dnat/ ) {
        if ( $map !~ s/^pinhole dynamic // ) {
            if ( $map !~ s/^dynamic // ) {
                debug("DNAT map does not start with '[pinhole] dynamic '");
                return 0;
            }
        }

        my @dnat_map = split / <- /, $map;
        if ( $dnat_map[1] !~ /^any/ ) {
            debug("DNAT map does not contain '<- any'");
            return 0;
        }

        #1:static, 2:dynamic
        $entry_type = 2;

        (
            $map_to_low_addr, $map_to_high_addr,
            $map_to_low_port, $map_to_high_port
        ) = map_line_parser( $dnat_map[0] );
    }

#Match format
#[proto <tcp |udp | icmp>]
# [from [filt_from_addr[/filt_from_mask]] [port (<filt_from_port> | filt_from_low_port : filt_from_high_port)]]
# [to [filt_to_addr[/filt_to_mask]] [port (<filt_to_port> | filt_to_low_port : filt_to_high_port)]]
    my $match_proto;
    my $match_from_addr, my $match_from_mask, my $match_from_low_port,
      my $match_from_high_port;
    my $match_to_addr, my $match_to_mask, my $match_to_low_port,
      my $match_to_high_port;
    my $match_proto_bitmap, my $match_proto_type;

    my $match = $rule->{match};
    $match =~ s/^\s+|\s+$//g;

    if ( $match =~ s/^proto(-final)? ([\w]*) // ) {
        $match_proto = $2;
    } else {
        $match_proto = 0;
    }

    #$match_proto_bitmap: 0:other, 1:ICMP, 2:UDP, 3:TCP
    #$match_proto_type: 1:none, 2:other, 3:ICMP, 4: UDP, 5:TCP
    if ( $match_proto =~ /icmp/i || $match_proto eq '1' ) {
        $match_proto_bitmap = 0b01000000;    #Bit 1 (MSB = bit 0 in octet)
        $match_proto_type   = 3;
    } elsif ( $match_proto =~ /udp/i || $match_proto eq '17' ) {
        $match_proto_bitmap = 0b001000000;    #Bit 2
        $match_proto_type   = 4;
    } elsif ( $match_proto =~ /tcp/i || $match_proto eq '6' ) {
        $match_proto_bitmap = 0b00010000;     #Bit 3
        $match_proto_type   = 5;
    } else {
        $match_proto_bitmap = 0;
        $match_proto_type   = 1;
    }

    if ( $match =~ s/from // ) {
        my ( $from, $to ) = split /to /, $match;
        (
            $match_from_addr,     $match_from_mask,
            $match_from_low_port, $match_from_high_port
        ) = match_line_parser($from);
        if ( defined $to ) {
            (
                $match_to_addr,     $match_to_mask,
                $match_to_low_port, $match_to_high_port
            ) = match_line_parser($to);
        }
    } elsif ( $match =~ s/to // ) {
        (
            $match_to_addr,     $match_to_mask,
            $match_to_low_port, $match_to_high_port
        ) = match_line_parser($match);
    }

#Unless constrained by the filter (i.e. match), DNAT and SNAT will translate from any
#destination or source address/ports respectively.  Set these default values before
#checking if the filters means that address/port that can be translated should be
#constrained.
    my $map_from_low_addr  = LOWEST_IPV4_ADDR;
    my $map_from_high_addr = HIGHEST_IPV4_ADDR;
    my $map_from_low_port  = LOWEST_PORT;
    my $map_from_high_port = HIGHEST_PORT;

    #Update address/port that may be translated if source address/port
    #defined in filter for SNAT
    if ( $nat_type =~ /snat/ ) {
        if ( defined $match_from_addr ) {
            if ( defined $match_from_mask ) {

                my $addr_num = ( unpack( "N", inet_aton($match_from_addr) ) );
                my $mask = ( 0xFFFFFFFF << ( 32 - $match_from_mask ) );

                #Exclude network and broadcast address?
                $map_from_low_addr =
                  inet_ntoa( pack( "N", ( $addr_num & $mask ) ) );
                $map_from_high_addr =
                  inet_ntoa( pack( "N", ( $addr_num | ~$mask ) ) );

            } else {
                $map_from_high_addr = $map_from_low_addr = $match_from_addr;
            }
        }

        if ( defined $match_from_low_port ) {
            $map_from_low_port = $map_from_high_port = $match_from_low_port;
            if ( defined $match_from_high_port ) {
                $map_from_high_port = $match_from_high_port;
            }
        }
    }

    #Update address/port that may be translated if destination address/port
    #defined in filter for DNAT
    if ( $nat_type =~ /dnat/ ) {
        if ( defined $match_to_addr ) {
            if ( defined $match_to_mask ) {

                my $addr_num = ( unpack( "N", inet_aton($match_to_addr) ) );
                my $mask = ( 0xFFFFFFFF << ( 32 - $match_to_mask ) );

                #Exclude network and broadcast address?
                $map_from_low_addr =
                  inet_ntoa( pack( "N", ( $addr_num & $mask ) ) );
                $map_from_high_addr =
                  inet_ntoa( pack( "N", ( $addr_num | ~$mask ) ) );

            } else {
                $map_from_high_addr = $map_from_low_addr = $match_to_addr;
            }
        }

        if ( defined $match_to_low_port ) {
            $map_from_low_port = $map_from_high_port = $match_to_low_port;
            if ( defined $match_to_high_port ) {
                $map_from_high_port = $match_to_high_port;
            }
        }
    }

    #Finally(!), all the parameters needed to update the MIB
    #have been determined so update...

    ##########################################################################################
    #natInterfaceTable -> $BASE_OID.3.1.x.ifIndex

    push @natInterfaceTableKey1, $ifindex;

    #natInterfaceRealm
    #1:private, 2:public
    $natInterfaceTable{"$BASE_OID.3.1.1.$ifindex"} = 2;

    #natInterfaceServiceType
    #Bitmap 0:basicNAT, 1:napt, 2:bidirectionalNat, 3:twiceNat
    $natInterfaceTable{"$BASE_OID.3.1.2.$ifindex"} =
      0b01000000;    #Bit 1 (MSB = bit 0 in octet)

    if ( $nat_type =~ /dnat/ ) {

        #natInterfaceInTranslates
        $natInterfaceTable{"$BASE_OID.3.1.3.$ifindex"} += $rule->{packets};

        #natInterfaceOutTranslates
        #Avoid MIB missing corresponding natInterfaceOutTranslates entry
        #in case SNAT never configured on this interface but do not
        #overwrite value if natInterfaceOutTranslates data already exists.
        if ( !exists $natInterfaceTable{"$BASE_OID.3.1.4.$ifindex"} ) {
            $natInterfaceTable{"$BASE_OID.3.1.4.$ifindex"} = UNSUPPORTED;
	}
    }

    if ( $nat_type =~ /snat/ ) {

        #natInterfaceInTranslates
        #Avoid MIB missing corresponding natInterfaceInTranslates entry
        #in case DNAT never configured on this interface but do not
        #overwrite value if natInterfaceInTranslates data already exists.
        if ( !exists $natInterfaceTable{"$BASE_OID.3.1.3.$ifindex"} ) {
            $natInterfaceTable{"$BASE_OID.3.1.3.$ifindex"} = UNSUPPORTED;
	}

        #natInterfaceOutTranslates
        $natInterfaceTable{"$BASE_OID.3.1.4.$ifindex"} += $rule->{packets};
    }

    #natInterfaceDiscards
    $natInterfaceTable{"$BASE_OID.3.1.5.$ifindex"} = UNSUPPORTED;

    #natInterfaceStorageType
    #1:other, 2:volatile. 3:nonVolatile, 4:permanent, 5:readOnly
    $natInterfaceTable{"$BASE_OID.3.1.6.$ifindex"} = 2;

#natInterfaceRowStatus
#1:active, 2:notInService, 3:notReady, 4:createAndGo, 5:createAndWait, 6:destroy
    $natInterfaceTable{"$BASE_OID.3.1.7.$ifindex"} = 2;

    ##########################################################################################
    #natAddrMapTable -> $BASE_OID.4.1.x.ifIndex.natAddrMapIndex

    push @natAddrMapTableKey1, $ifindex;
    push @natAddrMapTableKey2, $rule_id;

    #natAddrMapIndex
    $natAddrMapTable{"$BASE_OID.4.1.1.$ifindex.$rule_id"} = $rule_id;

    #natAddrMapName
    $natAddrMapTable{"$BASE_OID.4.1.2.$ifindex.$rule_id"} = $interface;

    #natAddrMapEntryType
    #1:static, 2:dynamic
    $natAddrMapTable{"$BASE_OID.4.1.3.$ifindex.$rule_id"} = $entry_type;

#natAddrMapTranslationEntity
#Bitmap 0:inboundSrcEndPoint, 1:outboundDstEndPoint, 2:inboundDstEndPoint, 3:outboundSrcEndPoint
    $natAddrMapTable{"$BASE_OID.4.1.4.$ifindex.$rule_id"} = $translation_entity;

    #natAddrMapLocalAddrType
    #0:unknown, 1:IPv4, 2:1Pv6
    $natAddrMapTable{"$BASE_OID.4.1.5.$ifindex.$rule_id"} = 1;

    #natAddrMapGlobalAddrType
    #0:unknown, 1:IPv4, 2:1Pv6
    $natAddrMapTable{"$BASE_OID.4.1.10.$ifindex.$rule_id"} = 1;

#DNAT: global destination address -> local destination address
#Local: [map_to_low_addr, map_to_high_addr, map_to_low_port, map_to_high_port]
#Global: [map_from_low_addr, map_from_high_addr, map_from_low_port, map_from_high_port]
    if ( $nat_type =~ /dnat/ ) {

        #natAddrMapLocalAddrFrom
        $natAddrMapTable{"$BASE_OID.4.1.6.$ifindex.$rule_id"} =
          $map_to_low_addr;

        #natAddrMapLocalAddrTo
        $natAddrMapTable{"$BASE_OID.4.1.7.$ifindex.$rule_id"} =
          $map_to_high_addr;

        #natAddrMapLocalPortFrom
        $natAddrMapTable{"$BASE_OID.4.1.8.$ifindex.$rule_id"} =
          $map_to_low_port;

        #natAddrMapLocalPortTo
        $natAddrMapTable{"$BASE_OID.4.1.9.$ifindex.$rule_id"} =
          $map_to_high_port;

        #natAddrMapGlobalAddrFrom
        $natAddrMapTable{"$BASE_OID.4.1.11.$ifindex.$rule_id"} =
          $map_from_low_addr;

        #natAddrMapGlobalAddrTo
        $natAddrMapTable{"$BASE_OID.4.1.12.$ifindex.$rule_id"} =
          $map_from_high_addr;

        #natAddrMapGlobalPortFrom
        $natAddrMapTable{"$BASE_OID.4.1.13.$ifindex.$rule_id"} =
          $map_from_low_port;

        #natAddrMapGlobalPortTo
        $natAddrMapTable{"$BASE_OID.4.1.14.$ifindex.$rule_id"} =
          $map_from_high_port;
    }

#SNAT: local source address -> global source address
#Local: [map_from_low_addr, map_from_high_addr, map_from_low_port, map_from_high_port]
#Global: [map_to_low_addr, map_to_high_addr, map_to_low_port, map_to_high_port]
    if ( $nat_type =~ /snat/ ) {

        #natAddrMapLocalAddrFrom
        $natAddrMapTable{"$BASE_OID.4.1.6.$ifindex.$rule_id"} =
          $map_from_low_addr;

        #natAddrMapLocalAddrTo
        $natAddrMapTable{"$BASE_OID.4.1.7.$ifindex.$rule_id"} =
          $map_from_high_addr;

        #natAddrMapLocalPortFrom
        $natAddrMapTable{"$BASE_OID.4.1.8.$ifindex.$rule_id"} =
          $map_from_low_port;

        #natAddrMapLocalPortTo
        $natAddrMapTable{"$BASE_OID.4.1.9.$ifindex.$rule_id"} =
          $map_from_high_port;

        #natAddrMapGlobalAddrFrom
        $natAddrMapTable{"$BASE_OID.4.1.11.$ifindex.$rule_id"} =
          $map_to_low_addr;

        #natAddrMapGlobalAddrTo
        $natAddrMapTable{"$BASE_OID.4.1.12.$ifindex.$rule_id"} =
          $map_to_high_addr;

        #natAddrMapGlobalPortFrom
        $natAddrMapTable{"$BASE_OID.4.1.13.$ifindex.$rule_id"} =
          $map_to_low_port;

        #natAddrMapGlobalPortTo
        $natAddrMapTable{"$BASE_OID.4.1.14.$ifindex.$rule_id"} =
          $map_to_high_port;
    }

    #natAddrMapProtocol
    #Bitmap 0:other, 1:ICMP, 2:UDP, 3:TCP
    $natAddrMapTable{"$BASE_OID.4.1.15.$ifindex.$rule_id"} =
      $match_proto_bitmap;

    if ( $nat_type =~ /dnat/ ) {

        #natAddrMapInTranslates
        $natAddrMapTable{"$BASE_OID.4.1.16.$ifindex.$rule_id"} =
          $rule->{packets};

        #natAddrMapOutTranslates
        $natAddrMapTable{"$BASE_OID.4.1.17.$ifindex.$rule_id"} = UNSUPPORTED;
    }

    if ( $nat_type =~ /snat/ ) {

        #natAddrMapInTranslates
        $natAddrMapTable{"$BASE_OID.4.1.16.$ifindex.$rule_id"} = UNSUPPORTED;

        #natAddrMapOutTranslates
        $natAddrMapTable{"$BASE_OID.4.1.17.$ifindex.$rule_id"} =
          $rule->{packets};
    }

    #natAddrMapDiscard
    #Not known
    $natAddrMapTable{"$BASE_OID.4.1.18.$ifindex.$rule_id"} = UNSUPPORTED;

    my $used = 0;
    if ( defined $rule->{protocols} ) {
        foreach my $prot ( @{ $rule->{protocols} } ) {
            $used += $prot->{used_ts};
        }
    } else {
        $used = $rule->{used_ts};
    }
    #natAddrMapAddrUsed
    $natAddrMapTable{"$BASE_OID.4.1.19.$ifindex.$rule_id"} = $used;

    #natAddrMapStorageType
    #1:other, 2:volatile. 3:nonVolatile, 4:permanent, 5:readOnly
    $natAddrMapTable{"$BASE_OID.4.1.20.$ifindex.$rule_id"} = 2;

#natAddrMapRowStatus
#1:active, 2:notInService, 3:notReady, 4:createAndGo, 5:createAndWait, 6:destroy
    $natAddrMapTable{"$BASE_OID.4.1.21.$ifindex.$rule_id"} = 2;

    ##########################################################################################

    #natProtocolTable -> $BASE_OID.10.1.x.match_proto_type
    push @natProtocolTableKey1, $match_proto_type;

    #natProtocol
    $natProtocolTable{"$BASE_OID.10.1.1.$match_proto_type"} = $match_proto_type;

    #natProtocolInTranslates
    if ( $nat_type =~ /dnat/ ) {

        #natProtocolInTranslates
        $natProtocolTable{"$BASE_OID.10.1.2.$match_proto_type"} +=
          $rule->{packets};

        #natProtocolOutTranslates
        #Avoid MIB missing corresponding natProtocolOutTranslates entry
        #in case SNAT never configured for this protocol but do not
        #overwrite value if natProtocolOutTranslates data already exists.
        if ( !exists $natProtocolTable{"$BASE_OID.10.1.3.$match_proto_type"} ) {
            $natProtocolTable{"$BASE_OID.10.1.3.$match_proto_type"} =
              UNSUPPORTED;
        }
    }

    #natProtocolOutTranslates
    if ( $nat_type =~ /snat/ ) {

        #natProtocolOutTranslates
        $natProtocolTable{"$BASE_OID.10.1.3.$match_proto_type"} +=
          $rule->{packets};

        #natProtocolInTranslates
        #Avoid MIB missing corresponding natProtocolInTranslates entry
        #in case DNAT never configured for this protocol but do not
        #overwrite value if natProtocolInTranslates data already exists.
        if ( !exists $natProtocolTable{"$BASE_OID.10.1.2.$match_proto_type"} ) {
            $natProtocolTable{"$BASE_OID.10.1.2.$match_proto_type"} =
              UNSUPPORTED;
        }
    }

    #natProtocolDiscards
    $natProtocolTable{"$BASE_OID.10.1.4.$match_proto_type"} = UNSUPPORTED;

    return 1;
}

#Called to print data for non-tabular OIDs.  Data is retrieved from global hash
#table, %NAT_MIB_OBJECTS{$oid}.
#Input: OID
#Output: 1 if OID data found and printed.  0 otherwise.
sub print_non_tabular_oid_data {
    my $oid = shift;
    my $rfc_type, my $netsnmp_type, my $value;

    if ( exists $NAT_MIB_OBJECTS{$oid} ) {
        $rfc_type     = $NAT_MIB_OBJECTS{$oid}[2];
        $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
        $value        = $NAT_MIB_OBJECTS{$oid}[3];
        if ( $netsnmp_type && defined $value ) {
            debug ("Output: $oid, $netsnmp_type, $value");
            print "$oid\n$netsnmp_type\n$value\n";
            return 1;
        }
    }

    debug("No data exists for $oid");
    debug("Output: NONE");
    print "NONE\n";
    return 0;
}

#Called to send the OID's data to SNMPd by printing to stdout after input OID has
#been validated for GET requests or next OID found for GETNEXT requests.  Will read
#data from appropriate tables and then  print "<OID>\n<TYPE>\n<VALUE>\n" or "NONE\n".
#OID data resides either in the different MIB tables or, for the non-tabular OIDs,
#in the global hash table, %NAT_MIB_OBJECTS{$oid}.
#to stdout.
#Input: OID
#Output: 1 if OID data found and printed.  0 otherwise.
sub print_oid_data {
    my $input_oid = my $oid = shift;
    my $rfc_type, my $netsnmp_type, my $value;

    #Does OID start with $BASE_OID?
    if ( ( $oid !~ s/^$BASE_OID.// ) || ( $oid eq "" ) ) {
        debug("Erroneous OID: $input_oid");
        return 0;
    }

 #Split OID subtree into numbers.  Be careful as may contain IPv4 addresses in
 #dotted decimal which will be split here. Should be OK as looking at only first
 #three values in OID sub-tree at this point so should not reach address.
    my @oid_numbers = split( '\.', $oid );

    #$BASE_OID.1 => natDefTimeouts
    if ( $oid_numbers[0] == 1 ) {

        return ( print_non_tabular_oid_data($input_oid) );

        #$BASE_OID.2 => natNotifCtrl
    } elsif ( $oid_numbers[0] == 2 ) {

        return ( print_non_tabular_oid_data($input_oid) );

        #$BASE_OID.3 => natInterfaceTable
    } elsif ( $oid_numbers[0] == 3 ) {

        #OID == $BASE_OID.3
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.3.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.3.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.3.1.[1-7].*
#Value ->         $natInterfaceTable{$BASE_OID.3.1.x.ifIndex}
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.3.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.3.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 8 ) ) {
                if ( exists $natInterfaceTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.3.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natInterfaceTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.4 => natAddrMapTable
    } elsif ( $oid_numbers[0] == 4 ) {

        #OID == $BASE_OID.4
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.4.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.4.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.4.1.[1-21].*
#Value ->         $natAddrMapTable{$BASE_OID.4.1.x.ifIndex.natAddrMapIndex}
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.4.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.4.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 22 ) ) {
                if ( exists $natAddrMapTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.4.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natAddrMapTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.5 => natAddrBindNumberOfEntries
    } elsif ( $oid_numbers[0] == 5 ) {

        #OID == $BASE_OID.5
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.6 => natAddrBindTable
    } elsif ( $oid_numbers[0] == 6 ) {

        #OID == $BASE_OID.6
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.6.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.6.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.6.1.[1-13].*
#Value ->         $natAddrBindTable{$BASE_OID.6.1.x.ifIndex.natAddrBindLocalAddrType.natAddrBindLocalAddr }
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.6.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.6.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 14 ) ) {
                if ( exists $natAddrBindTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.6.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natAddrBindTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.7 => natAddrPortBindNumberOfEntries
    } elsif ( $oid_numbers[0] == 7 ) {

        #OID == $BASE_OID.7
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.8 => natAddrPortBindTable
    } elsif ( $oid_numbers[0] == 8 ) {

        #OID == $BASE_OID.8
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.8.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.8.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.8.1.[1-16].*
#Value ->         $natAddrPortBindTable{$BASE_OID.8.1.x.ifIndex.natAddrPortBindLocalAddrType
#                 .natAddrPortBindLocalAddr.natAddrPortBindLocalPort.natAddrPortBindProtocol}
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.8.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.8.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 17 ) ) {
                if ( exists $natAddrPortBindTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.8.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natAddrPortBindTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.9 => natSessionTable
    } elsif ( $oid_numbers[0] == 9 ) {

        #OID == $BASE_OID.9
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.9.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.9.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.9.1.[1-23].*
#Value ->         $natSessionTable{$BASE_OID.9.1.x.ifIndex.natSessionIndex}
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.9.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.9.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 24 ) ) {
                if ( exists $natSessionTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.9.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natSessionTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

        #$BASE_OID.10 => natProtocolTable
    } elsif ( $oid_numbers[0] == 10 ) {

        #OID == $BASE_OID.10
        if ( !defined( $oid_numbers[1] ) ) {
            return ( print_non_tabular_oid_data($input_oid) );
        }

        #OID == $BASE_OID.10.1*
        if ( $oid_numbers[1] == 1 ) {

            #OID == $BASE_OID.10.1
            if ( !defined( $oid_numbers[2] ) ) {
                return ( print_non_tabular_oid_data($input_oid) );
            }

#OID == $BASE_OID.10.1.[1-7].*
#Value ->         $natProtocolTable{$BASE_OID.10.1.x.match_proto_type}
#RFC Type ->      $NAT_MIB_OBJECTS{$BASE_OID.10.1.x}[2]
#NetSNMP Type ->  $RFC_NetSNMP_type_mappings{$NAT_MIB_OBJECTS{$BASE_OID.10.1.x}[2]}
            my $i = $oid_numbers[2];
            if ( ( $i > 0 ) && ( $i < 5 ) ) {
                if ( exists $natProtocolTable{$input_oid} ) {
                    my $oid_key = "$BASE_OID.10.1.$i";
                    $rfc_type     = $NAT_MIB_OBJECTS{$oid_key}[2];
                    $netsnmp_type = $RFC_NetSNMP_type_mappings{$rfc_type};
                    $value        = $natProtocolTable{$input_oid};
                    if ( $netsnmp_type && defined $value ) {
                        debug ("Output: $input_oid, $netsnmp_type, $value");
                        print "$input_oid\n$netsnmp_type\n$value\n";
                        return 1;
                    }
                }
            }
        }

        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;

    } else {
        debug("No data exists for $input_oid");
        debug("Output: NONE");
        print "NONE\n";
        return 0;
    }
}

# Simple protocol between snmpd and this program:
# Handshake
#   + stdin: "PING\n"
#   + stdout: "PONG\n"
#
# GET request
#   + stdin: "get\n<OID>\n"
#   + stdout: "<OID>\n<TYPE>\n<VALUE>\n" or "NONE\n"
#
# GETNEXT request
#   + stdin: "getnext\n<OID>\n"
#   + stdout: "<OID>\n<TYPE>\n<VALUE>\n" or "NONE\n"
#
# SET request
#   + stdin: "set\n<OID>\n<TYPE> <VALUE>\n"
#   + stdout: "DONE\n" or "not-writable\n" or "wrong-type\n" or
#             "wrong-length\n" or "wrong-value\n" or "inconsistent-value\n"
#
# Shutdown
#  + stdin: "\n"
my $input;
while (<>) {
    $input = $_;
    chomp $input;

    if ( !$input ) {
        debug("No input; exiting");
        exit(0);

    } elsif ( $input eq "PING" ) {
        debug("------------------------------------------------------");
        print "PONG\n";

    } elsif ( $input eq "set" ) {

        #Consume inputs and indicate MIB not writeable
        my $oid = <>;
        chomp $oid;
        my $type_value = <>;
        chomp $type_value;
        debug("Input: SET $oid $type_value");
        debug("Output: not-writable");
        print "not-writable\n";

    } elsif ( $input eq "get" ) {
        my $oid = <>;
        chomp $oid;
        $oid =~ s/^\s+|\s+$//g;
        $oid =~ s/^\.//;
        debug("Input: GET $oid");
        if ( validate_oid($oid) ) {
            print_oid_data($oid);
        } else {
            debug("Output: NONE");
            print "NONE\n";
        }

    } elsif ( $input eq "getnext" ) {
        my $oid = <>;
        chomp $oid;
        $oid =~ s/^\s+|\s+$//g;
        $oid =~ s/^\.//;
        debug("Input: GETNEXT $oid");
        my $next_oid = get_next_oid($oid);
        if ($next_oid) {
            print_oid_data($next_oid);
        } else {
            debug("Output: NONE");
            print "NONE\n";
        }

    }
}
