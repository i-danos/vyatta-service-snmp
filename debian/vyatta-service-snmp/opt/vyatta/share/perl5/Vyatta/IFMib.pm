# Module: IFMib.pm
#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

package Vyatta::IFMib;
use strict;
use Readonly;
use Vyatta::Misc;
use NetAddr::IP qw(:lower);
use Net::IP qw(ip_bincomp ip_iptobin ip_expand_address ip_compress_address);
use IPC::System::Simple qw(capture);
use JSON qw( decode_json );

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Dataplane;
use Vyatta::PCIid;
use Vyatta::Interface;

use base qw( Exporter );
our @EXPORT_OK =
  qw(%mib ifmib_get ifmib_get_next ifmib_get_intf_hash get_octets get_descr);

Readonly::Hash our %mib => (
    IPV4_ADDR    => '1',
    IPV6_ADDR    => '2',
    IPV4_ADDRLEN => '4',
    IPV6_ADDRLEN => '16',
);

my $IPADDR_CMD = "ip addr show";
my %config_ipaddrs;

#
# returns hash of operational ip addresses and corresponding
# interfaces. The hash key is the ip address is expanded form
# allowing lexicographical sort of the keys for ipv6.
#
# param[in] filter on inet|inet6 [default inet]
#
sub ifmib_get_intf_hash {
    my $filter = shift;
    my @addresses;

    $filter ||= "inet";
    my $ip_version = $filter eq "inet6" ? 6 : 4;
    my $ifname;
    if ( open( my $ipcmd, "$IPADDR_CMD |" ) ) {
        while ( my $line = <$ipcmd> ) {
            my ( $proto, $addr, $brdkw, $bcast ) = split( ' ', $line );
            if ( $proto =~ /.*:$/ && $addr =~ /.*:$/ ) {
                $ifname = $addr;
                chop($ifname);
            }
            next unless ( $proto eq $filter );
            my ( $ipaddr, $plen ) = split( /\//, $addr );
            my $key = ip_expand_address( $ipaddr, $ip_version );
            $config_ipaddrs{$key}{ifname} = $ifname;
            $config_ipaddrs{$key}{addr}   = $ipaddr;
            $config_ipaddrs{$key}{plen}   = $plen;
            next unless ( $brdkw eq "brd" );
            $key = ip_expand_address( $bcast, $ip_version );
            $config_ipaddrs{$key}{ifname} = $ifname;
            $config_ipaddrs{$key}{addr}   = $bcast;
        }
    }
}

#
# return an oid given an exact match on the ipaddr in the provided hash.
#
# param[in] ipaddr NetAddr ip address for exact lookup
# param[in] ref the inet address hash table
# param[in] fn function which returns the corresponding mib value
#
sub lookup_oid {
    my ( $ipaddr, $fn ) = @_;

    my $key    = ip_expand_address( $ipaddr->addr(), $ipaddr->version() );
    my $ifname = $config_ipaddrs{$key}{ifname};
    if ( defined($ifname) ) {
        my $type = $fn->( $key, $ipaddr, $ifname );
        return unless defined($type);
        return ( "integer", $type );
    }
    return;
}

sub get_octet {
    my ($sval) = @_;

    my $high = hex($sval) >> 8;
    my $low  = hex($sval) & 0xFF;
    return "$high.$low";
}

sub get_octets {
    my ($addr) = @_;

    my ( $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8 ) = split /\:/, $addr;
    my $str = get_octet($a1) . '.' . get_octet($a2);
    $str = $str . '.' . get_octet($a3) . '.' . get_octet($a4);
    $str = $str . '.' . get_octet($a5) . '.' . get_octet($a6);
    $str = $str . '.' . get_octet($a7) . '.' . get_octet($a8);
    return ($str);
}

sub oid_to_octet {
    my ( $v1, $v2 ) = @_;

    my $high = $v1 << 8;
    my $val  = $high | $v2;
    $val = sprintf( "%x", $val );
    return "$val";
}

sub oid_to_v6addr {
    my ($addr) = @_;

    my $v6addr;
    my (
        $a1, $a2,  $a3,  $a4,  $a5,  $a6,  $a7,  $a8,
        $a9, $a10, $a11, $a12, $a13, $a14, $a15, $a16
    ) = split /\./, $addr;
    return "0::0" unless defined($a16);
    my $str = oid_to_octet( $a1, $a2 ) . ':' . oid_to_octet( $a3, $a4 );
    $str =
      $str . ':' . oid_to_octet( $a5, $a6 ) . ':' . oid_to_octet( $a7, $a8 );
    $str =
      $str . ':' . oid_to_octet( $a9, $a10 ) . ':' . oid_to_octet( $a11, $a12 );
    $str =
        $str . ':'
      . oid_to_octet( $a13, $a14 ) . ':'
      . oid_to_octet( $a15, $a16 );
    $v6addr = ip_compress_address( $str, 6 );
    return ($v6addr);
}

# return the next oid given an ipaddr which may be present in the hash.
#
# param[in] base_oid the base OID for the mib get next
# param[in] ipaddr NetAddr ip address for exact lookup
# param[in] ref the inet address hash table
# param[in] fn function which returns the corresponding mib value
#
sub search_oid {
    my ( $base_oid, $ip, $fn ) = @_;

    my $oid;
    my $ifname;

    foreach my $key ( sort( keys %config_ipaddrs ) ) {
        if ( $ip->version() == 4 ) {
            if ( valid_ip_addr($key) ) {
                my $ipkey = new NetAddr::IP $key;
                if ( $ip lt $ipkey ) {
                    $ifname = $config_ipaddrs{$key}{ifname};
                    my $type = $fn->( $key, $ipkey, $ifname );
                    next unless defined($type);
                    $oid =
                        $base_oid . '.'
                      . $mib{IPV4_ADDR} . '.'
                      . $mib{IPV4_ADDRLEN} . '.'
                      . $key;
                    return ( $oid, "integer", $type );
                }
            }
        }
        elsif ( $ip->version() == 6 ) {
            if ( valid_ipv6_addr($key) ) {
                my ( $ip_addr, $plen ) = split( /\//, $ip );

                $ip_addr = ip_expand_address( $ip_addr, 6 );
                my $key_bin = ip_iptobin( $key,     6 );
                my $ip_bin  = ip_iptobin( $ip_addr, 6 );

                if ( ip_bincomp( $ip_bin, 'lt', $key_bin ) ) {
                    my $ipv6addr = new NetAddr::IP $key;
                    $ifname = $config_ipaddrs{$key}{ifname};
                    my $type = $fn->( $key, $ipv6addr, $ifname );
                    next unless defined($type);
                    my $addr = get_octets($key);
                    $oid =
                        $base_oid . '.'
                      . $mib{IPV6_ADDR} . '.'
                      . $mib{IPV6_ADDRLEN} . '.'
                      . $addr;
                    return ( $oid, "integer", $type );
                }
            }
        }
    }
    return;
}

# return an oid given an exact mib get on the ipaddr in the provided hash.
#
# param[in] type the address type (1 inet, 2 inet6)
# param[in] octets the number of octets in the address
# param[in] addr the address specified in mib octet format
# param[in] fn function which returns the corresponding mib value
#
sub ifmib_get {
    my ( $type, $octets, $addr, $fn ) = @_;

    my $ref;
    my ( $oid_type, $oid_value );

    if ( $type eq $mib{IPV4_ADDR} ) {
        my $ip = new NetAddr::IP $addr;
        if ( defined($ip) && $ip->version() == 4 ) {
            ifmib_get_intf_hash("inet");
            ( $oid_type, $oid_value ) = lookup_oid( $ip, $fn );
        }
    }
    elsif ( $type eq $mib{IPV6_ADDR} ) {
        my $v6addr = oid_to_v6addr($addr);
        my $ip     = new NetAddr::IP $v6addr;
        if ( defined($ip) ) {
            ifmib_get_intf_hash("inet6");
            ( $oid_type, $oid_value ) = lookup_oid( $ip, $fn );
        }
    }
    if ( defined($oid_type) ) {
        return ( $oid_type, $oid_value );
    }
    return;
}

# return the next oid for the given oid (type, octets, addr)
#
# param[in] base_oid the base MIB oid
# param[in] type the address type (1 inet, 2 inet6)
# param[in] octets the number of octets in the address
# param[in] addr the address specified in mib octet format
# param[in] fn function which returns the corresponding mib value
#
sub ifmib_get_next {
    my ( $base_oid, $type, $octets, $addr, $fn ) = @_;

    my $ref;
    my ( $oid, $oid_type, $oid_value );

    if ( !defined($type) ) {
        $type = $mib{IPV4_ADDR};
        $addr = "0.0.0.0";
    }
    if ( $type eq $mib{IPV4_ADDR} ) {
        my $ip = new NetAddr::IP $addr;
        if ( !defined($ip) || $ip->version() != 4 ) {
            $ip = new NetAddr::IP "0.0.0.0";
        }
        $addr = $ip->addr();
        ifmib_get_intf_hash("inet");
        ( $oid, $oid_type, $oid_value ) =
          search_oid( $base_oid, $ip, $fn );
    }
    elsif ( $type eq $mib{IPV6_ADDR} ) {
        my $v6addr = oid_to_v6addr($addr);
        my $ip     = new NetAddr::IP $v6addr;
        if ( !defined($ip) || $ip->version() != 6 ) {
            $ip = new NetAddr::IP "0::0";
        }
        $addr = $ip->addr();
        ifmib_get_intf_hash("inet6");
        ( $oid, $oid_type, $oid_value ) =
          search_oid( $base_oid, $ip, $fn );
    }

    if ( defined($oid) ) {
        return ( $oid, $oid_type, $oid_value );
    }
    elsif ( $type eq $mib{IPV4_ADDR} ) {
        my $ip = new NetAddr::IP "0::0";
        $addr = $ip->addr();
        ifmib_get_intf_hash("inet6");
        ( $oid, $oid_type, $oid_value ) =
          search_oid( $base_oid, $ip, $fn );
        if ( defined($oid) ) {
            return ( $oid, $oid_type, $oid_value );
        }
    }
    return;
}

sub get_sysfs_pci_info {
    my $ifname = shift;

    my $vendor_id = eval { get_sysfs_value( "$ifname", "device/vendor" ); };
    return if $@;
    my $device_id = eval { get_sysfs_value( "$ifname", "device/device" ); };
    return if $@;

    if ( defined($vendor_id) && defined($device_id) ) {
        my $vendorid = substr $vendor_id, 2;
        my $deviceid = substr $device_id, 2;
        if ( defined($vendorid) && defined($deviceid) ) {
            my $vendor = pci_vendor($vendorid);
            my $device = pci_device( $vendorid, $deviceid );

            if ( defined($vendor) && defined($device) ) {
                my $pci_info = sprintf( "%s %s", $vendor, $device );
                return $pci_info;
            }
        }
    }
    return;    # undefined
}

sub get_dp_pci_info {
    my $results = shift;
    my $dp_id   = shift;

    my $ifinfo = $results->[$dp_id];
    return unless defined($ifinfo);

    my $ifname = $ifinfo->{name};
    my $dev    = $ifinfo->{dev};
    if ($dev) {
        my $pci = $dev->{pci};
        if ($pci) {
            my $vendor_id = sprintf( "%.4x", $pci->{id}->{vendor} );
            my $device_id = sprintf( "%.4x", $pci->{id}->{device} );

            my $vendor = pci_vendor($vendor_id);
            $vendor = $vendor_id unless defined($vendor);

            my $device = pci_device( $vendor_id, $device_id );
            $device = $device_id unless defined($device);

            my $pci_info = sprintf( "%s %s", $vendor, $device );
            return $pci_info;
        }
    }
    return;    # undefined
}

sub get_descr {
    my ($ifname) = @_;

    return unless defined($ifname);

    my $intf = new Vyatta::Interface($ifname);
    return get_sysfs_pci_info($ifname) unless defined($intf);

    my $dp_id = $intf->dpid();
    return get_sysfs_pci_info($ifname) unless defined($dp_id);

    my $descr;
    my $dp_ids;
    my $dp_conns;
    ( $dp_ids, $dp_conns ) = Vyatta::Dataplane::setup_fabric_conns($dp_id);
    my $response = vplane_exec_cmd( "ifconfig $ifname", $dp_ids, $dp_conns, 1 );
    if ( defined( $response->[$dp_id] ) ) {
        my $decoded = decode_json( $response->[$dp_id] );
        my $ifinfo  = $decoded->{interfaces}->[0];
        if ( defined($ifinfo) ) {
            my @results;
            $results[$dp_id] = $ifinfo;
            if ( $#results >= 0 ) {
                $descr = get_dp_pci_info( \@results, $dp_id );
            }
        }
    }
    Vyatta::Dataplane::close_fabric_conns( $dp_ids, $dp_conns );
    return $descr;
}

1;
