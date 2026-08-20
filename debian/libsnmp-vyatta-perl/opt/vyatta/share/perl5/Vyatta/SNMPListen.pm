# Module: SNMPMisc.pm
#
# Copyright (c) 2021, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

package Vyatta::SNMPListen;
use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";
use NetAddr::IP;
use Module::Load::Conditional qw[can_load];
use Vyatta::Config;
use Vyatta::Interface;

use base qw( Exporter );
our @EXPORT =
  qw(is_vrf_available get_rdid_or_vrfname get_routing_instances get_listen_addresses get_all_listen_addresses validate_listen_address);

my $DEFAULT_VRFNAME = 'default';

my $localhost      = new NetAddr::IP('localhost');
my $localhost_addr = $localhost->addr();

my $vrf_available = can_load(
    modules  => { "Vyatta::VrfManager" => undef },
    autoload => "true"
);

sub is_vrf_available {
    return defined($vrf_available);
}

# Are we using routing-domain VRF implementation, as opposed to VRF
# master implementation?
sub using_rd_vrf {
    return 1
      if -f "/proc/self/rtg_domain";
    return 0;
}

sub get_rdid_or_vrfname {
    my $vrf = shift;

    # Use ID for RD, name for VRF master
    if ( using_rd_vrf() ) {
        return Vyatta::VrfManager::get_vrf_id($vrf);
    }
    else {
        return $Vyatta::VrfManager::VRFMASTER_PREFIX . $vrf;
    }
}

sub get_all_vrf_intfs {
    my @vrf_intfs;
    my $rconfig = Vyatta::Config->new("routing routing-instance");
    my @vrfs    = $rconfig->listNodes();
    foreach my $vrf (@vrfs) {
        push @vrf_intfs, $rconfig->listNodes("$vrf interface");
    }
    return @vrf_intfs;
}

sub get_vrf_intfs {
    my ($vrf) = @_;
    my $rconfig =
      Vyatta::Config->new("routing routing-instance $vrf interface");
    return $rconfig->listNodes();
}

sub get_default_intfs {
    my @vrf_intfs = get_all_vrf_intfs();
    my %vintfs    = map { $_ => 1 } @vrf_intfs;

    my @def_intfs;
    my $iconfig = Vyatta::Config->new('interfaces');
    my @iftypes = $iconfig->listNodes();
    foreach my $iftype (@iftypes) {
        my @interfaces = $iconfig->listNodes("$iftype");
        foreach my $intf (@interfaces) {
            next if ( exists( $vintfs{$intf} ) );
            next if ( $intf eq 'lo' );
            next unless $iconfig->returnValues("$iftype $intf address");
            push @def_intfs, $intf;
        }
    }
    return @def_intfs;
}

sub get_routing_instances {
    my $rconfig = Vyatta::Config->new();
    return $rconfig->returnValues('service snmp routing-instance');
}

sub get_listen_addresses {
    my $lconfig = Vyatta::Config->new();
    return $lconfig->listNodes('service snmp listen-address');
}

sub is_local {
    my ( $ifnames, $addr ) = @_;
    return unless ( defined($ifnames) && defined($addr) );

    foreach my $name (@$ifnames) {
        my $intf = new Vyatta::Interface($name);
        return 0 unless $intf;
        my @addrs = Vyatta::Interface::get_interface_addrs($intf);
        foreach my $iaddr (@addrs) {
            my ( $intf_addr, undef ) = split( /\//, $iaddr );
            if ( $addr eq $intf_addr ) {
                return 1;
            }
        }
    }
    return 0;
}

sub is_local_address {
    my ( $addr, $vrf ) = @_;
    return unless ( defined($addr) && defined($vrf) );

    my @intfs;
    if ( $vrf eq $DEFAULT_VRFNAME ) {
        @intfs = get_default_intfs();
    }
    else {
        @intfs = get_vrf_intfs($vrf);
    }
    return is_local( \@intfs, $addr );
}

sub get_listen_addr {
    my ( $port, $addr, $vrf ) = @_;
    my %listen_addr;
    $listen_addr{'port'}       = $port;
    $listen_addr{'address'}    = $addr;
    $listen_addr{'vrf'}        = $vrf;
    $listen_addr{'no_address'} = 1
      if ( $addr && !is_local_address( $addr, $vrf ) );
    if ( $vrf eq $DEFAULT_VRFNAME ) {
        my $lintf = 'default';
        $lintf = 'lo' if $listen_addr{'address'} eq $localhost_addr;
        push @{ $listen_addr{'listen_interface'} }, $lintf;
    }
    else {
        push @{ $listen_addr{'listen_interface'} }, get_rdid_or_vrfname($vrf);
    }
    return \%listen_addr;
}

sub get_all_listen_addresses {
    my @vrfs     = get_routing_instances();
    my %vrfnames = map { $_ => 1 } @vrfs;
    my @listen_addrs;
    my $sconfig  = Vyatta::Config->new('service snmp listen-address');
    my @address  = $sconfig->listNodes();
    my $loopback = 0;
    if (@address) {
        foreach my $addr (@address) {
            my $port = $sconfig->returnValue("$addr port");
            $port = '161' unless $port;
            next if ( $addr eq '127.0.0.1' && $port eq '161' );
            my $vrf = $sconfig->returnValue("$addr routing-instance");
            if ($vrf) {
                push @listen_addrs, get_listen_addr( $port, $addr, $vrf );
            }
            else {
                if ( scalar(@vrfs) == 1 ) {
                    $vrf = $vrfs[0];
                    push @listen_addrs, get_listen_addr( $port, $addr, $vrf );
                }
                else {
                    $vrf = $DEFAULT_VRFNAME;
                    push @listen_addrs, get_listen_addr( $port, $addr, $vrf );
                    $loopback = 1;
                }
            }
            delete( $vrfnames{$vrf} );
        }
    }
    foreach my $vrf ( keys %vrfnames ) {
        push @listen_addrs, get_listen_addr( '161', "", $vrf );
    }
    if ( $loopback || !exists( $vrfnames{$DEFAULT_VRFNAME} ) ) {
        push @listen_addrs,
          get_listen_addr( '161', $localhost_addr, $DEFAULT_VRFNAME );
    }
    return \@listen_addrs;
}

# Check if the configured listen address
# is present in the configuration
sub validate_listen_address {
    my $listen_addrs = get_all_listen_addresses();
    foreach my $addr (@$listen_addrs) {
        next if $addr->{'address'} eq $localhost_addr;
        warn
"WARNING: Listen address '$addr->{'address'}' in routing-instance '$addr->{'vrf'}' is not present in the configuration\n"
          if ( $addr->{'no_address'} );
    }
}

1;
