#! /usr/bin/perl
#
# Copyright (c) 2017-2019 AT&T Intellectual Property.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#


use strict;
use warnings;
use Getopt::Long;
use Module::Load::Conditional qw[can_load];

my $vrf_available = can_load( modules => { "Vyatta::VrfManager" => undef },
    autoload => "true" );

sub show_group {
    print <<END;

SNMPv3 Groups:

Group               View
-----               ----
END

    foreach my $group ( listNodes("group") ) {
        my $view = returnValue("group $group view");
        my $mode = returnValue("group $group mode");
        if ( length($group) >= 20 ) {
            print "$group\n                    $view($mode)\n";
        }
        else {
            $~ = "GROUP_FORMAT";
            format GROUP_FORMAT =
@<<<<<<<<<<<<<<<<<< @*(@*)
$group, $view, $mode
.
            write;
        }
    }
    print "\n";
}

sub show_user {
    print <<END;

SNMPv3 Users:

User                Auth Priv Mode Group
----                ---- ---- ---- -----
END

    foreach my $user ( listNodes("user") ) {
        my $auth  = returnValue("user $user auth type");
        my $priv  = returnValue("user $user privacy type");
        my $mode  = returnValue("user $user mode");
        my $group = returnValue("user $user group");
        if ( length($user) >= 20 ) {
            print "$user\n                    $auth  $priv  $mode   $group\n";
        }
        else {
            $~ = "USER_FORMAT";
            format USER_FORMAT =
@<<<<<<<<<<<<<<<<<< @<<< @<<< @<<< @*
$user, $auth, $priv, $mode, $group
.
            write;
        }
    }
    print "\n";
}

sub show_trap {
    print <<END;

SNMPv3 Trap-targets:

Trap-target                   Port   Protocol Auth Priv Type   EngineID              User
-----------                   ----   -------- ---- ---- ----   --------              ----
END

    foreach my $trap ( listNodes("trap-target") ) {
        my $auth     = returnValue("trap-target $trap auth type");
        my $priv     = returnValue("trap-target $trap privacy type");
        my $type     = returnValue("trap-target $trap type");
        my $port     = returnValue("trap-target $trap port");
        my $user     = returnValue("trap-target $trap user");
        my $protocol = returnValue("trap-target $trap protocol");
        my $engineid = returnValue("trap-target $trap engineid");
        if ( length($trap) >= 30 ) {
            $~ = "TRAP_BIG_FORMAT";
            format TRAP_BIG_FORMAT =
^*
$trap
                              @<<<<< @<<<<<<< @<<< @<<< @<<<<< @<<<<<<<<<<<<<<<<<<<<... @*
$port, $protocol, $auth, $priv, $type, $engineid, $user
.
            write;
        }
        else {
            $~ = "TRAP_FORMAT";
            format TRAP_FORMAT =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<< @<<<<< @<<<<<<< @<<< @<<< @<<<<< @<<<<<<<<<<<<<<<<<<<<... @*
$trap, $port, $protocol, $auth, $priv, $type, $engineid, $user
.
            write;
        }
    }
    print "\n";
}

sub show_routing_instance_trap {
    print <<END;

SNMPv3 Trap-targets:

Trap-target                   Port   Protocol Auth Priv Type   EngineID              Routing-Instance User
-----------                   ----   -------- ---- ---- ----   --------              ---------------- ----
END

    foreach my $trap ( listNodes("trap-target") ) {
        my $auth     = returnValue("trap-target $trap auth type");
        my $priv     = returnValue("trap-target $trap privacy type");
        my $type     = returnValue("trap-target $trap type");
        my $port     = returnValue("trap-target $trap port");
        my $user     = returnValue("trap-target $trap user");
        my $protocol = returnValue("trap-target $trap protocol");
        my $engineid = returnValue("trap-target $trap engineid");
        my $vrf      = returnValue("trap-target $trap routing-instance");
        $vrf = "\'default\'" unless $vrf;
        if ( length($trap) >= 30 ) {
            $~ = "VRF_TRAP_BIG_FORMAT";
            format VRF_TRAP_BIG_FORMAT =
^*
$trap
                              @<<<<< @<<<<<<< @<<< @<<< @<<<<< @<<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<... @*
$port, $protocol, $auth, $priv, $type, $engineid, $vrf, $user
.
            write;
        }
        else {
            $~ = "VRF_TRAP_FORMAT";
            format VRF_TRAP_FORMAT =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<< @<<<<< @<<<<<<< @<<< @<<< @<<<<< @<<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<... @*
$trap, $port, $protocol, $auth, $priv, $type, $engineid, $vrf, $user
.
            write;
        }
    }
    print "\n";
}

sub show_all {
    show_user();
    show_group();
    if ($vrf_available) {
        show_routing_instance_trap();
    } else {
        show_trap();
    }
}

sub listNodes {
    my $path = shift;
    my @nodes =
      split( ' ', `cli-shell-api listActiveNodes service snmp v3 $path` );
    return map { substr $_, 1, -1 } @nodes;
}

sub returnValue {
    my $path  = shift;
    my $value = `cli-shell-api returnActiveValue service snmp v3 $path`;
    return $value;
}

my $all;
my $group;
my $user;
my $trap;

GetOptions(
    "all!"   => \$all,
    "group!" => \$group,
    "user!"  => \$user,
    "trap!"  => \$trap,
);

show_all()   if ($all);
show_group() if ($group);
show_user()  if ($user);
if ($vrf_available) {
    show_routing_instance_trap()  if ($trap);
} else {
    show_trap()  if ($trap);
}
