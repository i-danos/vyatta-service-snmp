#!/usr/bin/perl
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# Copyright (c) 2014-2017, Brocade Communications Systems, Inc.
# Copyright (c) 2007-2010 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";
use Module::Load::Conditional qw[can_load];
use Vyatta::Config;
use File::Copy;
use Getopt::Long;
use Socket;
use Socket6;

my $vrf_available = can_load( modules => { "Vyatta::VrfManager" => undef },
    autoload => "true" );
my $snmp_v3_level      = 'service snmp v3';
my $snmp_init          = 'service snmpd';
my $snmpd_conf         = '/etc/snmp/snmpd.conf';
my $snmpd_usr_conf     = '/usr/share/snmp/snmpd.conf';
my $snmpd_var_conf     = '/var/lib/snmp/snmpd.conf';
my $snmpd_conf_tmp     = "/tmp/snmpd.conf.$$";
my $snmpd_usr_conf_tmp = "/tmp/snmpd.usr.conf.$$";
my $snmpd_var_conf_tmp = "/tmp/snmpd.var.conf.$$";
my $versionfile        = '/opt/vyatta/etc/version';
my $local_agent        = 'unix:/var/run/snmpd.socket';

my $config = new Vyatta::Config;

my $oldEngineID = "";
my $setserialno = "";

my %OIDs = (
    "md5",  ".1.3.6.1.6.3.10.1.1.2", "sha", ".1.3.6.1.6.3.10.1.1.3",
    "aes",  ".1.3.6.1.6.3.10.1.2.4", "des", ".1.3.6.1.6.3.10.1.2.2",
    "none", ".1.3.6.1.6.3.10.1.2.1"
);

# generate a random character hex string
sub randhex {
    my $length = shift;
    return join "", map { unpack "H*", chr( rand(256) ) } 1 .. ( $length / 2 );
}

# Are we using routing-domain VRF implementation, as opposed to VRF
# master implementation?
sub using_rd_vrf {
    return 1
        if -f "/proc/self/rtg_domain";
    return 0;
}

# get vyatta version
sub get_version {
    my $version = "unknown-version";

    if ( open( my $f, '<', $versionfile ) ) {
        while (<$f>) {
            chomp;
            if (m/^Version\s*:\s*(.*)$/) {
                $version = $1;
                last;
            }
        }
        close $f;
    }
    return $version;
}

sub ipv6_disabled {
    socket( my $s, PF_INET6, SOCK_DGRAM, 0 )
      or return 1;
    close($s);
    return;
}

# write tsm config from current to snmpd_conf
sub set_tsm {
    $config->setLevel($snmp_v3_level);
    if ( $config->exists("tsm") ) {
        my $port      = $config->returnValue("tsm port");
        my $local_key = $config->returnValue("tsm local-key");
        system(
"sed -i 's/^agentaddress.*\$/&,tlstcp:$port,dtlsudp:$port/' $snmpd_conf_tmp"
        );
        system("echo \"[snmp] localCert $local_key\" >> $snmpd_conf_tmp");
    }
}

# delete all SNMP config files
# can be called directly
sub snmp_delete {
    system("systemctl stop snmpd > /dev/null 2>&1");

    my @files = ( $snmpd_conf, $snmpd_usr_conf, $snmpd_var_conf );
    foreach my $file (@files) {
        if ( -e $file ) {
            unlink($file);
        }
    }
}

# write groups from vyatta config to snmpd_conf
sub set_groups {
    print
"#access\n#             context sec.model sec.level match  read    write  notif\n";
    $config->setLevel($snmp_v3_level);
    foreach my $group ( $config->listNodes("group") ) {
        my $mode     = $config->returnValue("group $group mode");
        my $view     = $config->returnValue("group $group view");
        my $secLevel = $config->returnValue("group $group seclevel");
        if ( $mode eq "ro" ) {
            print "access $group \"\" usm $secLevel prefix $view none none\n";
            print "access $group \"\" tsm $secLevel prefix $view none none\n";
        }
        else {
            print "access $group \"\" usm $secLevel prefix $view $view none\n";
            print "access $group \"\" tsm $secLevel prefix $view $view none\n";
        }
    }
    print "\n";
}

# write users from vyatta config to snmpd_conf
sub set_users_in_etc {

    print "#group\n";
    my $tsm_counter = 0;
    $config->setLevel($snmp_v3_level);
    foreach my $user ( $config->listNodes("user") ) {
        $config->setLevel( $snmp_v3_level . " user $user" );
        if ( $config->exists("group") ) {
            my $group = $config->returnValue("group");
            print "group $group usm $user\n";
            print "group $group tsm $user\n";
        }
        if ( $config->exists("tsm-key") ) {
            my $cert = $config->returnValue("tsm-key");
            $tsm_counter++;
            print "certSecName $tsm_counter $cert --sn $user\n";
        }
    }

    print "\n";
}

# write users from vyatta config to config files in /usr & /var
sub set_users_to_other {
    open( my $usr_conf, '>>', $snmpd_usr_conf_tmp )
      or die "Couldn't open $snmpd_usr_conf_tmp - $!";
    open( my $var_conf, '>>', $snmpd_var_conf_tmp )
      or die "Couldn't open $snmpd_var_conf_tmp - $!";

    print $var_conf "\n";

    $config->setLevel($snmp_v3_level);
    my $needTsm = 0;
    if ( $config->exists("tsm") ) {
        $needTsm = 1;
    }

    my %trap_users = ();

    foreach my $trap ( $config->listNodes("trap-target") ) {
        $trap_users{ $config->returnValue("trap-target $trap user") } = 1;
    }

    foreach my $user ( $config->listNodes("user") ) {
        delete $trap_users{$user};
        $config->setLevel( $snmp_v3_level . " user $user" );
        my $auth_type = $config->returnValue("auth type");
        my $priv_type = $config->returnValue("privacy type");
        $priv_type = !defined($priv_type) ? "des" : $priv_type;
        if ( $config->exists("auth") ) {
            if ( $config->exists("auth plaintext-key") ) {
                my $auth_key = $config->returnValue("auth plaintext-key");
                my $priv_key = '';
                $priv_key = $config->returnValue("privacy plaintext-key")
                  if $config->exists("privacy plaintext-key");
                print $var_conf
"createUser $user \U$auth_type\E $auth_key \U$priv_type\E $priv_key\n";
            }
            else {
                my $name_print = get_printable_name($user);
                my $EngineID   = $config->returnValue("engineid");
                if ( $EngineID eq "" ) {
                    die "ERROR: user $user engineid is null\n";
                }
                my $auth_type_oid = $OIDs{$auth_type};
                my $auth_key_hex  = $config->returnValue("auth encrypted-key");

                my ( $priv_type_oid, $priv_key_hex );
                if ( $config->exists("privacy") ) {
                    $priv_type_oid = $OIDs{$priv_type};
                    $priv_key_hex =
                      $config->returnValue("privacy encrypted-key");
                }
                else {
                    $priv_type_oid = $OIDs{'none'};
                    $priv_key_hex  = '0x';
                }
                print $var_conf
"usmUser 1 3 $EngineID $name_print $name_print NULL $auth_type_oid $auth_key_hex $priv_type_oid $priv_key_hex 0x\n";
            }
        }
        my $mode = $config->returnValue("mode");
        my $end  = "auth";
        if ( $config->exists("privacy") ) {
            $end = "priv";
        }
        print $usr_conf $mode . "user $user $end\n";
        if ($needTsm) {
            print $usr_conf $mode . "user -s tsm $user $end\n";
        }
    }

# add users for trap if they do not exist in vyatta config /services/snmp/v3/user
    foreach my $user ( keys %trap_users ) {
        my $name_print = get_printable_name($user);
        print $var_conf "usmUser 1 3 0x"
          . randhex(26)
          . " $name_print $name_print NULL .1.3.6.1.6.3.10.1.1.2 0x"
          . randhex(32)
          . " .1.3.6.1.6.3.10.1.2.1 0x 0x\n";
        print $usr_conf "rouser $user auth\n";
    }

    print $var_conf "setserialno $setserialno\n"
      if !( $setserialno eq "" );
    print $var_conf "oldEngineID $oldEngineID\n"
      if !( $oldEngineID eq "" );

    close $usr_conf;
    close $var_conf;
}

# if name contains '-' then it must be printed in hex format
sub get_printable_name {
    my $name = shift;
    if ( $name =~ /-/ ) {
        my @array = unpack( 'C*', $name );
        my $stringHex = '0x';
        foreach my $c (@array) {
            $stringHex .= sprintf( "%lx", $c );
        }
        return $stringHex;
    }
    else {
        return "\"$name\"";
    }
}

# Print current value of a param.
sub snmp_show_output {
    my ( $config_name, $value ) = @_;

    $config->setLevel($snmp_v3_level);
    if ( $config->exists($config_name) ) {
        $value = $config->returnValue($config_name);
    }

    print " $value";
}

# Return default engineID from config file.
sub snmp_show_default_engineid {
    open( my $var_conf, '<', $snmpd_var_conf )
      or die "Couldn't open $snmpd_usr_conf - $!";

    while ( my $line = <$var_conf> ) {
        chomp($line);
        if ( $line =~ /^oldEngineID (.*)$/ ) {
            return $1;
        }
    }
    close $var_conf;
    return "";
}

# Parse existing users from config file.
sub snmp_show_user_list {
    open( my $var_conf, '<', $snmpd_var_conf )
      or die "Couldn't open $snmpd_usr_conf - $!";

    while ( my $line = <$var_conf> ) {
        if ( $line =~ /^usmUser / ) {
            my @values = split( / /, $line );
            my $name = $values[4];
            my $value;
            if ( $name =~ /^"(.*)"$/ ) {
                $name = $1;
            }
            else {
                $name = pack( 'H*', $name );
            }
            snmp_show_output( "user", $name );
        }
    }
    print "\n";
    close $var_conf;
}

# Print existing auth settings.
sub snmp_show_user_auth {
    my ( $key_word ) = @_;

    open( my $var_conf, '<', $snmpd_var_conf )
      or die "Couldn't open $snmpd_usr_conf - $!";

    while ( my $line = <$var_conf> ) {
        if ( $line =~ /^usmUser / ) {
            my @values = split( / /, $line );
            my $name = $values[4];
            my $value;
            if ( $name =~ /^"(.*)"$/ ) {
                $name = $1;
            }
            else {
                $name = pack( 'H*', $name );
            }

            if ( $key_word =~ /^$name/ ) {
                if ( $key_word =~ /auth encrypted-key/ ) {
                    $value = $values[8];
                }
                elsif ( $key_word =~ /privacy encrypted-key/ ) {
                    $value = $values[10];
                }
                if ( $value ne "\"\"" && $value ne "0x" ) {
                    snmp_show_output( $key_word, $value );
                    last;
                }
            }
        }
    }
    close $var_conf;
}

# Support for various 'allowed' config settings.  Parse
# the config file for some of them.
sub snmp_show {
    my ($key_word) = @_;

    if ( $key_word =~ /oldEngineID/ ) {
        my $eid = snmp_show_default_engineid();
        snmp_show_output( "engineid", $eid );
        return;
    }

    if ( $key_word =~ /user/ ) {
        snmp_show_user_list();
        return;
    }

    if ( $key_word =~ /encrypted-key/ ) {
        snmp_show_user_auth( $key_word );
        return;
    }

}

# write trap-target hosts from vyatta config to snmpd_conf
sub set_hosts {
    print "#trap-target\n";
    $config->setLevel($snmp_v3_level);
    my $vrf;
    foreach my $target ( $config->listNodes("trap-target") ) {
        my $vrf_option = '';
        $config->setLevel( $snmp_v3_level . " trap-target $target" );
        my $auth_key = '';
        if ( $config->exists("auth plaintext-key") ) {
            $auth_key = "-A " . $config->returnValue("auth plaintext-key");
        }
        else {
            $auth_key = "-3m " . $config->returnValue("auth encrypted-key");
        }
        my $auth_type   = $config->returnValue("auth type");
        my $user        = $config->returnValue("user");
        my $port        = $config->returnValue("port");
        my $protocol    = $config->returnValue("protocol");
        my $type        = $config->returnValue("type");
        if ( $vrf_available ) {
            $vrf        = $config->returnValue("routing-instance");
            $vrf_option = "-n $vrf" if ( defined($vrf) );
        }
        my $inform_flag = '-Ci';
        $inform_flag = '-Ci' if ( $type eq 'inform' );

        if ( $type eq 'trap' ) {
            $inform_flag = '-e ' . $config->returnValue("engineid");
        }
        my $privacy  = '';
        my $secLevel = 'authNoPriv';
        if ( $config->exists("privacy") ) {
            my $priv_key = '';
            if ( $config->exists("privacy plaintext-key") ) {
                $priv_key =
                  "-X " . $config->returnValue("privacy plaintext-key");
            }
            else {
                $priv_key =
                  "-3M " . $config->returnValue("privacy encrypted-key");
            }
            my $priv_type = $config->returnValue("privacy type");
            $privacy  = "-x $priv_type $priv_key";
            $secLevel = 'authPriv';
        }

        # TODO understand difference between master and local
        # Uses:
        # set -3m / -3M for auth / priv  for master
        # or -3k / -3K for local
        # Current use only master
        my $target_print = $target;
        if ( $target =~ /:/ ) {
            $target_print = "[$target]";
            $protocol     = $protocol . "6";
        }
        my $addr = "$protocol:$target_print:$port";
        if ( $vrf_available && defined($vrf) ) {
            # Use ID for RD, name for VRF master
            if ( using_rd_vrf() ) {
                $vrf = Vyatta::VrfManager::get_vrf_id($vrf);
            } else {
                # Dummy assign to suppress used once warning
                $Vyatta::VrfManager::VRFMASTER_PREFIX =
                    $Vyatta::VrfManager::VRFMASTER_PREFIX;
                $vrf = $Vyatta::VrfManager::VRFMASTER_PREFIX . $vrf;
            }
            $addr = "$addr:$vrf";
        }
        print
"trapsess -v 3 $vrf_option $inform_flag -u $user -l $secLevel -a $auth_type $auth_key $privacy $addr\n";
    }
    print "\n";
}

sub copy_conf_to_tmp {

    # these files already contain SNMPv2 configuration
    copy( $snmpd_conf, $snmpd_conf_tmp )
      or die "Couldn't copy $snmpd_conf to $snmpd_conf_tmp - $!";
    copy( $snmpd_usr_conf, $snmpd_usr_conf_tmp )
      or die "Couldn't copy $snmpd_usr_conf to $snmpd_usr_conf_tmp - $!";
    copy( $snmpd_var_conf, $snmpd_var_conf_tmp )
      or die "Couldn't copy $snmpd_var_conf to $snmpd_var_conf_tmp - $!";
}

# update all vyatta config
# can be called directly
sub snmp_update {

    copy_conf_to_tmp();

    set_tsm();

    open( my $fh, '>>', $snmpd_conf_tmp )
      or die "Couldn't open $snmpd_conf_tmp - $!";

    select $fh;

    set_groups();
    set_hosts();
    set_users_in_etc();

    close $fh;
    select STDOUT;

    move( $snmpd_conf_tmp, $snmpd_conf )
      or die "Couldn't move $snmpd_conf_tmp to $snmpd_conf - $!";

    $config->setLevel($snmp_v3_level);
    if ( $config->exists("engineid") ) {
        $oldEngineID = $config->returnValue("engineid");
    }

    system("systemctl stop snmpd > /dev/null 2>&1");

    #add newly added users to var config to get encrypted values
    set_users_to_other();

    move( $snmpd_usr_conf_tmp, $snmpd_usr_conf )
      or die "Couldn't move $snmpd_usr_conf_tmp to $snmpd_usr_conf - $!";
    move( $snmpd_var_conf_tmp, $snmpd_var_conf )
      or die "Couldn't move $snmpd_var_conf_tmp to $snmpd_var_conf - $!";

    system("systemctl start snmpd > /dev/null 2>&1");
}

my $update_snmp;
my $delete_snmp;
my $show;

GetOptions(
    "update-snmp!"  => \$update_snmp,
    "delete-snmp!"  => \$delete_snmp,
    "oldEngineID=s" => \$oldEngineID,
    "setserialno=s" => \$setserialno,
    "show=s"        => \$show,
);

snmp_update()    if ($update_snmp);
snmp_delete()    if ($delete_snmp);
snmp_show($show) if ($show);
