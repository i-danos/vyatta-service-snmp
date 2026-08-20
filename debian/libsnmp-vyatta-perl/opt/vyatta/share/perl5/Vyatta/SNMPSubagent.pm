# Module: SNMPSubagent.pm
#
# Copyright (c) 2018-2019, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

package Vyatta::SNMPSubagent;
use strict;
use warnings;

use Carp;
use NetSNMP::agent (':all');
use NetSNMP::ASN   (':all');

use lib "/opt/vyatta/share/perl5";
use Vyatta::MIBMisc;

my $running;

sub stop_agent {
    $running = 0;
}

sub new {
    my ( $class, $name ) = @_;

    return unless ( defined($name) );

    # Allocate new object
    my $self = {};

    bless( $self, $class );

    $self->{register_oids}   = {};
    $self->{last_populated}  = {};
    $self->{request_handler} = \&request_handler;

    $self->{name} = $name;
    $self->{agent} =
      new NetSNMP::agent( 'Name' => $self->{name}, 'AgentX' => 1 );
    $running = 1;

    $SIG{INT}  = \&stop_agent;
    $SIG{TERM} = \&stop_agent;
    $SIG{HUP}  = \&stop_agent;

    return $self;
}

sub register_oid {
    my ( $self, $oid, $func, $refresh ) = @_;

    croak "Error: OID or callback function not defined"
      if ( !defined($oid) || !defined($func) );
    croak "Error: $func is not a code reference"
      if ( ref($func) ne "CODE" );
    $refresh = 300 if ( !defined($refresh) );
    my @args = ( $func, $refresh );
    $self->{register_oids}->{$oid} = \@args;
    create_mib_tree($oid);
    eval { $func->($self); 1 }
      or croak "Unable to populate mib for $oid: $@";
    $self->{last_populated}->{$oid} = time();
    sort_mib_keys($oid);
    $self->{agent}->register( $self->{name}, $oid, $self->{request_handler} );
}

sub add_tree_entry {
    my ( $self, $entry_oid, $type, $value ) = @_;

    my $regoids = $self->{register_oids};
    foreach my $reg_oid ( keys %{$regoids} ) {
        if ( $entry_oid =~ /^$reg_oid/ ) {
            my @args = ( $type, $value );
            add_mib_entry( $reg_oid, $entry_oid, $type, $value );
            last;
        }
    }
}

sub add_oid {
    my ( $self, $oid, $index, $type, $value ) = @_;
    $self->add_tree_entry( "$oid.$index", $type, $value );
}

sub add_oid_str {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_OCTET_STR, "$value" );
}

sub add_oid_int {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_INTEGER, $value );
}

sub add_oid_unsigned {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_UNSIGNED, $value );
}

sub add_oid_gauge {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_GAUGE, $value );
}

sub add_oid_counter {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_COUNTER, $value );
}

sub add_oid_counter64 {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_COUNTER64, "$value" );
}

sub add_oid_objid {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_OBJECT_ID, $value );
}

sub add_oid_timeticks {
    my ( $self, $oid, $index, $value ) = @_;
    $self->add_oid( $oid, $index, ASN_TIMETICKS, $value );
}

sub refresh_mibs {
    my ($self) = @_;

    my $now     = time;
    my $regoids = $self->{register_oids};
    foreach my $reg_oid ( keys %{$regoids} ) {

        my ( $populate_mib, $refresh ) = @{ $regoids->{$reg_oid} };
        my $last = $self->{last_populated}->{$reg_oid};
        if ( $now > $last && ( ( $now - $last ) > $refresh ) ) {
            eval { $populate_mib->($self); 1 }
              or croak "Unable to populate mib for $reg_oid: $@";
            $self->{last_populated}->{$reg_oid} = time();
            sort_mib_keys($reg_oid);
        }
    }
}

sub run {
    my ($self) = @_;

    while ($running) {
        $self->refresh_mibs();
        $self->{agent}->agent_check_and_process(1);
    }
    $self->{agent}->shutdown();
}

sub request_handler {
    my ( $handler, $registration_info, $request_info, $requests ) = @_;
    my $request;

    for ( $request = $requests ; $request ; $request = $request->next() ) {
        my $oid = $request->getOID();
        if ( $request_info->getMode() == MODE_GET ) {
            my ( $type, $value ) = get_oid($oid);
            return if ( !defined($type) || !defined($value) );
            $request->setValue( $type, $value );
        }
        elsif ( $request_info->getMode() == MODE_GETNEXT ) {
            my ( $roid, $type, $value ) = get_next_oid($oid);
            return
              if ( !defined($roid) || !defined($type) || !defined($value) );
            $request->setOID($roid);
            $request->setValue( $type, $value );
        }
    }
}

1;
