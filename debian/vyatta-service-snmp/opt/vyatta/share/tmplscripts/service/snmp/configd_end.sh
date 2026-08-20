#!/opt/vyatta/bin/cliexec

if [[ -z "$VAR(v3/)" && -z "$VAR(community/)" && -z "$VAR(community6/)" && "$COMMIT_ACTION" != "DELETE" ]]; then
    echo "no snmp community or community6 or v3 is configured";
    exit 0;
fi
 
if [[ "$COMMIT_ACTION" == "DELETE" ]]; then
    systemctl stop vyatta-snmp-subagent
    rm -f /var/lib/snmp/vyatta-snmp-subagent.conf
    systemctl stop vyatta-entity-mibs-subagent
    rm -f /var/lib/snmp/vyatta-entity-mibs-subagent.conf
    systemctl stop vyatta-ptp-mib-subagent
    rm -f /var/lib/snmp/vyatta-ptp-mib-subagent.conf
    test -f /opt/vyatta/sbin/vyatta-snmp-vrf-agent && systemctl stop vyatta-snmp-vrf-agent
    /opt/vyatta/sbin/vyatta-snmp.pl --stop-snmp;
    rm -f /etc/snmp/snmpd.conf;
    rm -f /etc/snmp/snmptrapd.conf;
else
    engineid=$((cat /var/lib/snmp/snmpd.conf | grep oldEngineID| sed -re 's/oldEngineID/--oldEngineID/') 2>/dev/null)
    serialno=$((cat /var/lib/snmp/snmpd.conf | grep setserialno| sed -re 's/setserialno/--setserialno/') 2>/dev/null)
    extra_options="$engineid $serialno"

    /opt/vyatta/sbin/vyatta-snmp.pl --update-snmp || exit 1;

    if [ -n "$VAR(v3/)" ]; then
	/opt/vyatta/sbin/vyatta-snmp-v3.pl --update-snmp $extra_options;
    else
	systemctl start snmpd  > /dev/null 2>&1;
    fi

    rm -f /var/lib/snmp/vyatta-snmp-subagent.conf
    systemctl restart vyatta-snmp-subagent
    rm -f /var/lib/snmp/vyatta-entity-mibs-subagent.conf
    systemctl restart vyatta-entity-mibs-subagent
    rm -f /var/lib/snmp/vyatta-ptp-mib-subagent.conf
    systemctl restart vyatta-ptp-mib-subagent
    test -f /opt/vyatta/sbin/vyatta-snmp-vrf-agent && systemctl restart vyatta-snmp-vrf-agent
    # If snmpd just started, trigger routing daemons to reconnect
    if [[ -n "$(pidof snmpd)" ]]; then
        vtysh -c "configure terminal" -c "snmp restart bgp" \
              -c "snmp restart mrib" -c "snmp restart nsm" \
              -c "snmp restart ospf" -c "snmp restart ospf6" \
              -c "snmp restart pim" -c "snmp restart rib" \
              -c "snmp restart rip" -c "snmp restart bfd" \
              &> /dev/null
        # Don't return with error if call to vtysh fails
        true
    fi
fi
