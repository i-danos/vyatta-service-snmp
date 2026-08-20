#!/bin/bash
if [[ "$COMMIT_ACTION" == "DELETE" ]]; then
    perl /opt/vyatta/sbin/vyatta-snmp-v3.pl --delete-snmp
fi
