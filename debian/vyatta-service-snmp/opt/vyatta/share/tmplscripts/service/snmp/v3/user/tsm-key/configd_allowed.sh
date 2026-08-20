#!/bin/bash
if [ -d /etc/snmp/tls/certs ]; then
    ls /etc/snmp/tls/certs 2> /dev/null
else
    ls /config/snmp/tls/certs 2> /dev/null
fi
