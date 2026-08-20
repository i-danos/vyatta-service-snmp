#!/bin/bash
if [ -d "/config/snmp/tls" ]; then
    chown -R snmp /config/snmp/tls;
    chmod -R 600 /config/snmp/tls;
fi
