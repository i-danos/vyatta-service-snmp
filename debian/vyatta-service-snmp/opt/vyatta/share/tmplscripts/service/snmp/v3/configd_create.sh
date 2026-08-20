#!/bin/bash
if [ ! -d "/config/snmp/tls" ]; then
    mkdir /config/snmp/tls ; 
    if [ -d "/etc/snmp/tls" ] ; then 
	mv /etc/snmp/tls/* /config/snmp/tls > /dev/null 2>&1;
	chmod -R 600 /config/snmp/tls;
	rmdir /etc/snmp/tls > /dev/null 2>&1;
	rm /etc/snmp/tls > /dev/null 2>&1;
    fi
    ln -s /config/snmp/tls /etc/snmp/tls;
fi
lnk=$(readlink /etc/snmp/tls)
if [ "$lnk" != "/config/snmp/tls" ]; then
    rm -f /etc/snmp/tls;
    ln -s /config/snmp/tls /etc/snmp/tls;
fi
