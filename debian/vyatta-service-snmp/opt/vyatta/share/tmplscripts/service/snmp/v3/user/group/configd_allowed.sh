#!/bin/bash
list=$(cli-shell-api listNodes service snmp v3 group)
echo "$list"
