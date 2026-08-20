#!/bin/bash
list=$(cli-shell-api listNodes service snmp view)
echo "$list"
