#!/usr/bin/python3

# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Generates Storm Control SNMP Traps.
#

from __future__ import print_function
import os
import syslog
import zmq
import datetime

trapCmd = "/usr/bin/agentxtrap"

LOCAL_IPC = 'ipc:///var/run/vyatta/vplaned-event.pub'

Internet                      = '1.3.6.1'
MIB2ifIndex                   = Internet + '.2.1.2.2.1.1'
att                           = Internet + '.4.1.74'
StormCtlMib                   = att + '.1.32.4'
attVrStormCtlTimestamp        = StormCtlMib + '.0.1.1'
attVrStormCtlEvent            = StormCtlMib + '.0.1.2'
avscVlan                      = StormCtlMib + '.1.1.2.1.2'
attVrStormCtlTraffic          = StormCtlMib + '.1.2.1.1.2'
attVrStormCtlStatus           = StormCtlMib + '.1.2.1.1.3'
attVrStormCtlSuppressedPacket = StormCtlMib + '.1.2.1.1.5'

def getIfIndex(ifName):

    ifIndex = 0

    ifindex_path = '/sys/class/net/{}/ifindex'.format(ifName)
    try:
        with open(ifindex_path, mode='r', encoding='utf-8') as f:
            ifIndex = int(f.read().strip())
    except:
        print("Could not find ifIndex for {}\n".format(ifName))

    return ifIndex


def getTrafficType(name):

    types = {'unicast':3, 'multicast':2, 'broadcast':1}

    return types[name]


#
# Send a Trap to all targets.
#
def sendTraps(ifIndex, vlan, state, trafficType, suppressedPkt):

    intIndex = "{} i {} ".format(MIB2ifIndex, ifIndex)
    if not vlan == 0:
        vlan_notify = "{} i {} ".format(avscVlan, vlan)
    else:
        vlan_notify = " "

    status = "{} i {} ".format(attVrStormCtlStatus, state)
    notificationOID = "{}".format(attVrStormCtlEvent)
    trafficType = "{} i {} ".format(attVrStormCtlTraffic,
                                    trafficType)
    suppressedPkts = "{} C {} ".format(attVrStormCtlSuppressedPacket,
                                       suppressedPkt)

    utctime = datetime.datetime.utcnow().isoformat("T") + "Z"
    timestr = "{} s '{}' ".format(attVrStormCtlTimestamp, utctime)

    cmd = "{} {} {}".format(trapCmd, notificationOID,
                            intIndex + vlan_notify + status + timestr +
                            trafficType + suppressedPkts)

#    Emit command line for troubleshooting
#    syslog.syslog(syslog.LOG_ERR, "cmd = {}".format(cmd))

    ret = os.system(cmd)

    if not ret == 0:
        syslog.syslog(syslog.LOG_ERR,
                      "agentxtrap returned error status {}".format(ret))

#
# Listen for Storm Control Event from controller
#
def Listener():

    zmq_ctx = zmq.Context.instance()
    s = zmq_ctx.socket(zmq.SUB)
    s.connect(LOCAL_IPC)
    s.setsockopt_string(zmq.SUBSCRIBE, 'StormCtlEvent')

    while True:
        data = s.recv_multipart()
        numargs = len(data)
        if numargs is not 6:
            syslog.syslog(syslog.LOG_ERR,
                          "Storm Control notification - 6 args expected" +
                          ", received {}".format(numargs))
            continue

        intf = data[1].decode('utf-8')
        vlan = int.from_bytes(data[2], byteorder='little', signed=False)
        state = int.from_bytes(data[3], byteorder='little', signed=False)
        trafficType = data[4].decode('utf-8')
        suppressedPkts = int.from_bytes(data[5], byteorder='little',
                                        signed=False)

        ifindex = getIfIndex(intf)
        if ifindex != 0:
            sendTraps(ifindex, vlan, state, getTrafficType(trafficType),
                      suppressedPkts)

#
# main
#

Listener()
