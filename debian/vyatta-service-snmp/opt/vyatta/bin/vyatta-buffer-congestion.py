#!/usr/bin/python3

# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Generates Buffer Congestion SNMP Traps.
#

#
# ZMSG Message format to be parsed
#   |--------------------|
#   | msg queue          |
#   |--------------------|
#   | notification type  |  <= "MIBINIT","UPDATE","CLEAR","WARNING" and "ALERT"
#   |--------------------|
# Fields after the 'notification type' are defined as following:
# If type is "MIBINIT", only one data is appended:
#   |--------------------|
#   | max BDBs num       |
#   |--------------------|
# If type is "UPDATE", two data fields are appended:
#   |--------------------|
#   | buf used           |
#   |--------------------|
#   | packet dropped     |
#   |--------------------|
# If type is "CLEAR", only one data is appended:
#   |--------------------|
#   | number of samples  |
#   |--------------------|
# If type is "WARNING" or "ALERT", vfields values are:
#   1) fixed fields
#   |--------------------|
#   | threshold          |
#   |--------------------|
#   | number of E1       |
#   |--------------------|
#   | number of E2       |
#   |--------------------|
#   | number of E3       |
#   |--------------------|
#   | notify period type |
#   |--------------------|
#   2) Optional field (appended after fixed fields only when period type is
#      10-sec level):
#   |--------------------|
#   | utilization rate   |
#   |--------------------|
#

from __future__ import print_function
import os
import syslog
import zmq

LOCAL_IPC = 'ipc:///var/run/vyatta/vplaned-event.pub'

trapAgent = "/usr/bin/agentxtrap"

HrTypesStorageRam = '1.3.6.1.2.1.25.2.1.2'

HrStorageTable              = '1.3.6.1.2.1.25.2.3'
HrStorageEntry              = HrStorageTable + '.1'
HrStorageIndex              = HrStorageEntry + '.1'
HrStorageType               = HrStorageEntry + '.2'
HrStorageDescr              = HrStorageEntry + '.3'
HrStorageAllocationUnits    = HrStorageEntry + '.4'
HrStorageSize               = HrStorageEntry + '.5'
HrStorageUsed               = HrStorageEntry + '.6'
HrStorageAllocationFailures = HrStorageEntry + '.7'

qosHrStorageIndex              = HrStorageIndex + '.1'
qosHrStorageType               = HrStorageType + '.1'
qosHrStorageDescr              = HrStorageDescr + '.1'
qosHrStorageAllocationUnits    = HrStorageAllocationUnits + '.1'
qosHrStorageSize               = HrStorageSize + '.1'
qosHrStorageUsed               = HrStorageUsed + '.1'
qosHrStorageAllocationFailures = HrStorageAllocationFailures + '.1'

NotificationModeSeconds = 0

def SendSNMPTrap(traptype, oid, value):
    cmd = "{} {} {} {} {}".format(trapAgent, HrStorageEntry, oid, traptype, value)
    return os.system(cmd)

#
# Update BDB used and dropped packet num
#
def UpdateExtBufMIBs(bufUnitUsed, droppedPktNum):
    ret = SendSNMPTrap("i", qosHrStorageUsed, bufUnitUsed)
    if ret != 0:
        syslog.syslog(syslog.LOG_ERR,
            "agentxtrap returned error status {}".format(ret))

    if droppedPktNum != 0:
        ret = SendSNMPTrap("c", qosHrStorageAllocationFailures, droppedPktNum)
        if ret != 0:
            syslog.syslog(syslog.LOG_ERR,
                "agentxtrap returned error status {}".format(ret))

#
# Listen for buffer overflow Event from controller
#
def Listener():
    zmq_ctx = zmq.Context.instance()
    s = zmq_ctx.socket(zmq.SUB)
    s.connect(LOCAL_IPC)
    s.setsockopt_string(zmq.SUBSCRIBE, 'QosExtBufCongestion')

    while True:
        data = s.recv_multipart()
        numargs = len(data)

        if numargs < 2:
            syslog.syslog(syslog.LOG_ERR,
                "Buffer congestion notification - too few args" +
                ", received {} args".format(numargs))
            continue

        msg = data[0].decode('utf-8')
        notification_tag = data[1].decode('utf-8')

        if notification_tag == 'MIBINIT':
            if numargs < 3:
                syslog.syslog(syslog.LOG_ERR,
                    "Buffer congestion notification - too few args" +
                    ", received {} args".format(numargs))
                continue
            totalBDBs = int.from_bytes(data[2], byteorder='little', signed=False)
            SendSNMPTrap("i", qosHrStorageIndex, 1)
            SendSNMPTrap("o", qosHrStorageType, HrTypesStorageRam)
            SendSNMPTrap("s", qosHrStorageDescr, "External\ bundle\ descriptor\ buffers\ usage")
            SendSNMPTrap("i", qosHrStorageAllocationUnits, 1)
            SendSNMPTrap("i", qosHrStorageSize, totalBDBs)
            SendSNMPTrap("i", qosHrStorageUsed, 0)
            SendSNMPTrap("c", qosHrStorageAllocationFailures, 0)
        elif notification_tag == 'UPDATE':
            if numargs < 4:
                syslog.syslog(syslog.LOG_ERR,
                    "Buffer congestion notification - too few args" +
                    ", received {} args".format(numargs))
                continue
            bufUnitUsed = int.from_bytes(data[2], byteorder='little', signed=False)
            droppedPktNum = int.from_bytes(data[3], byteorder='little', signed=False)
            UpdateExtBufMIBs(bufUnitUsed, droppedPktNum)
        elif notification_tag == 'CLEAR':
            if numargs < 3:
                syslog.syslog(syslog.LOG_ERR,
                    "Buffer congestion notification - too few args" +
                    ", received {} args".format(numargs))
                continue
            samples_num = int.from_bytes(data[2], byteorder='little', signed=False)
            syslog.syslog(syslog.LOG_WARNING, "DEASSERT: QoS External Packet Buffer Events" +
                " after {} sample intervals.".format(samples_num))
        else:
            # For WARNING or ALERT
            if numargs < 6:
                syslog.syslog(syslog.LOG_ERR,
                        "Buffer congestion notification - 6 args expected" +
                        ", received {}".format(numargs))
                continue

            priority = syslog.LOG_WARNING
            if notification_tag == 'ALERT':
                priority = syslog.LOG_ALERT

            threshold = int.from_bytes(data[2], byteorder='little', signed=False)
            e1 = int.from_bytes(data[3], byteorder='little', signed=False)
            e2 = int.from_bytes(data[4], byteorder='little', signed=False)
            e3 = int.from_bytes(data[5], byteorder='little', signed=False)
            noti_period_type = int.from_bytes(data[6], byteorder='little', signed=False)

            logmsg = "ASSERT: {}: QoS External Packet Buffer ".format(notification_tag)
            if noti_period_type == NotificationModeSeconds:
                utilization = int.from_bytes(data[7], byteorder='little', signed=False)
                logmsg = logmsg + "Threshold/SampleUsage: {}/{}, ".format(threshold, utilization) + \
                    "Event counters: E1: {}, E2: {}, E3 {}".format(e1, e2, e3)
            else:
                logmsg = logmsg + "Threshold {}, ".format(threshold) + \
                    "Event counters: E1: {}, E2: {}, E3 {}".format(e1, e2, e3)

            syslog.syslog(priority, logmsg)

#
# main
#
Listener()
