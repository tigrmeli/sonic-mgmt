# -*- coding:UTF-8 -*-

import time
import re
from tests.common.ixia.ixia_helpers import (
    logger_msg,
    get_connection_info,
    get_dut_mac_address
)
from tests.common.helpers.assertions import pytest_assert
from restpyApi import restpyAPI

"""
This covers following testcases from testplan:

IP4/IP6，Error frame processing
            1. Layer2 Message

Topology Used:

       IXIA ---- DUT ---- IXIA
"""

###############################################################
#                  Declaring Global variables
###############################################################

sleep5 = 5
sleep10 = 10
sleep15 = 15
vlanId = 20
dutPort1Mac = "00:01:01:00:00:01"
dutPort2Mac = "00:02:02:00:00:02"

result = True
###############################################################
#                   Start of Test Procedure
###############################################################


def test_ipv4_ipv6_l2_msg(testbed, duthost, ixia_chassis, get_ixia_port_list):
    global result
    ###############################################################
    #                   STEP1: Prepare preconditions
    ###############################################################
    # 1.3 Get topology connection information, intf is used to configure DUT
    logger_msg(u'Get topology connection information.')
    intf, _ = get_connection_info(testbed)

    #   1.2 Create an Ixia session, return the session handle
    # and the port information to be used in the test environment
    logger_msg(u'创建 Ixia Session IP。')
    ixnServerIp = testbed['ptf_ip']
    ixChassisIp = ixia_chassis
    ixPortList = get_ixia_port_list
    ixObj = restpyAPI(ixnServerIp)
    ixObj.portObj.connectIxChassis(ixChassisIp)
    ixObj.portObj.assignPorts(ixPortList, createVports=True)

    ###############################################################
    #                   STEP2: DUT configuration
    ###############################################################
    logger_msg("Configure DUT")

    duthost.shell('sudo config vlan add 2')
    duthost.shell('sudo config vlan member add -u 2 {}'.format(intf['dut1port1']))
    duthost.shell('sudo config vlan member add -u 2 {}'.format(intf['dut1port2']))

    ret1 = str(duthost.shell('show vlan brief'))
    logger_msg(ret1)
    if re.search(intf['dut1port1'], ret1) and re.search(intf['dut1port2'], ret1):
        logger_msg("Interface Tagged in Vlan PASSED")
    else:
        logger_msg("Interface Tagged in Vlan FAILED")
        result = False
        raise Exception("Vlan Tag Failed. Aborting!!!")

    ###############################################################
    #        STEP3: Operations related to test instruments
    ###############################################################

    # 3.1: Load instrument configuration file
    logger_msg('Configure Ixia and create L2 traffic')
    topoObj1 = ixObj.protocolObj.createTopologyNgpf(portList=[ixPortList[0]], topologyName="Topo1")
    topoObj2 = ixObj.protocolObj.createTopologyNgpf(portList=[ixPortList[1]], topologyName="Topo2")
    deviceGroupObj1 = ixObj.protocolObj.createDeviceGroupNgpf(
        topoObj1,
        multiplier=1,
        deviceGroupName='DG1')

    ixObj.protocolObj.configEthernetNgpf(
        deviceGroupObj1,
        ethernetName='Eth1',
        macAddress={
            'start': dutPort1Mac,
            'direction': 'increment',
            'step': '00:00:00:00:00:00'
        },
        macAddressPortStep='01:00:00:00:00:01')

    deviceGroupObj2 = ixObj.protocolObj.createDeviceGroupNgpf(
        topoObj2,
        multiplier=1,
        deviceGroupName='DG2'
        )
    ixObj.protocolObj.configEthernetNgpf(
        deviceGroupObj2,
        ethernetName='Eth2',
        macAddress={
            'start': dutPort2Mac,
            'direction': 'increment',
            'step': '00:00:00:00:00:01'
        },
        macAddressPortStep='01:00:00:00:00:01')

    vport1 = ixObj.portObj.getVports([ixPortList[0]])
    vport2 = ixObj.portObj.getVports([ixPortList[1]])
    trafficStatus = ixObj.trafficObj.configTrafficItem(
        mode='create',
        trafficItem={
            'name': 'Raw L2 Traffic',
            'trafficType': 'raw',
            'biDirectional': False,
            'srcDestMesh': 'one-to-one',
            'routeMesh': 'oneToOne',
            'allowSelfDestined': False,
            'trackBy': ['flowGroup0']
        },
        endpoints=[
            {'name': 'Flow-Group-1', 'sources': [vport1[0]+'/protocols'], 'destinations': [vport2[0]+'/protocols']}],
        configElements=[{'transmissionType': 'fixedFrameCount',
                         'frameCount': 1000,
                         'frameRate': 10,
                         'frameRateType': 'percentLineRate',
                         'frameSize': 128
                         }])

    trafObj1 = trafficStatus[0]
    configElementObj1 = trafficStatus[2][0]

    # configure raw ethernet packet from ixia port1 to ixia port2
    logger_msg("set destination MAC as all 0 in traffic")
    stackObj = ixObj.trafficObj.getPacketHeaderStackIdObj(configElementObj1, stackId=1)

    ixObj.trafficObj.configPacketHeaderField(
        stackObj,
        fieldName='Source MAC Address',
        data={
            'valueType': 'increment',
            'startValue': dutPort1Mac,
            'stepValue': '00:00:00:00:00:00',
            'countValue': 1
        }
    )

    ixObj.trafficObj.configPacketHeaderField(
        stackObj,
        fieldName='Destination MAC Address',
        data={
            'valueType': 'increment',
            'startValue': '00:00:00:00:00:00',
            'stepValue': '00:00:00:00:00:00',
            'countValue': 3
        }
    )

    # 3.4: Protocol start
    logger_msg(u'protocol start')
    ixObj.protocolObj.startAllProtocols()
    time.sleep(sleep10)

    ###############################################################
    #                STEP4: Verify L2 traffic with Dest MAC all 0
    ###############################################################
    # 4:1 clear interface counters
    logger_msg("clear interface counters ")

    duthost.shell('sonic-clear counters')

    # 4:2 regenerate_traffic_item initialliy
    logger_msg(u'Regenerate and start traffic Item ')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)
    # 4:3 Verify L2 traffic
    logger_msg(u'verify L2 traffic with Dest MAC all 0. Expect No Packet Loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=False)
    ###############################################################
    #                STEP5: Verify No Errors in show interface counters
    ###############################################################
    # 5:1: Verify No errors in show interface counters
    logger_msg(u'Verify No errors in show interface counters as '
               u'traffic if flooded to all interfaces ')

    ret1 = str(duthost.shell('show dropcounters counts'))

    ###############################################################
    #                STEP6: Modify and set traffic Dest Mac is
    #                       Multicast address
    ###############################################################
    # 6:0 clear interface counters
    logger_msg("Clear interface counters")
    duthost.shell('sonic-clear counters')

    # 6:1 Modify and set traffic Dest MAC as mcast address
    ixObj.trafficObj.modifyTrafficItemDestMacAddress(trafficItemObj=trafObj1,
                                                     trafficItemName="Raw L2 Traffic",
                                                     endpointSetName='Flow-Group-1',
                                                     values='01:00:5E:00:01:01'
                                                     )

    ###############################################################
    #                STEP7: Verify ipv6 traffic with set traffic Dest Mac is Multicast address
    ###############################################################
    # 7:1 regenerate_traffic_item
    logger_msg(u'Regenerate and start traffic Item ')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)

    # 7:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with Dest Mac is Multicast address. Expect no packet loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=False)

    ###############################################################
    #                STEP8: Verify No Errors in show interface counters
    ###############################################################
    # 8:1: Verify errors in show interface counters
    logger_msg(u'Verify No errors in show interface counters when Dest Mac is Multicast address')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #                STEP9: Modify and set traffic Dest Mac is
    #                       DUT Mac
    ###############################################################
    # 9:0 clear interface counters
    duthost.shell('sonic-clear counters')

    # 9:1 Modify and set traffic Dest MAC as mcast address
    dut_mac = get_dut_mac_address(duthost)
    ixObj.trafficObj.modifyTrafficItemDestMacAddress(trafficItemObj=trafObj1,
                                                     trafficItemName="Raw L2 Traffic",
                                                     endpointSetName='Flow-Group-1',
                                                     values=str(dut_mac)
                                                     )
    ###############################################################
    #                STEP10: Verify ipv6 traffic with set traffic
    #                       Dest Mac is DUT Mac
    ###############################################################
    # 10:1 regenerate_traffic_item
    logger_msg(u'Regenerate and start traffic Item ')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)
    # 10:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with Dest Mac is DUT Mac address. Expect no packet loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=False)

    ###############################################################
    #                STEP11: Verify No Errors in show interface counters
    ###############################################################
    # 11:1: Verify errors in show interface counters
    logger_msg(u'Verify No errors in show interface counters when Dest Mac is DUT Mac address')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #                STEP11: Modify and set traffic Source Mac is
    #                       all 0
    ###############################################################
    # 11:1 Modify and set traffic Src MAC as all 0
    ixObj.trafficObj.modifyTrafficItemSrcMacAddress(
        trafficItemObj=trafObj1,
        trafficItemName="IPv4 Topo1 to Topo2",
        endpointSetName='Flow-Group-1',
        values="00:00:00:00:00:00")

    ixObj.trafficObj.modifyTrafficItemDestMacAddress(
        trafficItemObj=trafObj1,
        trafficItemName="IPv4 Topo1 to Topo2",
        endpointSetName='Flow-Group-1',
        values="ff:ff:ff:ff:ff:ff")

    ###############################################################
    #                STEP12: Verify ipv6 traffic with set traffic
    #                       Source Mac is set all 0
    ###############################################################
    # 12:0 clear counters
    logger_msg("Clear counters")
    duthost.shell('sonic-clear counters')

    # 12:1 regenerate_traffic_item
    logger_msg(u'Regenerating traffic Item')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)

    # 12:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with set traffic Src Mac is set all 0. Expect no packet loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=False)

    ###############################################################
    #                STEP13: Verify No Errors in show interface counters
    ###############################################################
    # 13:1: Verify errors in show interface counters
    logger_msg(u'Verify errors in show interface counters with set traffic Src Mac is all 0')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #                STEP14: Modify and set traffic Source Mac is
    #                       all F
    ###############################################################
    # 14:1 Modify and set traffic Dest MAC as mcast address
    ixObj.trafficObj.modifyTrafficItemSrcMacAddress(trafficItemObj=trafObj1,
                                                    trafficItemName="IPv4 Topo1 to Topo2",
                                                    endpointSetName='Flow-Group-1',
                                                    values="FF:FF:FF:FF:FF:FF")

    ###############################################################
    #                STEP15: Verify ipv6 traffic with set traffic
    #                       Source Mac is set all F
    ###############################################################
    # 15:0 clear counters
    duthost.shell('sonic-clear counters')

    # 15:1 regenerate_traffic_item
    logger_msg(u'Regenerating traffic Item')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)

    # 15:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with set traffic Src Mac is set all F. Traffic should fail')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=True)

    ###############################################################
    #                STEP16: Verify No Errors in show interface counters
    ###############################################################
    # 16:1: Verify errors in show interface counters
    logger_msg(u'Verify errors in show interface counters with set traffic Src Mac is all F')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #           STEP17: Modify and set traffic Source Mac is
    #                       Mcast address
    ###############################################################
    # 20:1 Modify and set traffic Src MAC as mcast address
    ixObj.trafficObj.modifyTrafficItemSrcMacAddress(trafficItemObj=trafObj1,
                                                    trafficItemName="IPv4 Topo1 to Topo2",
                                                    endpointSetName='Flow-Group-1',
                                                    values='01:00:5E:00:01:01')

    ###############################################################
    #                STEP18: Verify ipv6 traffic with set traffic
    #                       Source Mac is set to Mcast address
    ###############################################################
    # 18:0 clear counters
    duthost.shell('sonic-clear counters')

    # 18:1 regenerate_traffic_item
    logger_msg(u'Regenerating traffic Item')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)

    # 18:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with set traffic Src Mac is set Mcast Address.Expect packet loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=True)

    ###############################################################
    #                STEP19: Verify No Errors in show interface counters
    ###############################################################
    # 19:1: Verify errors in show interface counters
    logger_msg(u'Verify errors in show interface counters with set traffic Src Mac is Mcast address')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #                STEP20: Modify and set traffic Source Mac is
    #                       DUT mac address
    ###############################################################
    # 20:1 Modify and set traffic Src MAC as mcast address
    ixObj.trafficObj.modifyTrafficItemSrcMacAddress(trafficItemObj=trafObj1,
                                                    trafficItemName="IPv4 Topo1 to Topo2",
                                                    endpointSetName='Flow-Group-1',
                                                    values=str(dut_mac))

    ###############################################################
    #                STEP21: Verify ipv6 traffic with set traffic
    #                       Source Mac is set to DUT mac address
    ###############################################################
    # 21:0 clear counters
    duthost.shell('sonic-clear counters')

    # 21:1 regenerate_traffic_item
    logger_msg(u'Regenerating traffic Item')
    ixObj.trafficObj.startTraffic(regenerateTraffic=True, applyTraffic=True)

    # 21:2 Verify L2 traffic
    logger_msg(u'verify L2 traffic with set traffic Src Mac is set to DUT mac Address. Expect no packet loss')
    ixObj.trafficObj.stopTraffic()
    check_stat_for_loss(ixObj, expect_loss=False)

    ###############################################################
    #        STEP22: Verify No Errors in show interface counters
    ###############################################################
    logger_msg(u'Verify errors in show interface counters with set traffic Src Mac is DUT mac address')
    check_rx_err_for_interface(intf['dut1port1'], duthost)

    ###############################################################
    #             STEP23: Verify Errors while creating
    #                       Vlan 0 and 4095
    ###############################################################
    logger_msg("Verify Reserved Vlans and Exceeded Limit Vlans cannot be created")

    ret1 = str(duthost.shell('sudo config vlan add 0 || true'))
    if re.search("Error: Invalid VLAN", ret1):
        logger_msg("Cannot create Vlan 0 as expected. PASSED")
    else:
        logger_msg("Cannot create Vlan 0 as expected. FAILED", "ERROR")

    ret1 = str(duthost.shell('sudo config vlan add 4095 || true'))
    if re.search("Error: Invalid VLAN", ret1):
        logger_msg("Cannot create Vlan 4095 as expected. PASSED")
    else:
        logger_msg("Cannot create Vlan 4095 as expected. FAILED", "ERROR")
    ##############################################################
    #               STEP: Clear configuration
    ##############################################################
    logger_msg("Clear configuration")
    cleanup_dut(intf, duthost)

    ixObj.protocolObj.stopAllProtocols()
    ##############################################################
    # STEP: Check is the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv4_ipv6_l2_msg failed')


def cleanup_dut(intf, duthost):
    duthost.shell('sudo config vlan member del 2 {}'.format(intf['dut1port1']))
    duthost.shell('sudo config vlan member del 2 {}'.format(intf['dut1port2']))
    duthost.shell('sudo config vlan del 2')


def check_rx_err_for_interface(interface_name, duthost):
    global result
    # Split the output into lines
    cmd_output = str(duthost.shell('show dropcounters counts'))
    lines = cmd_output.split('\n')

    # Search for the line with the interface name
    for line in lines:
        match = re.search(r'{}\s+\S+\s+(\d+)'.format(interface_name), line)
        if match:
            if int(match.group(1)) > 0:
                logger_msg("RX_ERR in DUT1 is seen Dest Mac is Multicast address. Hence FAILED", "ERROR")
                result = False
            return

    logger_msg("Unable to measure RX_ERR in DUT1 Hence FAILED", "ERROR")
    result = False


def check_stat_for_loss(ixObj, expect_loss=False):
    global result
    stats = ixObj.statsObj.getStats(viewName='Flow Statistics')
    for flowGroup, values in stats.items():
        txPort = values['Tx Port']
        rxPort = values['Rx Port']
        txFrames = values['Tx Frames']
        rxFrames = values['Rx Frames']
        frameLoss = values['Frames Delta']
        logger_msg('{flowGroup:10} : {txPort:10} {rxPort:10} {txFrames:15} {rxFrames:15} '
                   '{frameLoss:10}'.format(flowGroup=flowGroup, txPort=txPort, rxPort=rxPort,
                                           txFrames=txFrames, rxFrames=rxFrames, frameLoss=frameLoss))

        if expect_loss and txFrames == rxFrames:
            logger_msg("tx and rx frames mismatch. FAILED", "ERROR")
            result = False

        if not expect_loss and txFrames != rxFrames:
            logger_msg("tx and rx frames mismatch. FAILED", "ERROR")
            result = False
