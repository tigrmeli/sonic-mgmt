# -*- coding:UTF-8 -*-
import time
import os
import sys
import re

from tests.common.reboot import logger
from tests.common.ixia.ixia_helpers import (
    logger_msg,
    load_config,
    modify_vlan,
    reserve_port,
    send_ping,
    start_protocols,
    get_connection_info
)
from tests.common.helpers.assertions import pytest_assert

"""
IP4/IP6 basics
Configure 9 ipv6 addresses on the layer 3 interface
"""


def test_ipv6_with_second_ip(ixiahost, testbed, duthost):
    ###############################################################
    #                   STEP1: Prepare preconditions
    ###############################################################
    #           1.1 Set the global result, the default is True,
    # if the intermediate detection point fails, update the value to False
    result = True

    # 1.2 Set the test IxNetwork configuration file name
    configFile = os.path.join(os.path.dirname(__file__), sys._getframe().f_code.co_name + '.ixncfg')
    logger.info(configFile)

    # 1.3 Get topology connection information, intf is used to configure DUT,
    #       and vlanid is used to update test configuration file
    logger_msg(u'Get topology connection information.')
    intf, vlanid = get_connection_info(testbed)

    # 1.4 Create an Ixia session, return the session and the port information
    #                   to be used in the test environment
    logger_msg(u'Create Ixia Session IPs.')
    session, portList = ixiahost

    ###############################################################
    #                   STEP2: Send DUT configuration
    ###############################################################
    logger_msg(u'配置DUT接口IP地址并UP接口。')
    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:0:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:1:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:2:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:3:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:4:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:5:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:6:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:7:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:8:1::1/64".format(intf['dut1port1']))
    time.sleep(5)

    ###############################################################
    #        STEP3: Operations related to test instruments
    ###############################################################

    # 3.1: Load instrument configuration file
    logger_msg(u'Load the configuration file.')
    load_config(session, configFile)

    # 3.2: Load the vlan corresponding to the port
    logger_msg(u'Update vlan.')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='0')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='1')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='2')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='3')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='4')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='5')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='6')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='7')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='8')

    # 3.3: Reserve port
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    # 3.4: Protocol start
    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(5)

    ###############################################################
    #                STEP4: Check the DUT ip interface
    ###############################################################

    logger_msg(u'View DUT interface ip')
    ret = str(duthost.shell('show ipv6 int'))
    logger_msg(ret)

    if re.search('2000:0:0:1::1/64', ret) and re.search('2000:0:1:1::1/64', ret) and \
            re.search('2000:0:2:1::1/64', ret) and re.search('2000:0:3:1::1/64', ret) and \
            re.search('2000:0:4:1::1/64', ret) and re.search('2000:0:5:1::1/64', ret) and \
            re.search('2000:0:6:1::1/64', ret) and re.search('2000:0:7:1::1/64', ret) and \
            re.search('2000:0:8:1::1/64', ret):
        logger_msg('CHECK1:Device ip Success.')
    else:
        logger_msg('CHECK1:Device ip Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP5: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping 2000:0:0:1::2')
    ret1 = str(duthost.shell('ping -c 3 2000:0:0:1::2'))
    logger_msg(ret1)
    logger_msg(u'DUT Ping 2000:0:1:1::2')
    ret2 = str(duthost.shell('ping -c 3 2000:0:1:1::2'))
    logger_msg(ret2)
    logger_msg(u'DUT Ping 2000:0:2:1::2')
    ret3 = str(duthost.shell('ping -c 3 2000:0:2:1::2'))
    logger_msg(ret3)
    logger_msg(u'DUT Ping 2000:0:3:1::2')
    ret4 = str(duthost.shell('ping -c 3 2000:0:3:1::2'))
    logger_msg(ret4)
    logger_msg(u'DUT Ping 2000:0:4:1::2')
    ret5 = str(duthost.shell('ping -c 3 2000:0:4:1::2'))
    logger_msg(ret5)
    logger_msg(u'DUT Ping 2000:0:5:1::2')
    ret6 = str(duthost.shell('ping -c 3 2000:0:5:1::2'))
    logger_msg(ret6)
    logger_msg(u'DUT Ping 2000:0:6:1::2')
    ret7 = str(duthost.shell('ping -c 3 2000:0:6:1::2'))
    logger_msg(ret7)
    logger_msg(u'DUT Ping 2000:0:7:1::2')
    ret8 = str(duthost.shell('ping -c 3 2000:0:7:1::2'))
    logger_msg(ret8)
    logger_msg(u'DUT Ping 2000:0:8:1::2')
    ret9 = str(duthost.shell('ping -c 3 2000:0:8:1::2'))
    logger_msg(ret9)

    if re.search('2000:0:0:1::2', ret1) and re.search('time', ret1) and \
       re.search('2000:0:1:1::2', ret2) and re.search('time', ret2) and \
       re.search('2000:0:2:1::2', ret3) and re.search('time', ret3) and \
       re.search('2000:0:3:1::2', ret4) and re.search('time', ret4) and \
       re.search('2000:0:4:1::2', ret5) and re.search('time', ret5) and \
       re.search('2000:0:5:1::2', ret6) and re.search('time', ret6) and \
       re.search('2000:0:6:1::2', ret7) and re.search('time', ret7) and \
       re.search('2000:0:7:1::2', ret8) and re.search('time', ret8) and \
       re.search('2000:0:8:1::2', ret9) and re.search('time', ret9):
        logger_msg('CHECK2:DUT ping ipv6 Success.')
    else:
        logger_msg('CHECK2:DUT ping ipv6 Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP6: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia api server ping DUT interface address 2000:0:0:1::1')
    res_1 = send_ping(session, '2000:0:0:1::2', '2000:0:0:1::1')
    logger_msg(res_1)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:1:1::1')
    res_2 = send_ping(session, '2000:0:1:1::2', '2000:0:1:1::1')
    logger_msg(res_2)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:2:1::1')
    res_3 = send_ping(session, '2000:0:2:1::2', '2000:0:2:1::1')
    logger_msg(res_3)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:3:1::1')
    res_4 = send_ping(session, '2000:0:3:1::2', '2000:0:3:1::1')
    logger_msg(res_4)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:4:1::1')
    res_5 = send_ping(session, '2000:0:4:1::2', '2000:0:4:1::1')
    logger_msg(res_5)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:5:1::1')
    res_6 = send_ping(session, '2000:0:5:1::2', '2000:0:5:1::1')
    logger_msg(res_6)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:6:1::1')
    res_7 = send_ping(session, '2000:0:6:1::2', '2000:0:6:1::1')
    logger_msg(res_7)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:7:1::1')
    res_8 = send_ping(session, '2000:0:7:1::2', '2000:0:7:1::1')
    logger_msg(res_8)
    logger_msg(u'Ixia api server ping DUT interface address 2000:0:8:1::1')
    res_9 = send_ping(session, '2000:0:8:1::2', '2000:0:8:1::1')
    logger_msg(res_9)

    if res_1['arg2'] is True & res_2['arg2'] is True \
            & res_3['arg2'] is True & res_4['arg2'] is True \
            & res_5['arg2'] is True & res_6['arg2'] is True \
            & res_7['arg2'] is True & res_8['arg2'] is True \
            & res_9['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')

    else:

        logger_msg('Check3: Ixia ping DUT Fail', 'ErrOR')
        if res_1['arg2'] is not True:
            logger_msg(res_1['arg3'])
        if res_2['arg2'] is not True:
            logger_msg(res_2['arg3'])
        if res_3['arg2'] is not True:
            logger_msg(res_3['arg3'])
        if res_4['arg2'] is not True:
            logger_msg(res_4['arg3'])
        if res_5['arg2'] is not True:
            logger_msg(res_5['arg3'])
        if res_6['arg2'] is not True:
            logger_msg(res_6['arg3'])
        if res_7['arg2'] is not True:
            logger_msg(res_7['arg3'])
        if res_8['arg2'] is not True:
            logger_msg(res_8['arg3'])
        if res_9['arg2'] is not True:
            logger_msg(res_9['arg3'])
        result = False

    ##############################################################
    #               STEP7: Clear configuration
    ##############################################################
    logger_msg(u'Clear configuration')
    duthost.shell("sudo config interface ip remove {} 2000:0:0:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:1:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:2:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:3:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:4:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:5:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:6:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:7:1::1/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:8:1::1/64".format(intf['dut1port1']))

    ##############################################################
    # STEP8: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv6_with_second_ip failed')
