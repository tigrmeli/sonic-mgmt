# -*- coding:UTF-8 -*-
import time
import os
import sys

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
Configure multiple ipv4 and ipv6 addresses on a layer 3 interface at the same time
"""


def test_ipv4_ipv6_with_l3_interface(ixiahost, testbed, duthost):
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
    logger_msg(u'Configure the DUT layer 3 interface')

    duthost.shell("sudo config interface ip add {} 11.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 11.1.2.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 11.1.3.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2001:0:0:1::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2001:0:0:2::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2001:0:0:3::2/64".format(intf['dut1port1']))

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

    # 3.4: Reserve port
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    # 3.5: Protocol start
    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(5)

    ###############################################################
    #                STEP4: Check the DUT ip interface
    ###############################################################
    ret_ipv6 = str(duthost.shell("show ipv6 int"))
    ret_ipv4 = str(duthost.shell("show ip int"))
    logger_msg(ret_ipv6)
    logger_msg(ret_ipv4)

    if ('11.1.1.2/24' in ret_ipv4) and ('11.1.2.2/24' in ret_ipv4) and ('11.1.3.2/24' in ret_ipv4) and \
       ('2001:0:0:1::2/64' in ret_ipv6) and ('2001:0:0:2::2/64' in ret_ipv6) and ('2001:0:0:3::2/64' in ret_ipv6):
        logger_msg('CHECK1:Device ip Success.')

    else:
        logger_msg('CHECK1:Device ip Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP5: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping')
    logger_msg(u'DUT Ping 11.1.1.1')
    ret1 = str(duthost.shell("ping -c 3 11.1.1.1"))
    logger_msg(ret1)
    logger_msg(u'DUT Ping 11.1.2.1')
    ret2 = str(duthost.shell("ping -c 3 11.1.2.1"))
    logger_msg(ret2)
    logger_msg(u'DUT Ping 11.1.3.1')
    ret3 = str(duthost.shell("ping -c 3 11.1.3.1"))
    logger_msg(ret3)
    logger_msg(u'DUT Ping 2001:0:0:1::1')
    ret4 = str(duthost.shell("ping -c 3 2001:0:0:1::1"))
    logger_msg(ret4)
    logger_msg(u'DUT Ping 2001:0:0:2::1')
    ret5 = str(duthost.shell("ping -c 3 2001:0:0:2::1"))
    logger_msg(ret5)
    logger_msg(u'DUT Ping 2001:0:0:3::1')
    ret6 = str(duthost.shell("ping -c 3 2001:0:0:3::1"))
    logger_msg(ret6)

    if ('11.1.1.1' in ret1) and ('time' in ret1) and  \
       ('11.1.2.1' in ret2) and ('time' in ret2) and  \
       ('11.1.3.1' in ret3) and ('time' in ret3) and  \
       ('2001:0:0:1::1' in ret4) and ('time' in ret4) and  \
       ('2001:0:0:2::1' in ret5) and ('time' in ret5) and  \
       ('2001:0:0:3::1' in ret6) and ('time' in ret6):
        logger_msg('CHECK2:DUT ping Success.')

    else:
        logger_msg('CHECK2:DUT ping Fail.', 'ErrOR')
        result = False
    ###############################################################
    #                STEP6: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia api server ping DUT interface address 11.1.1.2')
    res_1 = send_ping(session, '11.1.1.1', '11.1.1.2')
    logger_msg(res_1)
    logger_msg(u'Ixia api server ping DUT interface address 11.1.2.2')
    res_2 = send_ping(session, '11.1.2.1', '11.1.2.2')
    logger_msg(res_2)
    logger_msg(u'Ixia api server ping DUT interface address 11.1.3.2')
    res_3 = send_ping(session, '11.1.3.1', '11.1.3.2')
    logger_msg(res_3)
    logger_msg(u'Ixia api server ping DUT interface address 2001:0:0:1::2')
    res_4 = send_ping(session, '2001:0:0:1::1', '2001:0:0:1::2')
    logger_msg(res_4)
    logger_msg(u'Ixia api server ping DUT interface address 2001:0:0:2::2')
    res_5 = send_ping(session, '2001:0:0:2::1', '2001:0:0:2::2')
    logger_msg(res_5)
    logger_msg(u'Ixia api server ping DUT interface address 2001:0:0:3::2')
    res_6 = send_ping(session, '2001:0:0:3::1', '2001:0:0:3::2')
    logger_msg(res_6)
    if res_1['arg2'] is True & res_2['arg2'] is True \
            & res_3['arg2'] is True & res_4['arg2'] is True \
            & res_5['arg2'] is True & res_6['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')
    else:
        logger_msg('Check3: Ixia ping DUT Fail', 'ERROR')
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
        result = False

    ##############################################################
    #               STEP7: Clear configuration
    ##############################################################
    logger_msg(u'Clear configuration')

    duthost.shell("sudo config interface ip remove {} 11.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 11.1.3.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 11.1.2.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2001:0:0:2::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2001:0:0:3::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2001:0:0:1::2/64".format(intf['dut1port1']))
    time.sleep(5)

    ##############################################################
    # STEP8: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'test_ipv4_ipv6_with_l3_interface failed')
