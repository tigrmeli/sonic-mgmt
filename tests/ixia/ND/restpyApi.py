"""
This module contains the necessary fixtures for running test cases with
Ixia devices and IxNetwork. If more fixtures are required, they should be
included in this file.
"""

import sys
from os.path import dirname, abspath
import site

# Add necessary paths
site.addsitedir(dirname(abspath(__file__)) + "/lib")
sys.path.insert(0, "/var/AzDevOps/sonic-mgmt/tests/ixia/ND/restpy_library")

# Now, import the modules
from IxNetRestApi import Connect  # noqa: E402
from IxNetRestApiPortMgmt import PortMgmt  # noqa: E402
from IxNetRestApiTraffic import Traffic  # noqa: E402
from IxNetRestApiProtocol import Protocol  # noqa: E402
from IxNetRestApiStatistics import Statistics  # noqa: E402


class restpyAPI:
    def __init__(self, serverIp, osPlatform="linux"):
        if osPlatform == "linux":
            self.mainObj = Connect(
                apiServerIp=serverIp,
                username="admin",
                password="wrinkle!B12345",
                deleteSessionAfterTest=True,
                verifySslCert=False,
                serverOs=osPlatform,
                generateLogFile="ixiaDebuglog.log",
            )

        # For windows: serverIpPort=11009
        # For windowsConnectionMgr, must state the following params: httpsSecured=<bool>. serverIpPort=443
        if osPlatform in ["windows", "windowsConnectionMgr"]:
            self.mainObj = Connect(
                apiServerIp=serverIp,
                serverOs=osPlatform,
                # serverIpPort=11040,
                httpsSecured=True,
                deleteSessionAfterTest=True,
                generateLogFile="ixiaDebuglog.log",
            )
        self.portObj = PortMgmt(self.mainObj)
        self.trafficObj = Traffic(self.mainObj)
        self.protocolObj = Protocol(self.mainObj)
        self.statsObj = Statistics(self.mainObj)

    def close_session(self):
        Connect.deleteSession(self.mainObj)
