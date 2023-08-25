import re
import time
from IxNetRestApi import IxNetRestApiException
from IxNetRestApiFileMgmt import FileMgmt


class Statistics(object):
    def __init__(self, ixnObj=None):
        self.ixnObj = ixnObj

        # For takesnapshot()
        self.fileMgmtObj = FileMgmt(self.ixnObj)

    def setMainObject(self, mainObject):
        """
        Description
            For Python Robot Framework support.
        """
        self.ixnObj = mainObject

    def getStats(self, viewObject=None, viewName='Flow Statistics', csvFile=None, csvEnableFileTimestamp=False,
                 displayStats=True, silentMode=True, ignoreError=False):
        """
        Description
           Get stats for any viewName.
           The method calls two different methods based on the IxNetwork version that you are using.
           For IxNetwork version prior to 8.50, calls getStatsPage.
           For IxNetwork version >= 8.50, calls getStatsData. This has new APIs that is more robust and they don't
           work in versions prior to 8.50.

        Parameters
            csvFile = None or <filename.csv>.
                      None will not create a CSV file.
                      Provide a <filename>.csv to record all stats to a CSV file.
                      Example: getStats(sessionUrl, csvFile='Flow_Statistics.csv')

            csvEnableFileTimestamp = True or False. If True, timestamp will be appended to the filename.
            displayStats: True or False. True=Display stats.
            ignoreError: True or False.  Returns None if viewName is not found.
            viewObject: The view object: http://{apiServerIp:port}/api/v1/sessions/2/ixnetwork/statistics/view/13
                        A view object handle could be obtained by calling getViewObject().

            viewName options (Not case sensitive):
               NOTE: Not all statistics are listed here.
                  You could get the statistic viewName directly from the IxNetwork GUI in the statistics.
        """
        buildNumber = float(self.ixnObj.getIxNetworkVersion()[:3])
        if buildNumber >= 8.5:
            return self.getStatsData(
                viewObject=viewObject,
                viewName=viewName,
                csvFile=csvFile,
                csvEnableFileTimestamp=csvEnableFileTimestamp,
                displayStats=displayStats,
                silentMode=silentMode,
                ignoreError=ignoreError
            )
        else:
            return self.getStatsPage(
                viewObject=viewObject,
                viewName=viewName,
                csvFile=csvFile,
                csvEnableFileTimestamp=csvEnableFileTimestamp,
                displayStats=displayStats,
                silentMode=silentMode,
                ignoreError=ignoreError
            )

    def getStatsPage(self, viewObject=None, viewName='Flow Statistics', csvFile=None, csvEnableFileTimestamp=False,
                     displayStats=True, silentMode=True, ignoreError=False):
        """
        Description
            Get stats by the statistic name or get stats by providing a view object handle.
            This method uses deprecated APIs effective IxNetwork version 8.50: /statistics/statView/<id>/page
            Starting 8.50, the new API to use is: /statistics/statView/<id>/data, which is in getStatsData()

        Parameters
            csvFile = None or <filename.csv>.
                      None will not create a CSV file.
                      Provide a <filename>.csv to record all stats to a CSV file.
                      Example: getStats(sessionUrl, csvFile='Flow_Statistics.csv')

            csvEnableFileTimestamp = True or False. If True, timestamp will be appended to the filename.

            displayStats: True or False. True=Display stats.

            ignoreError: True or False.  Returns None if viewName is not found.

            viewObject: The view object: http://{apiServerIp:port}/api/v1/sessions/2/ixnetwork/statistics/view/13
                        A view object handle could be obtained by calling getViewObject().

            viewName options (Not case sensitive):
               NOTE: Not all statistics are listed here.
                  You could get the statistic viewName directly from the IxNetwork GUI in the statistics.

            'Port Statistics'
            'Tx-Rx Frame Rate Statistics'
            'Port CPU Statistics'
            'Global Protocol Statistics'
            'Protocols Summary'
            'Port Summary'
            'BGP Peer Per Port'
            'OSPFv2-RTR Drill Down'
            'OSPFv2-RTR Per Port'
            'IPv4 Drill Down'
            'L2-L3 Test Summary Statistics'
            'Flow Statistics'
            'Traffic Item Statistics'
            'IGMP Host Drill Down'
            'IGMP Host Per Port'
            'IPv6 Drill Down'
            'MLD Host Drill Down'
            'MLD Host Per Port'
            'PIMv6 IF Drill Down'
            'PIMv6 IF Per Port'
            'Flow View'

         Note: Not all of the viewNames are listed here. You have to get the exact names from
               the IxNetwork GUI in statistics based on your protocol(s).

         Return a dictionary of all the stats: statDict[rowNumber][columnName] == statValue
           Get stats on row 2 for 'Tx Frames' = statDict[2]['Tx Frames']
        """
        if viewObject is None:
            breakFlag = 0
            counterStop = 30
            for counter in range(1, counterStop+1):
                viewList = self.ixnObj.get(
                    '%s/%s/%s' % (self.ixnObj.sessionUrl, 'statistics', 'view'), silentMode=silentMode
                )
                views = [
                    '%s/%s/%s/%s' %
                    (self.ixnObj.sessionUrl, 'statistics', 'view', str(i['id'])) for i in viewList.json()
                ]
                if silentMode is False:
                    self.ixnObj.logInfo('\ngetStats: Searching for viewObj for viewName: %s' % viewName)

                for view in views:
                    # GetAttribute
                    response = self.ixnObj.get('%s' % view, silentMode=silentMode)
                    captionMatch = re.match(viewName, response.json()['caption'], re.I)
                    if captionMatch:
                        # viewObj: sessionUrl + /statistics/view/11'
                        viewObject = view
                        breakFlag = 1
                        break

                if breakFlag == 1:
                    break

                if counter < counterStop:
                    self.ixnObj.logInfo('\nGetting statview [{0}] is not ready. Waiting {1}/{2} seconds.'.format(
                        viewName, counter, counterStop), timestamp=False)
                    time.sleep(1)
                    continue

                if counter == counterStop:
                    if viewObject is None and ignoreError is False:
                        raise IxNetRestApiException("viewObj wasn't found for viewName: {0}".format(viewName))

                    if viewObject is None and ignoreError is True:
                        return None

        if silentMode is False:
            self.ixnObj.logInfo('\n[{0}] viewObj is: {1}'.format(viewName, viewObject))

        for counter in range(0, 31):
            response = self.ixnObj.get(viewObject+'/page', silentMode=silentMode)
            totalPages = response.json()['totalPages']
            if totalPages == 'null':
                self.ixnObj.logInfo('\nGetting total pages is not ready yet. Waiting %d/30 seconds' % counter)
                time.sleep(1)

            if totalPages != 'null':
                break

            if counter == 30:
                raise IxNetRestApiException('getStatsPage failed: Getting total pages')

        if csvFile is not None:
            import csv
            csvFileName = csvFile.replace(' ', '_')
            if csvEnableFileTimestamp:
                import datetime
                timestamp = datetime.datetime.now().strftime('%H%M%S')
                if '.' in csvFileName:
                    csvFileNameTemp = csvFileName.split('.')[0]
                    csvFileNameExtension = csvFileName.split('.')[1]
                    csvFileName = csvFileNameTemp+'_'+timestamp+'.'+csvFileNameExtension
                else:
                    csvFileName = csvFileName+'_'+timestamp

            csvFile = open(csvFileName, 'w')
            csvWriteObj = csv.writer(csvFile)

        # Get the stat column names
        columnList = response.json()['columnCaptions']
        if csvFile is not None:
            csvWriteObj.writerow(columnList)

        flowNumber = 1
        statDict = {}
        # Get the stat values
        for pageNumber in range(1, totalPages+1):
            self.ixnObj.patch(viewObject+'/page', data={'currentPage': pageNumber}, silentMode=silentMode)

            response = self.ixnObj.get(viewObject+'/page', silentMode=silentMode)
            statValueList = response.json()['pageValues']

            for statValue in statValueList:
                if csvFile is not None:
                    csvWriteObj.writerow(statValue[0])

                if displayStats:
                    self.ixnObj.logInfo('\nRow: %d' % flowNumber, timestamp=False)

                statDict[flowNumber] = {}
                index = 0
                for statValue in statValue[0]:
                    statName = columnList[index]
                    statDict[flowNumber].update({statName: statValue})
                    if displayStats:
                        self.ixnObj.logInfo('\t%s: %s' % (statName, statValue), timestamp=False)
                    index += 1
                flowNumber += 1

        if csvFile is not None:
            csvFile.close()
        return statDict

    def getStatsData(self, viewObject=None, viewName='Flow Statistics', csvFile=None, csvEnableFileTimestamp=False,
                     displayStats=True, silentMode=False, ignoreError=False):
        """
        Description
            For IxNetwork version >= 8.50.
            Get stats by the statistic name or get stats by providing a view object handle.
            This method get stats using /api/v1/sessions/{id}/ixnetwork/statistics/view/{id}/data to get
            attributes columnCaptions, pageValues and totalPages. This method uses new API starting in
            version 8.50.

        Parameters
            csvFile = None or <filename.csv>.
                      None will not create a CSV file.
                      Provide a <filename>.csv to record all stats to a CSV file.
                      Example: getStats(sessionUrl, csvFile='Flow_Statistics.csv')

            csvEnableFileTimestamp = True or False. If True, timestamp will be appended to the filename.
            displayStats: True or False. True=Display stats.
            ignoreError: True or False.  Returns None if viewName is not found.
            viewObject: The view object: http://{apiServerIp:port}/api/v1/sessions/2/ixnetwork/statistics/view/13
                        A view object handle could be obtained by calling getViewObject().

            viewName options (Not case sensitive):
               NOTE: Not all statistics are listed here.
                  You could get the statistic viewName directly from the IxNetwork GUI in the statistics.

            'Port Statistics'
            'Tx-Rx Frame Rate Statistics'
            'Port CPU Statistics'
            'Global Protocol Statistics'
            'Protocols Summary'
            'Port Summary'
            'BGP Peer Per Port'
            'OSPFv2-RTR Drill Down'
            'OSPFv2-RTR Per Port'
            'IPv4 Drill Down'
            'L2-L3 Test Summary Statistics'
            'Flow Statistics'
            'Traffic Item Statistics'
            'IGMP Host Drill Down'
            'IGMP Host Per Port'
            'IPv6 Drill Down'
            'MLD Host Drill Down'
            'MLD Host Per Port'
            'PIMv6 IF Drill Down'
            'PIMv6 IF Per Port'
            'Flow View'

         Note: Not all of the viewNames are listed here. You have to get the exact names from
               the IxNetwork GUI in statistics based on your protocol(s).

         Return a dictionary of all the stats: statDict[rowNumber][columnName] == statValue
           Get stats on row 2 for 'Tx Frames' = statDict[2]['Tx Frames']
        """
        if viewObject is None:

            breakFlag = 0
            counterStop = 30
            for counter in range(1, counterStop+1):
                viewList = self.ixnObj.get(
                    '%s/%s/%s' % (self.ixnObj.sessionUrl, 'statistics', 'view'), silentMode=silentMode
                )
                views = [
                    '%s/%s/%s/%s' %
                    (self.ixnObj.sessionUrl, 'statistics', 'view', str(i['id'])) for i in viewList.json()
                ]
                if silentMode is False:
                    self.ixnObj.logInfo('\ngetStats: Searching for viewObj for viewName: {0}'.format(
                        viewName), timestamp=False)

                for view in views:
                    # print('\nview:', view)
                    response = self.ixnObj.get('%s' % view, silentMode=True)
                    captionMatch = re.match(viewName, response.json()['caption'], re.I)
                    if captionMatch:
                        # viewObj: sessionUrl + /statistics/view/11'
                        viewObject = view
                        breakFlag = 1
                        break

                if breakFlag == 1:
                    break

                if counter < counterStop:
                    self.ixnObj.logInfo('\nGetting statview [{0}] is not ready. Waiting {1}/{2} seconds.'.format(
                        viewName, counter, counterStop), timestamp=False)
                    time.sleep(1)
                    continue

                if counter == counterStop:
                    if viewObject is None and ignoreError is False:
                        raise IxNetRestApiException("viewObj wasn't found for viewName: {0}".format(viewName))

                    if viewObject is None and ignoreError is True:
                        return None

        if silentMode is False:
            self.ixnObj.logInfo('\n[{0}] viewObj is: {1}'.format(viewName, viewObject))

        counterStop = 30
        for counter in range(0, counterStop+1):
            response = self.ixnObj.get(viewObject+'/data', silentMode=silentMode)
            totalPages = response.json()['totalPages']
            # self.ixnObj.logInfo('totalPages: {0}'.format(totalPages), timestamp=False)

            if totalPages == 'null' and counter < counterStop:
                self.ixnObj.logInfo('\nGetting total pages is not ready yet. Waiting {0}/{1} seconds'.format(
                    counter, counterStop), timestamp=False)
                time.sleep(1)
                continue

            if totalPages != 'null' and counter < counterStop:
                break

            if counter == counterStop:
                raise IxNetRestApiException('getStats failed: Getting total pages')

        if csvFile is not None:
            import csv
            csvFileName = csvFile.replace(' ', '_')
            if csvEnableFileTimestamp:
                import datetime
                timestamp = datetime.datetime.now().strftime('%H%M%S')
                if '.' in csvFileName:
                    csvFileNameTemp = csvFileName.split('.')[0]
                    csvFileNameExtension = csvFileName.split('.')[1]
                    csvFileName = csvFileNameTemp+'_'+timestamp+'.'+csvFileNameExtension
                else:
                    csvFileName = csvFileName+'_'+timestamp

            csvFile = open(csvFileName, 'w')
            csvWriteObj = csv.writer(csvFile)

        flowNumber = 1
        statDict = {}
        getColumnCaptionFlag = 0
        for pageNumber in range(1, totalPages+1):
            self.ixnObj.patch(viewObject+'/data', data={'currentPage': pageNumber}, silentMode=silentMode)

            counterStop = 30
            for counter in range(1, counterStop+1):
                response = self.ixnObj.get(viewObject+'/data', silentMode=silentMode)
                if counter < counterStop:
                    if response.json()['columnCaptions'] == [] or response.json()['pageValues'] == []:
                        self.ixnObj.logInfo('[{0}] stat values not ready yet. Wait {1}/{2} seconds.'.format(
                            viewName, counter, counterStop))
                        time.sleep(1)
                        continue

                    if response.json()['columnCaptions'] != [] or response.json()['pageValues'] != []:
                        break

                if counter == counterStop:
                    raise IxNetRestApiException('IxNetwork API server failed to provide stats')

            # Get the stat column names one time only
            if getColumnCaptionFlag == 0:
                getColumnCaptionFlag = 1
                columnList = response.json()['columnCaptions']
                if csvFile is not None:
                    csvWriteObj.writerow(columnList)

            statValueList = response.json()['pageValues']
            for statValue in statValueList:
                if csvFile is not None:
                    csvWriteObj.writerow(statValue[0])

                if displayStats:
                    self.ixnObj.logInfo('\nRow: %d' % flowNumber, timestamp=False)

                statDict[flowNumber] = {}
                index = 0
                for statValue in statValue[0]:
                    statName = columnList[index]
                    statDict[flowNumber].update({statName: statValue})
                    if displayStats:
                        self.ixnObj.logInfo('\t%s: %s' % (statName, statValue), timestamp=False)
                    index += 1
                flowNumber += 1

        if csvFile is not None:
            csvFile.close()
        return statDict

    def removeAllTclViews(self):
        """
        Description
           Removes all created stat views.
        """
        removeAllTclViewsUrl = self.ixnObj.sessionUrl+'/operations/removealltclviews'
        response = self.ixnObj.post(removeAllTclViewsUrl)
        self.ixnObj.waitForComplete(response, self.ixnObj.httpHeader + response.json()['url'])

    def takeSnapshot(self, viewName='Flow Statistics', windowsPath=None, isLinux=False, localLinuxPath=None,
                     renameDestinationFile=None, includeTimestamp=False, mode='overwrite'):
        """
        Description
            Take a snapshot of the vieweName statistics.  This is a two step process.
            1> Take a snapshot of the statistics that you want and store it in the C: drive for Windows.
               For Linux, the snapshot goes to /home/ixia_logs.
            2> Copy the statistics from the snapshot locations to the local Linux where you ran the script..

        Parameters
            viewName: The name of the statistics to get.
            windowsPath: For Windows|WindowsConnectionMgr only.
                         The C: drive + path to store the snapshot: Example: c:\\Results.
            isLinux: <bool>: Defaults to False.  Set to True if you're getting the snapshot from Linux chassis.
            localLinuxPath: None|path. Provide the local Linux path to put the snapshot file.
                            If None, this API won't copy the stat file to local Linux.
                            The stat file will remain on Windows c: drive.
            renameDestinationFile: None or a name of the file other than the viewName.
            includeTimestamp: True|False: To include a timestamp at the end of the file.
            mode: append|overwrite: append=To append stats to an existing stat file.
                                    overwrite=Don't append stats. Create a new stat file.

        Example:
            For Windows:
               statObj.takeSnapshot(
                    viewName='Flow Statistics', windowsPath='C:\\Results', localLinuxPath='/home/hgee',
                    renameDestinationFile='my_renamed_stat_file.csv', includeTimestamp=True)

            For Linux:
               statObj.takeSnapshot(viewName='Flow Statistics', isLinux=True, localLinuxPath='/home/hgee')
        """
        if mode == 'append':
            mode = 'kAppendCSVFile'

        if mode == 'overwrite':
            mode = 'kOverwriteCSVFile'

        if windowsPath:
            location = windowsPath

        if isLinux:
            location = '/home/ixia_logs'

        data = {'arg1': [viewName], 'arg2': [
                            "Snapshot.View.Contents: \"allPages\"",
                            "Snapshot.View.Csv.Location: \"{0}\"".format(location),
                            "Snapshot.View.Csv.GeneratingMode: \"%s\"" % mode,
                            "Snapshot.View.Csv.StringQuotes: \"True\"",
                            "Snapshot.View.Csv.SupportsCSVSorting: \"False\"",
                            "Snapshot.View.Csv.FormatTimestamp: \"True\"",
                            "Snapshot.View.Csv.DumpTxPortLabelMap: \"False\"",
                            "Snapshot.View.Csv.DecimalPrecision: \"3\""
                            ]
                }

        url = self.ixnObj.sessionUrl+'/operations/takeviewcsvsnapshot'
        response = self.ixnObj.post(url, data=data)
        self.ixnObj.waitForComplete(response, self.ixnObj.httpHeader + response.json()['url'])
        if isLinux:
            snapshotFile = location + '/' + viewName + '.csv'
            self.fileMgmtObj.copyFileLinuxToLocalLinux(
                linuxApiServerPathAndFileName=snapshotFile, localPath=localLinuxPath,
                renameDestinationFile=renameDestinationFile,
                includeTimestamp=includeTimestamp
            )

        if windowsPath and localLinuxPath:
            # Get the snapshot. Use the csvFilename that was specified and the location
            self.fileMgmtObj.copyFileWindowsToLocalLinux('{0}\\{1}.csv'.format(windowsPath, viewName), localLinuxPath,
                                                         renameDestinationFile=renameDestinationFile,
                                                         includeTimestamp=includeTimestamp)

    def getViewObject(self, viewName='Flow Statistics'):
        """
        Description
            To get just the statistic view object.
            Mainly used by internal APIs such as takeCsvSnapshot that
            requires the statistics view object handle.

        Parameter
         viewName:  Options (case sensitive):
            "Port Statistics"
            "Tx-Rx Frame Rate Statistics"
            "Port CPU Statistics"
            "Global Protocol Statistics"
            "Protocols Summary"
            "Port Summary"
            "OSPFv2-RTR Drill Down"
            "OSPFv2-RTR Per Port"
            "IPv4 Drill Down"
            "L2-L3 Test Summary Statistics"
            "Flow Statistics"
            "Traffic Item Statistics"
        """
        self.ixnObj.logInfo('\ngetStats: %s' % viewName)
        viewList = self.ixnObj.get("%s/%s/%s" % (self.ixnObj.sessionUrl, "statistics", "view"))
        views = [
            "%s/%s/%s/%s" % (self.ixnObj.sessionUrl, "statistics", "view", str(i["id"])) for i in viewList.json()
            ]
        for view in views:
            # GetAttribute
            response = self.ixnObj.get(view)
            caption = response.json()["caption"]
            if viewName == caption:
                # viewObj: sessionUrl + "/statistics/view/11"
                viewObj = view
                return viewObj
        return None

    def clearStats(self):
        """
        Description
            Clear all stats and wait for API server to finish.
        """
        url = self.ixnObj.sessionUrl + '/operations/clearstats'
        response = self.ixnObj.post(url, data={'arg1': ['waitForPortStatsRefresh']})
        self.ixnObj.waitForComplete(response, self.ixnObj.httpHeader + response.json()['url'])
