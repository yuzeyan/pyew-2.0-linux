#!/usr/bin/python
#coding:utf-8

import re
import hashlib
import requests

class CScanResult:
    scanned_time = ''
    scanned_result = ''
    file_name = ''
    report_url = ''
    reportList = []

class CVirScanScanner:
    printResults = False
    filename = None
    baseUrl = "http://md5.virscan.org/"
    findReport = re.compile('http://r.virscan.org/.*')
    md5 = None

    def getScanResult(self, report):
        key1 = 'var virinfo="'
        key2 = '";'
        pos1 = report.find(key1)
        if -1 != pos1:
            pos2 = report.find(key2, pos1)
            if -1 != pos2:
                buffer = report[pos1+len(key1):pos2-len(key2)]
                buffer = buffer.replace('\\r\\n', '\n')
                buffer = buffer.replace('\\r', '\n')
                report_flag = False
                scanResult = CScanResult()
                for line in buffer.split('\n'):
                    if 'Scanned time   :' in line:
                        scanResult.scanned_time = line.split(' : ')[1]
                    if 'Scanner results:' in line:
                        scanResult.scanned_result = line.split(': ')[1]
                    if 'File Name      :' in line:
                        scanResult.file_name = line.split(' : ')[1]
                    if 'Online report  :' in line:
                        scanResult.report_url = line.split(' : ')[1]
                    if 'Scanner        Engine Ver      Sig Ver           Sig Date    Time   Scan result' in line:
                        report_flag = True
                        continue
                    if report_flag :
                        itemList = line.split(' ')
                        print itemList
                        while len(itemList) > 7:
                            itemList.remove('')
                        scanResult.reportList.append( [itemList[0], itemList[1], itemList[3], itemList[5]] )
                return scanResult
        return None

    def getReportList(self, argmd5):
        reportList = []
        r = requests.get( self.baseUrl + argmd5 + ".html")
        if r.status_code:
            data = r.content
            key1 = '<dt>Scan Result</dt>'
            pos = data.find(key1)
            if -1 != pos:
                buffer = data[pos + len(key1):]
                resultList = re.findall(self.findReport , buffer)
                for reportUrl in set(resultList) :
                    reportUrl = reportUrl.strip('>')
                    reportUrl = reportUrl.strip('"')
                    r = requests.get( reportUrl )
                    if r.status_code:
                        reportList.append(r.content)
        return reportList

    def scan(self, filename, argmd5 = None):
        strmd5 = ''
        if argmd5:
            strmd5 = argmd5
        else:
            strmd5 = md5.md5(file(filename, "rb").read()).hexdigest()

        scanResultList = []
        for report in self.getReportList(strmd5):
            scanResult = self.getScanResult(report)
            scanResultList.append(scanResult )
        
        if self.printResults :
            for result in scanResultList:
                print result.scanned_time 
                print result.scanned_result 
                print result.file_name 
                print result.report_url 
                for item in result.reportList:
                    print item 

        self.filename = filename
        self.md5 = strmd5

        return 

def virScanSearch(pyew):
    """ Search the sample in VirScan """

    buf = pyew.getBuffer()
    x = hashlib.md5(buf).hexdigest()
    
    scanner = CVirScanScanner()
    scanner.printResults = True
    scanner.scan(pyew.filename, argmd5=x)

functions={"vs":virScanSearch}

