#!/usr/bin/python
#coding:utf-8

import re
import hashlib
import requests

class CScannerInfo:
    scanner = ''
    version = ''
    update  = ''
    result  = ''

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
    scanResultList = []

    def getScanResult(self, report):
        scanResult = CScanResult()

        key1 = 'var virinfo="'
        key2 = '";'
        pos1 = report.find(key1)
        if -1 != pos1:
            pos2 = report.find(key2, pos1)
            if -1 != pos2:
                buffer = report[pos1+len(key1):pos2-len(key2)]
                buffer = buffer.replace('\\r\\n', '\n')
                buffer = buffer.replace('\\r', '\n')
                for line in buffer.split('\n'):
                    if 'Scanned time   :' in line:
                        scanResult.scanned_time = line.split(' : ')[1]
                    if 'Scanner results:' in line:
                        scanResult.scanned_result = line.split(': ')[1]
                    if 'File Name      :' in line:
                        scanResult.file_name = line.split(' : ')[1]
                    if 'Online report  :' in line:
                        scanResult.report_url = line.split(' : ')[1]
                        break

        matches = re.findall(
            "\<td\>(.*)\<\/td\>\s*" + 
            "\<td\>(.*)\<\/td\>\s*" + 
            "\<td\>(.*)\<\/td\>\s*" + 
            "\<td\>(.*)\<\/td\>\s*" + 
            "\<td\>(.*)\<\/td\>\s*" , 
            report, re.MULTILINE or re.IGNORECASE)
        scanResult.reportList = []
        for item in matches :
            r = CScanResult()
            r.scanner = item[0]
            r.version = item[1]
            r.update = item[3]
            r.result = item[4]
            r.result = r.result.split('>')[2]
            r.result = r.result.split('<')[0]
            scanResult.reportList.append(r)
        return scanResult

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

        self.scanResultList = []
        for report in self.getReportList(strmd5):
            scanResult = self.getScanResult(report)
            self.scanResultList.append(scanResult )
        
        self.filename = filename
        self.md5 = strmd5

        if self.printResults :
            self.printSummary()

        return 

    def printSummary(self):
        msg = "File %s with MD5 %s" % (self.filename, self.md5)
        splitLine = "-" * len(msg)
        print msg
        print splitLine 
        print

        for result in self.scanResultList:
            print 'Scanned time   :' , result.scanned_time 
            print 'Scanner results:' , result.scanned_result 
            print 'File Name      :' , result.file_name 
            print 'Online report  :' , result.report_url 
            for r in result.reportList:
                if r.result  :
                    print r.scanner.rjust(25) + ": " + r.result  
            print splitLine 

def virScanSearch(pyew):
    """ Search the sample in VirScan [by SwordLea]"""

    buf = pyew.getBuffer()
    x = hashlib.md5(buf).hexdigest()
    
    scanner = CVirScanScanner()
    scanner.printResults = True
    scanner.scan(pyew.filename, argmd5=x)

def virScanUpload(pyew):
    """ Upload the sample to VirScan [by SwordLea]"""

    keyUrl = "http://virscan.org/"
    filename = pyew.filename
    if filename :
        #r = requests.get( keyUrl )
        #if r.status_code:
        #    data = r.content
        #    upkey = re.findall('\<input id="upkey" name="UPLOAD_IDENTIFIER" value="(.*)" type="hidden"\>', data)

        upUrl = "http://up.virscan.org/up.php"
        payload = dict(langkey = '1', setcookie = '0', fpath=filename , tempvar = "")
        #payload = dict(UPLOAD_IDENTIFIER = upkey, langkey = '1', setcookie = '0', fpath=filename , tempvar = "")
        files = {'file': (filename, open(filename , 'rb'), 'application/upload')}
        r = requests.post( upUrl , data = payload, files = files )
        if r.status_code:
            print r.headers
            print r.text

functions={"vs":virScanSearch,"vs_upload":virScanUpload}
