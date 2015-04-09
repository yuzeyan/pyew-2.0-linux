#!/usr/bin/env python

import sys
import re
import requests
from requests_toolbelt import multipart
import urllib2
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
# reload(sys)
# sys.setdefaultencoding('utf-8')


def todoList(pyew, doprint=True):
    """ Show todo list [by SwordLea]"""
    print '1. Add plugin "IPs/chkIP(phishing, malicious)/whois"'
    print '2. Add plugin "strings"'
    print '3. Fix plugin "chkbad"'
    print '4. Fix plugin "vs_upload"'


def upload2(pyew, doprint=True):
    """ upload file to virscan.org"""
    print sys.getdefaultencoding()
    register_openers()
    url = r'http://up.virscan.org/up.php'


    datagen, headers = multipart_encode({"upfile": open(pyew.filename, "rb"),
        'UPLOAD_IDENTIFIER' : 'KEYbc7cf6642fc84bf67747f1bbdce597f0',
        'langkey' : '1',
        'setcookie' : '0',
        'tempvar' : '',
        'fpath' : 'C:\\fakepath\\'+pyew.filename
        })


    request = urllib2.Request(url, datagen, headers)
    request.add_header('Host', 'up.virscan.org')
    request.add_header('Cache-Control', 'max-age=0')
    request.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.104 Safari/537.36')
    request.add_header('Host', 'up.virscan.org')
    request.add_header('Accept-Encoding', 'gzip, deflate')
    request.add_header('Accept-Language', 'zh-CN,zh;q=0.8,en;q=0.6')

    resp = urllib2.urlopen(request).read()
    if re.findall("innerHTML='(.*?) file upload", resp):
        print "Upload File Failed"
    else:
        print "Upload Success"
        #print resp


def upload1(pyew, doprint=True):
    """ requests upload file to virscan.org """
    s = requests.session()
    url = r'http://up.virscan.org/up.php'
    fpath = 'C:\\fakepath\\' + pyew.filename
    e = multipart.encoder.MultipartEncoder(
        {'UPLOAD_IDENTIFIER': 'KEY3e9cb5ba03485fe5270b9e7b4e218d35',
         'langkey': '1',
         'setcookie': '0',
         'tempvar': '',
         'upfile': (pyew.filename, open(pyew.filename, 'rb'), 'application/x-msdownload'),
         'fpath': fpath,
         }
    )

    headers = {'Host': 'up.virscan.org',
               'Connection': 'keep-alive',
               'Content-Length': '3807',
               'Cache-Control': 'max-age=0',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'Origin': 'http://www.virscan.org',
               'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.104 Safari/537.36',
               'Content-Type': 'multipart/form-data; ',
               'Referer': 'http://www.virscan.org/',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language': 'zh-CN,zh;q=0.8,en;q=0.6'
               }
    s.headers.update(headers)
    ct = {'Content-Type': e.content_type}
    s.headers.update(ct)
    try:
        r = s.post(url, data=e)
    # retxt = r.text.encode('utf-8')
    except Exception, e:
        print "Error occurred:", e
    print r.status_code
    if r.status_code == 200:
        if re.findall("innerHTML='(.*?) file upload", r.text):
            print "Upload File Failed"
        else:
            print "Upload Success"
    else:
        print "Connection error"


def bufprint(pyew, doprint=True):
    pyew.offset = 0
    pyew.seek(0)
    buf = pyew.buf + pyew.f.read()
    word = re.findall(r"([a-zA-Z0-9_@'\-./:\" ]+)", buf, re.S)
    a = [i for i in word if len(i) > 3]
    for x in a:
        print "%04X    %s" % (buf.index(x), x.lstrip())


functions = {"todo": todoList, "vs_upload1": upload1, "vs_upload2": upload2, "prbuf": bufprint}
