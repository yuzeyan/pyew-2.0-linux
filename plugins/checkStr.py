# -*- coding: cp936 -*-
import re
import pdb
import os, sys, socket, struct, select, time
searchChar = '([A-Za-z0-9])'
startChar = '[\w<_\.<]'
searchIP = '([0-255]{1,3}\.[0-255]{1,3}\.[0-255]{1,3}\.[0-255]{1,3})'
searchEmail = '([\w+]@.+\..+)'

# m = -1


def checkString(pyew, doprint=True):
    """ Search strings in the current document """
    m = -1
    pyew.offset = 0
    pyew.seek(0)
    buf = pyew.buf + pyew.f.read()
    print len(buf)
    # buf=file('f:\\test\\md5.exe','rb').read()
    output = ''
    for i in range(0, len(buf)):
        if len(repr(buf[i])) == 3:
            fetch_starChar = re.search(startChar, buf[i])
            if fetch_starChar is None:
                # print buf[i]
                if m == -1:
                    output = ''
                    continue
            # pdb.set_trace()
            if m == -1:
                m = i
            if '$' in buf[i]:
                output = ''
                m = -1
                continue
            output += buf[i]
        else:
            if len(output) <= 4:
                output = ''
                m = -1
                continue
            if len(output) <= 16:
                if '@' in output:
                    fetch = re.search(searchEmail, output)
                    if fetch is None:
                        output = ''
                        m = -1
                        continue
                fetch = re.search(searchChar, output)
                if fetch is None:
                    fetch = re.search(searchIP, output)
                    if fetch is None:
                        output = ''
                        m = -1
                        continue
                    # Filtering consecutive multiple characters
                count = 0
                b = False
                weiyiArray = []
                for i in output:
                    if i not in weiyiArray:
                        weiyiArray.append(i)
                for s in weiyiArray:
                    for val in output:
                        if val == s:
                            count += 1
                            if count >= 5:
                                b = True
                                break
                        else:
                            count = 0
                    if b:
                        output = ''
                        m = -1
                        break
                    count = 0
                else:
                    print '%04X    %s' % (m, output)
                    output = ''
                    m = -1
                weiyiArray[:] = []
            else:
                print '%04X    %s' % (m, output)
                output = ''
                m = -1




def ipExtract(pyew, doprint= True):
    moffset = pyew.offset
    FILTER=''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    pyew.seek(0)
    buf = pyew.buf + pyew.f.read()
    buf = buf.translate(FILTER)
    a=re.findall(r'(\d+\.\d+\.\d+\.\d+)', buf)
    return a

def print_ip(pyew,doprint= True):
    pyew.seek (0)
    buf =pyew.buf + pyew.f.read()
    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', buf)
    for ip in ips:
        print  "position :%04x IP : %s\n"%(ips.index(ip),ip)

def ping_ip(pyew,doprint = True):
    ips = ipExtract(pyew,doprint = False)
    for ip in ips:
        verbose_ping(ip,2,1)


def checksum(source_string):
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count < countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
  
    if countTo < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
  
    sum = (sum >> 16)  +  (sum & 0xffff)
    

    answer = ~sum

    answer = answer & 0xffff
  
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
  
    return answer
  
  
def receive_one_ping(my_socket, ID, timeout):
    """
    receive the ping from the socket.
    """
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return
  
        timeReceived = time.time()
        recPacket, addr = my_socket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
	if packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent
  
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return
  
  
def send_one_ping(my_socket, dest_addr, ID):
    """
    Send one ping to the given >dest_addr<.
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0
  
    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)  #压包
    #a1 = struct.unpack("bbHHh",header)    #my test
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", time.time()) + data
  
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)
  
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1
  
  
def do_one(dest_addr, timeout):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error
  
    my_ID = os.getpid() & 0xFFFF
  
    send_one_ping(my_socket, dest_addr, my_ID)
    delay = receive_one_ping(my_socket, my_ID, timeout)
  
    my_socket.close()
    return delay
  
  
def verbose_ping(dest_addr, timeout = 2, count = 100):
    """
    Send >count< ping to >dest_addr< with the given >timeout< and display
    the result.
    """
    for i in range(count):
        print "ping %s..." % dest_addr,
        try:
            delay  =  do_one(dest_addr, timeout)
        except socket.gaierror, e:
            print "failed. (socket error: '%s')" % e[1]
            break
 
        if delay  ==  None:
            print "failed. (timeout within %ssec.)" % timeout
        else:
            delay  =  delay * 1000
            print "get ping in %0.4fms" % delay


functions = {"chkStr": checkString, "printip": print_ip, "ping":ping_ip}

