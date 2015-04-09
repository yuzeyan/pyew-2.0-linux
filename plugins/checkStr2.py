import re
import pdb
searchChar = '([A-Za-z])'
startChar = '[\w<_\.<]'
searchIP = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
searchEmail = '([\w+]@.+\..+)'




def showString(output,m):
    if len(output) <= 4:
        output = ''
        m = -1
        return
    if len(output) <= 16:
        if '@' in output:
            fetch = re.search(searchEmail,output)
            if fetch is None:
                output = ''
                m = -1
                return
        fetch = re.search(searchChar,output)
        if fetch is None:
            #print output
            fetch = re.search(searchIP,output)
            if fetch is None:
                output = ''
                m = -1
                return
        #Filtering consecutive multiple characters
        count = 0
        b = False 
        weiyiArray=[]
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


def checkString(pyew,doprint=True):
    """ Search strings in the current document """
    pyew.offset = 0
    pyew.seek(0)
    buf = pyew.buf + pyew.f.read()
    print len(buf)
    bufSize = len(buf)
    size = 0
    m = -1
    output = ''
    for i in range(0,len(buf)):
        size += 1
        if len(repr(buf[i])) == 3:
            fetch_starChar = re.search(startChar,buf[i])
            if fetch_starChar is None:
                if m == -1:
                    output = ''
                    continue
            #pdb.set_trace()
            if m == -1:
                m = i
            if '$' in buf[i]:
                output = ''
                m = -1
                continue
            output += buf[i]
            if size == bufSize:
                showString(output,m)
        else:                            
            showString(output,m)
            output = ''
            m = -1

              
functions = {"chkStr2":checkString}        

