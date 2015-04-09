#!/usr/bin/env python
# guess hiding strings with 'mov byte' mode.
def guessString(pyew, doprint=True):
    """ Guess some strings [by SwordLea]"""
    if pyew.pe is None:
        return
    buf = pyew.getBuffer()
    length = pyew.bsize
    offset = pyew.offset 
    if pyew.maxsize - offset < length:
        length = pyew.maxsize - offset 
    if buf is None:
        return
    disLines = pyew.disassemble(buf[offset:offset + length], baseoffset=offset).split('\n')
    key = 'MOV BYTE '
    output = ''
    address = ''
    for line in disLines :
        pos = line.find(key)
        if pos != -1:
            if not address :
                address = line.split(' ')[0]
            tmp = line[pos:]
            tmp = tmp.split(',')
            if len(tmp) == 2 and '0x' in tmp[1]:
                c = int(tmp[1],16)
                output += chr(c)
        else:
            if address :
                print address, output 
                address = ''
                output  = ''
    return

functions = {"guess": guessString}
