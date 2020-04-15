# -*- coding=Latin1 -*-
# import os
import subprocess
import struct
import time
import sys

from context import context

def run_in_new_terminal(command, terminal = None, args = None):
    if terminal is None:
        if (context.terminal):
            terminal=context.terminal
        else:
            terminal=['ConEmu.exe','-Reuse','-run']
    if isinstance(args, tuple):    # args associety with tmminal not process
        args = list(args)
    if args is not None:
        argv=terminal+args
    else:
        argv=terminal
    if isinstance(command,str):
        argv+=[command]          # [terminal,args,command]
    elif isinstance(command,(list,tuple)):
        argv+=list(command)
    ter=subprocess.Popen(' '.join(argv))
    return ter

def NOPIE(fpath=""):
    import pefile
    pe_fp=pefile.PE(fpath)
    pe_fp.OPTIONAL_HEADER.DllCharacteristics &= \
        ~pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
    pe_fp.OPTIONAL_HEADER.CheckSum = pe_fp.generate_checksum()
    pe_fp.write(fpath)
def PIE(fpath=""):
    import pefile
    pe_fp=pefile.PE(fpath)
    pe_fp.OPTIONAL_HEADER.DllCharacteristics |= \
        pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
    pe_fp.OPTIONAL_HEADER.CheckSum = pe_fp.generate_checksum()
    pe_fp.write(fpath)

def pause():
    print(parse.color("\n[=]: pausing",'purple'))
    sys.stdin.readline()

def sleep(n):
    time.sleep(n)

def p64(i):
    l=struct.pack('<Q', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u64(s):
    return struct.unpack('<Q', Latin1_encode(s))[0]

def p32(i):
    l=struct.pack('<I', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u32(s):
    return struct.unpack('<I', Latin1_encode(s))[0]
    
def p16(i):
    l=struct.pack('<H', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u16(s):
    return struct.unpack('<H', Latin1_encode(s))[0]

def p8(i):
    l=struct.pack('<B', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u8(s):
    return struct.unpack('<B', Latin1_encode(s))[0]


def Latin1_encode(string):
    if sys.version_info[0]==3:
        return bytes(string,"Latin1")
    return bytes(string)
def Latin1_decode(string):
    if sys.version_info[0]==3:
        return str(string,'Latin1')
    return string

def color(content,color='purple'):
    if context.nocolor:
        return content
    c = {
        "black": 30,
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "purple": 35,
        "cyan": 36,
        "white": 37,
    }
    return "\033[0;{}m{}\033[0m".format(c.get(color), content)

def hexdump(src,length=16,all=True):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hex=''
        printable=''
        for i in range(len(chars)):
            chex="%02x " % ord(chars[i])
            pchar=("%s" % ((ord(chars[i]) <= 127 and FILTER[ord(chars[i])]) or '.'))
            if (i%4)==0:
                chex=' '+chex
                pchar=color('|','red')+pchar
            hex+=chex
            printable+=pchar
        lines.append(color(
            "{:04x}".format(c)) +
            "  {}  {}\n".format(color(hex.ljust(52,' '),'yellow'),printable)
        )
    if not all:
        if len(lines)>=0x20:
            lines=lines[0:8]+['......\n']+lines[-8:]
    print(''.join(lines).strip())

def log(*args):
    print(color("[+]: log",'purple'))
    line1=''
    j=0
    for i in args:
        if j!=0 and j%2==0:
            line1+='\n'
        if isinstance(i,int):
            line1+=hex(i).strip('L')+'\t'
        elif isinstance(i,str):
            line1+=i+'\t'
        elif isinstance(i,long):
            line1+=hex(i).strip('L')+'\t'
        j+=1
    print(color(line1,'yellow'))
    print(color('[-]: logged','purple'))