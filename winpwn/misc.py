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
    # print(argv,command)
    if isinstance(command,str):
        argv+=[command]          # [terminal,args,command]
    elif isinstance(command,(list,tuple)):
        argv+=list(command)
    ter=subprocess.Popen(argv)
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
    """p64(i) -> str
    Pack 64 bits integer (little endian)
    """
    l=struct.pack('<Q', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u64(s):
    """u64(s) -> int
    Unpack 64 bits integer from a little endian str representation
    """
    return struct.unpack('<Q', Latin1_encode(s))[0]

def p32(i):
    """p32(i) -> str
    Pack 32 bits integer (little endian)
    """
    l=struct.pack('<I', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u32(s):
    """u32(s) -> int
    Unpack 32 bits integer from a little endian str representation
    """
    return struct.unpack('<I', Latin1_encode(s))[0]
    
def p16(i):
    """p16(i) -> str
    Pack 16 bits integer (little endian)
    """
    l=struct.pack('<H', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u16(s):
    """u16(s) -> int
    Unpack 16 bits integer from a little endian str representation
    """
    return struct.unpack('<H', Latin1_encode(s))[0]

def p8(i):
    """p16(i) -> str
    Pack 16 bits integer (little endian)
    """
    l=struct.pack('<B', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l

def u8(s):
    """u16(s) -> int
    Unpack 16 bits integer from a little endian str representation
    """
    return struct.unpack('<B', Latin1_encode(s))[0]


def Latin1_encode(string):
    # deal input
    if sys.version_info[0]==3:
        # print(sys.getdefaultencoding())
        return bytes(string,"Latin1")
    return bytes(string)
def Latin1_decode(string):
    if sys.version_info[0]==3:
        return str(string,'Latin1')
    return string #.decode('Latin1')



class parse():
    @classmethod
    def color(clx,content,color='purple'):
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
    
    @classmethod
    def hexdump(clx,src,length=16,all=True):
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
                    pchar=clx.color('|','red')+pchar
                hex+=chex
                printable+=pchar
            # lines.append("%04x  %-*s  %s\n" % (c, length*3, hex.ljust(52,' '), printable))
            lines.append('\033[0;{}m{:04x}\033[0m  {}  {}\n'.format(35,c,clx.color(hex.ljust(52,' '),'yellow'),printable))
        if not all:
            if len(lines)>=0x20:
                lines=lines[0:8]+['......\n']+lines[-8:]
        print(''.join(lines).strip())

    @classmethod
    def mark(clx,type):
        line="\n[+]: {}"
        if type=='recv':
            line=line.format('Recving')
            print(clx.color(line,'blue'))
            return
        elif type=='send':
            line=line.format('Sending')
            print(clx.color(line,'cyan'))
            return
        elif type=='attach':
            line=line.format('attaching')
            print(clx.color(line,'green'))
            return
        elif type=='interact':
            line=line.format('Interacting')
            print(clx.color(line,'green'))
            return       
        line="\n[-]: {}"
        if type=='recved':
            line=line.format('^Recved')
            print(clx.color(line,'blue'))
            return            
        elif type=='sended':
            line=line.format('^Sended')
            print(clx.color(line,'cyan'))
            return
        elif type=='attached':
            line=line.format('^attached')
            print(clx.color(line,'green'))
            return
    # @classmethod
    # def log(clx,con='',color='yellow'):
    #     line="\n[+]: log\n"
    #     line+=clx.color(line,'purple')+clx.color(con,color)
    #     print(line)
    @classmethod
    def log(clx,*args):
        print(clx.color("[+]: log",'purple'))
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
        print(clx.color(line1,'yellow'))
        print(clx.color('[-]: logged','purple'))