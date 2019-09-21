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

def waiting_for_debugger():
    raw_input(parse.color("[=]: pausing\n\twaiting for debugger",'purple'))

def pause():
    raw_input(parse.color("[=]: pausing",'purple'))

def sleep(n):
    time.sleep(n)

def p64(i):
    """p64(i) -> str
    Pack 64 bits integer (little endian)
    """
    return struct.pack('<Q', i)

def u64(s):
    """u64(s) -> int
    Unpack 64 bits integer from a little endian str representation
    """
    return struct.unpack('<Q', s)[0]

def p32(i):
    """p32(i) -> str
    Pack 32 bits integer (little endian)
    """
    return struct.pack('<I', i)

def u32(s):
    """u32(s) -> int
    Unpack 32 bits integer from a little endian str representation
    """
    return struct.unpack('<I', s)[0]
    
def p16(i):
    """p16(i) -> str
    Pack 16 bits integer (little endian)
    """
    return struct.pack('<H', i)

def u16(s):
    """u16(s) -> int
    Unpack 16 bits integer from a little endian str representation
    """
    return struct.unpack('<H', s)[0]

def Latin1_encode(string):
    # deal input
    if sys.version_info[0]==3:
        # print(sys.getdefaultencoding())
        return bytes(string,sys.getdefaultencoding())
    return bytes(string)
def Latin1_decode(string):
    if sys.version_info[0]==3:
        return str(string,'Latin1')
    return string.decode('Latin1')

class parse():
    @classmethod
    def color(clx,content,color):
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
        return ''.join(lines).strip()

    @classmethod
    def mark(clx,type):
        line="\n[+]: {}"
        if type=='recv':
            line=line.format('Recving')
            return clx.color(line,'blue')
        elif type=='send':
            line=line.format('Sending')
            return clx.color(line,'cyan')
        elif type=='interact':
            line=line.format('Interacting')
            return clx.color(line,'green')
        line="\n[-]: {}"
        if type=='recved':
            line=line.format('^Recved')
            return clx.color(line,'blue')            
        elif type=='sended':
            line=line.format('^Sended')
            return clx.color(line,'cyan')