# -*- coding=Latin1 -*-
# import os
import subprocess
import struct
import time
import sys
import os

from .context import context

def run_in_new_terminal(command, terminal = None, args = None):
    """
    Run a new command in a new terminal.

    Args:
        command: (list): write your description
        terminal: (todo): write your description
    """
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
    """
    Generate a file.

    Args:
        fpath: (str): write your description
    """
    import pefile
    pe_fp=pefile.PE(fpath)
    pe_fp.OPTIONAL_HEADER.DllCharacteristics &= \
        ~pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
    pe_fp.OPTIONAL_HEADER.CheckSum = pe_fp.generate_checksum()
    pe_fp.write(fpath)
def PIE(fpath=""):
    """
    Writes the pIE file to disk.

    Args:
        fpath: (str): write your description
    """
    import pefile
    pe_fp=pefile.PE(fpath)
    pe_fp.OPTIONAL_HEADER.DllCharacteristics |= \
        pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"]
    pe_fp.OPTIONAL_HEADER.CheckSum = pe_fp.generate_checksum()
    pe_fp.write(fpath)

def pause(string=None):
    """
    Pause a string.

    Args:
        string: (str): write your description
    """
    print(color("\n[=]: pausing",'purple'))
    if string is not None:
        print(color(string,'purple'))
    sys.stdin.readline()
def sleep(n):
    """
    Sleep a number of the given n times.

    Args:
        n: (todo): write your description
    """
    time.sleep(n)

def p64(i):
    """
    Input : meth : bytes

    Args:
        i: (int): write your description
    """
    l=struct.pack('<Q', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l
def u64(s):
    """
    Encode a byte string into a byte string.

    Args:
        s: (int): write your description
    """
    return struct.unpack('<Q', Latin1_encode(s))[0]
def p32(i):
    """
    P32 a 32 bit integer.

    Args:
        i: (int): write your description
    """
    l=struct.pack('<I', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l
def u32(s):
    """
    Convert a 32 - bit integer.

    Args:
        s: (int): write your description
    """
    return struct.unpack('<I', Latin1_encode(s))[0]
def p16(i):
    """
    Convert a 16 - bit integer

    Args:
        i: (int): write your description
    """
    l=struct.pack('<H', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l
def u16(s):
    """
    Convert a string representation of bytes

    Args:
        s: (int): write your description
    """
    return struct.unpack('<H', Latin1_encode(s))[0]
def p8(i):
    """
    Input : i / }

    Args:
        i: (int): write your description
    """
    l=struct.pack('<B', i)
    if sys.version_info[0]==3:
        return Latin1_decode(l)
    return l
def u8(s):
    """
    Unpack a byte string into a byte string.

    Args:
        s: (int): write your description
    """
    return struct.unpack('<B', Latin1_encode(s))[0]

def Latin1_encode(string):
    """
    Encode a string.

    Args:
        string: (str): write your description
    """
    if sys.version_info[0]==3:
        return bytes(string,"Latin1")
    return bytes(string)
def Latin1_decode(string):
    """
    Decode a string.

    Args:
        string: (str): write your description
    """
    if sys.version_info[0]==3:
        return str(string,'Latin1')
    return string

def color(content,color='purple'):
    """
    Colorize a string with the given color.

    Args:
        content: (str): write your description
        color: (str): write your description
    """
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
    """
    Pretty print hexadecimal string.

    Args:
        src: (todo): write your description
        length: (int): write your description
        all: (todo): write your description
    """
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
def showbanner(markstr,colorstr='green',typestr='[+]',is_noout=None):
    """
    Prints a string to stdout.

    Args:
        markstr: (str): write your description
        colorstr: (str): write your description
        typestr: (str): write your description
        is_noout: (bool): write your description
    """
    if is_noout is None:
        is_noout=context.noout
    if not is_noout:
        print(color('\n'+typestr+': '+markstr,colorstr))
def showbuf(buf,is_noout=None):
    """
    Prints a buffer to stdout of the output.

    Args:
        buf: (str): write your description
        is_noout: (bool): write your description
    """
    if is_noout is None:
        is_noout=context.noout
    if not is_noout:
        if context.log_level=='debug':
            hexdump(buf)
        if buf.endswith(context.newline):
            os.write(sys.stdout.fileno(), Latin1_encode(buf))
        else:
            os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))