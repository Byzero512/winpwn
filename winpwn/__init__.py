# -*- coding=Latin1 -*-
import os
import sys

cwd = os.path.dirname(__file__)
sys.path=[cwd]+sys.path[1:]

from .winpwn import process,remote
from .dbg import gdb,windbg,x64dbg,windbgx
from .context import context
from .misc import p8,p16,p32,p64,u8,u16,u32,u64,parse,pause,sleep,NOPIE,PIE,Latin1_encode,Latin1_decode
from .asm import asm,disasm
from .winfile import winfile

from var import init_var
init_var()

hexdump=parse.hexdump
color=parse.color
log=parse.log
tostr=Latin1_decode
tobyte=Latin1_encode

__all__=[
    'process','remote','gdb','windbg','x64dbg','windbgx',
    'context',
    'p8','p16','p32','p64','u8','u16','u32','u64',
    'pause','sleep','hexdump','color','log',"NOPIE","PIE",
    "tostr",'tobyte',
    "asm","disasm",
    "winfile"
]

# winpwn  dbg  misc
# |
# |
# win    context