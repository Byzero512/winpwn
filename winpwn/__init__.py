# -*- coding=Latin1 -*-
import os
import sys

cwd = os.path.dirname(__file__)
sys.path=[cwd]+sys.path[1:]

from .winpwn import process,remote
from .dbg import gdb,windbg,x64dbg,windbgx,init_debugger
from .context import context
from .misc import p8,p16,p32,p64,u8,u16,u32,u64,pause,sleep,NOPIE,PIE,Latin1_encode,Latin1_decode,color,hexdump,log
from .asm import asm,disasm
from .winfile import winfile

init_debugger()

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