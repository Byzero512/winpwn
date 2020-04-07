# -*- coding=Latin1 -*-
import os
import sys

cwd = os.path.dirname(__file__)
sys.path=[cwd]+sys.path[1:]

from .winpwn import process,remote
from .dbg import dbg,gdb,windbg,x64dbg,kernel
from .context import context
from .misc import p8,p16,p32,p64,u8,u16,u32,u64,parse,pause,sleep,NOPIE,PIE
from .asm import asm,disasm
from .winfile import winfile

from var import init_var
init_var()

hexdump=parse.hexdump
color=parse.color
log=parse.log

__all__=[
    'process','remote','dbg','gdb','windbg','x64dbg','kernel',
    'context',
    'p8','p16','p32','p64','u8','u16','u32','u64',
    'pause','sleep','hexdump','color','log',"NOPIE","PIE",
    "asm","disasm",
    "winfile"
]

# winpwn  dbg  misc
# |
# |
# win    context