# -*- coding=Latin1 -*-
import os
import json

from misc import Latin1_encode
from misc import parse
ter=None             # obj create by subProcess.Popen
debugger={
    'i386':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    },
    'amd64':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    }
}

debugger_init={
    'i386':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    },
    'amd64':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    }
}

def init_var():
    winpwn_init=os.path.expanduser("~\\.winpwn") #+'\\.winpwn'
    if os.path.exists(winpwn_init):
        fd=open(winpwn_init,'r')
        js=Latin1_encode(''.join(fd.readlines()))
        x=json.loads(js)
        dbg=x['debugger']
        dbg_init=x['debugger_init']
        fd.close()
        debugger.update(dbg)
        debugger_init.update(dbg_init)
