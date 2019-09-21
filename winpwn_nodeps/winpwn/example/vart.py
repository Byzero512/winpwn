import os
import json
import sys
debugger={
    'i386':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
    },
    'amd64':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
    }
}


def init_var():
    winpwn_init=os.environ['HOME']+'\\.winpwn'
    if os.path.exists(winpwn_init):
        fd=open(winpwn_init,'r')
        js=Latin1_encode(''.join(fd.readlines()))
        dict1=json.loads(js)['debugger']
        fd.close()
        debugger.update(dict1)