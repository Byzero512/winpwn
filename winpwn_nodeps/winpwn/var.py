import os
import json

from misc import Latin1_encode

ter=None             # obj create by subProcess.Popen
debugger={
    'i386':{
        'windbg':'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\windbg.exe',
        'x64dbg':'F:\\ctfTools\debugTools\\x64debug\\release\\x32\\x32dbg.exe',
        'gdb':'F:\\ctfTools\\windows-gdb\\mingw-w64-686\\mingw32\\bin\\gdb.exe',
    },
    'amd64':{
        'windbg':'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe',
        'x64dbg':'F:\\ctfTools\debugTools\\x64debug\\release\\x64\\x64dbg.exe',
        'gdb':'F:\\ctfTools\\windows-gdb\\mingw-w64-64\\mingw64\\bin\\gdb64.exe',
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

    