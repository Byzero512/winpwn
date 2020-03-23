import os
import json
import sys
# debugger={
#     'i386':{
#         'windbg':'',
#         'x64dbg':'',
#         'gdb':'',
#     },
#     'amd64':{
#         'windbg':'',
#         'x64dbg':'',
#         'gdb':'',
#     }
# }
debugger ={"debugger_init":{
    "i386": {
        "x64dbg": "",
        "gdb": "",
        "windbg": ""
    },
    "amd64": {
        "x64dbg": "",
        "gdb": "",
        "windbg": ".load pykd;!py -g winext\\TWindbg\\TWindbg.py;"
    }
}
}
print(json.dumps(debugger))
def init_var():
    winpwn_init=os.environ['HOME']+'\\.winpwn'
    if os.path.exists(winpwn_init):
        fd=open(winpwn_init,'r')
        js=Latin1_encode(''.join(fd.readlines()))
        dict1=json.loads(js)['debugger']
        fd.close()
        debugger.update(dict1)
