# -*- coding=Latin1 -*-
import tempfile
import os
import sys
import subprocess

from .context import context
from .winpwn import process
import misc

class gdb():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        print(misc.color('[+]: attaching'))
        if context.gdb is None:
            gdbPath=debugger[context.arch]['gdb']
        else:
            gdbPath=context.gdb
        
        load_Dbg=gdbPath+' -p'+' {}'.format(target.pid)+' -q'
        def setInfo(sysroot=None):
            Info=''
            if context.arch=='amd64':
                Info+='set architecture i386:x86-64\n'
            else:
                Info+='set architecture i386\n'
            if context.endian:
                Info+='set endian {}\n'.format(context.endian)
            if sysroot:
                Info+='set sysroot {}\n'.format(sysroot)
            return Info

        pre = context.dbginit+'\n'+setInfo(sysroot)+debugger_init[context.arch]['gdb']
        pre_tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        pre_tmp.write(misc.Latin1_encode(pre))
        pre_tmp.flush()
        pre_tmp.close()

        script=(script+'\n' or '')
        script_tmp = tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        script_tmp.write(misc.Latin1_encode(script))
        script_tmp.flush()
        script_tmp.close()
        
        load_Dbg+=' -ix "{}"'.format(pre_tmp.name)
        load_Dbg+=' -ex source -command {}'.format(script_tmp.name)
        load_Dbg+=' -ex {}'.format('"shell del {}"'.format(script_tmp.name))
        load_Dbg+=' -ex {}'.format('"shell del {}"'.format(pre_tmp.name))
        cmd=[load_Dbg]
        ter=misc.run_in_new_terminal(cmd)
        while(os.path.exists(pre_tmp.name)):    # wait_for_debugger
            pass
        target.debugger=ter
        # misc.mark('attached')
        return ter.pid
    @classmethod
    def debug():
        pass

class windbg():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        
        print(misc.color('[+]: attaching'))
        if context.windbg is None:
            windbgPath=debugger[context.arch]['windbg']
        else:
            windbgPath=context.windbg
        load_windbg=[windbgPath,'-p']
        # if isinstance(target,process):
        #     load_windbg.append(str(target.pid))
        # elif isinstance(target,int):
        #     load_windbg.append(str(pid))
        load_windbg.append(str(target.pid))

        script=context.dbginit+'\n'+debugger_init[context.arch]['windbg']+'\n'+script+'\n'
        tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        tmp.write(misc.Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg+=['$$><{}'.format(tmp.name)+';.shell -x del {}'.format(tmp.name)]
        # print('script:',script)
        # print('load:',load_windbg)
        ter=subprocess.Popen(load_windbg)
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            pass
        target.debugger=ter
        # misc.mark('attached')
        return ter.pid

    @classmethod
    def com(clx,com,script="",baudrate=115200):
        print(misc.color('[+]: attaching'))
        if context.windbg is None:
            windbgPath=debugger[context.arch]['windbg']
        else:
            windbgPath=context.windbg
        load_windbg=[windbgPath]
        load_windbg+=["-k com:pipe,port={},baud={},reconnect".format(com,baudrate)]

        script=context.dbginit+'\n'+debugger_init[context.arch]['windbg']+'\n'+script+'\n'
        tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        tmp.write(misc.Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg+=['"$$><{}'.format(tmp.name)+';.shell -x del {}"'.format(tmp.name)]
        # ter=subprocess.Popen(misc.Latin1_encode(' '.join(load_windbg)))
        ter=subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            misc.sleep(0.05)
            # pass
        # target.debugger=ter
        # misc.mark('attached')
        return ter.pid
    @classmethod
    def net(clx):
        pass

class windbgx():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        print(misc.color('[+]: attaching'))
        if context.windbgx is None:
            windbgxPath=debugger[context.arch]['windbgx']
        else:
            windbgxPath=context.windbgx
        load_windbg=[windbgxPath,'-p']

        # if isinstance(target,process):
        #     load_windbg.append(str(target.pid))
        # elif isinstance(target,int):
        #     load_windbg.append(str(pid))
        load_windbg.append(str(target.pid))
        script=context.dbginit+'\n'+debugger_init[context.arch]['windbgx']+'\n'+script+'\n'

        tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        tmp.write(misc.Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg+=['"$$><{}'.format(tmp.name)+';.shell -x del {}"'.format(tmp.name)]
        # print('script:',script)
        # print('load:',load_windbg)
        ter=subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            pass
        target.debugger=ter
        # misc.mark('attached')
        return ter.pid

    @classmethod
    def com(clx,com,script="",baudrate=115200):
        print(misc.color('[+]: attaching'))
        if context.windbgx is None:
            windbgxPath=debugger[context.arch]['windbgx']
        else:
            windbgxPath=context.windbgx
        load_windbg=[windbgxPath]
        load_windbg+=["-k com:pipe,port={},baud={},reconnect".format(com,baudrate)]

        script=context.dbginit+'\n'+debugger_init[context.arch]['windbgx']+'\n'+script+'\n'
        tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        tmp.write(misc.Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg+=['"$$><{}'.format(tmp.name)+';.shell -x del {}"'.format(tmp.name)]
        # ter=subprocess.Popen(misc.Latin1_encode(' '.join(load_windbg)))
        ter=subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            misc.sleep(0.05)
            # pass
        # target.debugger=ter
        # misc.mark('attached')
        return ter.pid
    @classmethod
    def net(clx):
        pass

class x64dbg():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        if context.x64dbg is None:
            x64dbgPath=debugger[context.arch]['x64dbg']
        else:
            x64dbgPath=context.x64dbg
        load_x64dbg=[x64dbgPath,'-p']
        # if isinstance(target,process):
        #     load_x64dbg.append(str(target.pid))
        # elif isinstance(target,int):
        #     load_x64dbg.append(str(pid))
        load_x64dbg.append(str(target.pid))
        ter=subprocess.Popen(load_x64dbg)
        target.debugger=ter
        print(misc.color("[=]: pausing\n\twaiting for debugger",'purple'))
        sys.stdin.readline()
        return ter.pid         

    @classmethod
    def debug(clx,target,script="",sysroot=None):
        pass


# -*- coding=Latin1 -*-


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

def init_debugger():
    import json
    winpwn_init=os.path.expanduser("~\\.winpwn")
    if os.path.exists(winpwn_init):
        fd=open(winpwn_init,'r')
        js=misc.Latin1_encode(''.join(fd.readlines()))
        x=json.loads(js)
        dbg=x['debugger']
        dbg_init=x['debugger_init']
        fd.close()
        debugger.update(dbg)
        debugger_init.update(dbg_init)
