import tempfile
import os
import subprocess

import misc
import var
from context import context
from pwintools import Process as process

class dbg(object):
    @classmethod
    def attach(clx,target,script=None,sysroot=None):
        """
            use context.debugger or gdbType to decide use which debugger
                default is mingw-gdb
        """
        use_gdb=0
        use_windbg=0
        use_x64dbg=0
        if context.debugger=='x64dbg' or gdbType=='x64dbg':
            use_x64dbg=1
        elif context.debugger=='windbg' or gdbType=='windbg':
            use_windbg=1
        else:
            use_gdb=1
        if use_gdb:
            gdb.attach(target=target,script=script,gdbType='gdb',sysroot=sysroot)
        elif use_windbg:
            windbg.attach(target=target,script=script,gdbType='windbg')
        elif use_x64dbg:
            x64dbg.attach(target=target,script=script,gdbType='x64dbg')
        else:
            return None

    @classmethod
    def debug(clx,target,script=None,sysroot=None):
        pass

class gdb():
    @classmethod
    def attach(clx,target,script=None,sysroot=None):
        """
            use context.arch or gdbType to decide mingw-gdb64 or mingw-gdb to be used
        """
        # clx.gdbType=gdbType        # mingw-gdb or windbg, mingw-gdb in default
        clx.gdbType=var.debugger[context.arch]['gdb']
        load_Dbg=None        # how to attach to process and init debugger
        if isinstance(target,process):
            load_Dbg=clx.gdbType+' -p'+' {}'.format(target.pid)+' -q'
        elif isinstance(target,int):
            load_Dbg=clx.gdbType+' -p'+' {}'.format(target)+' -q'
        # if script and not script.endswith('\n'):
        #     # script+='\n'
        #     pass
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

        pre=setInfo(sysroot)
        script=pre+(script or '')
        tmp = tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        if script:    # write script to a tmp file
            tmp.write(script)
            tmp.flush()
            load_Dbg+=' -ix {}'.format(tmp.name)
        # load_Dbg+=' -ex {}'.format('"shell rm {}"'.format(tmp.name))
        load_Dbg+=' -ex {}'.format('"shell del {}"'.format(tmp.name))
        tmp.close()
        cmd=[load_Dbg]
        ter=misc.run_in_new_terminal(cmd)
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            pass
        var.ter=ter
        return var.ter.pid
    @classmethod
    def debug():
        pass

class windbg():
    @classmethod
    def attach(clx,target,script=None,gdbType=None):
        load_windbg=[var.debugger[context.arch]['windbg'],'-p']
        if isinstance(target,process):
            load_windbg.append(str(target.pid))
        elif isinstance(target,int):
            load_windbg.append(str(pid))
        # load_windbg+=['-a','pykd']  # laad ext
        load_windbg+=['-c']             # exec command
        tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        # cmd='!py -g winext\TWindbg\TWindbg.py\n'
        cmd=""
        if script:
            cmd=script+'\n'+cmd                       # how to delete the files
        tmp.write(cmd)
        tmp.flush()
        tmp.close()
        load_windbg+=['$<{}'.format(tmp.name)]
        #load_windbg.append(cmd)
        ter=subprocess.Popen(load_windbg)
        var.ter=ter
        print(misc.parse.color("\n[=]: Waiting for debugger","purple"))
        misc.wait_for_debugger()
        os.remove(tmp.name)
        return var.ter.pid

    @classmethod
    def debug(clx,target,script=None,gdbType=None):
        pass

class x64dbg():
    @classmethod
    def attach(clx,target,script=None,gdbType=None):
        clx.gdbType=gdbType        # mingw-gdb or windbg, mingw-gdb in default
        if clx.gdbType is None:
            if context.arch=='amd64':
                clx.gdbType='x64dbg.exe'      # have been place into $PATH
            else:
                clx.gdbType='x32dbg.exe'
        load_x64dbg=[clx.gdbType,'-p']
        if isinstance(target,process):
            load_x64dbg.append(str(target.pid))
        elif isinstance(target,int):
            load_x64dbg.append(str(pid))
        ter=subprocess.Popen(load_x64dbg)
        var.ter=ter
        misc.wait_for_debugger()
        return var.ter.pid                

    @classmethod
    def debug(clx,target,script=None,gdbType=None):
        pass