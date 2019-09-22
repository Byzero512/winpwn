import tempfile
import os
import subprocess

from .context import context
from .winpwn import process
import misc
import var


class dbg(object):
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        """
            use context.debugger or gdbType to decide use which debugger
                default is mingw-gdb
        """
        if context.debugger=='x64dbg':# or gdbType=='x64dbg':
            x64dbg.attach(target=target,script=script,sysroot=sysroot)
            
        elif context.debugger=='windbg':# or gdbType=='windbg':
            windbg.attach(target=target,script=script,sysroot=sysroot)
        else:
            gdb.attach(target=target,script=script,sysroot=sysroot)
            return None

    @classmethod
    def debug(clx,target,script="",sysroot=None):
        pass

class gdb():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        """
            use context.arch or gdbType to decide mingw-gdb64 or mingw-gdb to be used
        """
        print(misc.parse.mark('attach'))
        # gdbType=gdbType        # mingw-gdb or windbg, mingw-gdb in default
        gdbType=var.debugger[context.arch]['gdb']
        load_Dbg=None        # how to attach to process and init debugger
        if isinstance(target,process):
            load_Dbg=gdbType+' -p'+' {}'.format(target.pid)+' -q'
        elif isinstance(target,int):
            load_Dbg=gdbType+' -p'+' {}'.format(target)+' -q'
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

        pre = setInfo(sysroot)+var.debugger_init[context.arch]['gdb']
        pre_tmp=tempfile.NamedTemporaryFile(prefix = 'winpwn_', suffix = '.dbg',delete=False)
        pre_tmp.write(misc.Latin1_encode(pre))
        pre_tmp.flush()
        pre_tmp.close()

        script=(script or '')
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
        var.ter=ter
        print(misc.parse.mark('attached'))
        return var.ter.pid
    @classmethod
    def debug():
        pass

class windbg():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        print(misc.parse.mark('attach'))
        load_windbg=[var.debugger[context.arch]['windbg'],'-p']
        if isinstance(target,process):
            load_windbg.append(str(target.pid))
        elif isinstance(target,int):
            load_windbg.append(str(pid))
        # load_windbg+=['-a','pykd']  # laad ext
        # script+='\n!py -g winext\TWindbg\TWindbg.py\n'
        script=var.debugger_init[context.arch]['windbg']+'\n'+script
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
        var.ter=ter
        print(misc.parse.mark('attached'))
        return var.ter.pid

    @classmethod
    def debug(clx,target,script="",sysroot=None):
        pass

class x64dbg():
    @classmethod
    def attach(clx,target,script="",sysroot=None):
        load_x64dbg=[var.debugger[context.arch]['x64dbg'],'-p']
        if isinstance(target,process):
            load_x64dbg.append(str(target.pid))
        elif isinstance(target,int):
            load_x64dbg.append(str(pid))
        ter=subprocess.Popen(load_x64dbg)
        var.ter=ter
        raw_input(misc.parse.color("[=]: pausing\n\twaiting for debugger",'purple'))
        return var.ter.pid                

    @classmethod
    def debug(clx,target,script="",sysroot=None):
        pass
