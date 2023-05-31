# -*- coding=Latin1 -*-
import tempfile
import os
import sys
import subprocess

from .context import context
from .winpwn import process
from .misc import showbanner, Latin1_encode, sleep, run_in_new_terminal, pause


class gdb():
    @classmethod
    def attach(clx, target, script="", sysroot=None):
        showbanner('attaching', 'purple', '[=]')
        if context.gdb is None:
            gdbPath = debugger[context.arch]['gdb']
        else:
            gdbPath = context.gdb

        load_Dbg = gdbPath
        if isinstance(target, int):
            load_Dbg += ' -p'+' {}'.format(target)+' -q'
        else:
            load_Dbg += ' -p'+' {}'.format(target.pid)+' -q'

        def setInfo(sysroot=None):
            Info = ''
            if context.arch == 'amd64':
                Info += 'set architecture i386:x86-64\n'
            else:
                Info += 'set architecture i386\n'
            if context.endian:
                Info += 'set endian {}\n'.format(context.endian)
            if sysroot:
                Info += 'set sysroot {}\n'.format(sysroot)
            return Info

        pre = context.dbginit+'\n' + \
            setInfo(sysroot)+debugger_init[context.arch]['gdb']
        pre_tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        pre_tmp.write(Latin1_encode(pre))
        pre_tmp.flush()
        pre_tmp.close()

        script = (script+'\n' or '')
        script_tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        script_tmp.write(Latin1_encode(script))
        script_tmp.flush()
        script_tmp.close()

        load_Dbg += ' -ix "{}"'.format(pre_tmp.name)
        load_Dbg += ' -ex source -command {}'.format(script_tmp.name)
        load_Dbg += ' -ex {}'.format('"shell del {}"'.format(script_tmp.name))
        load_Dbg += ' -ex {}'.format('"shell del {}"'.format(pre_tmp.name))
        cmd = [load_Dbg]
        ter = run_in_new_terminal(cmd)
        while(os.path.exists(pre_tmp.name)):    # wait_for_debugger
            pass
        target.debugger = ter
        return ter.pid

    @classmethod
    def debug():
        pass


class windbg():
    @classmethod
    def attach(clx, target, script="", sysroot=None):

        showbanner('attaching', 'purple', '[=]')
        if context.windbg is None:
            windbgPath = debugger[context.arch]['windbg']
        else:
            windbgPath = context.windbg
        load_windbg = [windbgPath, '-p']

        if isinstance(target, int):
            load_windbg.append(target)
        else:
            load_windbg.append(str(target.pid))

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbg']+'\n'+script+'\n'
        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['$$><{}'.format(tmp.name) +
                        ';.shell -x del {}'.format(tmp.name)]
        # print('script:',script)
        # print('load:',load_windbg)
        ter = subprocess.Popen(load_windbg)
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            pass
        target.debugger = ter
        return ter.pid

    @classmethod
    def com(clx, com, script="", baudrate=115200):
        showbanner('attaching', 'purple', '[=]')
        if context.windbg is None:
            windbgPath = debugger[context.arch]['windbg']
        else:
            windbgPath = context.windbg
        load_windbg = [windbgPath]
        load_windbg += [
            "-k com:pipe,port={},baud={},reconnect".format(com, baudrate)]

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbg']+'\n'+script+'\n'
        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['"$$><{}'.format(tmp.name) +
                        ';.shell -x del {}"'.format(tmp.name)]
        # ter=subprocess.Popen(Latin1_encode(' '.join(load_windbg)))
        ter = subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            sleep(0.05)
            # pass
        # target.debugger=ter
        # mark('attached')
        return ter.pid

    @classmethod
    def net(clx):
        pass


class windbgx():
    @classmethod
    def attach(clx, target, script="", sysroot=None):
        showbanner('attaching', 'purple', '[=]')
        if context.windbgx is None:
            windbgxPath = debugger[context.arch]['windbgx']
        else:
            windbgxPath = context.windbgx
        load_windbg = [windbgxPath, '-p']

        if isinstance(target, int):
            load_windbg.append(target)
        else:
            load_windbg.append(str(target.pid))

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbgx']+'\n'+script+'\n'

        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['"$$><{}'.format(tmp.name) +
                        ';.shell -x del {}"'.format(tmp.name)]
        # print('script:',script)
        # print('load:',load_windbg)
        ter = subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            pass
        target.debugger = ter
        # mark('attached')
        return ter.pid

    @classmethod
    def remote(clx, target, script=""):
        showbanner('attaching', 'purple', '[=]')
        if context.windbgx is None:
            windbgxPath = debugger[context.arch]['windbgx']
        else:
            windbgxPath = context.windbgx

        IP = ''
        port = 1025
        if ',' in target:
            idx = target.find(',')
            IP = target[0:target.find(',')]
            port = int(target[target.find(',')+1:])
        else:
            IP = target

        load_windbg = [windbgxPath]
        load_windbg += [
            "-premote tcp:server={},port={}".format(IP, port)]

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbgx']+'\n'+script+'\n'
        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['"$$><{}'.format(tmp.name) +
                        ';.shell -x del {}"'.format(tmp.name)]

        ter = subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            sleep(0.05)
        return ter.pid

    @classmethod
    def com(clx, com, script="", baudrate=115200):
        showbanner('attaching', 'purple', '[=]')
        if context.windbgx is None:
            windbgxPath = debugger[context.arch]['windbgx']
        else:
            windbgxPath = context.windbgx
        load_windbg = [windbgxPath]
        load_windbg += [
            "-k com:pipe,port={},baud={},reconnect".format(com, baudrate)]

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbgx']+'\n'+script+'\n'
        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['"$$><{}'.format(tmp.name) +
                        ';.shell -x del {}"'.format(tmp.name)]
        # ter=subprocess.Popen(Latin1_encode(' '.join(load_windbg)))
        ter = subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            sleep(0.05)
        return ter.pid

    @classmethod
    def net(clx, key, script = ""):
        showbanner('attaching', 'purple', '[=]')
        if context.windbgx is None:
            windbgxPath = debugger[context.arch]['windbgx']
        else:
            windbgxPath = context.windbgx

        IP = ''
        port = 50000
        if ',' in key:
            idx = key.find(',')
            IP = key[0:key.find(',')]
            port = int(key[key.find(',')+1:])
        else:
            IP = key

        load_windbg = [windbgxPath]
        load_windbg += [
            "-k net:port={},key={}".format(port, key)]

        script = context.dbginit+'\n' + \
            debugger_init[context.arch]['windbgx']+'\n'+script+'\n'
        tmp = tempfile.NamedTemporaryFile(
            prefix='winpwn_', suffix='.dbg', delete=False)
        tmp.write(Latin1_encode(script))
        tmp.flush()
        tmp.close()
        load_windbg += ['-c']             # exec command
        load_windbg += ['"$$><{}'.format(tmp.name) +
                        ';.shell -x del {}"'.format(tmp.name)]

        ter = subprocess.Popen(' '.join(load_windbg))
        while(os.path.exists(tmp.name)):    # wait_for_debugger
            sleep(0.05)
        return ter.pid


class x64dbg():
    @classmethod
    def attach(clx, target, script="", sysroot=None):
        showbanner('attaching', 'purple', '[=]')
        if context.x64dbg is None:
            x64dbgPath = debugger[context.arch]['x64dbg']
        else:
            x64dbgPath = context.x64dbg
        load_x64dbg = [x64dbgPath, '-p']
        # if isinstance(target,process):
        #     load_x64dbg.append(str(target.pid))
        # elif isinstance(target,int):
        #     load_x64dbg.append(str(pid))
        load_x64dbg.append(str(target.pid))
        ter = subprocess.Popen(load_x64dbg)
        target.debugger = ter
        pause('\twaiting for debugger')
        sys.stdin.readline()
        return ter.pid

    @classmethod
    def debug(clx, target, script="", sysroot=None):
        pass


# -*- coding=Latin1 -*-


debugger = {
    'i386': {
        'windbg': '',
        'x64dbg': '',
        'gdb': '',
        "windbgx": ""
    },
    'amd64': {
        'windbg': '',
        'x64dbg': '',
        'gdb': '',
        "windbgx": ""
    }
}

debugger_init = {
    'i386': {
        'windbg': '',
        'x64dbg': '',
        'gdb': '',
        "windbgx": ""
    },
    'amd64': {
        'windbg': '',
        'x64dbg': '',
        'gdb': '',
        "windbgx": ""
    }
}


def init_debugger():
    import json
    winpwn_init = os.path.expanduser("~\\.winpwn")
    if os.path.exists(winpwn_init):
        fd = open(winpwn_init, 'r')
        js = Latin1_encode(''.join(fd.readlines()))
        x = json.loads(js)
        dbg = x['debugger']
        dbg_init = x['debugger_init']
        fd.close()
        debugger.update(dbg)
        debugger_init.update(dbg_init)
