"""
    the module based on pwintools from 
        https://github.com/masthoon/pwintools
"""

import os
import sys
import time
import ctypes
import string
import socket
import logging
import threading

import windows
import windows.winobject
import windows.winproxy
#import windows.native_exec.nativeutils
import windows.generated_def as gdef
from windows.generated_def.winstructs import *
#import windows.native_exec.simple_x64 as x64

from .context import context
import var
from misc import parse


CreatePipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.PHANDLE, gdef.PHANDLE, gdef.LPSECURITY_ATTRIBUTES, gdef.DWORD)
CreatePipeParams = ((1, 'hReadPipe'), (1, 'hReadPipe'), (1, 'lpPipeAttributes'), (1, 'nSize'))

@windows.winproxy.Kernel32Proxy('CreatePipe', deffunc_module=sys.modules[__name__])
def CreatePipe(lpPipeAttributes=None, nSize=0):
    hReadPipe = gdef.HANDLE()
    hWritePipe = gdef.HANDLE()
    CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)
    return hReadPipe.value, hWritePipe.value

PeekNamedPipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.HANDLE, gdef.LPVOID, gdef.DWORD, gdef.LPDWORD, gdef.LPDWORD, gdef.LPDWORD)
PeekNamedPipeParams = ((1, 'hNamedPipe'), (1, 'lpBuffer'), (1, 'nBufferSize'), (1, 'lpBytesRead'), (1, 'lpTotalBytesAvail'), (1, 'lpBytesLeftThisMessage'))

@windows.winproxy.Kernel32Proxy('PeekNamedPipe', deffunc_module=sys.modules[__name__])
def PeekNamedPipe(hNamedPipe):
    lpTotalBytesAvail = gdef.DWORD()
    PeekNamedPipe.ctypes_function(hNamedPipe, None, 0, None, lpTotalBytesAvail, None)
    return lpTotalBytesAvail.value

_msgtype_prefixes = {
    'status'       : 'x',
    'success'      : '+',
    'failure'      : '-',
    'debug'        : 'DEBUG',
    'info'         : '*',
    'warning'      : '!',
    'error'        : 'ERROR',
    'exception'    : 'ERROR',
    'critical'     : 'CRITICAL'
}

class DuplicateFilter(object):
    def __init__(self):
        self.msgs = set()

    def filter(self, record):
        # Only filter `EOFError:`
        rv = True
        if record.msg and "EOFError:" in record.msg:
            rv = record.msg not in self.msgs
            self.msgs.add(record.msg)
        return rv

class MiniLogger(object):
    """Python simple logger implementation"""
    def __init__(self):
        self.logger = logging.getLogger("mini")
        streamHandler = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        streamHandler.setFormatter(formatter)
        self.logger.addHandler(streamHandler)
        self.logger.addFilter(DuplicateFilter())
        self.log_level = 'info'
        
    def get_log_level(self):
        return self._log_level

    def set_log_level(self, log_level):
        self._log_level = log_level
        if isinstance(log_level, int):
            self.logger.setLevel(log_level)
        else:
            self.logger.setLevel(logging._levelNames[log_level.upper()])

    log_level = property(get_log_level, set_log_level)
    
    def success(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'success')

    def failure(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'failure')
        
    def debug(self, message, *args, **kwargs):
        self._log(logging.DEBUG, message, args, kwargs, 'debug')

    def info(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'info')

    def warning(self, message, *args, **kwargs):
        self._log(logging.WARNING, message, args, kwargs, 'warning')

    def error(self, message, *args, **kwargs):
        self._log(logging.ERROR, message, args, kwargs, 'error')
        raise Exception(message % args)

    def exception(self, message, *args, **kwargs):
        kwargs["exc_info"] = 1
        self._log(logging.ERROR, message, args, kwargs, 'exception')
        raise

    def critical(self, message, *args, **kwargs):
        self._log(logging.CRITICAL, message, args, kwargs, 'critical')

    def log(self, level, message, *args, **kwargs):
        self._log(level, message, args, kwargs, None)
        
    def _log(self, level, msg, args, kwargs, msgtype):
        if msgtype:
            msg = '[%s] %s' % (_msgtype_prefixes[msgtype], str(msg))
        self.logger.log(level, msg, *args, **kwargs)


def interact(obj, escape = False):
    """Base standard input/ouput interaction with a pipe/socket stolen from pwntools"""
    go = threading.Event()
    go.clear()
    def recv_thread():                   # recv
        while not go.is_set():
            cur = obj.recvall(timeout = 200,interactive=True)
            cur = cur.replace('\r\n', '\n')
            if escape:
                cur = cur.encode('string-escape')
                cur = cur.replace('\\n', '\n')
                cur = cur.replace('\\t', '\t')
                cur = cur.replace('\\\\', '\\')
            if cur:
                sys.stdout.write(cur)
                if escape and not cur.endswith('\n'):
                    sys.stdout.write('\n')
                sys.stdout.flush()
            go.wait(0.2)

    t = threading.Thread(target = recv_thread)
    t.daemon = True
    t.start()
    try:
        while not go.is_set():               # write
            # Impossible to timeout readline
            # Wait a little and check obj
            go.wait(0.2)
            try:
                obj.check_closed()
                data = sys.stdin.readline() 
                if data:
                    obj.send(data,interactive=True)
                else:
                    go.set()
            except EOFError:
                go.set()
    except KeyboardInterrupt:
        go.set()
        
    while t.is_alive():
        t.join(timeout = 0.1)

class Pipe(object):
    """Windows pipe support"""
    def __init__(self, bInheritHandle = 1):
        attr = SECURITY_ATTRIBUTES()
        attr.lpSecurityDescriptor = 0
        attr.bInheritHandle = bInheritHandle
        attr.nLength = ctypes.sizeof(attr)
        self._rpipe, self._wpipe = CreatePipe(attr)
        self._timeout = 500 # ms
        self.tick = 40 # ms
        
    def get_handle(self, mode = 'r'):
        """get_handle(mode = 'r') returns the 'r'ead / 'w'rite HANDLE of the pipe"""
        if mode and mode[0] == 'w':
            return self._wpipe
        return self._rpipe
        
    def __del__(self):
        windows.winproxy.CloseHandle(self._rpipe)
        windows.winproxy.CloseHandle(self._wpipe)
    
    def select(self):
        """select() returns the number of bytes available to read on the pipe"""
        return PeekNamedPipe(self._rpipe)
        
    def _read(self, size):
        if size == 0:
            return ''
        buffer = ctypes.create_string_buffer(size)
        windows.winproxy.ReadFile(self._rpipe, buffer)
        return buffer.raw
        
    def read(self, size):
        """read(size) returns the bytes read on the pipe (returned length <= size)"""
        if self.select() < size:
            elapsed = 0
            while elapsed <= self._timeout and self.select() < size:
                time.sleep(float(self.tick) / 1000)
                elapsed += self.tick
        return self._read(min(self.select(), size))
    
    def write(self, buffer):
        """write(buffer) sends the buffer on the pipe"""
        windows.winproxy.WriteFile(self._wpipe, buffer)



class Remote(object):
    """
        Wrapper for remote connections
            Remote("127.0.0.1", 8888)
    """
    def __init__(self, ip, port, family = socket.AF_INET, type = socket.SOCK_STREAM):
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self._timeout = 500 # ms
        self._default_timeout = 500 # ms
        try:
            self.sock.connect((ip, port))
        except socket.timeout:
            self._closed = True
            log.error("EOFError: Socket {:s} connection failed".format(self))
        
        if context.timeout is None:
            self._timeout = 500           # ms
        else:
            self._timeout=context.timeout
        self._default_timeout = 500      # ms
        # byzero add
        self.set_timeout(self._timeout)

        self._closed = False
        # context.newline = '\r\n'
        # if context.newline:
        # context.newline=context.newline
    
    def __repr__(self):
        return '<{0} "{1}:{2}" at {3}>'.format(self.__class__.__name__, self.ip, self.port, hex(id(self)))
    
    def close(self):
        """close() closes the connection"""
        self.sock.close()
        self._closed = True
        
    def check_closed(self, force_exception = True):
        if self._closed and force_exception:
            raise(EOFError("Socket {:s} closed".format(self)))
        elif self._closed:
            log.warning("EOFError: Socket {:s} closed".format(self))
        return self._closed
    
    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout=None):
        if timeout:
            self._timeout = timeout
            self.sock.settimeout(float(timeout) / 1000)
        elif self._timeout != self._default_timeout:
            self._timeout = self._default_timeout
            
    timeout = property(get_timeout, set_timeout)
    """timeout in ms for read on the socket"""

    def read(self, n, timeout = None, no_warning = False):
        """read(n, timeout = None, no_warning = False) tries to read n bytes on the socket before timeout"""
        _save_timeout=None
        if timeout:
            _save_timeout=self._timeout
            self._timeout = timeout
            self.set_timeout(self._timeout)
        buf = ''
        # if not self.check_closed(False):
        try:
            buf = self.sock.recv(n)
        except socket.timeout:
            if not no_warning:
                log.warning("EOFError: Timeout {:s} ".format(self))
        except socket.error:
            self._closed = True
            if not no_warning:
                log.warning("EOFError: Socket {:s} closed".format(self))
        try:
            if _save_timeout:
                self._timeout=_save_timeout
                self.settimeout(self._timeout)
        except:
            pass        
        return buf
    
    def write(self, buf,interactive=False):
        """write(buf) sends the buf to the socket"""
        # if not self.check_closed(True):
        #     try:
        #         return self.sock.send(buf)
        #     except socket.error:
        #         self._closed = True
        #         log.warning("EOFError: Socket {:s} closed".format(self))
        rs=self.sock.send(buf)
        if not interactive:
            print(parse.mark('send'))     
            if context.log_level=='debug':
                print(parse.hexdump(buf))
            if context.length is None or len(buf)<context.length:    
                sys.stdout.write(buf)
            else:
                print(parse.color("[-]: str too long, not show sending",'red'))
            print(parse.mark('sended'))
        return rs 
            
    def send(self, buf,interactive=False):
        """send(buf) sends the buf to the process stdin"""
        self.write(buf,interactive=interactive)
        
    def sendline(self, line):
        """sendline(line) sends the line adding newline to the process stdin"""
        self.write(line + context.newline)

    # try to read, no exception
    def recv(self, n, timeout = None):
        """recv(n, timeout = None) tries to read n bytes on the process stdout before timeout"""
        print(parse.mark('recv'))
        buf=''
        if var.ter is not None:
            # if var.ter.poll() is None:
            while(len(buf)!=n):
                buf+=self.read(n-len(buf),timeout)
            # else:
                # var.ter=None
                # buf=self.read(n, timeout)
        else:
            buf=self.read(n, timeout)
        if context.log_level=='debug':
            parse.hexdump(buf)
        print(parse.mark('recved'))
        return buf

    # must read n bytes
    def recvn(self, n, timeout = None,local_call=False):
        """recvn(n, timeout = None) reads exactly n bytes on the process stdout before timeout"""
        if not local_call:
            print(parse.mark('recv'))
        buf=''
        if var.ter is not None:
            # if var.ter.poll() is None:
            while(len(buf)!=n):
                    # print("winpwn run to here")
                buf += self.read(n-len(buf), timeout)
            # else:
                # print("winpwn run to here1",var.ter.poll())
                # var.ter=None
                # buf=self.read(n, timeout)                
        else:
            buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError("Timeout {:s} ".format(self)))
        
        if not local_call and context.log_level=='debug':
            print(parse.hexdump(buf)) 
        if not local_call:
            print(parse.mark('recved'))
        return buf
    # recv all bytes within in timeout
    def recvall(self, timeout = None,interactive=False):
        """recvall(timeout = None) reads all bytes available on the process stdout before timeout"""
        if not interactive:
            print(parse.mark('recv'))
        buf=self.read(0x100000, timeout, no_warning = True)
        if context.log_level=='debug': # and not interactive:
            parse.hexdump(buf)
        if not interactive:
            print(parse.mark('recved'))
        return buf

    # base on recvn()
    def recvuntil(self, delim, timeout = None):
        """recvuntil(delim, timeout = None) reads bytes until the delim is present on the process stdout before timeout"""
        print(parse.mark('recv'))
        # self.timeout=1000
        buf = ''
        # while delim not in buf:
        while (len(buf)<len(delim) or buf[-len(delim):]!=delim):
            buf += self.recvn(1, timeout,local_call=True)
        if context.log_level=='debug':
            print(parse.hexdump(buf))
        print(parse.mark('recved'))
        return buf
    
    # base on recvuntil(); show on recvuntil
    def recvline(self, timeout = None):
        """recvline(timeout = None) reads one line on the process stdout before timeout"""
        return self.recvuntil(context.newline, timeout)
            
    def interactive(self, escape = False):
        print(parse.mark('interact'))
        """interactive(escape = None) allows to interact directly with the socket (escape to show binary content received)"""
        interact(self, escape)
        
    def interactive2(self):
        """interactive2() with telnetlib"""
        fs = self.sock._sock
        import telnetlib
        t = telnetlib.Telnet()
        t.sock = fs
        t.interact()

class Process(windows.winobject.process.WinProcess):
    """
        Wrapper for Windows process
            Process(r"C:\Windows\system32\mspaint.exe")
            Process("pwn.exe", CREATE_SUSPENDED)
            Process([r"C:\Windows\system32\cmd.exe", '-c', 'echo', 'test'])
    """
    def __init__(self, target, flags = 0, nostdhandles = False):
        self.cmd = target
        self.flags = flags
        self.stdhandles = not nostdhandles
        # context.newline = '\r\n'
        # if context.newline:
        # context.newline=context.newline
        if self.stdhandles:
            self.stdin = Pipe()
            self.stdout = Pipe()
            # stderr mixed with stdout self.stderr = Pipe()
            
            if context.timeout is None:
                self._timeout = 500           # ms
            else:
                self._timeout=context.timeout
            self._default_timeout = 500      # ms
            # byzero add
            self.set_timeout(self._timeout)
        if self._create_process() != 0:
            raise(ValueError("CreateProcess failed - Invalid arguments"))
        super(Process, self).__init__(pid=self.__pid, handle=self.__phandle)
        if not (flags & CREATE_SUSPENDED):
            self.wait_initialized()

    def check_initialized(self):
        is_init = False
        try: # Accessing PEB
            self.peb.modules[1]
            is_init = True
        except:
            pass
        if not is_init:
            log.info("Process {:s} initializing ...".format(self))
        return is_init
    
    def wait_initialized(self):
        while not self.check_initialized():
            time.sleep(0.05)
                
    def __del__(self):
        # TODO: Kill the debugger too
        if self.__pid and not self.is_exit:
            self.exit(0)
    
    def _create_process(self):
        proc_info = PROCESS_INFORMATION()
        lpStartupInfo = None
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        if self.stdhandles:
            StartupInfo.dwFlags = gdef.STARTF_USESTDHANDLES
            StartupInfo.hStdInput = self.stdin.get_handle('r')
            StartupInfo.hStdOutput = self.stdout.get_handle('w')
            StartupInfo.hStdError = self.stdout.get_handle('w')
        lpStartupInfo = ctypes.byref(StartupInfo)
        lpCommandLine = None
        lpApplicationName = self.cmd
        if isinstance(self.cmd, (list,)):
            lpCommandLine = (" ".join([str(a) for a in self.cmd]))
            lpApplicationName = None
        try:
            windows.winproxy.CreateProcessA(lpApplicationName, lpCommandLine=lpCommandLine, bInheritHandles=True, dwCreationFlags=self.flags, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=lpStartupInfo)
            windows.winproxy.CloseHandle(proc_info.hThread)
            self.__pid = proc_info.dwProcessId
            self.__phandle = proc_info.hProcess
        except Exception:
            self.__pid = None
            self.__phandle = None
            log.warning("Process {:s} failed to start!".format(self.cmd))
            return -1
        return 0
    
    def close(self):
        """close() closes the process"""
        if not self.is_exit:
            self.exit(0)

    def check_exit(self, raise_exc=False):
        if self.is_exit:
            if raise_exc:
                raise(EOFError("Process {:s} exited".format(self)))
            else:
                log.warning("EOFError: Process {:s} exited".format(self))
    
    def check_closed(self):
        self.check_exit(True)
    
    def get_timeout(self):
        if self.stdhandles:
            return self._timeout
        return -1

    def set_timeout(self, timeout=None):
        if timeout:
            self._timeout = timeout
            if self.stdhandles:
                self.stdin.timeout = timeout
                self.stdout.timeout = timeout
        elif self._timeout != self._default_timeout:
            self._timeout = self._default_timeout

    timeout = property(get_timeout, set_timeout)
    
    """timeout in ms for read on the process stdout (pipe)"""
    
    def read(self, n, timeout = None, no_warning = False):
        """read(n, timeout = None, no_warning = False) tries to read n bytes on process stdout before timeout"""
        _save_timeout=None
        if timeout:
            _save_timeout=self._timeout
            self._timeout = timeout
            self.set_timeout(self._timeout)
        buf = ''
        if self.stdhandles: # and not self.check_exit():
            buf = self.stdout.read(n)
            if var.ter is None:
                if not no_warning and len(buf) != n:
                    log.warning("EOFError: Timeout {:s} ".format(self))
        try:
            if _save_timeout:
                self._timeout=_save_timeout
                self.settimeout(self._timeout)
        except:
            pass
        return buf

    def write(self, buf,interactive=False):
        """write(buf) sends the buf to the process stdin"""
        self.check_exit(True)
        if self.stdhandles: # and not self.check_exit(True):
            # byzero add
            rs=self.stdin.write(buf)
            if not interactive:
                print(parse.mark('send'))     
                if context.log_level=='debug':
                    print(parse.hexdump(buf))
                if context.length is None or len(buf)<context.length:    
                    sys.stdout.write(buf)
                else:
                    print(parse.color("[-]: str too long, not show sending",'red'))
                print(parse.mark('sended'))
            return rs 

    def send(self, buf,interactive=False):
        """send(buf) sends the buf to the process stdin"""
        self.write(buf,interactive=interactive)
        
    def sendline(self, line):
        """sendline(line) sends the line adding newline to the process stdin"""
        self.write(line + context.newline)

    # try to read, no exception
    def recv(self, n, timeout = None):
        """recv(n, timeout = None) tries to read n bytes on the process stdout before timeout"""
        print(parse.mark('recv'))
        buf=''
        if var.ter is not None:
            # if var.ter.poll() is None:
            while(len(buf)!=n):
                buf+=self.read(n-len(buf),timeout)
            # else:
                # var.ter=None
                # buf=self.read(n, timeout)
        else:
            buf=self.read(n, timeout)
        if context.log_level=='debug':
            parse.hexdump(buf)
        print(parse.mark('recved'))
        return buf

    # must read n bytes
    def recvn(self, n, timeout = None,local_call=False):
        """recvn(n, timeout = None) reads exactly n bytes on the process stdout before timeout"""
        if not local_call:
            print(parse.mark('recv'))
        buf=''
        if var.ter is not None:
            # if var.ter.poll() is None:
            while(len(buf)!=n):
                    # print("winpwn run to here")
                buf += self.read(n-len(buf), timeout)
            # else:
                # print("winpwn run to here1",var.ter.poll())
                # var.ter=None
                # buf=self.read(n, timeout)                
        else:
            buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError("Timeout {:s} ".format(self)))
        
        if not local_call and context.log_level=='debug':
            print(parse.hexdump(buf)) 
        if not local_call:
            print(parse.mark('recved'))
        return buf
    # recv all bytes within in timeout
    def recvall(self, timeout = None,interactive=False):
        """recvall(timeout = None) reads all bytes available on the process stdout before timeout"""
        if not interactive:
            print(parse.mark('recv'))
        buf=self.read(0x100000, timeout, no_warning = True)
        if context.log_level=='debug': # and not interactive:
            parse.hexdump(buf)
        if not interactive:
            print(parse.mark('recved'))
        return buf

    # base on recvn()
    def recvuntil(self, delim, timeout = None):
        """recvuntil(delim, timeout = None) reads bytes until the delim is present on the process stdout before timeout"""
        print(parse.mark('recv'))
        # self.timeout=1000
        buf = ''
        # while delim not in buf:
        while (len(buf)<len(delim) or buf[-len(delim):]!=delim):
            buf += self.recvn(1, timeout,local_call=True)
        if context.log_level=='debug':
            print(parse.hexdump(buf))
        print(parse.mark('recved'))
        return buf
    
    # base on recvuntil(); show on recvuntil
    def recvline(self, timeout = None):
        """recvline(timeout = None) reads one line on the process stdout before timeout"""
        return self.recvuntil(context.newline, timeout)
            
    def interactive(self, escape = False):
        print(parse.mark('interact'))
        """interactive(escape = None) allows to interact directly with the socket (escape to show binary content received)"""
        interact(self, escape)
        
log = MiniLogger()