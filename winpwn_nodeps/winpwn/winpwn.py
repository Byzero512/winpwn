import platform

import threading
import sys
import socket

from .win import winProcess
from .context import context
from .misc import parse
import var


class tupe(object):
    def get_timeout(self):
        pass
    def set_timeout(self,timeout=None):
        pass
    timeout=property(get_timeout,set_timeout)

    def read(self,n,timeout=None):
        pass
    def write(self,buf,timeout=None):
        pass
    
    def send(self,buf,timeout=None):
        rs=self.write(buf,timeout)
        print(parse.mark('send'))     
        if context.log_level=='debug':
            print(parse.hexdump(buf))
        if context.length is None or len(buf)<context.length:    
            sys.stdout.write(buf)
        else:
            print(parse.color("[-]: str too long, not show sending",'red'))
        print(parse.mark('sended'))
        return rs
    
    def sendline(self,buf,timeout=None):
        return self.send(buf+context.newline)
    
    def recv(self,n,timeout=None,local_call=False):
        # try to read n bytes, no exception
        if not local_call:
            print(parse.mark('recv'))
        buf=''
        if var.ter is not None:
            while(len(buf)!=n):
                buf+=self.read(n-len(buf),timeout)
        else:
            buf=self.read(n, timeout)
        if not local_call:
            if context.log_level=='debug':
                print(parse.hexdump(buf))
            print(parse.mark('recved'))
        return buf

    def recvn(self,n,timeout=None,local_call=False):
        # must recvn with in timeout
        if not local_call:
            print(parse.mark('recv'))
        if timeout is None:
            if self.timeout:
                timeout=self.timeout
            elif context.timeout:
                timeout=context.timeout
        buf=''
        if var.ter is not None:
            while(len(buf)!=n):
                buf += self.recv(n-len(buf), timeout,local_call=True)              
        else:
            buf = self.recv(n, timeout,local_call=True)
        if len(buf) != n:
            raise(EOFError("Timeout when use recvn"))
        if not local_call :
            if context.log_level=='debug':
                print(parse.hexdump(buf))
            print(parse.mark('recved'))
        return buf
  
    def recvuntil(self,delim,timeout=None):
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

    def recvline(self,timeout=None):
        return self.recvuntil(context.newline)

    def recvall(self,n,timeout=None):
        print(parse.mark('recv'))
        buf=self.recv(0x100000, timeout,local_call=True)
        if context.log_level=='debug': # and not interactive:
            print(parse.hexdump(buf))
        print(parse.mark('recved'))
        return buf   

    # based on read/write
    def interactive(self, escape = False):
        print(parse.mark('interact'))
        go = threading.Event()
        go.clear()
        def recv_thread():                   
            while not go.is_set():
                cur = self.read(512)
                if cur:
                    sys.stdout.write(cur)
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
                    buf = sys.stdin.readline()
                    if buf:
                        self.write(buf)
                    else:
                        go.set()
                except EOFError:
                    go.set()
        except KeyboardInterrupt:
            go.set()
        while t.is_alive():
            t.join(timeout = 0.1)

class remote(tupe):
    def __init__(self, ip, port, family = socket.AF_INET, type = socket.SOCK_STREAM):
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self.__timeout=0.0625
        try:
            self.sock.connect((ip, port))
            self.sock.settimeout(float(0.0625))
        except:
            print("connect failed")
            quit()
    def read(self,n,timeout=None):
        return self.sock.recv(n)
    def write(self,buf,timeout=None):
        return self.sock.write(buf)
    def close(self):
        self.sock.close()
    def get_timeout(self):
        return self.__timeout
    def set_timeout(self,timeout=None):
        self.sock.settimeout(float(timeout))
        self.__timeout=timeout
    timeout=property(get_timeout,set_timeout)

    def debug(self):
        print("winProcess timeout: ",self.timeout)

class process(tupe):
        def __init__(self,argv,pwd=None,flags=None):
            self.Process=winProcess(argv,pwd,flags)
            self.pid=self.Process.pid
        def read(self,n,timeout=None):
            return self.Process.read(n,timeout=timeout)
        def write(self, buf, timeout=None):
            return self.Process.write(buf,timeout=timeout)
        def close(self):
            self.Process.close()        # need to kill process
        def get_timeout(self):
            return self.Process.timeout
        def set_timeout(self,timeout=None):
            if timeout is not None:
                self.Process.timeout=timeout
        timeout=property(get_timeout,set_timeout)
        def debug(self):
            print("winpwn process timeout: ",self.timeout)