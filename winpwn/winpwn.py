# -*- coding=Latin1 -*-
import platform

import threading
import sys
import socket
import time
import os
from .win import winProcess
from .context import context
from .misc import Latin1_encode,Latin1_decode,NOPIE,PIE,color,hexdump

class tube(object):
    def __init__(self):
        self._timeout=context.timeout
        self.debugger=None
        
    def read(self,n,timeout=None):
        pass
    def write(self,buf):
        pass
    def is_exit(self,buf):
        pass
    @property
    def timeout(self):
        return self._timeout
    @timeout.setter
    def timeout(self,timeout):
        pass
    def __showbuf(self,buf,is_show=True,is_send=False):
        if is_show and not context.noout:
            if is_send:
                markstr='Send'
            else:
                markstr='Recv'
            print(color('[+]: '+markstr+'ing','green'))
            if context.log_level=='debug':
                hexdump(buf)
            if buf.endswith(context.newline):
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
            # print(color('[-]: '+markstr+'ed','green'))
             
    def send(self,buf):
        # if not context.noout:
        #     mark('send')
        rs=self.write(buf)
        self.__showbuf(buf,is_show=True,is_send=True)
        return rs
    
    def sendline(self,buf,newline=None):
        if newline is None:
            newline=context.newline
        return self.send(buf+newline)

    def recv(self,n,timeout=None,local_call=False):
        # try to read n bytes, no exception
        buf=''
        buf=self.read(n, timeout)
        self.__showbuf(buf,is_show=not local_call)
        return buf

    def recvn(self,n,timeout=None,local_call=False):
        # must recv n bytes within timeout
        buf=''
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError("Timeout when use recvn"))
        self.__showbuf(buf,is_show=not local_call)
        return buf
    
    def recvuntil(self,delim,timeout=None):
        if timeout is None:
            if self.timeout:
                timeout=self.timeout
            else:
                timeout=context.timeout
        buf = ''
        st=time.time()
        xt=st
        while (buf[-len(delim):]!=delim):
            buf += self.read(1, timeout=timeout-(xt-st))
            if self.debugger is None:
                xt=time.time()
                if (xt-st)>=timeout:
                    break
        if not buf.endswith(delim):
            raise(EOFError(color("[Error]: Recvuntil error",'red')))
        self.__showbuf(buf,is_show=True)
        return buf

    def recvline(self,timeout=None,newline=None):
        if newline is None:
            newline=context.newline
        return self.recvuntil(newline)

    def recvall(self,timeout=None):
        buf=self.read(0x100000, timeout)
        self.__showbuf(buf,is_show=True)
        return buf   

    # based on read/write
    def interactive(self):
        # it exited, contrl+C, timeout
        if not context.noout:
            print(color('\n[+]: Interacting','green'))
        go = threading.Event()
        go.clear()
        def recv_thread():
            try:                  
                while not go.is_set():
                    buf = self.read(0x10000,0.125,interactive=True)
                    if buf:
                        self.__showbuf(buf,is_show=True,is_send=False)
                        if not context.noout:
                            print(color('\n[+]: Interacting','green'))
                    go.wait(0.2)
            except KeyboardInterrupt:
                go.set()
                print(color('[pwn-EOF]: Exited','red'))
        t = threading.Thread(target = recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.is_set():
                go.wait(0.2)
                try:
                    if self.is_exit():
                        time.sleep(0.2) # wait for time to read output
                    buf = sys.stdin.readline()
                    if buf:
                        self.write(buf)
                except:     # exited
                    go.set()
                    print(color('[pwn-EOF]: Exited','red'))
                    break
        except KeyboardInterrupt: # control+C
            go.set()
            print(color('[pwn-EOF]: Exited','red'))
        while t.is_alive():
            t.join(timeout = 0.1)

class remote(tube):
    def __init__(self, ip, port, family = socket.AF_INET, type = socket.SOCK_STREAM):
        tube.__init__(self)
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self._is_exit=False
        try:
            self.sock.connect((ip, port))
            self.sock.settimeout(self.timeout)
        except:
            raise(EOFError("Connect failed"))
    def read(self,n,timeout=None,interactive=False):
        if timeout is not None:
            self.sock.settimeout(timeout)
        buf=b''
        try:
            buf=self.sock.recv(n) # ignore Exception
        except:
            pass
        self.sock.settimeout(self.timeout)
        return Latin1_decode(buf)

    def write(self,buf):
        return self.sock.send(Latin1_encode(buf))
    def close(self):
        self.sock.close()
        self._is_exit=True
    def is_exit(self):
        if self._is_exit:
            return True
        return False
    @tube.timeout.setter
    def set_timeout(self,timeout):
        self._timeout=timeout
        self.sock.settimeout(self._timeout)

class process(tube):
    def __init__(self,argv,cwd=None,flags=None):
        tube.__init__(self)
        # en/disable PIE, need: pip install pefile
        if context.pie is not None:
            fpath=""
            if not isinstance(argv,list):
                fpath=argv
            else:
                fpath=argv[0]
            if context.pie:
                PIE(fpath)
            else:
                NOPIE(fpath)
        self.Process=winProcess(argv,cwd,flags)
        self.pid=self.Process.pid
    def read(self,n,timeout=None,interactive=False):
        buf=''
        if self.debugger is not None and interactive is False:
            while(len(buf)!=n):
                buf+=self.Process.read(n-len(buf),timeout)
        else:
            buf=self.Process.read(n, timeout)
        return buf
    def write(self, buf):
        return self.Process.write(buf)
    def readm(self,addr,n):
        return self.Process.readm(addr,n)
    def writem(self,addr,con):
        return self.Process.writem(addr,con)
    def close(self):
        self.Process.close()        # need to kill process
    def is_exit(self):
        return self.Process.is_exit()
    @tube.timeout.setter
    def timeout(self,timeout):
        self._timeout=timeout
        self.Process.pipe.timeout=timeout