# -*- coding=Latin1 -*-
import platform

import threading
import sys
import socket
import time
import os
from .win import winProcess
from .context import context
from .misc import parse,Latin1_encode,Latin1_decode,NOPIE,PIE
import var

class tube(object):
    def get_timeout(self):
        pass
    def set_timeout(self,timeout=None):
        pass
    timeout=property(get_timeout,set_timeout)
    
    def read(self,n,timeout=None):
        pass
    def write(self,buf):
        pass
    
    def send(self,buf):
        rs=self.write(buf)
        if not context.noout:
            parse.mark('send')
            if context.log_level=='debug':
                parse.hexdump(buf)
            if context.length is None or len(buf)<context.length:    
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                parse.color("[-]: str too long, not show sending",'red')
            parse.mark('sended')
        return rs
    
    def sendline(self,buf,newline=None):
        if newline is None:
            newline=context.newline
        return self.send(buf+newline)
    
    def recv(self,n,timeout=None,local_call=False):
        # try to read n bytes, no exception
        if not local_call and not context.noout:
            parse.mark('recv')
        buf=''
        buf=self.read(n, timeout)
        if not local_call and not context.noout:
            if context.log_level=='debug':
                parse.hexdump(buf)
            if buf.endswith(context.newline):
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                # x=Latin1_encode(buf)
                # print(buf) # will error
                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
            parse.mark('recved')
        return buf

    def recvn(self,n,timeout=None,local_call=False):
        # must recv n bytes within timeout
        if not local_call and not context.noout:
            parse.mark('recv')
        buf=''
        buf = self.recv(n, timeout,local_call=True)
        if len(buf) != n:
            raise(EOFError("Timeout when use recvn"))
        if not local_call and not context.noout:
            if context.log_level=='debug':
                parse.hexdump(buf)
            if buf.endswith(context.newline):
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
            parse.mark('recved')
        return buf
    
    def recvuntil(self,delim,timeout=None):
        if timeout is None:
            timeout=self.timeout
        if not context.noout:
            parse.mark('recv')
        buf = ''
        st=time.time()
        xt=0.0
        while (len(buf)<len(delim) or buf[-len(delim):]!=delim):
            buf += self.recv(1, timeout=timeout-(xt-st),local_call=True)
            if var.ter is None:
                xt=time.time()
                if (xt-st)>=timeout:
                    break
        if buf.endswith(delim) and not context.noout:
            if context.log_level=='debug':
                parse.hexdump(buf)
            if buf.endswith(context.newline):
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
            parse.mark('recved')
            return buf
        else:
            raise(EOFError(parse.color("[Error]: Recvuntil error",'red')))

    def recvline(self,timeout=None,newline=None):
        if newline is None:
            newline=context.newline
        return self.recvuntil(newline)

    def recvall(self,timeout=None):
        parse.mark('recv')
        buf=self.recv(0x100000, timeout,local_call=True)
        if not context.noout:
            if context.log_level=='debug': # and not interactive:
                parse.hexdump(buf)
            if buf.endswith(context.newline):
                os.write(sys.stdout.fileno(), Latin1_encode(buf))
            else:
                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
            parse.mark('recved')
        return buf   

    # based on read/write
    def interactive(self):
        # it exited, contrl+C, timeout
        parse.mark('interact')
        go = threading.Event()
        go.clear()
        def recv_thread():
            try:                  
                while not go.is_set():
                    try:
                        buf = self.read(0x10000,0.125,interactive=True)
                        if buf:
                            parse.mark('recv')
                            if context.log_level=='debug':
                                parse.hexdump(buf)
                            if buf.endswith(context.newline):                    
                                os.write(sys.stdout.fileno(), Latin1_encode(buf))
                            else:
                                os.write(sys.stdout.fileno(), Latin1_encode(buf+'\n'))
                            parse.mark('recved')
                        go.wait(0.2)
                    except:      # does this handle have use?????
                        parse.color('[pwn-EOF]: exited','red')
                        go.set()
            except KeyboardInterrupt:
                go.set()
                parse.color('[pwn-EOF]: exited','red')
        t = threading.Thread(target = recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.is_set():
                go.wait(0.2)
                try:
                    if self.is_exit():
                        time.sleep(0.2) # wait for time to read output
                        # parse.color('[pwn-EOF]: exited','red')
                    buf = sys.stdin.readline()
                    if buf:
                        self.write(buf)
                except:     # exited
                    go.set()
                    parse.color('[pwn-EOF]: exited','red')
        except KeyboardInterrupt: # control+C
            go.set()
            parse.color('[pwn-EOF]: exited','red')
        while t.is_alive():
            t.join(timeout = 0.1)

class remote(tube):
    def __init__(self, ip, port, family = socket.AF_INET, type = socket.SOCK_STREAM):
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self._timeout=context.timeout
        self._is_exit=False
        try:
            self.sock.connect((ip, port))
            self.sock.settimeout(float(context.timeout))
        except:
            raise(EOFError("Connect failed"))
    def read(self,n,timeout=None,interactive=False):
        save_timeout=self.timeout
        if timeout is not None:
            self.timeout=timeout
        buf=b''
        # if interactive is False:
        #     buf=Latin1_decode(self.sock.recv(n)) # have bugs; remote() have not considered remote-debug
        # else:
        #     try:                           # for interactive read
        #         buf=Latin1_decode(self.sock.recv(n))
        #     except socket.timeout:
        #         return buf
        try:
            if interactive is False:
                buf=self.sock.recv(n)
            else:
                buf=self.sock.recv(n)
        except socket.timeout:
            pass
        self.timeout=save_timeout
        return Latin1_decode(buf)
        # buf=Latin1_decode(buf)
        # return buf

    def write(self,buf):
        return self.sock.send(Latin1_encode(buf))
    def close(self):
        self.sock.close()
        self._is_exit=True
    def is_exit(self):
        if self._is_exit:
            return True
        return False
    def get_timeout(self):
        return self._timeout
    def set_timeout(self,timeout=None):
        self.sock.settimeout(float(timeout))
        self._timeout=timeout
    timeout=property(get_timeout,set_timeout)

class process(tube):
        def __init__(self,argv,pwd=None,flags=None):
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

            self.Process=winProcess(argv,pwd,flags)
            self.pid=self.Process.pid
        def read(self,n,timeout=None,interactive=False):
            buf=''
            if var.ter is not None and interactive is False:
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
        def get_timeout(self):
            return self.Process.timeout
        def set_timeout(self,timeout=None):
            if timeout is not None:
                self.Process.timeout=timeout
        timeout=property(get_timeout,set_timeout)
