# -*- coding=Latin1 -*-
import platform

import threading
import sys
import socket
import time
import os

from .win import winProcess
from .context import context
from .misc import Latin1_encode,Latin1_decode,NOPIE,PIE,color,showbanner,showbuf

class tube(object):
    def __init__(self):
        """
        Initialize a new thread.

        Args:
            self: (todo): write your description
        """
        self._timeout=context.timeout
        self.debugger=None
        
    def read(self,n,timeout=None,interactive=False):
        """
        Read up to n bytes.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (todo): write your description
            interactive: (todo): write your description
        """
        pass
    def write(self,buf):
        """
        Write a buffer.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        pass
    def is_exit(self,buf):
        """
        Is the given buffer?

        Args:
            self: (todo): write your description
            buf: (todo): write your description
        """
        pass
    @property
    def timeout(self):
        """
        The timeout.

        Args:
            self: (todo): write your description
        """
        return self._timeout
    @timeout.setter
    def timeout(self,timeout):
        """
        Waits the given timeout.

        Args:
            self: (todo): write your description
            timeout: (float): write your description
        """
        pass             
    def send(self,buf):
        """
        Send a buffer to the device.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        showbanner('Send')
        rs=self.write(buf)
        showbuf(buf)
        return rs
    
    def sendline(self,buf,newline=None):
        """
        Send a newline.

        Args:
            self: (todo): write your description
            buf: (str): write your description
            newline: (str): write your description
        """
        if newline is None:
            newline=context.newline
        return self.send(buf+newline)

    def recv(self,n,timeout=None):
        """
        Receive n bytes from the socket.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (float): write your description
        """
        # try to read n bytes, no exception
        showbanner('Recv')
        buf=self.read(n, timeout)
        showbuf(buf)
        return buf

    def recvn(self,n,timeout=None):
        """
        Receive a message from the socket

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (float): write your description
        """
        # must recv n bytes within timeout
        showbanner("Recv")
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise(EOFError(color("[-]: Timeout when use recvn",'red')))
        showbuf(buf)
        return buf
    
    def recvuntil(self,delim,timeout=None):
        """
        Receive a message from the socket.

        Args:
            self: (todo): write your description
            delim: (str): write your description
            timeout: (float): write your description
        """
        showbanner("Recv")
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
            raise(EOFError(color("[-]: Recvuntil error",'red')))
        showbuf(buf)
        return buf

    def recvline(self,timeout=None,newline=None):
        """
        Receive a line from the socket.

        Args:
            self: (todo): write your description
            timeout: (float): write your description
            newline: (todo): write your description
        """
        if newline is None:
            newline=context.newline
        return self.recvuntil(newline)

    def recvall(self,timeout=None):
        """
        Receive a message from the socket.

        Args:
            self: (todo): write your description
            timeout: (float): write your description
        """
        showbanner('Recv')
        buf=self.read(0x100000, timeout)
        showbuf(buf)
        return buf   

    # based on read/write
    def interactive(self):
        """
        Main loop.

        Args:
            self: (todo): write your description
        """
        # it exited, contrl+C, timeout
        showbanner('Interacting',is_noout=False)
        go = threading.Event()
        go.clear()
        def recv_thread():
            """
            Reads a message

            Args:
            """
            try:                  
                while not go.is_set():
                    buf = self.read(0x10000,0.125,interactive=True)
                    if buf:
                        showbuf(buf,is_noout=False)
                        showbanner('Interacting',is_noout=False)
                    go.wait(0.2)
            except KeyboardInterrupt:
                go.set()
                print(color('[-]: Exited','red'))
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
                        self.write(buf)           # remote.write() may cause exception
                except:
                    go.set()
                    print(color('[-]: Exited','red'))
                    break
        except KeyboardInterrupt: # control+C
            go.set()
            print(color('[-]: Exited','red'))
        while t.is_alive():
            t.join(timeout = 0.1)

class remote(tube):
    def __init__(self, ip, port, family = socket.AF_INET, socktype = socket.SOCK_STREAM):
        """
        Initialize the socket.

        Args:
            self: (todo): write your description
            ip: (str): write your description
            port: (int): write your description
            family: (todo): write your description
            socket: (todo): write your description
            AF_INET: (int): write your description
            socktype: (todo): write your description
            socket: (todo): write your description
            SOCK_STREAM: (str): write your description
        """
        tube.__init__(self)
        self.sock = socket.socket(family, socktype)
        # self.ip = ip
        # self.port = port
        self._is_exit=False
        try:
            showbanner("Connecting to ({},{})".format(ip,port))
            self.sock.settimeout(self.timeout)
            self.sock.connect((ip, port))
        except:
            raise(EOFError(color("[-]: Connect to ({},{}) failed".format(ip,port),'red')))
    def read(self,n,timeout=None,interactive=False):
        """
        Read exactly n bytes from the socket.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (todo): write your description
            interactive: (todo): write your description
        """
        if timeout is not None:
            self.sock.settimeout(timeout)
        buf=b''
        try:
            buf=self.sock.recv(n) # ignore timeout error
        except KeyboardInterrupt:
            self.close()
            raise(EOFError(color("[-]: Exited by CTRL+C",'red')))
        except:
            pass
        self.sock.settimeout(self.timeout)
        return Latin1_decode(buf)
    def write(self,buf):
        """
        Write the given number of bytes to the socket.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        return self.sock.send(Latin1_encode(buf))
    def close(self):
        """
        Close the socket.

        Args:
            self: (todo): write your description
        """
        self.sock.close()
        self._is_exit=True
    def is_exit(self):
        """
        Returns true if the exit is closed.

        Args:
            self: (todo): write your description
        """
        if self._is_exit:
            return True
        return False
    @tube.timeout.setter
    def timeout(self,timeout):
        """
        Sets the timeout of the connection.

        Args:
            self: (todo): write your description
            timeout: (float): write your description
        """
        self._timeout=timeout
        self.sock.settimeout(self._timeout)

class process(tube):
    def __init__(self,argv,cwd=None,flags=None):
        """
        Initialize the process.

        Args:
            self: (todo): write your description
            argv: (list): write your description
            cwd: (int): write your description
            flags: (int): write your description
        """
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
        """
        Read up to n bytes from the socket.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (todo): write your description
            interactive: (todo): write your description
        """
        buf=''
        try:
            if self.debugger is not None and interactive is False:
                while(len(buf)!=n):
                    buf+=self.Process.read(n-len(buf),timeout)
            else:
                buf=self.Process.read(n, timeout)
        except KeyboardInterrupt:
            self.close()
            raise(EOFError(color("[-]: Exited by CTRL+C",'red')))       
        return buf
    def write(self, buf):
        """
        Write the given buffer to the buffer.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        return self.Process.write(buf)
    def readm(self,addr,n):
        """
        Read n bytes from the socket.

        Args:
            self: (todo): write your description
            addr: (todo): write your description
            n: (todo): write your description
        """
        return self.Process.readm(addr,n)
    def writem(self,addr,con):
        """
        Writes the given address.

        Args:
            self: (todo): write your description
            addr: (str): write your description
            con: (todo): write your description
        """
        return self.Process.writem(addr,con)
    def close(self):
        """
        Closes the socket.

        Args:
            self: (todo): write your description
        """
        self.Process.close()        # need to kill process
    def is_exit(self):
        """
        Returns true if the exit is exit false otherwise.

        Args:
            self: (todo): write your description
        """
        return self.Process.is_exit()
    @tube.timeout.setter
    def timeout(self,timeout):
        """
        Waits the request todo.

        Args:
            self: (todo): write your description
            timeout: (float): write your description
        """
        self._timeout=timeout
        self.Process.pipe.timeout=timeout