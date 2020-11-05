# -*- coding=Latin1 -*-
# ctypes:
#   create_string_buffer
#   create_unicode_buffer
# windll.kernel32.CreateProcessA
# windll.kernel32.CreatePipe
# windll.kernel32.PeekNamedPipe
# windll.kernel32.ReadFile
# windll.kernel32.WriteFile
# windll.kernel32.SetHandleInformation
# windll.kernel32.GetStdHandle
# windll.kernel32.CloseHandle

import os
import sys
import time

from ctypes import windll,byref,sizeof,wintypes,create_string_buffer,GetLastError,c_size_t
from ctypes.wintypes import HANDLE,LPVOID,LPSTR,DWORD,WORD,BOOL,BYTE
from ctypes import POINTER,Structure

from .context import context
from .misc import Latin1_encode,Latin1_decode,color,showbanner

# some var to CreatePipe or CreateProcessA
HANDLE_FLAG_INHERIT=1
STARTF_USESTDHANDLES=256
STILL_ACTIVE=259
CREATE_SUSPENDED=0x4
PROCESS_VM_READ=0x10
PROCESS_VM_WRITE=0x20
PROCESS_VM_OPERATION=0x8
PAGE_READWRITE=0x4

# for createPipe
class SECURITY_ATTRIBUTES(Structure):
    _fields_= [
        ('nLength',DWORD),
        ('lpSecurityDescriptor',LPVOID),
        ('bInheritHandle',BOOL),
    ]
# for createProcess
class PROCESS_INFORMATION(Structure):
    _fields_= [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId',DWORD),
        ('dwThreadId',DWORD),
    ]
# for createProcess
class STARTUPINFO(Structure):
    _fields_=[
        ('cb',DWORD),
        ('lpReserved',LPSTR),
        ('lpDesktop',LPSTR),
        ('lpTitle',LPSTR),
        ('dwX',DWORD),
        ('dwY',DWORD),
        ('dwXSize',DWORD),
        ('dwYSize',DWORD),
        ('dwXCountChars',DWORD),
        ('dwYCountChars',DWORD),
        ('dwFillAttribute',DWORD),
        ('dwFlags',DWORD),
        ('wShowWindow',WORD),
        ('cbReserved2',WORD),
        ('lpReserved2',POINTER(BYTE)),
        ('hStdInput',HANDLE),
        ('hStdOutput',HANDLE),
        ('hStdError',HANDLE),
    ]

# class winApi():
    # @classmethod
    # def VirtualAllocEx(clx):
    #     pass
    # @classmethod
    # def VirtualFreeEx(clx,addr,size):
    #     pass
    # @classmethod
    # def GetModuleHandle(clx):
    #     pass
    # @classmethod
    # def VirtualProtectEx(clx,hProcess,addr,size,protect,oldprotect):
    #     return windll.kernel32.VirtualProtectEx(hProcess,)
    # @classmethod
    # def ReadProcessMemory(clx,hProcess,addr,n):
    #     beenRead=wintypes.DWORD()
    #     buf=create_string_buffer(n)
    #     x=windll.kernel32.ReadProcessMemory(self.hProcess,addr,buf,n,byref(beenRead))
    #     if x==0:
    #         raise(EOFError())
    #     return Latin1_decode(buf.raw)
    # @classmethod
    # def WriteProcessMemory(clx,hProcess,addr,buf):
    #     n=len(buf)
    #     written=wintypes.DWORD()
    #     x=windll.kernel32.WriteProcessMemory(self.hProcess,addr,buf,n,byref(written))
    #     if x==0:
    #         raise(EOFError())
    #     return written.value
    # @classmethod
    # def ResumeThread(clx,hThread):
    #     return windll.kernel32.ResumeThread(hThread)

class winPipe():
    def __init__(self,bInheritHandle = 1):
        """
        Initialize a new child.

        Args:
            self: (todo): write your description
            bInheritHandle: (todo): write your description
        """
        self.timeout=context.timeout
        self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe=self.create(bInheritHandle=bInheritHandle)

    def create(self,bInheritHandle = 1):
        """
        Creates a c { pipe } instance.

        Args:
            self: (int): write your description
            bInheritHandle: (int): write your description
        """
        # set attr
        attr=SECURITY_ATTRIBUTES()
        attr.lpSecurityDescriptor=0
        attr.bInheritHandle = bInheritHandle
        attr.nLength = sizeof(attr)

        hReadPipe=wintypes.HANDLE()      # father read, child write
        hWritePipe=wintypes.HANDLE()     # father write, child read
        child_hReadPipe=wintypes.HANDLE()
        child_hWritePipe=wintypes.HANDLE()

        rs1=windll.kernel32.CreatePipe(byref(hReadPipe),byref(child_hWritePipe),byref(attr),0)
        rs2=windll.kernel32.CreatePipe(byref(child_hReadPipe),byref(hWritePipe),byref(attr),0)
        
        rs3=windll.kernel32.SetHandleInformation(hReadPipe.value,HANDLE_FLAG_INHERIT,0)
        rs4=windll.kernel32.SetHandleInformation(hWritePipe.value,HANDLE_FLAG_INHERIT,0)

        if(rs1 and rs2 and rs3 and rs4):
            return (hReadPipe.value,hWritePipe.value,child_hReadPipe.value,child_hWritePipe.value)
        else:
            raise(EOFError(color("[-]: Create Pipe error",'red')))

    def read(self,n,timeout=None):
        """
        Read up to n bytes from the device.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (todo): write your description
        """
        def count():
            """
            Return the total number of the number.

            Args:
            """
            byteAvail=wintypes.DWORD()
            x=windll.kernel32.PeekNamedPipe(self.hReadPipe,0,0,0,byref(byteAvail),0)
            return byteAvail.value
        if timeout is None:
            if self.timeout:
                timeout=self.timeout
            else:
                timeout=context.timeout
        x_time=0
        if count()<n:
            while(x_time<timeout and count()<n):
                time.sleep(context.tick)
                x_time+=context.tick
        cn=min(count(),n)
        beenRead=wintypes.DWORD()
        buf=create_string_buffer(cn)
        if cn>0:
            windll.kernel32.ReadFile(self.hReadPipe,buf,cn,byref(beenRead),None)
        return Latin1_decode(buf.raw)

    def write(self,buf=''):
        """
        Writes bytes from the buffer.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        buf=Latin1_encode(buf)
        length=len(buf)
        written=wintypes.DWORD()
        x=windll.kernel32.WriteFile(self.hWritePipe,buf,length,byref(written),None)
        if x==0:
            raise(EOFError())
        return written.value
    
    def getHandle(self):
        """
        Get the child of the child.

        Args:
            self: (todo): write your description
        """
        return (self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe)

    def close(self):
        """
        Close the kernel.

        Args:
            self: (todo): write your description
        """
        # windll.kernel32.CloseHandle(self.child_hReadPipe)
        # windll.kernel32.CloseHandle(self.child_hWritePipe)
        windll.kernel32.CloseHandle(self.hReadPipe)
        windll.kernel32.CloseHandle(self.hWritePipe)

class winProcess(object):
    def __init__(self,argv,cwd=None,flags=0):
        """
        Initialize the pid.

        Args:
            self: (todo): write your description
            argv: (list): write your description
            cwd: (int): write your description
            flags: (int): write your description
        """
        self.pipe=winPipe()
        self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe=self.pipe.getHandle()
        self.pid=0
        self.phandle=0
        self.tid=0
        self.thandle=0
        self.create(argv,cwd,flags)
    def create(self,argv,cwd=None,flags=None):
        """
        Create a process.

        Args:
            self: (int): write your description
            argv: (list): write your description
            cwd: (int): write your description
            flags: (int): write your description
        """
        lpCurrentDirectory=cwd
        lpEnvironment=None
        dwCreationFlags=flags
        bInheritHandles=True
        lpProcessAttributes=None
        lpThreadAttributes=None

        lpProcessInformation = PROCESS_INFORMATION()

        StartupInfo = STARTUPINFO()
        StartupInfo.cb = sizeof(StartupInfo)

        StartupInfo.dwFlags = STARTF_USESTDHANDLES
        StartupInfo.hStdInput = self.child_hReadPipe
        StartupInfo.hStdOutput =self.child_hWritePipe
        StartupInfo.hStdError = self.child_hWritePipe
        
        lpStartupInfo = byref(StartupInfo)
        
        lpCommandLine =  None
        lpApplicationName = None

        if not isinstance(argv,list):
            lpApplicationName = Latin1_encode(argv)
        else:
            lpCommandLine = Latin1_encode((" ".join([str(a) for a in argv])))
        try: 
            bs=windll.kernel32.CreateProcessA(
                lpApplicationName,          
                lpCommandLine,              
                lpProcessAttributes,        
                lpThreadAttributes,         
                bInheritHandles,            
                dwCreationFlags,            
                lpEnvironment,              
                lpCurrentDirectory,         
                byref(StartupInfo),         
                byref(lpProcessInformation)
            )
            self.pid=lpProcessInformation.dwProcessId
            self.phandle=lpProcessInformation.hProcess
            self.tid=lpProcessInformation.dwThreadId
            self.thandle=lpProcessInformation.hThread
            showbanner('Create process success #pid 0x{:x}'.format(self.pid))
        except:
            raise(EOFError(color("[-]: Create process error",'red')))

    def read(self,n,timeout=None):
        """
        Read at most n bytes from the socket.

        Args:
            self: (todo): write your description
            n: (todo): write your description
            timeout: (todo): write your description
        """
        return self.pipe.read(n,timeout=timeout)
    def write(self,buf):
        """
        Write the given bytes.

        Args:
            self: (todo): write your description
            buf: (str): write your description
        """
        return self.pipe.write(buf)
    def is_exit(self):
        """
        Check if the exit is running.

        Args:
            self: (todo): write your description
        """
        x=wintypes.DWORD()
        n=windll.kernel32.GetExitCodeProcess(self.phandle,byref(x))
        if n!=0 and x.value==STILL_ACTIVE:
            return False
        return True
    def close(self):           # need to kill process ..............
        """
        Closes the kernel.

        Args:
            self: (todo): write your description
        """
        self.pipe.close()
        windll.kernel32.TerminateProcess(self.phandle,1)
    def readm(self,addr,n):
        """
        Reads memory from memory.

        Args:
            self: (todo): write your description
            addr: (todo): write your description
            n: (todo): write your description
        """
        addr=c_size_t(addr)
        handle=windll.kernel32.OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,0,self.pid)
        oldprotect=wintypes.DWORD()
        x=windll.kernel32.VirtualProtectEx(handle,addr,n,PAGE_READWRITE,byref(oldprotect))
        
        buf=create_string_buffer(n)
        
        x=windll.kernel32.ReadProcessMemory(handle,addr,buf,n,0)
        if x==0:
            raise(MemoryError)

        windll.kernel32.VirtualProtectEx(handle,addr,n,oldprotect.value,0)
        windll.kernel32.CloseHandle(handle)

        return Latin1_decode(buf.raw)

    def writem(self,addr,buf):
        """
        Writes the pid file.

        Args:
            self: (todo): write your description
            addr: (str): write your description
            buf: (str): write your description
        """
        buf=Latin1_encode(buf)
        addr=c_size_t(addr)
        n=len(buf)
        # print(n)
        handle=windll.kernel32.OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,0,self.pid)
        
        oldprotect=wintypes.DWORD()
        x=windll.kernel32.VirtualProtectEx(handle,addr,n,PAGE_READWRITE,byref(oldprotect))
        written=c_size_t(0)
        x=windll.kernel32.WriteProcessMemory(handle,addr,buf,n,byref(written))
        if x==0:
            raise(MemoryError)
        
        windll.kernel32.VirtualProtectEx(handle,addr,n,oldprotect.value,0)
        windll.kernel32.CloseHandle(handle)

        return written.value