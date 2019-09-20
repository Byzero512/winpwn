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

from ctypes import windll,byref,sizeof,wintypes,create_string_buffer,GetLastError
from ctypes.wintypes import HANDLE,LPVOID,LPSTR,DWORD,WORD,BOOL,BYTE
from ctypes import POINTER,Structure

from context import context
from misc import parse,Latin1_encode,Latin1_decode

# some var to CreatePipe or CreateProcessA
HANDLE_FLAG_INHERIT=1
STARTF_USESTDHANDLES=256
STILL_ACTIVE=259

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

# def Latin1_encode(string):
#     if sys.version_info[0]==3:
#         return bytes(string,'utf-8')
#     return str(string)

class winPipe():
    def __init__(self,bInheritHandle = 1):
        self.timeout=context.timeout
        self.tick=context.tick
        self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe=self.create(bInheritHandle=bInheritHandle)
        # if context.timeout:
        #     self.timeout=context.timeout

    def create(self,bInheritHandle = 1):
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
            raise(EOFError(parse.color("[-]: Create Pipe error",'red')))

    def read(self,n,timeout=None):
        def count():
            byteAvail=wintypes.DWORD()
            x=windll.kernel32.PeekNamedPipe(self.hReadPipe,0,0,0,byref(byteAvail),0)

            return byteAvail.value
        if timeout is None:
            timeout=self.timeout
        x_time=0
        if count()<n:
            while(x_time<timeout and count()<n):
                time.sleep(float(self.tick))
                x_time+=self.tick
        cn=min(count(),n)
        beenRead=wintypes.DWORD()
        buf=create_string_buffer(cn)
        if cn>0:
            windll.kernel32.ReadFile(self.hReadPipe,buf,cn,byref(beenRead),None)
        # if sys.version_info[0]==3:
        #     return str(buf.raw,'Latin1')
        # return str(buf.raw)
        return Latin1_decode(buf.raw)

    def write(self,buf=''):
        length=len(buf)
        written=wintypes.DWORD()
        x=windll.kernel32.WriteFile(self.hWritePipe,buf,length,byref(written),None)
        if x==0:
            raise(EOFError())
        return written.value
    
    def getHandle(self):
        return (self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe)

    def close(self):
        windll.kernel32.CloseHandle(self.hReadPipe)
        windll.kernel32.CloseHandle(self.hWritePipe)

    def debug(self):
        print("winPipe timeout: ",self.timeout)
        print("winPipe tick: ",self.tick)

class winProcess(object):
    def __init__(self,argv,pwd=None,flags=0):

        self.pipe=winPipe()
        self.hReadPipe,self.hWritePipe,self.child_hReadPipe,self.child_hWritePipe=self.pipe.getHandle()
        self.pid=0
        self.phandle=0
        self.create(argv,pwd,flags)

    def create(self,argv,pwd=None,flags=None):
        lpCurrentDirectory=pwd
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
            # windll.kernel32.CloseHandle(lpProcessInformation.hThread)
            self.pid=lpProcessInformation.dwProcessId
            self.phandle=lpProcessInformation.hProcess
            print("process runing, pid: {}".format(hex(self.pid)))
        except:
            raise(EOFError(parse.color("[-]: Create process error",'red')))

    def read(self,n,timeout=None):
        return self.pipe.read(n,timeout=timeout)
    def write(self,buf):
        return self.pipe.write(Latin1_encode(buf))
    def is_exit(self):
        x=wintypes.DWORD()
        n=windll.kernel32.GetExitCodeProcess(self.phandle,byref(x))
        if n!=0 and x.value==STILL_ACTIVE:
            return False
        return True
    def close(self):           # need to kill process ..............
        self.pipe.close()
        windll.kernel32.TerminateProcess(self.phandle,1)
    def readMem(self):
        pass
    def writeMem(self):
        pass      
    def get_timeout(self):
        return self.pipe.timeout
    def set_timeout(self,timeout=None):
        # if timeout is not None:
        self.pipe.timeout=timeout
    # an property to set global timeout of the pipe
    timeout=property(get_timeout,set_timeout)
    def debug(self):
        print("winProcess timeout: ",self.timeout)