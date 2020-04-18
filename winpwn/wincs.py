import socket
import threading
import os
import sys

from .winpwn import remote
from .asm import asm as ASM
from .asm import disasm as DISASM
from .misc import u32,p32,u64,p64,Latin1_encode,Latin1_decode,showbanner,showbuf,color
from .context import context

class wincs():
    def __init__(self,ip=None,port=512):
        self.wins=None
        self.winc=None
        if ip is None: # server
            self.wins = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.wins.bind((socket.gethostname(), port))
            self.wins.listen(5)
            threading.Thread(target=self.__winser_thread).start()
        else: # client
            self.winc=remote(ip,port)
    def __winser_thread(self):
        try:
            while(True):
                (conn, client) = self.wins.accept() # need to used select not accept.
                threading.Thread(target=self.__handle_conn,args=(conn, client)).start()
        except KeyboardInterrupt:
            raise(EOFError(color("[-]: Exited by CTRL+C",'red')))

    def __handle_conn(self,conn,client):
        # (conn, client) = args            
        while(1):
            # [0:1]-> opcode;
            opcode=Latin1_decode(conn.recv(1))
            if opcode=='':
                showbanner('wincs connection of {} closed'.format(client),'yellow','[-]')
                return
            if opcode=='\x03':
                self.wins.close()
                showbanner('wincs server closed','yellow','[-]')
                # raise(EOFError(color("[-]: wincs server closed",'red')))
                quit()
            else:
                # [0:1]->opcode; [1:5]->arch; [5:13]->addr [13:22]->length; [22:22+length]->asmcode/machinecode
                arch=Latin1_decode(conn.recv(4))
                addr=u64(Latin1_decode(conn.recv(8)))
                length=u32(Latin1_decode(conn.recv(4)))
                code=Latin1_decode(conn.recv(length))
                is_asm=opcode=='\x01'
                if is_asm:
                    markstr='asm'
                else:
                    markstr='disasm'
                showbanner('wincs '+markstr)
                showbuf(code)
                if is_asm:
                    rs=ASM(code,addr=addr,arch=arch)
                else:
                    rs=DISASM(code,addr=addr,arch=arch)
                showbanner('wincs '+markstr+' result')
                showbuf(rs)
                conn.send(
                    Latin1_encode(
                        p32(len(rs))+rs
                    )
                )  

    def __asm_disasm(self,code,addr,arch=None,is_asm=True):
        if arch is None:
            arch=context.arch
        if is_asm:
            markstr='asm'
            opcode='\x01'
        else:
            markstr='disasm'
            opcode='\x02'
        showbanner(markstr)
        showbuf(code)

        self.winc.write(
            opcode+arch.ljust(4,'\x00')+p64(addr)+p32(len(code))+code
        )
        rs=self.winc.read(
            u32(self.winc.read(4))
        )
        showbanner(markstr+' result')
        showbuf(rs)
        return rs

    def asm(self,asmcode,addr=0,arch=None):
        return self.__asm_disasm(code=asmcode,addr=addr,arch=arch,is_asm=True)
    def disasm(self,machinecode,addr=0,arch=None):
        return self.__asm_disasm(code=machinecode,addr=addr,arch=arch,is_asm=False)
    def close(self): # just close connect
        self.winc.close()
    def close_server(self):
        self.winc.send('\x03')