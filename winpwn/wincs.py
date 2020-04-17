import socket
import threading
import os
import sys

from .winpwn import remote
from .asm import asm as ASM
from .asm import disasm as DISASM
from .misc import u32,p32,u64,p64,Latin1_encode,Latin1_decode,showbanner,showbuf
from .context import context

class wincs():
    def __init__(self,ip=None,port=512):
        self.winser_socket=None
        self.wincli_socket=None
        if ip is None: # server
            self.winser_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.winser_socket.bind((socket.gethostname(), port))
            self.winser_socket.listen(5)
            threading.Thread(target=self.__winser_thread).start()
        else: # client
            self.wincli_socket=remote(ip,port)
    def __winser_thread(self):
        while(True):
            (conn, client) = self.winser_socket.accept()
            threading.Thread(target=self.__winser_connect,args=(conn, client)).run()

    def __winser_connect(self,conn,client):
        # (conn, client) = args            
        while(1):
            # [0:1]-> opcode;
            opcode=Latin1_decode(conn.recv(1))
            if opcode=='':
                showbanner('wincs connection of {} closed'.format(client),'yellow','end')
                return
            if opcode=='\x03':
                self.winser_socket.close()
                showbanner('wincs server closd','yellow','end')
                return
            else:
                # [0:1]->opcode; [1:5]->arch; [5:13]->addr [13:22]->length; [22:22+length]->asmcode/machinecode
                arch=Latin1_decode(conn.recv(4))
                addr=u64(Latin1_decode(conn.recv(8)))
                length=u32(Latin1_decode(conn.recv(4)))
                code=Latin1_decode(conn.recv(length))
                is_asm=opcode=='\x01'
                if is_asm:
                    markstr='asming'
                else:
                    markstr='disasming'
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
            markstr='asming'
            opcode='\x01'
        else:
            markstr='disasming'
            opcode='\x02'
        showbanner(markstr)
        showbuf(code)
        self.wincli_socket.write(
            Latin1_encode(
            opcode+arch.ljust(4,'\x00')+p64(addr)+p32(len(code))+code
            )
        )
        rs=self.wincli_socket.read(
            u32(self.wincli_socket.read(4))
        )
        showbanner(markstr+' result')
        showbuf(rs)
        return rs

    def asm(self,asmcode,addr=0,arch=None):
        return self.__asm_disasm(code=asmcode,addr=addr,arch=arch,is_asm=True)
    def disasm(self,machinecode,addr=0,arch=None):
        return self.__asm_disasm(code=asmcode,addr=addr,arch=arch,is_asm=False)
    def close(self): # just close connect
        self.wincli_socket.close()
    def close_server(self):
        self.wincli_socket.send(Latin1_encode('\x03'))