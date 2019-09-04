from winpwn import *
context.log_level='debug'
context.arch='i386'
# context.terminal=['ConEmu.exe']
context.timeout=10000
is_debug=1
if is_debug:
    if context.arch=='amd64':
        p=process('./dotest64.exe')
        gdb.attach(p) 
    else:
        p=process('./dotest.exe')
        gdb.attach(p)
else:
    if context.arch=='amd64':
        p=process('./dotest64.exe')
    else:
        p=process('./dotest.exe')
        
p.recvuntil('please input:\r\n')
# pause()
# p.sendline('aaaaaaaaaaaaaaaa')
p.interactive()