from winpwnn import *
context.log_level='debug'
context.arch='amd64'
# context.terminal=['ConEmu.exe']
# context.timeout=10000
is_debug=1
if is_debug:
    if context.arch=='amd64':
        p=process('./dotest64.exe')
        windbg.attach(p,'.echo 0000')
        # gdb.attach(p) 
    else:
        p=process('./dotest.exe')
        windbg.attach(p,'.echo 0000')
        # gdb.attach(p)
else:
    if context.arch=='amd64':
        p=process('./dotest64.exe')
    else:
        p=process('./dotest.exe')
p.recvuntil('please input:\r\n')
p.sendline('aaaaaaaaaa')
p.recvline()
p.send('123456')
p.interactive()