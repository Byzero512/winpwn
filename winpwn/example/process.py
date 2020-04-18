from winpwn import *
context.log_level='debug'
context.arch='amd64'
context.log_level='debug'
is_debug=1
if is_debug:
    if context.arch=='amd64':
        p=process(['./dotest64.exe','aaaaaaaaaaaaa'])
        # windbg.attach(p)
        # x64dbg.attach(p)
        # gdb.attach(p)
        windbgx.attach(p)
    else:
        p=process('./dotest.exe')
        # windbg.attach(p)
        # gdb.attach(p)
        # x64dbg.attach(p)
        windbgx.attach(p)
else:
    if context.arch=='amd64':
        p=process('./dotest64.exe')
    else:
        p=process('./dotest.exe')

p.recvuntil('please input:\r\n')
p.interactive()