from winpwn import *
context.log_level='debug'
context.arch='amd64'
# is_debug=0
# if is_debug:
#     if context.arch=='amd64':
#         p=process(['./dotest64.exe'])
#         # windbg.attach(p,'.echo 0000')
#         # gdb.attach(p) 
#     else:
#         p=process('./dotest.exe')
#         # windbg.attach(p,'.echo 0000')
#         # gdb.attach(p)
# else:
#     if context.arch=='amd64':
#         p=process('./dotest64.exe')
#     else:
#         p=process('./dotest.exe')

# p.recvuntil('please input:\r\n')
# p.sendline('aaaaaaaaaa')
# p.recvline()
# p.interactive()

p=remote('39.108.134.72',1236)
print(p.recv(100))
p.send('11111111111')
p.interactive()