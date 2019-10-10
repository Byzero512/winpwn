from winpwn import *
context.log_level='debug'
context.arch="amd64"
# context.terminal=['ConEmu.exe']
# context.timeout=10000

p = process("./test1.exe")
# gdb.attach(p)
# p.recvuntil("0000000000404000")
p.recvn(100)
p.interactive()