from winpwn import *
# windbgx.com("\\\\.\\pipe\\bcn_com","bp 0;")
p=remote("192.168.47.148",445)
p.interactive()