## winpwn: mini pwntools for Windows
for CTF windows pwn and IAT/EAT hook


### pre
1. support python2 and python3
2. support windbg/windbgx/x64dbg/mingw-gdb

### install
> use pip or pip3

### install with pip
<b>pip install winpwn </b>
### config for debug
1. copy file [.winpwn](./.winpwn) to windows <b>HOMEDIR</b>
2. then configure it yourself
3. optional:
   + pip install pefile
   + pip install keystone
   + pip install capstone

### usage
```python
1. process
   + process("./pwn")
   + process(["./pwn","argv[1]","argv[2]"])
   + p.readm(addr,n) # read process memory
   + p.writem(addr,con="") # write process memory
2. remote
   + remote("127.0.0.1", 65535)

3. context
   + context.timeout=512
   + context.debugger="gdb" # or "windbg" or "x64dbg"
   + context.endian="little"
   + context.log_level="" # or "debug"
   + context.terminal=[ ]
   + context.newline="\r\n"
   + context.arch="i386" # or "amd64"
   + content.pie=None
   + context.dbginit=None # used to set debugger init script
   + context.windbg=None # set debugger path, or use .winpwn to find debugger path
   + context.windbgx=None
   + content.gdb=None
   + context.x64dbg=None
   
4. dbg: gdb(mingw gdb), windbg, x64dbg
   + windbgx.attach(p,script="bp 0x401000")
   + windbg.attach(p,script="bp 0x401000")
   + gdb.attach(p, script="b *0x401000")
   + x64dbg.attach(p) #can not parse script file yet

5. disable PIE: need "pip install pefile"
   + PIE(exe_fpath="")
   + NOPIE(exe_fpath="")
6. asm/disasm, need "pip install keystone/capstone"
   + asm("push ebp")
   + disasm("\x55")
   
7. winfile(fpath="./main.exe"), need "pip install pefile"
   + winfile.symbols["CreateProcessA"] # return symbol's IAT/EAT offset of CreateProcessA by image base
```

### configure
if you want to use debugger like gdb-peda, you need to deal with the deps yourself

#### windbgx/windbg
1. [pykd](https://githomelab.ru/pykd/pykd)
2. [bywin](https://github.com/Byzero512/debugger-scripts/tree/master/windbgx/bywin)

#### mingw-gdb
1. [wibe](https://github.com/Byzero512/wibe) (gdb-peda like; just support python2)

## photos

### windbg

![windbgx](./img/windbgx.png)

### mingw gdb

![gdb](./img/winpwn1.png)

### x64dbg
> because lacks some commandline options, so just can use x64dbg attach to process and can not deliver init script yet

### refs
1. https://github.com/masthoon/pwintools
2. https://github.com/hakril/PythonForWindows
