## winpwn: mini pwntools for Windows
for CTF windows pwn


### pre
1. there are two versions of winpwn: winpwn-deps and winpwn-nodeps
2. winpwn-deps: based on pwintools, have bugs and will not update any more, need install from source.
3. winpwn:
   + support python2 and python3
   + for basic function, just use ctypes to invoke Windows API. 
   + please run it with <b>cmder(CMD not Bash)</b> if you want to debug


### install
1. install with pip
   + <b>pip install winpwn </b>
   + <b>or pip3 install winpwn</b>
2. other config
   + copy file: https://github.com/Byzero512/winpwn/blob/master/winpwn_nodeps/.winpwn to your windows HOMEDIR and configure it yourself

optional:
ppip install pefile
pip install keystone
pip install capstone

### usage
```python
1. process
   + process("./pwn")
   + process(["./pwn"])
   + p.readm(addr,n) read process memory
   + p.writem(addr,con="") write process memory
2. remote
   + remote("127.0.0.1", 65535)
   
3. context
   + context.timeout=512
   + context.debugger="gdb" # or "windbg" or "x64dbg"
   + context.endian="little"
   + context.log_level="" # or "debug"
   + context.terminal=[ ]
   + context.newline="\r\n"
   + context.arch="i386"
   
4. dbg: gdb(mingw gdb), windbg, x64dbg
   + gdb.attach(p, script="b *0x401000")
   + windbg.attach(p,script="bp 0x123456")
   + x64dbg.attach(p) #can not parse script file yet
5. disable PIE: need "pip install pefile"
   + PIE(exe_fpath="")
   + NOPIE(exe_fpath="")
6. asm/disasm, need "pip install keystone/capstone"
   + asm("push ebp")
   + disasm("\x55")
7. winfile(fpath="./main.exe"), need "pip install pefile"
   + winfile.symbols["CreateProcessA"]: return symbol's IAT/EAT offset of CreateProcessA by image base
```

### configure
if you want to use debugger like gdb-peda, you need to deal with the deps yourself

#### mingw-gdb
1. https://github.com/Byzero512/wibe (gdb-peda like; just support python2)

#### windbg
1. pykd
2. TWindbg: https://github.com/bruce30262/TWindbg


## photos

### mingw gdb

![gdb](./img/winpwn1.png)

### windbg

![windbg](./img/winpwn2.png)

### x64dbg
> because lacks some commandline options, so just can use x64dbg attach to process and can not deliver init script yet
