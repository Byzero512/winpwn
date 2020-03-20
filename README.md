## winpwn: mini pwntools for Windows
for CTF windows pwn


### pre
1. there are two versions of winpwn: winpwn-deps and winpwn-nodeps
2. winpwn-deps: based on pwintools, have bugs and will not update any more, need install from source.
3. winpwn-nodeps:
   + support python2 and python3
   + for basic function, just use ctypes to invoke Windows API. 


### install
1. install with pip
   + <b>pip install winpwn </b>
   + <b>or pip3 install winpwn</b>
2. other config
   + copy file: https://github.com/Byzero512/winpwn/blob/master/winpwn_nodeps/.winpwn to your windows HOMEDIR
   + configure path of debugger in ".winpwn"

### usage
```python
1. process
   + process("./pwn")
   + process(["./pwn"])
2. remote
   + remote("127.0.0.1", 65535)
   
3. context
   + context.timeout=512
   + context.debugger="gdb" # or "windbg" or "x64dbg"
   + context.endian="little"
   + context.log_level="" # or "debug"
   + context.terminal=[ ]
   + context.newline="\r\n"
   
4. dbg: gdb(mingw gdb), windbg, x64dbg
   + gdb.attach(p, script="b *0x401000")
   + windbg.attach(p,script="bp 0x123456")
   + x64dbg.attach(p) #can not parse script file yet
5. disable PIE: need "pip install pefile"
   + PIE(exe_fpath="")
   + NOPIE(exe_fpath="")
6. asm/disasm, need keystone/capstone, need "pip install keystone/capstone"
   + asm("push ebp")
   + disasm("\x55")
```

### configure
if you want to use debugger like gdb-peda, you need to deal with the deps yourself

#### mingw-gdb
for gdb-peda like show  as bellow, you need:
1. mingw-gdb installer: 
+ https://sourceforge.net/projects/mingw-w64/files/External%20binary%20packages%20%28Win64%20hosted%29/gdb/
2. https://github.com/Byzero512/wibe (a gdb-peda like gdb-script supports mingw-gdb on windows)
3. https://github.com/Byzero512/vmmap-win-cmd (for the command "vmmap" in wibe)

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
