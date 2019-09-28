## winpwn: mini pwntools for Windows
for CTF windows pwn

### pre
1. there are two versions of winpwn: winpwn-deps and winpwn-nodeps
2. for winpwn-deps: 
   + based on pwintools,but I complete the IO interactive and debug module
   + have bug, and I will not update it anymore, so I suggest you use winpwn-nodeps
   + not support python3 and just can install from source code
3. for winpwn-nodeps: written by myself. 
   + just use ctypes to invoke Windows API. 
   + support python2.7 and python3
   + <b>can use pip to install winpwn-nodeps</b>


## install
1. for debug
   + if you install by source code, modify the PATH of debugger in <b>winpwn/var.py</b>
   + or if you use winpwn-nodeps, touch a json file in HOMEDIR(named "<b>.winpwn</b>") whose content format refers winpwn-nodeps/.winpwn
2. <b>I just test winpwn on cmder</b>(if use cmder , please must use it on <b>"cmd::cmder as Admin"</b>, not bash)

### winpwn-nodeps

#### install with pip
   + <b>pip install winpwn </b>
   + <b>or pip3 install winpwn</b>

#### install from source code
1. git clone  https://github.com/Byzero512/winpwn.git
2. cd winpwn\winpwn-nodeps
3. python setup.py install / python3 setup.py install

### usage
```python
1. process
   + process("./pwn")
   + process(["./pwn"])
2. remote
   + remote("127.0.0.1", 65535)
   
3. context
   + context.timeout=1000
   + context.debugger="gdb"
   + context.endian="little"
   + context.log_level=""
   + context.terminal=[ ]
   + context.newline="\r\n"
   
4. dbg: gdb(mingw gdb), windbg, x64dbg
   + gdb.attach(p, script="b *0x401000")
   + windbg.attach(p,script="bp 0x123456")
   + x64dbg.attach(p) #can not parse script file yet
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
> because lacks some commandline options, so just can use x64dbg attach to process and can not convert init script yet
