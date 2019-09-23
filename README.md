## winpwn: mini pwntools for Windows
for CTF windows pwn

### pre
1. there are two versions of winpwn: winpwn-deps and winpwn-nodeps
2. for winpwn-deps: based on pwintools,but I complete the IO interactive and debug module
3. for winpwn-nodeps: written by myself. 
   + just use ctypes to invoke Windows API. 
   + It supports python2.7 and python3
   + can<b>use pip to install winpwn-nodeps</b>(pip install winpwn)


## install
1. if you want to debug, 
   + if you install by source code, modify the path of modify the PATH of debugger in <b>winpwn/var.py</b>
   + or if you use <b>winpwn-nodeps</b>, you can also create a json file in HOME dir(named "<b>.winpwn</b>"). Its content format refers winpwn-nodeps/.winpwn
2. <b>I just test winpwn on cmder</b>(if use cmder , please must use it on <b>"cmd::cmder as Admin"</b>, not bash)

### winpwn-nodeps

#### install from source code
1. git clone  https://github.com/Byzero512/winpwn.git
2. cd winpwn\winpwn-nodeps
3. python setup.py install / python3 setup.py install

#### pip
   + <b>pip install winpwn </b>
   + <b>or pip3 install winpwn</b>


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
if you want to use debugger module, you need to deal with the deps yourself

#### mingw-gdb
for gdb-peda like show  as bellow, you need:
mingw-gdb installer: https://sourceforge.net/projects/mingw-w64/files/External%20binary%20packages%20%28Win64%20hosted%29/gdb/

1. https://github.com/Byzero512/wibe (a gdb-peda like gdb-script supports mingw-gdb on windows)
2. https://github.com/Byzero512/vmmap-win-cmd (for the command "vmmap" in wibe)

#### windbg
1. pykd
2. TWindbg: https://github.com/bruce30262/TWindbg


## photos

### mingw gdb

![gdb](./img/winpwn1.png)

### windbg

![windbg](./img/winpwn2.png)

### x64dbg
not support {x64dbg.attach(p,"b*??")} yet
