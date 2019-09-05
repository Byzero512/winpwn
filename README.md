## winpwn: mini pwntools on windows

### pre

> base on pwintools, but I complete the parts of IO interactive and debug

## install

1. git clone  https://github.com/Byzero512/winpwn.git
1. cd winpwn
1. pip install pythonforwindows
1. python setup.py install





### usage

1. process

   1. process\("./pwn"\)
1. remote

   1. remote\("127.0.0.1", 65535\)
1. context

   1. context\.timeout=None

   1. context\.debugger=None

   1. context\.endian="little"

   1. context\.log\_level=""

   1. context\.terminal=\[\]

   1. context\.newline=None \(because newline may be "\\n" or "\\r\\n", default is "\\r\\n", you can set it with this attr\)
1. dbg: gdb\(mingw gdb\), windbg, x64dbg

   1. gdb\.attach\(p, script="b \*0x401000"\)

   1. x64dbg\.attach\(p\,script="bp 0x123456")

   1. windbg\.attach\(p\): can not parse script file yet

### demands
1. shellcode(I delete this funcitons exisit in pwintools, because I do not want to import too many deps)
2. complete debugger module for x64dbg and windbg(I have no good idea to wait for debugger to let it have enough time to execs the command when attach to it, and I am not familiar with x64dbg and windbg) 


### others

for gdb-peda like show  as bellow, you need:

1. https://github.com/Byzero512/wibe (a gdb-peda like gdb-script supports mingw-gdb on windows)
1. https://github.com/Byzero512/vmmap-win-cmd (for the command "vmmap" on wibe)
2. for debuggers, you need to modify the PATH of debugger in <b>winpwn/var.py</b>
3. I just test winpwn on cmder(please use <b>"cmd::cmder as Admin"</b>, not bash)

## photos

### mingw gdb

![gdb](./img/winpwn1.png)

### windbg
![windbg](./img/winpwn2.png)
