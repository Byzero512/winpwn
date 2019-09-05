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

   1. endian="little"

   1. log\_level=None

   1. terminal=None

   1. newline=None \(because newline may be "\\n" or "\\r\\n", default is "\\r\\n", you can set it with this attr\)
1. dbg: gdb\(mingw gdb\), windbg, x64dbg

   1. gdb\.attach\(p, script="b \*0x401000"\)

   1. x64dbg\.attach\(p\): can not parse script file yet

   1. windbg\.attach\(p\): can not parse script file yet



### others

for gdb\-peda like show  as bellow, you need:

1. https://github.com/Byzero512/wibe
1. https://github.com/Byzero512/vmmap\-win\-cmd
2. for debuggers, you need to modify the PATH of debugger in winpwn/var.py
3. for terminal, I just test on cmder

## photos
![enter description here](./img/winpwn1.png)
