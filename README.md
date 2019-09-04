# winpwn
mini pwntools on windows

1. process
2. remote
3. context
4. dbg: gdb(mingw gdb), windbg, x64dbg

> testing

## problems:
1. how to wait for debugger attach? 
3. I am not familiar with windbg and x64dbg, so the support with them may be not quite useful yet

## pre
1. based on pwintools, but I complete the part of IO interact

## install
1. pip install pythonforwindows
2. git clone https://github.com/Byzero512/winpwn.git
3. python setup.py install

## tips
1. to use gdb(lke gdb-peda): you need
  + wibe: https://github.com/Byzero512/wibe
  + vmmap: https://github.com/Byzero512/vmmap-win-cmd
  + if you use cmder, please run in "cmd::cmder as admin", can not run in "bash"
2. for debuggers, you need to modify the PATH of debugger in winpwn/var.py
3. for terminal, I just test on cmder

## photos
![enter description here](./img/winpwn1.png)
