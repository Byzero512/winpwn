# winpwn
mini pwntools on windows

1. process
2. remote
3. context
4. dbg: gdb(mingw gdb), windbg, x64dbg

> testing

## problems:
1. how to wait for debugger attach? gdb is completed;
2. how to use ".shell" on windbg?? It always error;
3. for x64dbg, it has no command line options to exec cmd when attach

## pre
1. based on pythonforwindows, pwintools

## install
1. pip install pythonforwindows
2. git clone https://github.com/Byzero512/winpwn.git
3. python setup.py install

## tips
1. to use gdb(lke gdb-peda): you need 
  + wibe: https://github.com/Byzero512/wibe
  + vmmap: https://github.com/Byzero512/vmmap-win-cmd
2. for debuggers, you need to modify the PATH of debugger in var.py
3. for terminal, I just test on cmder
