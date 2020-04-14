# -*- coding=Latin1 -*-
class context():
    # init
    terminal=[]

    # basic
    arch='i386'
    endian='little'
    log_level=""
    timeout=512
    tick=0.0625
    length=None
    newline='\r\n'
    pie=None

    # input output
    noout=None
    nocolor=None

    # debug
    dbginit=""
    gdb=None
    windbg=None
    windbgx=None
    x64dbg=None


    # dev
    devdebug=False