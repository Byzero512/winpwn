# attaching=False
ter=None             # obj create by subProcess.Popen

# debug_path
debugger={
    'i386':{
        'windbg':'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\windbg.exe',
        'x64dbg':'F:\\ctfTools\debugTools\\x64debug\\release\\x32\\x32dbg.exe',
        #'gdb':'F:\\ctfTools\\windows-gdb\\mingw-w64-686\\mingw32\\bin\\gdb.exe',
        'gdb':'gdb.exe',
    },
    'amd64':{
        'windbg':'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\windbg.exe',
        'x64dbg':'F:\\ctfTools\debugTools\\x64debug\\release\\x64\\x64dbg.exe',
        # 'gdb':'F:\\ctfTools\\windows-gdb\\mingw-w64-64\\mingw64\\bin\\gdb64.exe',
        'gdb':'gdb64.exe',
    }
}