from .context import context
from .misc import Latin1_encode,Latin1_decode

def disasm(machine_code,addr=0):
    import capstone
    machine_code=Latin1_encode(machine_code)
    disasmer=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if context.arch=="amd64":
        disasmer=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    l=""
    for i in disasmer.disasm(machine_code,addr):
        l+="{:8s} {};\n".format(i.mnemonic,i.op_str)
    return Latin1_decode(Latin1_encode(l.strip('\n')))

def asm(asm_code,addr=0):
    import keystone
    asm_code=Latin1_encode(asm_code)
    asmer=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_32)
    if context.arch=="amd64":
        asmer=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64)
    l=""
    for i in asmer.asm(asm_code,addr)[0]:
        l+=chr(i)
    return Latin1_decode(Latin1_encode(l.strip('\n')))


