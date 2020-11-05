from .context import context
from .misc import Latin1_encode,Latin1_decode

def disasm(machine_code,addr=0,arch=None):
    """
    Disassemble a machine code.

    Args:
        machine_code: (str): write your description
        addr: (str): write your description
        arch: (array): write your description
    """
    import capstone
    machine_code=Latin1_encode(machine_code)
    if arch is None:
        arch=context.arch
    if arch=='i386':
        disasmer=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif arch=="amd64":
        disasmer=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    l=""
    for i in disasmer.disasm(machine_code,addr):
        l+="{:8s} {};\n".format(i.mnemonic,i.op_str)
    return Latin1_decode(Latin1_encode(l.strip('\n')))

def asm(asm_code,addr=0,arch=None):
    """
    Returns the code ascii.

    Args:
        asm_code: (str): write your description
        addr: (str): write your description
        arch: (str): write your description
    """
    import keystone
    asm_code=Latin1_encode(asm_code)
    if arch is None:
        arch=context.arch
    if arch=='i386':
        asmer=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_32)
    elif arch=="amd64":
        asmer=keystone.Ks(keystone.KS_ARCH_X86,keystone.KS_MODE_64)
    l=""
    for i in asmer.asm(asm_code,addr)[0]:
        l+=chr(i)
    return Latin1_decode(Latin1_encode(l.strip('\n')))


