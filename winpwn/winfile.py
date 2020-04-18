from .misc import Latin1_decode

class winfile(object):
    def __init__(self,fpath=""):
        self._address=0
        self.imsyms={}
        self.exsyms={}
        self.symbols={}
        self.update(fpath)
    def update(self,fpath):
        import pefile
        pe=pefile.PE(fpath)
        if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # l={}
                # print(entry.dll)
                for imp in entry.imports:
                    self.imsyms.update({
                            Latin1_decode(imp.name):self._address+imp.address-pe.OPTIONAL_HEADER.ImageBase,
                        }
                    )
        if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                # print(hex(pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions+4*(exp.ordinal-1)))
                # print(hex(exp.address))         # EAT element value
                # print(exp.name)                  # str: funcname
                self.exsyms.update({
                        Latin1_decode(exp.name):self._address+pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions+4*(exp.ordinal-1)
                    }
                )
        self.symbols.update(self.exsyms)
        self.symbols.update(self.imsyms)
    
    @property
    def address(self):
        return self._address
    @address.setter
    def address(self,base):
        self._address=base
        for sym in self.imsyms:
            self.imsyms.update({sym:base+self.imsyms[sym]})
        for sym in self.exsyms:
            self.exsyms.update({sym:base+self.exsyms[sym]})
        self.symbols.update(self.exsyms)
        self.symbols.update(self.imsyms)
        
            
