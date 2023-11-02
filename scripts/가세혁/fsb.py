import re
import idautils
import idc
import idaapi

class _func:
    def __init__(self, f):
        self.func = f
        self.loc = hex(f)
        self.name = idc.get_func_name(f)
    def get_dec_func(self):
        return idaapi.decompile(self.func)
    
def log(func, msg):
    print(f"[{func.hex}:{func.name}] {msg}")

def check_printf(func):
    log(func, "Checking printf")
    dec_func = func.get_dec_func().split("\n")
    for line in range(len(dec_func)):
        printf = re.findall(r'printf\(\"(.*)\"\)', dec_func[line])
    print(printf)

def main():
    for f in idautils.Functions():
        func = _func(f)


print(main())