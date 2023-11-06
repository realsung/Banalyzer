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
        return idaapi.decompile(self.func).__str__()
    
    
def log(func, msg):
    print(f"[{func.loc}:{func.name}] {msg}")

def check_printf(func) -> list:
    ret = []
    log(func, "Checking printf")
    dec_func = func.get_dec_func().split('\n')
    for line in range(len(dec_func)):
        arg = re.findall(r'printf\((\w+)\)', dec_func[line])
        if arg:
            arg = arg[0].split(',')
            ret.append((line+1,arg))
    return ret
            
def check_fsb(line, arg):
    for a in arg:
        if "%" in a:
            return False
    return True

def main():
    for f in idautils.Functions():
        func = _func(f)
        printf = check_printf(func)
        for line, arg in printf:
            if check_fsb(line, arg):
                log(func, f"FSB found at line {line} with arg {arg}")

main()