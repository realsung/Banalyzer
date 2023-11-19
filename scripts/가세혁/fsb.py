import re
import idautils
import idc
import idaapi
import sys

class _func:
    def __init__(self, f):
        self.func = f
        self.loc = hex(f)
        self.name = idc.get_func_name(f)
        try:
            self.var = idaapi.decompile(self.func).get_lvars()
        except:
            self.var = []
    def get_dec_func(self):
        try:
            return idaapi.decompile(self.func).__str__()
        except:
            return ""
    

logger = open("C:\\Users\\Public\\idatlog.txt", "a")
    
def log(func, msg):
    print(f"[{func.loc}:{func.name}] {msg}")
    sys.stdout.write(f"[{func.loc}:{func.name}] {msg}")
    logger.write(f"[{func.loc}:{func.name}] {msg}\n")

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

def print_func(func):
    print(f"Function: {func.name}")
    print(f"Location: {func.loc}")
    print(f"Decompiled: {func.get_dec_func()}")
    print(f"Var: {func.var}")

def main():
    idc.auto_wait()
    for f in idautils.Functions():
        func = _func(f)
        #print_func(func)
        printf = check_printf(func)
        for line, arg in printf:
            if check_fsb(line, arg):
                log(func, f"FSB found at line {line} with arg {arg}")

main()
logger.close()
idc.qexit(0)