import re
import idautils
import idc
import idaapi
import ida_frame
import ida_hexrays
from idautils import FuncItems
from idaapi import PluginForm

class _func:
    def __init__(self, f):
        self.func = idaapi.get_func(f)
        self.loc = hex(f)
        self.name = idc.get_func_name(f)  # 함수의 이름

    def get_dec_func(self) -> str:
        try:
            return idaapi.decompile(self.func).__str__()
        except:
            return "ERROR"

fsb_vuln_func = ['printf', 'sprintf', 'fprintf', 'snprintf']
fsb_strcpy_func = ['strcpy', 'strncpy', 'strcat', 'strncat']

system_func_list = [
    'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 
    'memmove', 'fread', 'malloc', 'free', 'read', 'write', 'system', 'exec', 'popen'
]

exec_func_list = [
    'system', 'exec', 'popen', 'ShellExecute', 'ShellExecuteA', 'ShellExecuteW',
    'CreateProcess', 'CreateProcessA', 'CreateProcessW'
]

def analyze_function(f):  # 여기서 'f'는 함수의 주소
    func = _func(f)  # _func 클래스의 인스턴스 생성
    dec_func = func.get_dec_func()
    results = []
    
    failed_result = []
    
    if dec_func == "ERROR":
        results.append(f"Could not decompile function {func.name} at {func.loc}")
    else:
        for vuln_func in system_func_list + exec_func_list:
            if vuln_func in dec_func:
                results.append(f"Potentially vulnerable or dangerous function '{vuln_func}' found in {func.name} at {func.loc}")
                
        vulns = check_fsb_vuln(func)
        
        for line, arg in vulns:
            results.append(f"FSB vulnerability found? : {func.name} at {line} with arg {arg}")
            
        
    return '\n'.join(results)

def xrefs_var(func, var, origin_line):
    varalpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"
    dec_func = func.get_dec_func()
    xrefs = []
    xrefs.append((origin_line, var))
    for line, code in enumerate(dec_func.split('\n')):
        if var in code:
            if line >= origin_line:
                continue
            if code[code.index(var)+ len(var)] in varalpha:
                continue
            for strcpy in fsb_strcpy_func:
                if strcpy in code:
                    args = re.findall(rf'{strcpy}(\(.+\))\;', code)
                    if args:
                        arg_list = args[0].split(',')
                        xrefs.append((line + 1, re.findall(rf'(.+)', arg_list[-1])[0]))
                        if xrefs and "\"" in xrefs[-1][1] or "'" in xrefs[-1][1]:
                            continue
                        xrefs_var(func, xrefs[-1][1], line)
    return xrefs

def check_fsb_vuln(func) -> list:
    ret = []
    dec_func = func.get_dec_func().split('\n')
    for line, code in enumerate(dec_func):
        for vuln_func in fsb_vuln_func:
            if vuln_func in code:
                args = re.findall(rf'{vuln_func}(\(.+\))\;', code)
                if args:
                    arg_list = args[0].split(',')
                    if not any("%" in arg for arg in arg_list):
                        var = arg_list[-1]
                        var = re.findall(rf'(\w+)', var)[-1]
                        xrefs = xrefs_var(func, var, line)
                        if len(xrefs) == 1:
                            ret.append((xrefs[0][0], xrefs[0][1]))
                            continue
                        for xref in xrefs[1:]:
                            if "\"" in xref[1]:
                                continue
                            ret.append((xref[0], xref[1]))

    return ret

for f in idautils.Functions():
    result = analyze_function(f)
    print(result)