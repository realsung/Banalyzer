import re
# import idautils
# import idc
# import idaapi

input_vars = []


def checkScanf(dec_funcc, funcname):
    input_var = re.findall(r'scanf\(\"%s\", (\w+)\)', str(dec_funcc))
    if input_var:
        print("[FROM", funcname,"]Input var(scanf): ", input_var)
        for var in input_var:
            pattern = re.compile(f'(\w+)\(.*{var}')
            input_use = re.findall(pattern, str(dec_funcc))
            if input_use:
                print("[FROM", funcname,"]Input var(", var, "): ", input_use)
                input_vars.append(var)
    else :
        print("[FROM", funcname,"]Input var(scanf): ", "None")

def checkGets(dec_funcc, funcname):
    input_var = re.findall(r'gets\((\w+)\)', str(dec_funcc))
    if input_var:
        print("[FROM", funcname,"]Input var(gets): ", input_var)
        for var in input_var:
            pattern = re.compile(f'(\w+)\(.*{var}')
            input_use = re.findall(pattern, str(dec_funcc))
            if input_use:
                print("[FROM", funcname,"]Input var(", var, "): ", input_use)
                input_vars.append(var)
    else :
        print("[FROM", funcname,"]Input var(gets): ", "None")

def checkStrcpy(dec_funcc, src_var, funcname):
    dst_var = re.compile(f'strcpy\((\w+), {src_var}\)').findall(str(dec_funcc))
    for var in dst_var:
        if var in input_vars:
            pass
        else:
            for var in dst_var:
                pattern = re.compile(f'(\w+)\(.*{var}')
                input_use = re.findall(pattern, str(dec_funcc))
                if input_use:
                    print(f"[FROM", funcname,f"]strcpy, {src_var} -> {var}\n[{var}] Used in:", input_use)
                input_vars.append(dst_var)
                checkStrcpy(dec_funcc, var, funcname)
    else :
        print("[FROM", funcname,"]Input var(strcpy): ", "None")

def find_path_traversal(dec_funcc, funcname):
    regex_path = r'.+(?=:)  \/.*'
    path_traversal = re.findall(regex_path, str(dec_funcc))
    print(path_traversal)

find_path_traversal("/etc/passwd", "main")

def main():
    for func in idautils.Functions():
        func_loc = hex(func)
        func_name = idc.get_func_name(func)
        for (startea, endea) in idautils.Chunks(func):
            funcc = idaapi.get_func(startea)
            assert funcc is not None
            try :
                dec_funcc = idaapi.decompile(funcc)
            except idaapi.DecompilationFailure:
                continue
            assert dec_funcc is not None
            # if func_name == "main":
            #     print("Found: ", func_loc, func_name)
            #     print(dec_funcc)
            #     print("Functions: ", re.findall(r'(\w+)\(', str(dec_funcc)))
            print("Found: ", func_loc, func_name)
            # if func_name != "_main":
            #     continue
            func_list = re.findall(r'(\w+)\(', str(dec_funcc))
            print(func_list)
            #func_list.remove(func_name)
            if "scanf" in func_list:
                checkScanf(dec_funcc, func_name)
            if "gets" in func_list:
                checkGets(dec_funcc, func_name)
            if "strcpy" in func_list:
                for var in input_vars:
                    checkStrcpy(dec_funcc, var, func_name)