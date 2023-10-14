import re
import idautils
import idc
import idaapi

input_vars = ['cdd']

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
        #     print("Functions: ", re.findall(r'(\w+)\(', str(dec_funcc)).pop())
        print("Found: ", func_loc, func_name)
        if func_name != "_main":
            continue
        func_list = re.findall(r'(\w+)\(', str(dec_funcc))
        print(func_list)
        #func_list.remove(func_name)
        if "scanf" in func_list:
            input_var = re.findall(r'scanf\(\"%s\", (\w+)\)', str(dec_funcc))
            if input_var:
                print("Input var(scanf): ", input_var)
                for var in input_var:
                    pattern = re.compile(f'(\w+)\(.*{var}')
                    input_use = re.findall(pattern, str(dec_funcc))
                    if input_use:
                        print("Input var(", var, "): ", input_use)
                        input_vars.append(var)
            else :
                print("Input var(scanf): ", "None")
        if "gets" in func_list:
            input_var = re.findall(r'gets\((\w+)\)', str(dec_funcc))
            if input_var:
                print("Input var(gets): ", input_var)
                for var in input_var:
                    pattern = re.compile(f'(\w+)\(.*{var}')
                    input_use = re.findall(pattern, str(dec_funcc))
                    if input_use:
                        print("Input var(", var, "): ", input_use)
                        input_vars.append(var)
            else :
                print("Input var(gets): ", "None")
        if "strcpy" in func_list:
            input_var = re.findall(r'strcpy\(\w+, (\w+)\)', str(dec_funcc))
            for var in input_var:
                if var in input_vars:
                    print("Input var(strcpy): ", input_var)
                    for var in input_var:
                        pattern = re.compile(f'(\w+)\(.*{var}')
                        input_use = re.findall(pattern, str(dec_funcc))
                        var_to = re.findall(r'strcpy\((\w+), \w+\)', str(dec_funcc))
                        if input_use:
                            print("Copy var from(", var, ") to (", var_to, "): ", input_use)
            else :
                print("Input var(strcpy): ", "None")
