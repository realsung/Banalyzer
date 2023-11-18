import idautils
import idc

func_list = ["strcpy", "printf", "malloc", "free", "strcmp", "strncmp", "gets", "sprintf", "sscanf"]

vuln_func_list = {}

for func in idautils.Functions():
    func_loc = hex(func)
    func_name = idc.get_func_name(func)
    if func_name in func_list:
        print("Found: ", func_loc, func_name)
        vuln_func_list.setdefault(func_name, func_loc)


print(vuln_func_list)