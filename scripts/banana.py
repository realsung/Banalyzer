import idautils
import idc
import idaapi

vuln_func_list = ['strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 'memmove', 'fread', 'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW', 'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy', 'StrCpyN', 'strcatA', 'strcatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', 'StrCatN', 'StrCatNA', 'StrCatNW', 'strncatA', 'strncatW', 'wcsncat', 'StrCatN', 'StrCatNA', 'StrCatNW', 'sprintfA', 'sprintfW', 'wsprintf', 'wsprintfA', 'wsprintfW', 'sprintfW', 'sprintfA', 'swprintf', 'swprintfA', 'swprintfW', 'vswprintf', 'vswprintfA', 'vswprintfW', 'vsprintfA', 'vsprintfW', 'vsprintf', 'strcpyA', 'strcpyW', 'wcscpy', 'StrCpy', 'lstrcpy', 'lstrcpyA', 'lstrcpyW', 'StrCpyA', 'StrCpyW', 'lstrcpyn', 'lstrcpynA', 'lstrcpynW', 'StrCpyNW', 'StrCpyNA', 'StrNCpy', 'strncpyA', 'strncpyW', 'wcsncpy', 'StrCpyN', 'strcatA', 'strcatW', 'lstrcat', 'lstrcatA', 'lstrcatW', 'StrCat', 'StrCatA', 'StrCatW', 'StrCatBuff', 'StrCatBuffA', 'StrCatBuffW', 'StrCatChainW', 'StrCatN', 'StrCatNA','malloc', 'free']
vuln_func_called_list = {}
func_list = {}

vuln_func_list += ['.' + func_name for func_name in vuln_func_list]

def find_functions():
    user_defined_functions = {}
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        user_defined_functions[func_name] = func_ea
    return user_defined_functions

def main():
    functions = find_functions()

    for func_name, func_address in functions.items():
        print(f"Function '{func_name}' found at address: 0x{func_address:08X}")
        func_list[func_name] = f"0x{func_address:08X}"

    for func in idautils.Functions():
        func_name = idc.get_func_name(func)
        if func_name in vuln_func_list:
            func_loc = hex(func)
            print("Found: ", func_loc, func_name)
            vuln_func_called_list.setdefault(func_name, func_loc)

    main_func = idc.get_name_ea_simple("main")
    if main_func == idaapi.BADADDR:
        print("Main function not found")
        return

    calls = []
    calls_func = []
    for i in func_list.keys():
        for j in vuln_func_called_list.keys():
            caller_ea = idc.get_name_ea_simple(i)
            target_ea = idc.get_name_ea_simple(j)
            
            for (startea, endea) in idautils.Chunks(caller_ea):
                for head in idautils.Heads(startea, endea):
                    if idc.print_insn_mnem(head) == "call":
                        target_address = idc.get_operand_value(head, 0)
                        if target_address == target_ea:
                            calls.append(hex(head))
                            if i not in calls_func:
                                calls_func.append(i)

    print(calls_func)



if __name__ == "__main__":
    main()
